// #define _GNU_SOURCE // g++ does this for us
#include <new>
#include <vector>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <algorithm>
#include <thread>
#include <sstream>

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <cassert>

#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#include "utility.hpp"
#include "hash.hpp"
#include "ws.hpp"

/*
 * Scaling read() and write() needs edge-trigger + EPOLLONESHOT, to prevent race
 * condition where two thread both read incomplete (and maybe reordered) data of
 * one socket.
 * After reading or writing, this fd need to EPOLL_CTL_MOD again with this mask.
 */
constexpr uint32_t CONN_SOCK_RECV_EVENT_MASK = EPOLLIN | EPOLLET | EPOLLONESHOT;
constexpr uint32_t CONN_SOCK_SEND_EVENT_MASK = EPOLLOUT | EPOLLONESHOT;

constexpr int BUFSIZE = 4096;
// print error and exit when ret == -1
static int guard(int ret, const char *errmsg)
{
	if (ret == -1) {
		perror(errmsg);
		exit(EXIT_FAILURE);
	} else {
		return ret;
	}
}

const char *filename = "msg.txt";
void handle_frame(Frame *frame, FILE *file)
{
	int nwritten = fwrite(frame->payload.data(), 1, frame->payload.size(),
			file);
	fprintf(stderr, "write file: nwritten = %d, payload size %lu\n",
			nwritten, frame->payload.size());
	if (nwritten < frame->payload.size()) {
		perror("write file failed");
	}

	if (frame->fin) {
		fclose(file);
	}
}

enum WsState {
	HANDSHAKE,
	FRAME_HEADER,
	FRAME_PAYLOAD,

	// after parsing a complete frame, make sure next buffer aligns with next
	// unhandled frame.
	FRAME_HANDLE_REMAINING_BUFFER,

	FRAME_COMPLETE,
};
class EpollContext {
public:
	const size_t len = BUFSIZE;
	int fd;
	int epfd;
	int send_epfd;
	void * const buf; // nullptr if this fd is a listen sock

	EpollContext(int fd, int epfd, int send_epfd)
		: EpollContext(fd, epfd, send_epfd, operator new(BUFSIZE)) { }

	EpollContext(int fd, int epfd, int send_epfd, void *buf)
		: fd{fd}, epfd{epfd}, send_epfd{send_epfd}, buf{buf} {
			if (buf != nullptr) { // not a listen sock
				std::stringstream ss;
				ss << filename << '-' << fd;
				auto fname = ss.str();

				file = fopen(fname.c_str(), "w+");
				if (!file) {
					perror(fname.c_str());
					exit(EXIT_FAILURE);
				}
			}
		}

	~EpollContext() {
		// TODO remove self from some external lookup map
		lock_queues();
		operator delete(buf);
	}

	/*
	 * `len`: valid content length of buffer.
	 *
	 * Copy contents from temporary `buf` to `recv_queue`. Only call this
	 * function if `buf` has reasonable content.
	 */
	void process_buf(size_t len) {
		using namespace std;

		copy_to_recv_queue(buf, len);

		// now that we've waken up, we might have enough buffer to parse into
		// header or frames.
		parse();
	}

	void push_send_queue(const std::vector<u8> &buf) {
		std::scoped_lock lock(send_mtx);
		send_queue.push_back(buf);
		try_add_to_send_epoll();
	}

	/*
	 * Pops first item from send queue. If the queue is empty, remove this fd
	 * from send epoll.
	 * Note that locking is required when epoll_ctl'ing because we want to keep
	 * the consistency of SEND_QUEUE and EPOLLOUT.
	 */
	std::vector<u8> pop_send_queue() {
		std::scoped_lock lock(send_mtx);
		if (send_queue.empty()) {
			guard(epoll_ctl(send_epfd, EPOLL_CTL_DEL, fd, NULL),
					"failed removing from send epoll");
			return std::vector<u8>();
		}
		auto vec = send_queue.front();
		send_queue.pop_front();
		return vec;
	}

	/*
	 * insert VEC to the beginning of SEND_QUEUE, in case the popped vec is not
	 * completely written and needs to write next time.
	 */
	void unget_send_queue(std::vector<u8> &vec) {
		std::scoped_lock lock(send_mtx);
		send_queue.push_front(vec);
		try_add_to_send_epoll();
	}

	void rearm_send_epoll() {
		fprintf(stderr, "[debug] re-arm send\n");
		struct epoll_event ev;
		ev.data.ptr = this;

		ev.events = CONN_SOCK_SEND_EVENT_MASK;
		guard(epoll_ctl(send_epfd, EPOLL_CTL_MOD, fd, &ev),
			"re-arm send epoll failed");
	}

	void rearm_recv_epoll() {
		fprintf(stderr, "[debug] re-arm recv\n");
		struct epoll_event ev;
		ev.data.ptr = this;

		ev.events = CONN_SOCK_RECV_EVENT_MASK;
		guard(epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev),
			"re-arm recv epoll failed");
	}

private:
	enum WsState state = HANDSHAKE;
	std::mutex send_mtx;
	std::condition_variable send_cv;

	// these deques are inserted at the end, and removed from the front
	std::deque<std::vector<u8>> send_queue;
	std::deque<std::vector<u8>> recv_queue;

	FILE *file = nullptr;

	// current parsing frame
	Frame *frame = nullptr;
	// total bytes copied to current frame payload.
	// only used in parse().
	u64 ncopied = 0;
	// start position of unprocessed data in a buffer
	u64 buf_start;

	void copy_to_recv_queue(void *buf, size_t len) {
		recv_queue.emplace_back(len);
		memmove(recv_queue.back().data(), buf, len);
	}

	void lock_queues() {
		send_mtx.lock();
	}

	/*
	 * Try to add this socket to send epoll.
	 * If already in send epoll then do nothing.
	 *
	 * Will panic on other errors.
	 */
	void try_add_to_send_epoll() {
		fprintf(stderr, "[debug] adding send\n");
		struct epoll_event ev;
		ev.events = CONN_SOCK_SEND_EVENT_MASK;
		ev.data.ptr = this;
		int ep_ret = epoll_ctl(send_epfd, EPOLL_CTL_ADD, fd, &ev);
		if (ep_ret == -1) {
			if (errno == EEXIST) {
				// already waiting or processing, do nothing
			} else {
				perror("add to send epoll failed");
				exit(EXIT_FAILURE);
			}
		}
	}

	void parse() {
		using namespace std;

		while (!recv_queue.empty() || state == FRAME_COMPLETE) {
			// auto buf = recv_queue.front();
			// recv_queue.pop_front();

			switch (state) {
			case HANDSHAKE: {
				// TODO read header precisely

				auto &buf = recv_queue.front();
				string header(buf.begin(), buf.end());
				recv_queue.pop_front();
				fprintf(stderr, "[debug] received header:\n%s", header.c_str());
				WsReqHeader req_header(header);

				push_send_queue(req_header.build_success_resp());

				state = FRAME_HEADER;
				break;
			}
			case FRAME_HEADER: {
				fprintf(stderr, "[debug] received frame header\n");

				auto buf = recv_queue.front();
				recv_queue.pop_front();

				int header_len;
				frame = Frame::try_parse_header(buf, header_len);
				if (frame == nullptr) {
					// if this buf contains incomplete frame header

					if (recv_queue.empty()) {
						recv_queue.push_front(buf);
						return; // wait for more buffers
					}

					auto next_buf = recv_queue.front();
					recv_queue.pop_front();

					// try again with larger buffer
					buf.insert(buf.end(), next_buf.begin(), next_buf.end());
					recv_queue.push_front(buf);
					continue;
				}

				WsState intent = frame->payload.size() > 0 ?
					FRAME_PAYLOAD : FRAME_COMPLETE;

				// if buffer contains more than a frame header
				if (header_len < buf.size()) {
					switch (intent) {
					case FRAME_PAYLOAD:
						buf_start = header_len;
						recv_queue.push_front(buf);
						state = FRAME_PAYLOAD;
						break;
					case FRAME_COMPLETE:
						state = FRAME_HANDLE_REMAINING_BUFFER;
						break;
					default:
						fprintf(stderr, "Impossible intent in parse()\n");
						exit(EXIT_FAILURE);
					}
				} else {
					state = intent;
				}

				break;
			}
			case FRAME_PAYLOAD: {
				auto &buf = recv_queue.front();

				assert(frame != nullptr);

				u64 ncopied_now = frame->append_payload(ncopied, buf, buf_start);

				bool buf_has_remaining = buf_start + ncopied_now < buf.size();
				bool frame_complete =
					ncopied + ncopied_now == frame->payload.size();

				if (buf_has_remaining) {
					assert(frame_complete);
					buf_start += ncopied_now;

					//recv_queue.push_front(buf);
					state = FRAME_HANDLE_REMAINING_BUFFER;
					break;
				}

				// current buffer is done.
				recv_queue.pop_front();

				if (frame_complete) {
					state = FRAME_COMPLETE;
				} else {
					assert(!buf_has_remaining);
					ncopied += ncopied_now;
					buf_start = 0;
					state = FRAME_PAYLOAD;
				}

				break;
			}
			case FRAME_HANDLE_REMAINING_BUFFER: {
				auto &buf = recv_queue.front();
				// current frame is all copied. this new `remaining` must
				// starts at next frame border.
				std::vector<u8> remaining(buf.size() - buf_start);
				memmove(remaining.data(), &buf[buf_start],
						buf.size() - buf_start);
				buf = remaining;

				state = FRAME_COMPLETE;
				break;
			}
			case FRAME_COMPLETE: {
				// TODO handle complete frame
				printf("Frame: %s\n", frame->header_to_string().c_str());

				handle_frame(frame, file);

				delete frame;

				ncopied = 0;
				state = FRAME_HEADER;

				break;
			}
			} // switch

		} // while recv_queue !empty
	} // void parse()

};

int create_listen_sock(const char *port)
{
	struct addrinfo hints, *result, *rp;
	int sock, s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	s = getaddrinfo(NULL, port, &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC,
				rp->ai_protocol);

		if (sock == -1)
			continue;
		if (bind(sock, rp->ai_addr, rp->ai_addrlen) == 0)
			break; // success

		close(sock);
	}

	// all addresses failed
	if (rp == NULL) {
		int e = errno;
		fprintf(stderr, "cannot bind on port %s: %s\n", port, strerror(e));
		
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(result);

	listen(sock, 4096);
	return sock;
}

/*
 * Need to check whether peer closes its writing end, i.e. `nread` == 0.
 * Note that this function may invalidate a socket.
 *
 * Returns true when socket is still valid.
 */
bool handle_epollin(struct epoll_event &ev)
{
	EpollContext *ctx = (EpollContext *) ev.data.ptr;
	int sock = ctx->fd;
	void *buf = ctx->buf;

	int nread;
	for (;;) {
		nread = read(sock, buf, ctx->len);
		if (nread == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			// we've exhausted the socket
			break;
		} else if (nread == 0) {
			// peer closed write end, we can now cleanup
			delete ctx;
			close(sock);
			return false;
		} else if (nread > 0) {
			// we have something to read
			ctx->process_buf(nread);
			if (nread < BUFSIZE) // exhausted socket
				break;
		} else {
			perror("process_recv_event read failed");
			exit(EXIT_FAILURE);
		}
	}

	return true;
}

void handle_epollout(struct epoll_event &ev)
{
	EpollContext *ctx = (EpollContext *) ev.data.ptr;
	int sock = ctx->fd;

	std::vector<u8> buf;
	while (!(buf = ctx->pop_send_queue()).empty()) {
		int nwritten = write(sock, buf.data(), buf.size());
		if (nwritten == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			break; // cannot write yet
		} else if ((nwritten == -1) && (errno == EBADF)) {
			// The socket and its EpollContext is closed. Silent ignoring is
			// fine here.
			fprintf(stderr, "EPOLLOUT socket EBADF\n");
			return;
		} else if (nwritten == 0) {
			fprintf(stderr, "fd %d wrote 0 byte, WTF\n", ctx->fd);
			break;
		} else if (nwritten > 0) {
			if (nwritten < buf.size()) {
				std::vector<u8> remaining(buf.size() - nwritten);
				memmove(remaining.data(), buf.data() + nwritten,
						buf.size() - nwritten);

				// We can safely unget the remaining buf back to deque head
				// because we have EPOLLONESHOT in CONN_SOCK_SEND_EVENT_MASK,
				// making current thread the only one processing this socket
				// for EPOLLOUT, i.e. only current thread is manipulating deque
				// head.
				ctx->unget_send_queue(remaining);
			}
			// else if (nwritten == buf.size()): this buf is processed, continue
		} else {
			perror("process_recv_event write failed");
			exit(EXIT_FAILURE);
		}

	}

	if (!buf.empty()) {
		// we didn't (completely) consume this buffer, unget it
		ctx->unget_send_queue(buf);
		ctx->rearm_send_epoll();
	}
}

/*
 * `epfd`: epoll instance for recv.
 */
void process_recv_event(int epfd, struct epoll_event &ev)
{
	bool valid = true;
	if (ev.events & EPOLLIN) {
		// handle_epollin may invalidate current socket
		valid = handle_epollin(ev);
	}

	if (valid) {
		// re-arm into recv epoll because of EPOLLONESHOT (see epoll_ctl(2))
		EpollContext *ctx = (EpollContext *) ev.data.ptr;
		ctx->rearm_recv_epoll();
	}
}

/*
 * `epfd`: epoll instance for sending.
 */
void process_send_event(int epfd, struct epoll_event &ev)
{
	handle_epollout(ev);
}

int create_recv_epfd(const int listen_sock)
{
	struct epoll_event ev;

	int epfd = guard(epoll_create1(EPOLL_CLOEXEC), "create_recv_epfd failed");

	/*
	 * Scaling accept() needs level-trigger + EPOLLEXCLUSIVE, to wake up each
	 * thread with a new incoming connection.
	 * (also see CONN_SOCK_RECV_EVENT_MASK)
	 */
	ev.events = EPOLLIN | EPOLLEXCLUSIVE;
	// listen_sock doesn't need send_epfd and recv buffer
	ev.data.ptr = new EpollContext(listen_sock, epfd, -1, nullptr);
	guard(epoll_ctl(epfd, EPOLL_CTL_ADD, listen_sock, &ev),
			"epoll_ctl: listen_sock");

	return epfd;
}

// Monitoring conn sock to send.
int create_send_epfd()
{
	int epfd = guard(epoll_create1(EPOLL_CLOEXEC), "create_send_epfd failed");
	return epfd;
}

constexpr int MAX_EPOLL_EVENTS = 20;
void recv_event_loop(const int recv_epfd, const int send_epfd, const int listen_sock)
{
	struct epoll_event ev, events[MAX_EPOLL_EVENTS];
	for (;;) {
		fprintf(stderr, "[debug] recv waiting\n");
		int nfds = epoll_wait(recv_epfd, events, MAX_EPOLL_EVENTS, -1);
		if (nfds == -1) {
			if (errno == EINTR) {
				continue; // ignore GDB breakpoint
			} else {
				perror("recv epoll_wait failed");
				exit(EXIT_FAILURE);
			}
		}

		fprintf(stderr, "[debug] received %d recv events\n", nfds);

		for (int i = 0; i < nfds; i++) {
			EpollContext *ctx = (EpollContext *) events[i].data.ptr;
			if (ctx->fd == listen_sock) {
				int conn_sock = guard(accept4(listen_sock, NULL, NULL,
							SOCK_NONBLOCK | SOCK_CLOEXEC), "cannot accept");
				fprintf(stderr, "[debug] accepted\n");

				ev.events = CONN_SOCK_RECV_EVENT_MASK;
				ev.data.ptr = new EpollContext(conn_sock, recv_epfd, send_epfd);

				guard(epoll_ctl(recv_epfd, EPOLL_CTL_ADD, conn_sock, &ev),
						"epoll_ctl: cannot add conn_sock");
			} else {
				// if epoll'ed a conn_sock
				process_recv_event(recv_epfd, events[i]);
			}
		}
	}
}

/*
 * `epfd`: the epoll instance for sending.
 */
void send_event_loop(const int epfd)
{
	struct epoll_event events[MAX_EPOLL_EVENTS];
	for (;;) {
		fprintf(stderr, "[debug] send waiting\n");
		int nfds = epoll_wait(epfd, events, MAX_EPOLL_EVENTS, -1);
		if (nfds == -1) {
			if (errno == EINTR) {
				continue; // ignore GDB breakpoint
			} else {
				perror("send epoll_wait failed");
				exit(EXIT_FAILURE);
			}
		}
		fprintf(stderr, "[debug] ready to send to %d sockets\n", nfds);

		for (int i = 0; i < nfds; i++) {
			process_send_event(epfd, events[i]);
		}
	}
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "[debug] usage: epd <port>\n");
		exit(EXIT_FAILURE);
	}

	if (argc == 3) {
		filename = argv[2];
	}

	int listen_sock = create_listen_sock(argv[1]);
	int recv_epfd = create_recv_epfd(listen_sock);
	int send_epfd = create_send_epfd();

	std::thread send_loop(send_event_loop, send_epfd);
	recv_event_loop(recv_epfd, send_epfd, listen_sock);
}
