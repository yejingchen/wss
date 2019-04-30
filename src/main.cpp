// #define _GNU_SOURCE // g++ does this for us
#include <new>
#include <map>
#include <queue>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <algorithm>
#include <thread>
#include <functional>
#include <utility>

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>

#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>

// trimming
#include <algorithm>
#include <cctype>
#include <locale>

// trim from start (in place)
static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
        return !std::isspace(ch);
    }));
}

// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}
// trimming end

typedef uint8_t u8;

/*
 * Scaling read() and write() needs edge-trigger + EPOLLONESHOT, to prevent race
 * condition where two thread both read incomplete (and maybe reordered) data of
 * one socket.
 * After reading or writing, this fd need to EPOLL_CTL_MOD again with this mask.
 */
constexpr uint32_t CONN_SOCK_RECV_EVENT_MASK = EPOLLIN | EPOLLET | EPOLLONESHOT;
constexpr uint32_t CONN_SOCK_SEND_EVENT_MASK = EPOLLOUT | EPOLLONESHOT;

constexpr int BUFSIZE = 4096;

enum WsState {
	HANDSHAKE, WEBSOCKET
};

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

std::string string_tolower(std::string s)
{
	std::transform(s.begin(), s.end(), s.begin(),
			[](char c) { return tolower(c); });
	return s;
}

std::string base64_encode(const std::string  &s)
{
	std::string digest;

	CryptoPP::StringSource foo(s, true,
			new CryptoPP::Base64Encoder(
				new CryptoPP::StringSink(digest), /* newline= */ false));

	return digest;
}

std::string sha1_then_base64_encode(const std::string &s)
{
    std::string digest;
    CryptoPP::SHA1 sha1;

    CryptoPP::StringSource foo(s, true,
    new CryptoPP::HashFilter(sha1,
      new CryptoPP::Base64Encoder(
         new CryptoPP::StringSink(digest), /* newline= */ false)));

    return digest;
}

class WsReqHeader {
public:
	WsReqHeader(const std::string &h) {
		using namespace std;
		deque<string> lines = string_split(h, "\r\n");

		first_line = lines.front();
		lines.pop_front();

		for_each(lines.begin(), lines.end(),
				[&](const string &s) {
					int pos = s.find(":");
					auto key = s.substr(0, pos);
					auto value = s.substr(pos + 1);
					trim(key);
					trim(value);
					key = string_tolower(key);
					//value = string_tolower(value);

					headers.insert(pair(key, value));
				});
	}

	bool validate() {
		return true;
	}

	std::vector<u8> build_success_resp() {
		std::string resp;
		resp = "HTTP/1.1 101 Switching Protocols\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Accept: ";
		
		auto req_sec_key = headers.find(SEC_WEBSOCKET_KEY);
		if (req_sec_key == headers.end()) {
			fprintf(stderr, "[FATAL] cannot find Sec-WebSocket-Key in valid"
					" request");
			exit(EXIT_FAILURE);
		}

		std::string key = req_sec_key->second;
		resp += sha1_then_base64_encode(key + KEY_MAGIC);
		resp += "\r\n\r\n";

		return std::vector<u8>(resp.begin(), resp.end());
	}

private:
	std::string first_line;
	std::map<std::string, std::string> headers;

	static const char *HOST, *UPGRADE, *CONNECTION,
				 *SEC_WEBSOCKET_KEY, *SEC_WEBSOCKET_VERSION;
	static const char *KEY_MAGIC;

	std::deque<std::string> string_split(const std::string &s,
			const std::string &delim)
	{
		std::deque<std::string> d;
		int64_t start = 0, pos;

		while ((pos = s.find(delim, start)) != -1) {
			d.emplace_back(s.substr(start, pos - start));
			start = pos + delim.size();
		}

		return d;
	}
};

const char *WsReqHeader::HOST = "host";
const char *WsReqHeader::UPGRADE = "upgrade";
const char *WsReqHeader::CONNECTION = "connection";
const char *WsReqHeader::SEC_WEBSOCKET_KEY = "sec-websocket-key";
const char *WsReqHeader::SEC_WEBSOCKET_VERSION = "sec-websocket-version";
const char *WsReqHeader::KEY_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

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
		: fd{fd}, epfd{epfd}, send_epfd{send_epfd}, buf{buf} { }
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

		// parse handshake or frames
		switch (state) {
		case HANDSHAKE: {
			// TODO parse multiple buffer
			auto buf = recv_queue.front();
			recv_queue.pop_front();
			string header(buf.begin(), buf.end());
			fprintf(stderr, "[debug] received header:\n%s", header.c_str());
			WsReqHeader req_header(header);

			push_send_queue(req_header.build_success_resp());

			state = WEBSOCKET;
			break;
		}
		case WEBSOCKET: {
			fprintf(stderr, "[debug] received frame\n");
			auto buf = recv_queue.front();
			recv_queue.pop_front();
			write(1, buf.data(), buf.size());
			break;
		}
		}
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
		int nfds = guard(epoll_wait(recv_epfd, events, MAX_EPOLL_EVENTS, -1),
				"epoll_wait failed");
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
		int nfds = guard(epoll_wait(epfd, events, MAX_EPOLL_EVENTS, -1),
				"send_event_loop epoll_wait");
		fprintf(stderr, "[debug] ready to send to %d sockets\n", nfds);

		for (int i = 0; i < nfds; i++) {
			process_send_event(epfd, events[i]);
		}
	}
}

int main(int argc, char *argv[])
{
	if (argc == 1) {
		fprintf(stderr, "[debug] usage: epd <port>\n");
		exit(EXIT_FAILURE);
	}

	int listen_sock = create_listen_sock(argv[1]);
	int recv_epfd = create_recv_epfd(listen_sock);
	int send_epfd = create_send_epfd();

	std::thread send_loop(send_event_loop, send_epfd);
	recv_event_loop(recv_epfd, send_epfd, listen_sock);
}
