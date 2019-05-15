// #define _GNU_SOURCE // g++ does this for us

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <csignal>
#include <mqueue.h>

#include "common.hpp"
#include "utility.hpp"
#include "hash.hpp"
#include "ws.hpp"
#include "epoll.hpp"

/*
 * Scaling read() and write() needs edge-trigger + EPOLLONESHOT, to prevent race
 * condition where two thread both read incomplete (and maybe reordered) data of
 * one socket.
 * After reading or writing, this fd need to EPOLL_CTL_MOD again with this mask.
 */


/*
 * Mask all signals from current thread.
 */
void mask_all_sig(void)
{
	sigset_t set;
	sigfillset(&set);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
}

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

int create_recv_epfd(const int listen_sock, const mqd_t mqd)
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
			"create recv: listen_sock");

	ev.events = EPOLLIN;
	ev.data.ptr = new EpollContext(mqd, epfd, -1, nullptr);
	guard(epoll_ctl(epfd, EPOLL_CTL_ADD, mqd, &ev), "create recv: add mqd");

	return epfd;
}

// Monitoring conn sock to send.
int create_send_epfd()
{
	int epfd = guard(epoll_create1(EPOLL_CLOEXEC), "create_send_epfd failed");
	return epfd;
}

constexpr int MAX_EPOLL_EVENTS = 20;
void recv_event_loop(const int recv_epfd, const int send_epfd,
		const int listen_sock, const mqd_t mqd)
{
	mask_all_sig();
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
			} else if (ctx->fd == mqd) {
				// We notify to shutdown by closing remote mq peer.
				// But don't remove mqd from epoll, main thread will clean
				// it up
				fprintf(stderr, "recv loop shutting down\n");
				return;
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
void send_event_loop(const int epfd, const mqd_t mqd)
{
	mask_all_sig();
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

	pid_t pid = getpid();
	std::string mq_filename("/wss-mq-");
	mq_filename += pid;
	mqd_t mqd = mq_open(mq_filename.c_str(), O_RDWR | O_CLOEXEC | O_NONBLOCK);

	int listen_sock = create_listen_sock(argv[1]);
	int recv_epfd = create_recv_epfd(listen_sock, mqd);
	int send_epfd = create_send_epfd();

	std::thread send_loop([=]() {
			send_event_loop(send_epfd, mqd);
	});
	std::thread recv_loop([=]() {
			recv_event_loop(recv_epfd, send_epfd, listen_sock, mqd);
	});

	recv_loop.join();

	mq_close(mqd);
	mq_unlink(mq_filename.c_str());
}
