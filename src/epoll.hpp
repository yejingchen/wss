#pragma once

#include <new>
#include <vector>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <algorithm>
#include <thread>
#include <sstream>

#include <cstring>
#include <cassert>

#include <sys/epoll.h>

#include "ws.hpp"

constexpr uint32_t CONN_SOCK_RECV_EVENT_MASK = EPOLLIN | EPOLLET | EPOLLONESHOT;
constexpr uint32_t CONN_SOCK_SEND_EVENT_MASK = EPOLLOUT | EPOLLONESHOT;

extern const char *filename;
void handle_frame(Frame *frame, FILE *file);

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
	int epfd; // recv epoll
	int send_epfd; // send epoll
	void * const buf; // nullptr if this fd is a listen sock

	EpollContext(int fd, int epfd, int send_epfd);
	EpollContext(int fd, int epfd, int send_epfd, void *buf);
	~EpollContext();

	void process_buf(size_t len);

	void push_send_queue(const std::vector<u8> &buf);
	std::vector<u8> pop_send_queue();
	void unget_send_queue(std::vector<u8> &vec);

	void rearm_send_epoll();
	void rearm_recv_epoll();

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

	void copy_to_recv_queue(void *buf, size_t len);
	void lock_queues();
	void try_add_to_send_epoll();
	void parse();
};
