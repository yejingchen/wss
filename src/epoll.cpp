#include "epoll.hpp"

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

EpollContext::EpollContext(int fd, int epfd, int send_epfd)
	: EpollContext(fd, epfd, send_epfd, operator new(BUFSIZE)) { }

EpollContext::EpollContext(int fd, int epfd, int send_epfd, void *buf)
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

EpollContext::~EpollContext() {
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
void EpollContext::process_buf(size_t len) {
	using namespace std;

	copy_to_recv_queue(buf, len);

	// now that we've waken up, we might have enough buffer to parse into
	// header or frames.
	parse();
}

void EpollContext::push_send_queue(const std::vector<u8> &buf) {
	std::scoped_lock lock(send_mtx);
	send_queue.push_back(buf);
	try_add_to_send_epoll();
}

std::vector<u8> EpollContext::pop_send_queue() {
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
void EpollContext::unget_send_queue(std::vector<u8> &vec) {
	std::scoped_lock lock(send_mtx);
	send_queue.push_front(vec);
	try_add_to_send_epoll();
}

void EpollContext::rearm_send_epoll() {
	fprintf(stderr, "[debug] re-arm send\n");
	struct epoll_event ev;
	ev.data.ptr = this;

	ev.events = CONN_SOCK_SEND_EVENT_MASK;
	guard(epoll_ctl(send_epfd, EPOLL_CTL_MOD, fd, &ev),
			"re-arm send epoll failed");
}

void EpollContext::rearm_recv_epoll() {
	fprintf(stderr, "[debug] re-arm recv\n");
	struct epoll_event ev;
	ev.data.ptr = this;

	ev.events = CONN_SOCK_RECV_EVENT_MASK;
	guard(epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev),
			"re-arm recv epoll failed");
}

void EpollContext::copy_to_recv_queue(void *buf, size_t len) {
	recv_queue.emplace_back(len);
	memmove(recv_queue.back().data(), buf, len);
}

void EpollContext::lock_queues() {
	send_mtx.lock();
}

/*
 * Try to add this socket to send epoll.
 * If already in send epoll then do nothing.
 *
 * Will panic on other errors.
 */
void EpollContext::try_add_to_send_epoll() {
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

void EpollContext::parse() {
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
				buf_start = header_len;
				recv_queue.push_front(buf);

				switch (intent) {
				case FRAME_PAYLOAD:
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
				buf_start = 0;
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
			memmove(remaining.data(), &buf[buf_start], remaining.size());
			buf = remaining;

			state = FRAME_COMPLETE;
			break;
		}
		case FRAME_COMPLETE: {
			// TODO handle complete frame
			printf("Frame: %s\n", frame->header_to_string().c_str());

			handle_frame(frame, file);

			delete frame;
			frame = nullptr;

			ncopied = 0;
			state = FRAME_HEADER;

			break;
		}
		} // switch

	} // while recv_queue !empty
} // void parse()
