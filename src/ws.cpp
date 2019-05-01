#define _DEFAULT_SOURCE

#include <sstream>
#include <iostream>
#include <iomanip>

#include <arpa/inet.h>
#include <endian.h>
#include <cstring>

#include "ws.hpp"

const char *WsReqHeader::HOST = "host";
const char *WsReqHeader::UPGRADE = "upgrade";
const char *WsReqHeader::CONNECTION = "connection";
const char *WsReqHeader::SEC_WEBSOCKET_KEY = "sec-websocket-key";
const char *WsReqHeader::SEC_WEBSOCKET_VERSION = "sec-websocket-version";
const char *WsReqHeader::KEY_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

WsReqHeader::WsReqHeader(const std::string &h)
{
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

bool WsReqHeader::validate()
{
	return true;
}

std::vector<u8> WsReqHeader::build_success_resp()
{
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

Frame::Frame()
{
}

u8 *Frame::do_mask(u8 *dst, const u8 *src, u64 len) const
{
	for (u64 i = 0; i < len; i++)
		dst[i] = src[i] ^ masking_key[i & 3u];

	return dst;
}

/*
 * `buf` must start at frame border.
 *
 * Returns nullptr if `buf` doesn't contain complete frame header,
 * otherwise a pointer to a Frame object, with each field extracted from `buf`
 * and payload sapce allocated.
 *
 * `header_len` is an output parameter, when successfully parsed a frame header,
 * `header_len` contains the length of the parsed header. Otherwise it is not
 * modified.
 *
 * This function does not copy frame payload in `buf` to Frame::payload.
 * It merely allocates space enough to hold the whole payload.
 */
Frame *Frame::try_parse_header(const std::vector<u8> buf, int &header_len)
{
	int _header_len = 2;
	Frame *frame = nullptr;

#define check_length() do {\
	if (buf.size() < _header_len) {\
		delete frame;\
		return nullptr;\
	}\
} while (0)

	check_length();

	// parsing length
	u8 len7 = buf[1] & 0x7Fu;
	if (len7 < 126) {
		frame = new Frame();
		frame->payload = std::vector<u8>(len7);
	} else if (len7 == 126) {
		_header_len += 2;
		check_length();

		u16 len16 = *(u16 *) &buf[2];
		len16 = ntohs(len16);

		frame = new Frame();
		frame->payload = std::vector<u8>(len16);
	} else if (len7 == 127) {
		_header_len += 8;
		check_length();

		u64 len64 = *(u64 *) &buf[2];
		len64 = be64toh(len64);

		if (len64 > INT64_MAX) {
			fprintf(stderr, "[warn] frame length(%lu) larger than INT64_MAX\n",
					len64);
		}

		frame = new Frame();
		frame->payload = std::vector<u8>(len64);
	}

	// fill fields if successfully parsed length
	bool mask = (buf[1] & 0x80u) != 0;
	if (mask) {
		_header_len += 4;
		check_length();
	}

	frame->fin = (buf[0] & 0x80u) != 0;
	frame->rsv[1] = (buf[0] & 0x40u) != 0;
	frame->rsv[2] = (buf[0] & 0x20u) != 0;
	frame->rsv[3] = (buf[0] & 0x10u) != 0;
	frame->opcode = OpCode(buf[0] & 0xFu);
	frame->mask = mask;
	memmove(frame->masking_key, &buf[_header_len - 4], 4);

	header_len = _header_len;
#undef check_length
	return frame;
}

/*
 * `start`: position to copy to in Frame::payload
 * `buf`: raw bytes buffer, not necessarily start at frame border
 * `buf_start`: position of `buf` to start copying
 *
 * Returns the number of bytes copied.
 */
u64 Frame::append_payload(u64 start, const std::vector<u8> buf, u64 buf_start)
{
	u64 ncopy = std::min(payload.size() - start, buf.size() - buf_start);
	memmove(&payload[start], &buf[buf_start], ncopy);
	return ncopy;
}

std::string Frame::header_to_string() const
{
	using namespace std;
	stringstream ss;

	ss << "Header: { fin=" << fin << ' ';

	ss << "rsv={";
	for (int i = 1; i <= 3; i++)
		ss << (rsv[i] ? '1' : '0');
	ss << "} ";

	ss << "OpCode=" << OPCODE_NAMES[opcode] << ' ';
	ss << "payload_len=" << payload.size() << ' ';
	ss << "mask=0x";
	for (int i = 0; i < 4; i++)
		ss << hex << uppercase << setfill('0') << setw(2) << (u32) masking_key[i];

	return ss.str() + "}\n";
}

const char *Frame::OPCODE_NAMES[16] = {
	"CONTINUATION", "TEXT", "BINARY", NULL, NULL, NULL, NULL, NULL,
	"CLOSE", "PING", "PONG",
};
