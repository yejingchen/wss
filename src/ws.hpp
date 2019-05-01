#pragma once

#include <string>
#include <deque>
#include <vector>
#include <map>
#include <functional>
#include <utility>

#include "common.hpp"
#include "utility.hpp"
#include "hash.hpp"

class WsReqHeader {
public:
	WsReqHeader(const std::string &h);

	bool validate();

	std::vector<u8> build_success_resp();

private:
	std::string first_line;
	std::map<std::string, std::string> headers;

	static const char *HOST, *UPGRADE, *CONNECTION,
				 *SEC_WEBSOCKET_KEY, *SEC_WEBSOCKET_VERSION;
	static const char *KEY_MAGIC;
};

class Frame {
public:
	enum OpCode {
		CONTINUATION = 0x0, TEXT = 0x1, BINARY = 0x2,
		CLOSE = 0x8, PING = 0x9, PONG = 0xA
	};

	bool fin;
	bool rsv[4] = { false, false, false, false }; // rsv[0] is not used.
	enum OpCode opcode;

	bool mask;
	u8 masking_key[4];

	/*
	 * payload len must be less than INT64_MAX per RFC (MSB must be 0)
	 */
	std::vector<u8> payload;

	Frame();

	std::vector<u8> to_bytes() const;

	/*
	 * `buf` must start at frame border
	 */
	static Frame *try_parse_header(const std::vector<u8> buf, int &header_len);
	
	u64 append_payload(u64 start, const std::vector<u8> buf, u64 payload_start);

	std::string header_to_string() const;
private:
	u8 *do_mask(u8 *dst, const u8 *src, u64 len) const;
	static const char * OPCODE_NAMES[];
};
