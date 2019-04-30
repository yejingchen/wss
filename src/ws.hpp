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

	enum WsState {
		HANDSHAKE, WEBSOCKET
	};
};
