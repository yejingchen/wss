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
