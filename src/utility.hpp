#pragma once

#include <string>
#include <deque>

void ltrim(std::string &s);
void rtrim(std::string &s);
void trim(std::string &s);
std::string string_tolower(std::string s);
std::deque<std::string> string_split(const std::string &s,
		const std::string &delim);
