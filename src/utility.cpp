#include "utility.hpp"

#include <algorithm>
#include <cctype>
#include <locale>

// trim from start (in place)
void ltrim(std::string &s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
        return !std::isspace(ch);
    }));
}

// trim from end (in place)
void rtrim(std::string &s)
{
    s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

// trim from both ends (in place)
void trim(std::string &s)
{
    ltrim(s);
    rtrim(s);
}

std::string string_tolower(std::string s)
{
	std::transform(s.begin(), s.end(), s.begin(),
			[](char c) { return tolower(c); });
	return s;
}

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
