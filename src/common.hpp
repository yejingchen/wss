#pragma once
#include <cstdio>
#include <cstdint>
#include <cstdlib>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

constexpr int BUFSIZE = 4096;

// print error and exit when ret == -1
inline int guard(int ret, const char *errmsg)
{
	if (ret == -1) {
		perror(errmsg);
		exit(EXIT_FAILURE);
	} else {
		return ret;
	}
}
