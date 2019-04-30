#include "hash.hpp"

#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>

std::string base64_encode(const std::string  &s)
{
	std::string digest;

	CryptoPP::StringSource foo(s, true,
			new CryptoPP::Base64Encoder(
				new CryptoPP::StringSink(digest), /* newline= */ false));

	return digest;
}

std::string sha1_then_base64_encode(const std::string &s)
{
    std::string digest;
    CryptoPP::SHA1 sha1;

    CryptoPP::StringSource foo(s, true,
    new CryptoPP::HashFilter(sha1,
      new CryptoPP::Base64Encoder(
         new CryptoPP::StringSink(digest), /* newline= */ false)));

    return digest;
}
