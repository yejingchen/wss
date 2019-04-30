#pragma once

#include <string>
#include "common.hpp"

std::string base64_encode(const std::string  &s);
std::string sha1_then_base64_encode(const std::string &s);
