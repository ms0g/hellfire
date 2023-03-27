#pragma once

#include <cstdint>
#include <string>

namespace Hf::Utility::Ip {

uint32_t inet_bf(const char* addr);

std::string inet_pf(uint32_t addr);

} //namespace Hf::utility::ip
