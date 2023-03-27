#pragma once

#include <string_view>
#include <vector>

namespace Hf {

class IOCDevice {
public:
    IOCDevice();

    ~IOCDevice();

    [[nodiscard]] bool write(std::string_view policy) const;

    [[nodiscard]] bool bulkWrite(const std::vector<std::string>& policyList) const;

    [[nodiscard]] bool flush() const;

    [[nodiscard]] bool del(std::string_view query);

private:
    int fd;
    char buf[100]{};

};

} //namespace Hf