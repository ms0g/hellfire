#pragma once

#include <string_view>
#include <vector>

namespace Hf {

class IOCDevice {
public:
    IOCDevice();

    ~IOCDevice();

    void write(std::string_view policy) const;

    void bulkWrite(const std::vector<std::string>& policyList) const;

    void read(std::string_view query);

    void del(std::string_view query);

    void flush() const;

private:
    int fd;
    char buf[100]{};

};

} //namespace Hf