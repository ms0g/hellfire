#pragma once

#include <string_view>

class IOCDevice {
public:
    IOCDevice();

    ~IOCDevice();

    void sendTo(std::string_view pol) const;

    void read(std::string_view query);

    void del(std::string_view query);

    void flush() const;

private:
    int fd;
    char buf[100]{};

};