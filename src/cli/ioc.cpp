#include "ioc.h"
#include <iostream>
#include <cstring>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include "policy.h"

#define DEV_NAME "/dev/hellfire"

#define HF_IOC_MAGIC 0x73 //'S'
#define HF_IOC_POL_FLUSH _IO(HF_IOC_MAGIC, 1)
#define HF_IOC_POL_DEL   _IOWR(HF_IOC_MAGIC, 2, char*)

namespace Hf {

IOCDevice::IOCDevice() {
    fd = open(DEV_NAME, O_RDWR);
}

IOCDevice::~IOCDevice() {
    close(fd);
}

bool IOCDevice::write(std::string_view policy) const {
    std::cout << "Policy: " << policy << std::endl;
    if ((::write(fd, policy.data(), policy.size())) == -1) {
        std::cerr << DEV_NAME << " ioctl: Cannot write the device " << std::endl;
        return false;
    }
    return true;
}

bool IOCDevice::flush() const {
    if (ioctl(fd, static_cast<unsigned long>(HF_IOC_POL_FLUSH)) == -1) {
        std::cerr << DEV_NAME << " ioctl: HF_IOC_POL_FLUSH Error\n";
        return false;
    }
    std::cout << DEV_NAME << " ioctl: Flushed the policy table\n";
    return true;
}

bool IOCDevice::del(std::string_view query) {
    std::strcpy(buf, query.data());
    if (ioctl(fd, static_cast<unsigned long>(HF_IOC_POL_DEL), buf) == -1) {
        std::cerr << DEV_NAME << " ioctl: HF_IOC_POL_DEL Error\n";
        return false;
    }

    if (std::string_view{buf}.starts_with("success"))
        return true;
    return false;
}

bool IOCDevice::bulkWrite(const std::vector<std::string>& policyList) const {
    for (const auto& p: policyList) {
        auto res = write(p);
        if (!res) return res;
    }
    return true;
}

} //namespace Hf
