#include <ifaddrs.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <fstream>
#include <unistd.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <net/if.h>
#include <linux/if_packet.h>
#include <cjson/cJSON.h>
#include "RegisterClient.h"

RegisterClient::RegisterClient(const std::string& Url)
    : serverUrl(Url) {}

bool RegisterClient::registerHost() {
     
    try {
        http_client Client(U("https://" + serverUrl+"/api/client/register/"));
        // 创建要发送的 JSON 对象
        json::value postData;
        postData[U("ip")] = json::value::string(U(getIPAddress()));
        postData[U("uuid")] = json::value::string(U("cfa4f341e58646b1966e135f9cce3ba2000c29097dc3"));
        postData[U("hostname")] = json::value::string(U(getHostName()));
        postData[U("mac")] = json::value::string(U(getMACAddress()));
        postData[U("os")] = json::value::string(U(getOSName()));
        postData[U("machine_model")] = json::value::string(U(getMachineModel()));
        postData[U("client_ver")] = json::value::string(U(getClientVer()));
        postData[U("virus_ver")] = json::value::string(U(""));
        postData[U("vuln_ver")] = json::value::string(U(""));
        postData[U("login_user")] = json::value::string(U(getLoginName()));
        postData[U("ipv6")] = json::value::string(U(getIPv6Address()));
        postData[U("install_token")] = json::value::string(U(""));

        // 构建请求
        http_request request(methods::POST);
        request.set_body(postData);
        request.headers().set_content_type(U("application/json"));

        // 注意：以下 SSL 配置与生产环境的安全实践不符，仅用于测试
        http_client_config client_config;
        client_config.set_validate_certificates(false); // 禁用 SSL 证书验证
        Client = http_client(U("https://" + serverUrl+"/api/client/register/"), client_config);

        http_response response = Client.request(request).get(); // 同步发送请求
        if (response.status_code() == status_codes::OK) {
            // 处理成功响应
            return true;
        } else {
            // 处理失败响应
            return false;
        }
    } catch (const http_exception& e) {
        // 处理异常
        std::wcout << L"HTTP request failed: " << e.what() << std::endl;
        return false;
    }
}

std::string RegisterClient::getIPAddress() {
    struct ifaddrs *interfaces = nullptr;
    struct ifaddrs *addr = nullptr;
    std::string ipAddress;

    if (getifaddrs(&interfaces) == -1) {
        return "";
    }

    for (addr = interfaces; addr != nullptr; addr = addr->ifa_next) {
        if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET) { // IPv4
            char* ip = inet_ntoa(((struct sockaddr_in *)addr->ifa_addr)->sin_addr);
            if (std::string(ip) != "127.0.0.1") {  // 跳过本地回环地址
                ipAddress = ip;
                break;
            }
        }
    }
    freeifaddrs(interfaces);
    return ipAddress;
}

std::string RegisterClient::getMACAddress() {
    struct ifaddrs *ifaddr, *ifa;
    char addrStr[18];  // MAC 地址的长度

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return "";
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET && !(ifa->ifa_flags & IFF_LOOPBACK)) {
            struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
            if (s->sll_addr) {
                std::ostringstream oss;
                for (int i = 0; i < 6; i++) {
                    oss << std::setfill('0') << std::setw(2) << std::hex << (int)s->sll_addr[i];
                    if (i != 5) oss << ":";
                }
                strcpy(addrStr, oss.str().c_str());
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return std::string(addrStr);
}

std::string RegisterClient::getHostName() {
    char hostname[1024];
    hostname[1023] = '\0';
    gethostname(hostname, 1023);
    return std::string(hostname);
}

std::string RegisterClient::getOSName() {
    std::ifstream file("/etc/os-release");
    if (!file.is_open()) {
        return "Unknown Operating System";
    }

    std::string line, osName;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string key;
        if (std::getline(std::getline(iss, key, '=') >> std::ws, line) && key == "PRETTY_NAME") {
            // 移除引号
            if (line.size() >= 2 && line.front() == '\"' && line.back() == '\"') {
                line = line.substr(1, line.size() - 2);
            }
            osName = line;
            break;
        }
    }

    if (!osName.empty()) {
        return osName + " Linux"; // 在这里加上 " Linux"
    }

    return "Unknown Operating System";
}

std::string RegisterClient::getPhysicalMemorySize() {
    // 获取物理内存大小的逻辑...
    std::ifstream file("/proc/meminfo");
    std::string line;
    if (file) {
        while (std::getline(file, line)) {
            if (line.find("MemTotal:") != std::string::npos) {
                std::istringstream iss(line);
                std::string key, value, unit;
                iss >> key >> value >> unit;
                return value + " " + unit;
            }
        }
    }
    return "";
}

std::string RegisterClient::getMachineModel() {
    std::ifstream file("/sys/class/dmi/id/product_name");
    if (!file.is_open()) {
        return "Unknown"; // 无法打开文件，可能是宿主机或者无法确定
    }

    std::string line;
    std::getline(file, line);
    file.close();

    if (line.find("VMware") != std::string::npos) {
        return "VMware Virtual Platform";
    }

    if (line.find("VirtualBox") != std::string::npos) {
        return "VirtualBox Virtual Platform";
    }

    if (line.find("Hyper-V") != std::string::npos) {
        return "Hyper-V Virtual Platform";
    }

    // 添加其他虚拟机类型的检测逻辑（如 VirtualBox, Hyper-V 等）

    return "Host Machine"; // 默认为宿主机
}

void RegisterClient::setClientVer(const std::string&str)  {
    ClientVersionStr=str;
}

std::string RegisterClient::getClientVer()  {
    return ClientVersionStr;
}

std::string RegisterClient::getLoginName() {
    char* loginName = getlogin();
    if (loginName != nullptr) {
        return std::string(loginName);
    } else {
        // 如果 getlogin 返回 nullptr，使用环境变量
        return std::string(std::getenv("USER"));
    }
}

std::string RegisterClient::getIPv6Address() {
    struct ifaddrs *ifaddr, *ifa;
    int family;
    char addrStr[INET6_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return "";
    }

    // 遍历所有接口
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;  

        family = ifa->ifa_addr->sa_family;
        // 检查地址族是否是 AF_INET6
        if (family == AF_INET6) {
            // 获得 IPv6 地址
            void* tmpAddrPtr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            inet_ntop(AF_INET6, tmpAddrPtr, addrStr, INET6_ADDRSTRLEN);
            if (strcmp(ifa->ifa_name, "lo") != 0) {  // 忽略本地回环地址
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return std::string(addrStr);
}
