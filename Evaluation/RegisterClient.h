#ifndef REGISTERCLIENT_H
#define REGISTERCLIENT_H

#include <string>
#include <cpprest/http_client.h>   

using namespace utility;                    // Common utilities like string conversions
using namespace web;                        // Common features like URIs.
using namespace web::http;                  // Common HTTP functionality
using namespace web::http::client;          // HTTP client features
using namespace concurrency::streams;       // Asynchronous streams

class RegisterClient {
public:
    RegisterClient(const std::string& Url);

    bool registerHost();
    void setClientVer(const std::string&);

private:
    std::string serverUrl;
    std::string ClientVersionStr;

    std::string getIPAddress();
    std::string getMACAddress();
    std::string getHostName();
    std::string getOSName();
    std::string getPhysicalMemorySize();
    std::string getMachineModel();
    std::string getClientVer();
    std::string getLoginName();
    std::string getIPv6Address();
};

#endif // REGISTERCLIENT_H
