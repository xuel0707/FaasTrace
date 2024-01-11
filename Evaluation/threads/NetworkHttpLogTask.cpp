#include "NetworkHttpLogTask.h"
#include <curl/curl.h>
#include <arpa/inet.h>

NetworkHttpLogTask::NetworkHttpLogTask(const std::string& name, std::queue<NETWORK2REQUEST*>& logQueue, const std::string& serverUrl)
    : ThreadTask(name), logQueue(logQueue), serverUrl(serverUrl) {}

void NetworkHttpLogTask::execute() {
    while (1) {
        std::cout << "Executing NetworkHttpLog task in thread.\n";
        std::unique_lock<std::mutex> lock(queueMutex2);
        queueCondVar2.wait(lock, [this]{ return !logQueue.empty(); });

        while (!logQueue.empty()) {
            std::cout << "NetworkHttpLog pop Queue size: " << network2RequestQueue.size() << std::endl;
            NETWORK2REQUEST* logEntry = logQueue.front();
            // 解析并处理logEntry
            parseAndProcessLogEntry(logEntry);
            logQueue.pop();
            delete logEntry;
        }
    }
}

void NetworkHttpLogTask::parseAndProcessLogEntry(NETWORK2REQUEST* entry) {
     // 打印基本信息
    std::cout << "UID: " << entry->uid
              << ", GID: " << entry->gid
              << ", PID: " << entry->pid
              << ", TGID: " << entry->tgid
              << ", Net Type: " << entry->net_type << std::endl;

    // 打印命令名和父命令名
    std::cout << "Comm: " << entry->comm
              << ", Parent Comm: " << entry->parent_comm << std::endl;

    // 打印父进程ID
    std::cout << "Parent PID: " << entry->parent_pid << std::endl;

    // 打印协议和各种标志
    std::cout << "Protocol: " << static_cast<unsigned>(entry->protocol) 
              << ", FIN: " << entry->fin
              << ", SYN: " << entry->syn
              << ", RST: " << entry->rst
              // ... 打印其他标志 ...
              << std::endl;

    // 打印端口和网络地址
    std::cout << "Source Port: " << ntohs(entry->sport)
              << ", Destination Port: " << ntohs(entry->dport) << std::endl;

    char saddrStr[INET_ADDRSTRLEN], daddrStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(entry->saddr), saddrStr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(entry->daddr), daddrStr, INET_ADDRSTRLEN);
    std::cout << "Source IP: " << saddrStr
              << ", Destination IP: " << daddrStr << std::endl;

    // ... 打印其他字段 ...

    // 如果结构体中包含其他复杂类型（如结构体或数组），继续按类型打印
    // 例如:
    // std::cout << "Some Field in pinfo: " << entry->pinfo.someField << std::endl;

    // 打印时间戳
    std::cout << "Event Time: " << entry->event_tv.tv_sec << " seconds, " 
              << entry->event_tv.tv_usec << " microseconds" << std::endl;

    // 打印路径名
    std::cout << "Pathname: " << entry->pathname
              << ", Parent Pathname: " << entry->parent_pathname << std::endl;

}

void NetworkHttpLogTask::sendToServer(const NETWORK2REQUEST* logEntry) {
    // 你的日志发送逻辑，例如使用CURL库发送HTTP POST请求
    // 你可能需要根据FILE2REQUEST的结构来格式化数据
    CURL *curl = curl_easy_init();
    if(curl) {
        // 设置CURL选项，发送数据
        // ...

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);
    }
}
