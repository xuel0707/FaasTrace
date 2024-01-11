#include "ProcessHttpLogTask.h"
#include <curl/curl.h>
#include <arpa/inet.h>

ProcessHttpLogTask::ProcessHttpLogTask(const std::string& name, std::queue<PROCESS2REQUEST*>& logQueue, const std::string& serverUrl)
    : ThreadTask(name), logQueue(logQueue), serverUrl(serverUrl) {}

void ProcessHttpLogTask::execute() {
    while (1) {
        std::cout << "Executing ProcessHttpLog task in thread.\n";
        std::unique_lock<std::mutex> lock(queueMutex3);
        queueCondVar3.wait(lock, [this]{ return !logQueue.empty(); });

        while (!logQueue.empty()) {
            std::cout << "ProcessHttpLog pop Queue size: " << process2RequestQueue.size() << std::endl;
            PROCESS2REQUEST* logEntry = logQueue.front();
            // 解析并处理logEntry
            parseAndProcessLogEntry(logEntry);
            logQueue.pop();
            delete logEntry;
        }
    }
}

void ProcessHttpLogTask::parseAndProcessLogEntry(PROCESS2REQUEST* entry) {
     // 打印基本信息
    std::cout << "UID: " << entry->uid
              << ", PPID: " << entry->ppid
              << ", EUID: " << entry->euid
              << ", PID: " << entry->pid
              << ", TGID: " << entry->tgid << std::endl;

    // 打印命令名和父命令名
    std::cout << "Comm: " << entry->comm
              << ", Parent Comm: " << entry->parent_comm << std::endl;

    // 打印父进程ID
    std::cout << "Parent PID: " << entry->parent_pid << std::endl;

    // 打印参数列表
    std::cout << "Arguments: ";
    for (int i = 0; i < 8; ++i) {
        std::cout << entry->args[i];
        if (i < 7) std::cout << ", ";
    }
    std::cout << std::endl;

    // 打印其他字段
    std::cout << "Process Time: " << entry->proctime
              << ", PipeIn: " << entry->pipein
              << ", PipeOut: " << entry->pipeout
              << ", ExeIno: " << entry->exeino
              << ", CmdLen: " << entry->cmdlen
              << ", ArgsLen: " << entry->argslen
              << ", CwdLen: " << entry->cwdlen
              << ", Argc: " << entry->argc
              << ", Options: " << entry->options
              << ", MntID: " << entry->mnt_id << std::endl;

    // 如果结构体中包含其他复杂类型（如结构体或数组），继续按类型打印
    // 例如:
    // std::cout << "Some Field in pinfo: " << entry->pinfo.someField << std::endl;

    // 打印其他字符串字段
    std::cout << "TTY: " << entry->tty
              << ", NodeName: " << entry->nodename
              << ", Command: " << entry->cmd
              << ", Current Working Directory: " << entry->cwd << std::endl;


}

void ProcessHttpLogTask::sendToServer(const PROCESS2REQUEST* logEntry) {
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
