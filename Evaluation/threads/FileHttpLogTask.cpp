#include "FileHttpLogTask.h"
#include <curl/curl.h>

FileHttpLogTask::FileHttpLogTask(const std::string& name, std::queue<FILE2REQUEST*>& logQueue, const std::string& serverUrl)
    : ThreadTask(name), logQueue(logQueue), serverUrl(serverUrl) {}

void FileHttpLogTask::execute() {
    while (1) {
        std::cout << "Executing FileHttpLog task in thread.\n";
        std::unique_lock<std::mutex> lock(queueMutex);
        queueCondVar.wait(lock, [this]{ return !logQueue.empty(); });

        while (!logQueue.empty()) {
            std::cout << "FileHttpLogTask pop Queue size: " << file2RequestQueue.size() << std::endl;
            FILE2REQUEST* logEntry = logQueue.front();
            // 解析并处理logEntry
            parseAndProcessLogEntry(logEntry);
            logQueue.pop();
            delete logEntry;
        }
    }
}

void FileHttpLogTask::parseAndProcessLogEntry(FILE2REQUEST* entry) {
    // 打印基本进程和用户信息
    std::cout << "UID: " << entry->uid << ", PID: " << entry->pid << ", TGID: " << entry->tgid << std::endl;
    std::cout << "Comm: " << entry->comm << ", Parent Comm: " << entry->parent_comm << std::endl;

    // 打印文件信息
    std::cout << "Filename: " << entry->filename << ", Size: " << entry->size << ", Path Length: " << entry->path_len << std::endl;
    std::cout << "TTY: " << entry->tty << std::endl;

    // 打印命令行参数
    std::cout << "Args: ";
    for (int i = 0; i < 4; ++i) {
        std::cout << entry->args[i] << " ";
    }
    std::cout << std::endl;

    // 打印进程路径和执行信息
    std::cout << "Pro Len: " << entry->pro_len << ", Abs Path: " << entry->abs_path << std::endl;
    std::cout << "Did Exec: " << entry->did_exec << std::endl;

    // 打印时间和处理信息
    std::cout << "Event Time: " << entry->event_tv.tv_sec << " sec, " << entry->event_tv.tv_usec << " usec" << std::endl;
    std::cout << "Proc Time: " << entry->proctime << std::endl;

    // 打印管道和文件信息
    std::cout << "Pipe In: " << entry->pipein << ", Pipe Out: " << entry->pipeout << std::endl;
    std::cout << "Exe Inode: " << entry->exeino << std::endl;
    // 注意: exe_file 是一个指针，可能需要特殊处理

    // 打印操作类型和文件信息
    std::cout << "Op Type: " << entry->op_type << ", Type: " << entry->type << std::endl;
    std::cout << "Mode: " << entry->mode << ", Flags: " << entry->flags << std::endl;
    std::cout << "Mnt ID: " << entry->mnt_id << std::endl;

    // 打印更多文件信息
    std::cout << "Mtime: " << entry->mtime_sec << " sec, " << entry->mtime_nsec << " nsec" << std::endl;
    std::cout << "File Size: " << entry->file_size << ", New File Size: " << entry->newfile_size << std::endl;

    // 打印新文件和路径信息
    std::cout << "New Filename: " << entry->new_filename << ", Newpath Len: " << entry->newpath_len << std::endl;
    std::cout << "Pro Pathname: " << entry->pro_pathname << std::endl;

    // 打印进程结束和系统信息
    std::cout << "Terminate: " << entry->terminate << ", Nodename: " << entry->nodename << std::endl;
    std::cout << "Cmd: " << entry->cmd << ", CWD: " << entry->cwd << ", Argc: " << entry->argc << std::endl;
}

void FileHttpLogTask::sendToServer(const FILE2REQUEST* logEntry) {
    // 确保 logEntry 不是空指针
    if (!logEntry) return;

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
