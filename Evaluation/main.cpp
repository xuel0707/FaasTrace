#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <vector>
#include <memory>
#include "threads/ProcessTask.h"
#include "threads/ProcessHttpLogTask.h"
#include "threads/FileTask.h"
#include "threads/FileHttpLogTask.h"
#include "threads/NetworkTask.h"
#include "threads/NetworkHttpLogTask.h"
#include "ReadLog.h"
#include "ebpf/load_ebpf.h" 
#include "RegisterClient.h"

using namespace std;

#define AUDIT_PATH "/var/log/audit/audit.log"
std::string serverUrl;

bool fileExists(const std::string& filename) {
    struct stat buffer;   
    return (stat (filename.c_str(), &buffer) == 0); 
}

void createFileIfNotExist(const std::string& filePath) {
    if (!fileExists(filePath)) {
        std::string command = "touch " + filePath;
        system(command.c_str());
        command = "echo 192.168.1.70:443>" + filePath;
        system(command.c_str());
    }
}

bool readFileContents(const std::string& filePath, std::string& serverUrl) {
    std::ifstream file(filePath);
    if (file) {
        serverUrl.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        serverUrl.erase(std::remove(serverUrl.begin(), serverUrl.end(), '\n'), serverUrl.end());
        return true;
    }
    return false;
}

int start_threads()
{
    std::vector<std::unique_ptr<ThreadTask>> tasks;

    tasks.push_back(std::make_unique<ProcessTask>());
    tasks.push_back(std::make_unique<ProcessHttpLogTask>("SendProcessLog2Server", process2RequestQueue, serverUrl));
    tasks.push_back(std::make_unique<FileTask>(serverUrl));
    tasks.push_back(std::make_unique<FileHttpLogTask>("SendFileLog2Server", file2RequestQueue, serverUrl));
    tasks.push_back(std::make_unique<NetworkTask>());
    tasks.push_back(std::make_unique<NetworkHttpLogTask>("SendNetworkLog2Server", network2RequestQueue, serverUrl));

    // 启动所有线程
    for (auto& task : tasks) {
        task->start();
    }

    // 等待所有线程完成
    for (auto& task : tasks) {
        task->join();
    }

    return 0;
}


int main()
{
    ReadLog logReader(AUDIT_PATH); // 替换为你的日志文件路径

    if (logReader.open()) {
        logReader.parseLog();
    } else {
        std::cerr << "failed to open /var/log/audit/audit.log" << std::endl;
        return -1;
    }

    std::string filePath = "/etc/sniper.conf";
    

    createFileIfNotExist(filePath);

    if (readFileContents(filePath, serverUrl)) {
        std::cout << "Get server address: " << serverUrl << std::endl;
    } else {
        std::cout << "Unable to read the /etc/sniper.conf." << std::endl;
        return -1;
    }

    
    RegisterClient client(serverUrl);
    client.setClientVer("20240109");
    if (client.registerHost()) {
        std::cout << "Host registered successfully." << std::endl;
    } else {
        std::cout << "Failed to register host." << std::endl;
        return -1;
    }

    //加载内核模块
    if (load_ebpf_program() < 0) {
		printf("load ebpf program fail@%s line:%d\n", __FILE__,__LINE__);
		return -1;
	}

    start_threads();

    // 卸载 eBPF 程序
    if (unload_ebpf_program() < 0) {
        std::cerr << "Failed to unload eBPF program." << std::endl;
        return -1;
    }

    return 0;
}
