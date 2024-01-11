#include "ReadLog.h"
#include<time.h>

ReadLog::ReadLog(const std::string &filename): filename(filename)
{

}

ReadLog::~ReadLog() 
{
    if (logFile.is_open()) {
        logFile.close();
    }
}

std::vector<std::string> ReadLog::split(const std::string &str, char delim) const {
    std::stringstream ss(str);
    std::string item;
    std::vector<std::string> tokens;
    while (std::getline(ss, item, delim)) {
        tokens.push_back(item);
    }
    return tokens;
}

// 打开文件的方法
bool ReadLog::open() {
    logFile.open(filename);
    return logFile.is_open();
}

// 读取并解析日志的方法
void ReadLog::parseLog() {
    if (!logFile.is_open()) {
        std::cerr << "open log failed" << std::endl;
        return;
    }

    json allEntries;
    std::string line;
    long long count=0;
    while (std::getline(logFile, line)) {
        std::vector<std::string> fields = split(line, ' '); // 假设字段是用空格分隔的
        json entry;
        for (const auto &field : fields) {
            auto keyValue = split(field, '=');  
            if (keyValue.size() == 2) {
                entry[keyValue[0]] = keyValue[1];
            }
        }
        allEntries.push_back(entry);
        count++;
    }
    std::cout<<"Have parsed "<<count<<" Audit logs"<<std::endl;
    std::cout<<"Time used "<<(double)clock()/CLOCKS_PER_SEC<<"seconds"<<std::endl;

    // 将 JSON 写入文件
    std::ofstream jsonFile("parsedLog.json");
    if (jsonFile.is_open()) {
        jsonFile << allEntries.dump(4);
        jsonFile.close();
    } else {
        std::cerr << "Unable to open JSON file for writing." << std::endl;
    }

}
