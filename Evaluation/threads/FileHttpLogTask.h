#ifndef FILEHTTPLOGTASK_H
#define FILEHTTPLOGTASK_H

#include "ThreadTask.h"
#include <queue>
#include <string>
#include <iostream>
#include <mutex>
#include <condition_variable>
#include "File4eBPF.h"

class FileHttpLogTask : public ThreadTask {
public:
    FileHttpLogTask(const std::string& name, std::queue<FILE2REQUEST*>& logQueue, const std::string& serverUrl);
protected:
    void execute() override;
    

private:
    std::queue<FILE2REQUEST*>& logQueue;
    std::string serverUrl;

    void parseAndProcessLogEntry(FILE2REQUEST* entry);
    void sendToServer(const FILE2REQUEST* logEntry);

};

#endif // FILEHTTPLOGTASK_H
