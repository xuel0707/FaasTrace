#ifndef PROCESSHTTPLOGTASK_H
#define PROCESSHTTPLOGTASK_H

#include "ThreadTask.h"
#include <queue>
#include <string>
#include <iostream>
#include <mutex>
#include <condition_variable>
#include "Process4eBPF.h"

class ProcessHttpLogTask : public ThreadTask {
public:
    ProcessHttpLogTask(const std::string& , std::queue<PROCESS2REQUEST*>& , const std::string& );
protected:
    void execute() override;
    

private:
    std::queue<PROCESS2REQUEST*>& logQueue;
    std::string serverUrl;

    void parseAndProcessLogEntry(PROCESS2REQUEST* entry);
    void sendToServer(const PROCESS2REQUEST* logEntry);

};

#endif // PROCESSHTTPLOGTASK_H
