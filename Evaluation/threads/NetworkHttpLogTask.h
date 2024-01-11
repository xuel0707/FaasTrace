#ifndef NETWORKHTTPLOGTASK_H
#define NETWORKHTTPLOGTASK_H

#include "ThreadTask.h"
#include <queue>
#include <string>
#include <iostream>
#include <mutex>
#include <condition_variable>
#include "Network4eBPF.h"

class NetworkHttpLogTask : public ThreadTask {
public:
    NetworkHttpLogTask(const std::string& , std::queue<NETWORK2REQUEST*>& , const std::string& );
protected:
    void execute() override;
    

private:
    std::queue<NETWORK2REQUEST*>& logQueue;
    std::string serverUrl;

    void parseAndProcessLogEntry(NETWORK2REQUEST* entry);
    void sendToServer(const NETWORK2REQUEST* logEntry);

};

#endif // NETWORKHTTPLOGTASK_H
