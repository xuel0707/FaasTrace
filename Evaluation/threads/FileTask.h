#ifndef FILETASK_H
#define FILETASK_H

#include "ThreadTask.h"
#include "File4eBPF.h"
class FileTask : public ThreadTask {
public:
    FileTask( const std::string& );

    void execute() override;

private:
    std::string serverUrl;

    void sendToServer(const FILE2REQUEST* );

};

#endif // FILETASK_H
