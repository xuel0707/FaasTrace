#ifndef PROCESSTASK_H
#define PROCESSTASK_H

#include "ThreadTask.h"

class ProcessTask : public ThreadTask {
public:
    ProcessTask();

    void execute() override;
};

#endif // PROCESSTASK_H
