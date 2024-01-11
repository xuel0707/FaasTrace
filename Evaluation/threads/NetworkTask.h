#ifndef NETWORKTASK_H
#define NETWORKTASK_H

#include "ThreadTask.h"

class NetworkTask : public ThreadTask {
public:
    NetworkTask();

    void execute() override;
};

#endif // NETWORKTASK_H
