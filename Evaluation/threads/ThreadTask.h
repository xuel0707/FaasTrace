#ifndef THREADTASK_H
#define THREADTASK_H

#include <string>
#include <thread>

class ThreadTask {
public:
    ThreadTask(const std::string& name);
    virtual ~ThreadTask();

    void start();
    void join();

    virtual void execute() = 0;

protected:
    std::string threadName;

private:
    std::thread thread;
};

#endif // THREADTASK_H
