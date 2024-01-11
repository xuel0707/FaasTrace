#include "ThreadTask.h"
#include <iostream>

ThreadTask::ThreadTask(const std::string& name) : threadName(name) {}

ThreadTask::~ThreadTask() {
    if (thread.joinable()) {
        thread.join();
    }
}

void ThreadTask::start() {
    thread = std::thread(&ThreadTask::execute, this);
}

void ThreadTask::join() {
    if (thread.joinable()) {
        thread.join();
    }
}
