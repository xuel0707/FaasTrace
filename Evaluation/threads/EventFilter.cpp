#include "EventFilter.h"

EventFilter::EventFilter() {
    // 初始化逻辑（如果需要）
}

void EventFilter::setFileFilterCallback(const FilterCallback& callback) {
    fileFilterCallback = callback;
}

void EventFilter::setNetworkFilterCallback(const FilterCallback& callback) {
    networkFilterCallback = callback;
}

void EventFilter::setProcessFilterCallback(const FilterCallback& callback) {
    processFilterCallback = callback;
}

void EventFilter::filterFileEvent(FILE2REQUEST* request) {
    if (fileFilterCallback && request) {
        fileFilterCallback(request);
    }
}

void EventFilter::filterNetworkEvent(NETWORK2REQUEST* request) {
    if (networkFilterCallback && request) {
        networkFilterCallback(request);
    }
}

void EventFilter::filterProcessEvent(PROCESS2REQUEST* request) {
    if (processFilterCallback && request) {
        processFilterCallback(request);
    }
}
