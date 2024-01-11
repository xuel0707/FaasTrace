#ifndef EVENTFILTER_H
#define EVENTFILTER_H

#include <functional>
#include "File4eBPF.h"
#include "Network4eBPF.h"
#include "Process4eBPF.h"

// 定义过滤器回调类型
using FilterCallback = std::function<void(const void*)>;

class EventFilter {
public:
    EventFilter();

    // 设置回调函数
    void setFileFilterCallback(const FilterCallback& callback);
    void setNetworkFilterCallback(const FilterCallback& callback);
    void setProcessFilterCallback(const FilterCallback& callback);

    // 执行过滤
    void filterFileEvent(FILE2REQUEST* request);
    void filterNetworkEvent(NETWORK2REQUEST* request);
    void filterProcessEvent(PROCESS2REQUEST* request);

private:
    FilterCallback fileFilterCallback;
    FilterCallback networkFilterCallback;
    FilterCallback processFilterCallback;
};

#endif // EVENTFILTER_H
