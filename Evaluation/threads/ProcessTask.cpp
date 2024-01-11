/* std */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>
#include <pthread.h>
#include <curl/curl.h>
#include <sys/resource.h> 

/* libbpf */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ProcessTask.h"
#include "Process4eBPF.h"
#include "ebpf/load_ebpf.h"
#include "EventFilter.h"

void bump_memlock_rlimit3(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if(setrlimit(RLIMIT_MEMLOCK, &rlim_new)){
		printf("Failed to increase RLIMIT_MEMLOCK limit@%s line:%d\r\n",__FILE__,__LINE__);
		exit(1);
	}
}

constexpr size_t MAX_QUEUE_SIZE = 100000; // 定义队列最大容量为10万
constexpr size_t ITEMS_TO_DROP = 100;     // 定义达到最大容量时要丢弃的元素数量
// 使用 std::queue 存储 FILE2REQUEST* 实例
std::mutex queueMutex3;
std::condition_variable queueCondVar3;
std::queue<PROCESS2REQUEST*> process2RequestQueue;
EventFilter processEventFilter;
static int ringbuf_event3(void *ctx, void *data, size_t size) {

	const PROCESS2EVENT *e = (PROCESS2EVENT *)data;

	PROCESS2REQUEST *req=(PROCESS2REQUEST *)malloc(sizeof(PROCESS2REQUEST));
	if(!req) return -1;

	memset(req,0,sizeof(PROCESS2REQUEST));
	
	req->pid=e->pid;
    req->tgid=e->tgid;

    memcpy(req->parent_comm,e->parent_comm,sizeof(e->parent_comm));
	memcpy(req->comm,e->comm,sizeof(e->comm));
	memcpy(req->args,e->args,sizeof(e->args));
	memcpy(req->cmd,e->args[0],sizeof(e->args[0]));
	req->argc=e->argc;
	req->pinfo.task[0].pid=e->pinfo.task[0].pid;
	memcpy(req->pinfo.task[0].comm,e->pinfo.task[0].comm,sizeof(e->pinfo.task[0].comm));
	req->cwdlen=strlen(req->comm);
	req->cmdlen=strlen(req->cmd);

	processEventFilter.filterProcessEvent(req);

	std::unique_lock<std::mutex> lock(queueMutex3);
	 // 检查队列是否达到最大容量
    if (process2RequestQueue.size() >= MAX_QUEUE_SIZE) {
        // 如果队列已满，丢弃最早的100个元素
        for (size_t i = 0; i < ITEMS_TO_DROP && !process2RequestQueue.empty(); ++i) {
            PROCESS2REQUEST* front = process2RequestQueue.front();
            process2RequestQueue.pop();
            // 这里应该添加代码来释放 front 指向的资源
            free(front); 
        }
    }
	process2RequestQueue.push(req);
	lock.unlock();
    queueCondVar3.notify_one(); 

    return 0;
}

ProcessTask::ProcessTask() : ThreadTask("process") {}

void ProcessTask::execute() {
    std::cout << "Executing process task in thread.\n";
    // 实现具体的进程任务
    processEventFilter.setProcessFilterCallback([](const void* data) {
        const PROCESS2REQUEST* request = static_cast<const PROCESS2REQUEST*>(data);
        // 这里实现您的进程事件过滤逻辑
        // 如果事件符合规则，则发送数据到服务器
    });
    // Bump RLIMIT_MEMLOCK to create BPF maps 
	bump_memlock_rlimit3();

	// get_bpf_object
	struct bpf_object *process_bpf_obj = get_bpf_object(EBPF_EXECVE);
	if (!process_bpf_obj) printf("get_bpf_object@%s line:%d\r\n",__FILE__,__LINE__);

	// bpf_object__find_map_by_name
	struct bpf_map *p_ringbuf_map = bpf_object__find_map_by_name(process_bpf_obj, "process_exc_ringbuf");
	if (!p_ringbuf_map) printf("bpf_object__find_map_by_name@%s line:%d\r\n",__FILE__,__LINE__);

	// bpf_map__fd
	int ringbuf_map_fd =bpf_map__fd(p_ringbuf_map);
	if (!ringbuf_map_fd<0) printf("bpf_map__fd[%d]@%s line:%d\r\n",ringbuf_map_fd,__FILE__,__LINE__);

	// ring_buffer__new
	struct ring_buffer *p_ringbuf = ring_buffer__new(ringbuf_map_fd, ringbuf_event3, NULL, NULL);
	if (!p_ringbuf){
		printf("failed to create ringbuf@%s line:%d\r\n",__FILE__,__LINE__);
		goto clean_up;
	} 
    while(1){
        int err = ring_buffer__poll(p_ringbuf, 100 /* timeout, ms */);
		if (err < 0) {
			printf("Error polling processreq_ringbuf: %d\n", err);
			break;
		}
    }
    
clean_up:
	/* Clean up */
	ring_buffer__free(p_ringbuf);
	bpf_object__close(process_bpf_obj);
	printf("ProcessTask thread exit\n");
	return;    
}
