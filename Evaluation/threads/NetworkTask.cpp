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

#include "NetworkTask.h"
#include "Network4eBPF.h"
#include "ebpf/load_ebpf.h"
#include "EventFilter.h"

void bump_memlock_rlimit2(void)
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
std::mutex queueMutex2;
std::condition_variable queueCondVar2;
std::queue<NETWORK2REQUEST*> network2RequestQueue;
EventFilter networkEventFilter;
static int ringbuf_event2(void *ctx, void *data, size_t size) {

	const NETWORK2EVENT *e = (NETWORK2EVENT *)data;

	NETWORK2REQUEST *req=(NETWORK2REQUEST *)malloc(sizeof(NETWORK2REQUEST));
	if(!req) return -1;

	memset(req,0,sizeof(NETWORK2REQUEST));
	
	req->uid=e->uid;
    req->gid=e->gid;
	req->pid=e->pid;
    req->tgid=e->tgid;
    req->net_type=e->net_type;

	req->dport=e->dport;
	req->daddr=e->daddr;
	req->sport=e->sport;
	req->saddr=e->saddr;
	req->protocol=e->protocol;

	req->sessionid=e->sessionid;
    req->start_time=e->start_time;
	req->parent_pid=e->parent_pid;
	req->fin=e->fin;
	req->syn=e->syn;
	req->ack=e->ack;

	memcpy(req->parent_pathname,e->parent_pathname,sizeof(e->parent_pathname));
    memcpy(req->parent_comm,e->parent_comm,sizeof(e->parent_comm));
    memcpy(req->pathname,e->pathname,sizeof(e->pathname));
	memcpy(req->comm,e->comm,sizeof(e->comm));

	networkEventFilter.filterNetworkEvent(req);
	
	std::unique_lock<std::mutex> lock(queueMutex2);

	// 检查队列是否达到最大容量
    if (network2RequestQueue.size() >= MAX_QUEUE_SIZE) {
        // 如果队列已满，丢弃最早的100个元素
        for (size_t i = 0; i < ITEMS_TO_DROP && !network2RequestQueue.empty(); ++i) {
            NETWORK2REQUEST* front = network2RequestQueue.front();
            network2RequestQueue.pop();
            // 这里应该添加代码来释放 front 指向的资源
            free(front); 
        }
    }

	network2RequestQueue.push(req);
	lock.unlock();
    queueCondVar2.notify_one(); 

    return 0;
}

NetworkTask::NetworkTask() : ThreadTask("network") {}

void NetworkTask::execute() {
    std::cout << "Executing network task in thread.\n";
    // 实现具体的网络任务
    networkEventFilter.setNetworkFilterCallback([](const void* data) {
        const NETWORK2REQUEST* request = static_cast<const NETWORK2REQUEST*>(data);
        // 这里实现您的网络事件过滤逻辑
        // 如果事件符合规则，则发送数据到服务器
    });

    // Bump RLIMIT_MEMLOCK to create BPF maps 
	bump_memlock_rlimit2();

	// get_bpf_object
	struct bpf_object *network_bpf_obj = get_bpf_object(EBPF_NET);
	if (!network_bpf_obj) printf("get_bpf_object@%s line:%d\r\n",__FILE__,__LINE__);

	// bpf_object__find_map_by_name
	struct bpf_map *p_ringbuf_map = bpf_object__find_map_by_name(network_bpf_obj, "xdp_ringbuf");
	if (!p_ringbuf_map) printf("bpf_object__find_map_by_name@%s line:%d\r\n",__FILE__,__LINE__);

	// bpf_map__fd
	int ringbuf_map_fd =bpf_map__fd(p_ringbuf_map);
	if (!ringbuf_map_fd<0) printf("bpf_map__fd[%d]@%s line:%d\r\n",ringbuf_map_fd,__FILE__,__LINE__);

	// ring_buffer__new
	struct ring_buffer *p_ringbuf = ring_buffer__new(ringbuf_map_fd, ringbuf_event2, NULL, NULL);
	if (!p_ringbuf){
		printf("failed to create ringbuf@%s line:%d\r\n",__FILE__,__LINE__);
		goto clean_up;
	} 
    while(1){
        int err = ring_buffer__poll(p_ringbuf, 100 /* timeout, ms */);
		if (err < 0) {
			printf("Error polling networkreq_ringbuf: %d\n", err);
			break;
		}
    }
    
clean_up:
	/* Clean up */
	ring_buffer__free(p_ringbuf);
	bpf_object__close(network_bpf_obj);
	printf("NetworkTask thread exit\n");
	return;    
}
