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

#include "FileTask.h"
#include "File4eBPF.h"
#include "ebpf/load_ebpf.h"
#include "EventFilter.h"
#include <algorithm>

#include <ifaddrs.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <fstream>
#include <unistd.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <net/if.h>
#include <linux/if_packet.h>
#include <cjson/cJSON.h>
#include <cpprest/http_client.h>
#include <cpprest/json.h>

using namespace web;
using namespace web::http;
using namespace web::http::client;

void bump_memlock_rlimit(void)
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
std::mutex queueMutex;
std::condition_variable queueCondVar;
std::queue<FILE2REQUEST*> file2RequestQueue;
EventFilter fileEventFilter;

static int ringbuf_event(void *ctx, void *data, size_t size) {

	const FILE2EVENT *e = (FILE2EVENT *)data;

	FILE2REQUEST *req=(FILE2REQUEST *)malloc(sizeof(FILE2REQUEST));
	if(!req) return -1;

	memset(req,0,sizeof(FILE2REQUEST));
	
	req->pid=e->pid;
	req->tgid=e->tgid;
	req->uid=e->uid;
	req->path_len=e->path_len;
	req->pro_len=e->pro_len;
	req->size=e->size;

	memcpy(req->comm,e->comm,sizeof(e->comm));
	memcpy(req->parent_comm,e->parent_comm,sizeof(e->parent_comm));
	memcpy(req->filename,e->filename,sizeof(e->filename));
	memcpy(req->tty,e->tty,sizeof(e->tty));
	memcpy(req->args,e->args,sizeof(e->args));
	memcpy(req->abs_path,e->abs_path,sizeof(e->abs_path));

	// 循环中获取事件
	fileEventFilter.filterFileEvent(req);

	std::unique_lock<std::mutex> lock(queueMutex);
	// 检查队列是否达到最大容量
    if (file2RequestQueue.size() >= MAX_QUEUE_SIZE) {
        // 如果队列已满，丢弃最早的100个元素
        for (size_t i = 0; i < ITEMS_TO_DROP && !file2RequestQueue.empty(); ++i) {
            FILE2REQUEST* front = file2RequestQueue.front();
            file2RequestQueue.pop();
            // 这里应该添加代码来释放 front 指向的资源
            free(front);
        }
    }

	file2RequestQueue.push(req);
	lock.unlock();
    queueCondVar.notify_one(); 

    return 0;
}

FileTask::FileTask(const std::string& serverUrl) : ThreadTask("file") , serverUrl(serverUrl){}
void FileTask::execute() {
    std::cout << "Executing file task in thread.\n";
    // 实现具体的文件任务
    fileEventFilter.setFileFilterCallback([this](const void* data) {
        const FILE2REQUEST* request = static_cast<const FILE2REQUEST*>(data);
		// 检查文件操作类型
		if (request->op_type == OP_OPEN_W && 
			(request->type != F_BLACK_AFTER &&
			request->type != F_SAFE &&
			request->type != F_ENCRYPT)) {
			this->sendToServer(request);
			file2RequestQueue.pop();
			delete request;
		}

		// 检查进程名称是否为 "vim"
		if (strcmp(request->comm, "vim") == 0) {
			// 根据文件名设置不同的类型
			if (strstr(request->filename, ".php") || 
				strstr(request->filename, ".jsp") || 
				strstr(request->filename, ".as") || 
				strstr(request->filename, ".cdx") || 
				strstr(request->filename, ".cer") || 
				strstr(request->filename, ".cgi")) {

				this->sendToServer(request);
				file2RequestQueue.pop();
				delete request;
			}
		}

    });
    // Bump RLIMIT_MEMLOCK to create BPF maps 
	bump_memlock_rlimit();

	// get_bpf_object
	struct bpf_object *file_bpf_obj = get_bpf_object(EBPF_FILE);
	if (!file_bpf_obj) printf("get_bpf_object@%s line:%d\r\n",__FILE__,__LINE__);

	// bpf_object__find_map_by_name
	struct bpf_map *p_ringbuf_map = bpf_object__find_map_by_name(file_bpf_obj, "fileopen_ringbuf");
	if (!p_ringbuf_map) printf("bpf_object__find_map_by_name@%s line:%d\r\n",__FILE__,__LINE__);

	// bpf_map__fd
	int ringbuf_map_fd =bpf_map__fd(p_ringbuf_map);
	if (!ringbuf_map_fd<0) printf("bpf_map__fd[%d]@%s line:%d\r\n",ringbuf_map_fd,__FILE__,__LINE__);

	// ring_buffer__new
	struct ring_buffer *p_ringbuf = ring_buffer__new(ringbuf_map_fd, ringbuf_event, NULL, NULL);
	if (!p_ringbuf){
		printf("failed to create ringbuf@%s line:%d\r\n",__FILE__,__LINE__);
		goto clean_up;
	} 
    while(1){
        int err = ring_buffer__poll(p_ringbuf, 100 /* timeout, ms */);
		if (err < 0) {
			printf("Error polling filereq_ringbuf: %d\n", err);
			break;
		}
    }
    
clean_up:
	/* Clean up */
	ring_buffer__free(p_ringbuf);
	bpf_object__close(file_bpf_obj);
	printf("FileTask thread exit\n");
	return;    
}


void FileTask::sendToServer(const FILE2REQUEST* logEntry) {
    // 确保 logEntry 不是空指针
    if (!logEntry) return;

    try {
        http_client Client(U("https://" + serverUrl + "/api/client/log"));
        // 创建要发送的 JSON 对象
        json::value postData;
        
        // 使用 logEntry 中的数据填充 JSON 对象
		postData[U("uid")] = json::value::number(logEntry->uid);
		postData[U("pid")] = json::value::number(logEntry->pid);
		postData[U("tgid")] = json::value::number(logEntry->tgid);
		postData[U("comm")] = json::value::string(U(logEntry->comm));
		postData[U("filename")] = json::value::string(U(logEntry->filename));
		postData[U("size")] = json::value::number(logEntry->size);
		postData[U("abs_path")] = json::value::string(U(logEntry->abs_path));
		postData[U("op_type")] = json::value::number(logEntry->op_type);
		postData[U("type")] = json::value::number(logEntry->type);

		// 静态字段或从其他数据源获取的字段
		postData[U("id")] = json::value::string(U("46a267f6-fe9f-482b-9e48-83899242b520"));
		postData[U("log_name")] = json::value::string(U("FileMonitor"));
		postData[U("log_category")] = json::value::string(U("File"));
		postData[U("event")] = json::value::boolean(false); // 示例值
		postData[U("event_type")] = json::value::number(8); // 示例值
		postData[U("level")] = json::value::number(1); // 示例值
		postData[U("behavior")] = json::value::number(0); // 示例值
		postData[U("result")] = json::value::number(1); // 示例值
		postData[U("operating")] = json::value::string(U("Change")); // 示例值
		postData[U("terminate")] = json::value::number(logEntry->terminate);
		postData[U("host_name")] = json::value::string(U("debian95")); // 示例值
		postData[U("ip_address")] = json::value::string(U("192.167.7.212")); // 示例值
		postData[U("mac")] = json::value::string(U("00-0C-29-A3-1C-D8")); // 示例值
		postData[U("uuid")] = json::value::string(U("9ea0d80b124a435abad806710edd5c1e000c29a31cd800000000000000000000")); // 示例值
		postData[U("user")] = json::value::string(U("root")); // 从 logEntry 获取
		postData[U("os_type")] = json::value::number(2); // 示例值
		postData[U("os_version")] = json::value::string(U("debian95")); // 示例值
		postData[U("timestamp")] = json::value::number(1611807769131); // 示例值
		postData[U("policy_id")] = json::value::string(U("")); // 示例值
		postData[U("source")] = json::value::string(U("Agent")); // 示例值

		// 构建 arguments 对象
		json::value arguments;
		arguments[U("process_uuid")] = json::value::string(U("1887114692-2488")); // 示例值
		arguments[U("process_name")] = json::value::string(U(logEntry->comm)); // 从 logEntry 获取
		arguments[U("process_id")] = json::value::number(logEntry->pid); // 从 logEntry 获取
		arguments[U("thread_id")] = json::value::number(1); // 示例值
		arguments[U("process_path")] = json::value::string(U(logEntry->abs_path)); // 从 logEntry 获取
		arguments[U("process_commandline")] = json::value::string(U("/bin/ps -ef | /bin/grep /sbin/sniper")); // 示例值
		arguments[U("process_timestamp")] = json::value::number(logEntry->event_tv.tv_sec); // 从 logEntry 获取
		arguments[U("filename")] = json::value::string(U(logEntry->filename)); // 从 logEntry 获取
		arguments[U("file_uuid")] = json::value::string(U("ba7e365f049496ff")); // 示例值
		arguments[U("filepath")] = json::value::string(U(logEntry->abs_path)); // 从 logEntry 获取
		arguments[U("size")] = json::value::string(std::to_string(logEntry->size)); // 从 logEntry 获取
		arguments[U("extension")] = json::value::string(U(".exe")); // 示例值
		arguments[U("md5")] = json::value::string(U("3ff5cbd47b2c25c9be0e505aefc60cd8")); // 示例值
		arguments[U("new_filepath")] = json::value::string(U(logEntry->new_filename)); // 从 logEntry 获取
		arguments[U("user")] = json::value::string(U("root")); // 从 logEntry 获取
		arguments[U("session_uuid")] = json::value::string(U("xxxxx")); // 示例值

		postData[U("arguments")] = arguments;

        // 构建请求
        http_request request(methods::POST);
        request.set_body(postData);
        request.headers().set_content_type(U("application/json"));

        // 注意：以下 SSL 配置与生产环境的安全实践不符，仅用于测试
        http_client_config client_config;
        client_config.set_validate_certificates(false); // 禁用 SSL 证书验证
        Client = http_client(U("https://" + serverUrl + "/api/client/register/"), client_config);

        http_response response = Client.request(request).get(); // 同步发送请求
        if (response.status_code() == status_codes::OK) {
            // 处理成功响应
            std::wcout << L"HTTP request success"<< std::endl;

        } else {
            // 处理失败响应
            std::wcout << L"HTTP request failed"<< std::endl;

        }
    } catch (const http_exception& e) {
        // 处理异常
        std::wcout << L"HTTP exception: " << e.what() << std::endl;

    }
}

