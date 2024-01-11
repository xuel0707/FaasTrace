#ifndef NETWORK4EBPF_H
#define NETWORK4EBPF_H

#include <iostream>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <thread>
#include <memory>
#include <string>

#define TASK_COMM_LEN 			16
#define S_IPLEN         				64  	// IP地址长度
#define S_DOMAIN_NAMELEN  				256 	// 域名长度

/* definition of a sample sent to user-space from BPF program */
typedef struct network2event {
	unsigned int uid; 
	unsigned int gid;                        	
	unsigned int pid;
	unsigned int tgid;
	unsigned int net_type;   
	char comm[TASK_COMM_LEN]; 
	char parent_comm[TASK_COMM_LEN]; 
	unsigned int parent_pid;
	unsigned char protocol; 
	unsigned short res1: 4;
	unsigned short doff: 4;
	unsigned short fin: 1;
	unsigned short syn: 1;
	unsigned short rst: 1;
	unsigned short psh: 1;
	unsigned short ack: 1;
	unsigned short urg: 1;
	unsigned short ece: 1;
	unsigned short cwr: 1;             
	unsigned short dport;                       
	unsigned short sport;  
	unsigned int daddr;                      
	unsigned int saddr;
	unsigned int sessionid;
	unsigned long start_time;
	char pathname[64];
	char parent_pathname[64];                       
} NETWORK2EVENT;

struct timeval3 {
	long tv_sec;     // 秒
	long tv_usec;    // 微秒
};

struct ebpf_task_simple_info {
	unsigned int 			uid;              // 用户ID
	unsigned int 			euid;             // 有效用户ID
	unsigned int 			pid;              // 进程ID
	int 			did_exec;         // 标志进程是否执行过exec操作
	char 			comm[16];         // 进程的命令名
	unsigned long 	proctime;         // 进程创建时间，用作进程标识
};

struct ebpf_parent_info {
	struct ebpf_task_simple_info task[4];  // 父进程信息数组，保存最多4个父进程的信息
};

typedef struct network2request {              
	unsigned int uid; 
	unsigned int gid;                        	
	unsigned int pid;
	unsigned int tgid;
	unsigned int net_type;   
	char comm[TASK_COMM_LEN]; 
	char parent_comm[TASK_COMM_LEN]; 
	unsigned int parent_pid;
	unsigned char protocol; 
	unsigned short res1: 4;
	unsigned short doff: 4;
	unsigned short fin: 1;
	unsigned short syn: 1;
	unsigned short rst: 1;
	unsigned short psh: 1;
	unsigned short ack: 1;
	unsigned short urg: 1;
	unsigned short ece: 1;
	unsigned short cwr: 1;                
	unsigned short dport;                       
	unsigned short sport;  
	unsigned int daddr;                      
	unsigned int saddr;
	unsigned int sessionid;
	unsigned long start_time;
	char pathname[64];
	char parent_pathname[64];   
	struct ebpf_parent_info pinfo;     
	unsigned long exeino;               
	unsigned long proctime;             
	struct timeval3 event_tv; 
	unsigned short type;          
    
	unsigned int repeat;                
	int domain_query_type;              
	unsigned int effective_time;        
	unsigned int portscan_lockip_time;  
	unsigned int portscan_max;         
	unsigned int honey_lockip_time;    
	unsigned int ports_count;           
	unsigned short reason;             
	char ip[S_IPLEN];                   
	char domain[S_DOMAIN_NAMELEN];      
} NETWORK2REQUEST;

// 使用 std::queue 存储 NETWORK2REQUEST* 实例
extern std::mutex queueMutex2;
extern std::condition_variable queueCondVar2;
extern std::queue<NETWORK2REQUEST*> network2RequestQueue;

#endif
