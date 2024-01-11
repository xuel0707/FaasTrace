#ifndef PROCESS4EBPF_H
#define PROCESS4EBPF_H

#include <iostream>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <thread>
#include <memory>
#include <string>

#define TASK_COMM_LEN 			16
#define S_TTYLEN        		30 
#define S_NAMELEN       		64
#define S_CWDLEN        		200
#define S_CMDLEN        		400
#define S_COMMLEN       		16  	// 进程名称长度
#define SNIPER_PGEN 			8  		// 父进程信息中最大的父进程数量

struct task_simple_info3 {
	uid_t uid;              			// 用户ID
	uid_t euid;             			// 有效用户ID
	pid_t pid;             			 	// 进程ID
	int did_exec;           			// 标志进程是否执行过exec操作
	char comm[S_COMMLEN];   			// 进程的命令名
	unsigned long proctime; 			// 进程创建时间，用作进程标识
};

struct parent_info3 {
	struct task_simple_info3 task[SNIPER_PGEN];  // 父进程信息数组，保存最多SNIPER_PGEN个父进程的信息
};

/* definition of a sample sent to user-space from BPF program */
typedef struct process2event {
	unsigned int pid;
	unsigned int tgid;
	char comm[TASK_COMM_LEN]; 
	char parent_comm[TASK_COMM_LEN]; 
	unsigned parent_pid;
	char args[8][32]; 
	unsigned short argc;  
	struct parent_info3 pinfo;        // 父进程信息（最多4代）                   
} PROCESS2EVENT;

struct ebpf_task_simple_info3 {
	uid_t 			uid;              // 用户ID
	uid_t 			euid;             // 有效用户ID
	pid_t 			pid;              // 进程ID
	int 			did_exec;         // 标志进程是否执行过exec操作
	char 			comm[16];         // 进程的命令名
	unsigned long 	proctime;         // 进程创建时间，用作进程标识
};

struct ebpf_parent_info3 {
	struct ebpf_task_simple_info3 task[4];  // 父进程信息数组，保存最多4个父进程的信息
};
typedef struct process2request {              
	int uid;                                        
	int ppid;                     
	unsigned int euid;            
	unsigned int pid;
	unsigned int tgid;
	char comm[TASK_COMM_LEN]; 
	char parent_comm[TASK_COMM_LEN]; 
	unsigned parent_pid;
	char args[8][32];   

	unsigned long proctime;      
	unsigned long pipein;        
	unsigned long pipeout;      
	unsigned long exeino;        
	unsigned short cmdlen;      
	unsigned short argslen;     
	unsigned short cwdlen;     
	unsigned short argc;         
	unsigned short options;      
	unsigned int mnt_id;       
	struct ebpf_parent_info3 pinfo; 
	struct file *exe_file;        
	char tty[S_TTYLEN];          
	char nodename[S_NAMELEN+1];    
	char cmd[S_CMDLEN];          
	char cwd[S_CWDLEN];        
} PROCESS2REQUEST;

// 使用 std::queue 存储 FILE2REQUEST* 实例
extern std::mutex queueMutex3;
extern std::condition_variable queueCondVar3;
extern std::queue<PROCESS2REQUEST*> process2RequestQueue;

#endif
