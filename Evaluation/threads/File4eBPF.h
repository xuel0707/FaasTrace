#ifndef FILE4EBPF_H
#define FILE4EBPF_H

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

/* 操作文件类型 */
#define OP_OPEN 				1        	// 打开文件
#define OP_CLOSE 				2        	// 关闭文件
#define OP_UNLINK 				3        	// 删除文件
#define OP_RENAME 				4        	// 重命名文件
#define OP_LINK 				5        	// 创建硬链接
#define OP_SYMLINK 				6        	// 创建符号链接
#define OP_READ 				7        	// 读取文件内容
#define OP_WRITE 				8        	// 写入文件内容
#define OP_OPEN_W 				9        	// 打开文件（写入模式）
#define OP_OPEN_C 				10       	// 打开文件（创建模式）
#define OP_OPEN_R 				11       	// 打开文件（只读模式）


#define F_SENSITIVE 			1                	// 敏感文件
#define F_LOG_DELETE 			2               	// 日志异常删除
#define F_SAFE 					3                   // 安全文件
#define F_LOGCOLLECTOR 			4             		// 日志采集
#define F_MIDDLE_TARGET 		5            		// 中间件目标文件
#define F_BINARY_FILTER 		6            		// 可执行文件过滤
#define F_MIDDLE_SCRIPT 		7           		// 中间件脚本文件
#define F_ILLEGAL_SCRIPT 		8           		// 非法脚本文件
#define F_WEBSHELL_DETECT 		9          			// Webshell文件检测
#define F_PRINTER 				10                 	// 打印监控
#define F_CDROM 				11                  // 刻录监控
#define F_ENCRYPT_BACKUP 		12          		// 勒索加密文件备份
#define F_ENCRYPT_REPORT 		13          		// 勒索加密报告
#define F_ENCRYPT 				14                 	// 勒索加密防护
#define F_BLACK_AFTER 			15             		// 文件黑名单
#define F_ABNORMAL 				16                	// 异常文件
#define F_USB 					17                  // USB文件监控
#define F_VIRUS 				18                  // 病毒文件

/* definition of a sample sent to user-space from BPF program */
typedef struct file2event {
	unsigned uid;                         	
	unsigned int pid;
	unsigned int tgid;                          
	char comm[TASK_COMM_LEN];
	char parent_comm[TASK_COMM_LEN]; 
	char filename[32];
	unsigned int pro_len;
	unsigned int size;
	unsigned int path_len;
	char tty[S_TTYLEN];
	char args[4][64];
	char abs_path[256];                     
} FILE2EVENT;

struct task_simple_info {
	unsigned int uid;
	unsigned int euid;
	int did_exec;
	char comm[16];
	unsigned long proctime; //进程创建时间，作为进程标识
};

struct parent_info {
	struct task_simple_info task[4];  // 父进程信息，最多4代
};

struct timeval2 {
	long tv_sec;     // 秒
	long tv_usec;    // 微秒
};

typedef struct file2request {              
	int uid;                         	
	int pid;
	int tgid;                          
	char comm[TASK_COMM_LEN];         
	char parent_comm[TASK_COMM_LEN];    
	char filename[32];
	int size;
	int path_len;
	char tty[S_TTYLEN];
	char args[4][64];
	int pro_len;
	char abs_path[256];    

	int did_exec;  
	struct timeval2 event_tv;
	unsigned long proctime;					
	unsigned long pipein;            
	unsigned long pipeout;           
	unsigned long exeino;             
	struct file *exe_file;             
	unsigned short op_type;            
	unsigned short type;                    
	unsigned int mode;                
	unsigned int flags;                
	unsigned int mnt_id;               
	long mtime_sec;                    
	long mtime_nsec;                 
	long long int file_size;          
	long long int newfile_size;       
	struct parent_info pinfo;          
	           
	char new_filename[64];             
	unsigned int newpath_len;          
	char pro_pathname[64];             
       
	int terminate;                             
	char nodename[S_NAMELEN+1];       
	char cmd[S_CMDLEN];              
	char cwd[S_CWDLEN];               
    int argc;        
} FILE2REQUEST;

// 使用 std::queue 存储 FILE2REQUEST* 实例
extern std::mutex queueMutex;
extern std::condition_variable queueCondVar;
extern std::queue<FILE2REQUEST*> file2RequestQueue;

#endif
