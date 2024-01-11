#ifndef LOAD_EBPF_H
#define LOAD_EBPF_H

// Enum for eBPF program types
enum ebpf_program_type {
    EBPF_EXECVE,
    EBPF_FILE,
    EBPF_NET,
    EBPF_PROGRAMS_NUM
};

// Paths to the eBPF programs
// Replace these with the actual paths to your eBPF programs
#define EBPF_EXECVE_HOOK_PROGRAM	"ebpf_process_kern.o"
#define EBPF_FILE_HOOK_PROGRAM      "ebpf_file_kern.o"
#define EBPF_NET_HOOK_PROGRAM       "ebpf_net_kern.o"

// Function declarations

#ifdef __cplusplus
extern "C" {
#endif

extern int load_ebpf_program(void);
extern int unload_ebpf_program(void);
extern struct bpf_object *get_bpf_object(int);

#ifdef __cplusplus
}
#endif
#endif // LOAD_EBPF_H


