#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/version.h>
#include "structs.h"
#include "support_function.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);   //256 KB
} fileopen_ringbuf SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(sample_file_open, struct file *file, int ret) {
  
  /* ret is the return value from the previous BPF program
  * or 0 if it's the first hook.
  */
  if (ret != 0)
      return ret;

  struct fevent *e;
	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&fileopen_ringbuf, sizeof(*e), 0);
	if (!e)
		return 0;

  struct task_struct *current = bpf_get_current_task_btf();

  e->uid= current->cred->uid.val;
	e->pid = bpf_get_current_pid_tgid() ;
  e->tgid = bpf_get_current_pid_tgid() >> 32;
  e->size=file->f_path.dentry->d_inode->i_size;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
  e->pro_len=my_strlen(e->comm);

  bpf_probe_read_kernel_str(e->filename, sizeof(file->f_path.dentry->d_iname),file->f_path.dentry->d_iname);
  bpf_probe_read_kernel_str(e->parent_comm, sizeof(current->real_parent->comm), current->real_parent->comm);
  e->path_len=256;
  
  /* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);

  return 0;
}

// Some eBPF programs must be GPL licensed. This depends on program types.
char _license[] SEC("license") = "GPL";
