// #include "vmlinux.h"
#include "dm_crypt.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


// 总体信息，包括加密层和
struct crypt_io_info {
	u64 base_bio_ptr;      		// 原始 BIO 地址
    u32 sector;            		// 起始扇区
    u32 len;               		// IO 长度
	char cipher_name[32];		// 加密函数名称

	u64 crypt_map_time;			// 进入dm_crypt
	u64 crypt_start;			// 进入加密时间
	u64 crypt_end;				// 加密结束时间

    u64 pure_crypt_time;        // 纯粹的cpu加密时间
	int crypt_convert_calls;	// 调用次数
};

// 用于定位上下文
struct thread_crypt {
	void *io_ptr;		
	u64 start_us;
}; 

// 用tid来定位加密计算 负责计算纯净加密时间
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(struct thread_crypt));
} crypt_con_tmp SEC(".maps");

// struct bio 和 struct io_info的哈希表 通过bio来定位io_info
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct crypt_io_info));
} io_map SEC(".maps");

// ringbuffer
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 进入加密层
SEC("kprobe/dm_crypt_queue_io")
int BPF_KPROBE(dm_crypt_queue_io, struct dm_crypt_io *io)
{
	void *io_ptr = (void *)io;
	struct crypt_io_info info;

	// 初始化信息
	info.base_bio_ptr = (u64)BPF_CORE_READ(io, base_bio);
	info.sector = BPF_CORE_READ(io, sector);
	info.crypt_map_time = bpf_ktime_get_ns();

	// 获取算法名称
	struct crypt_config *cc = BPF_CORE_READ(io, cc);
	BPF_CORE_READ_STR_INTO(info.cipher_name, cc, cipher_string);

	bpf_map_update_elem(&io_map, &io_ptr, &info, BPF_ANY);
	return 0;
}

// 加密处理函数
SEC("kprobe/crypt_convert")
int BPF_KPROBE(crypt_convert_entery, struct crypt_config *cc, struct convert_context *dm_ctx)
{	
	u64 tid = bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();
	struct thread_crypt t_cry;
	struct crypt_io_info *info;
	
	// 获取dm_crypt_io 当作标识符
	size_t offset = bpf_core_field_offset(struct dm_crypt_io, ctx);
	struct dm_crypt_io *io = (void *)((char *)ctx - offset);
	
	info = bpf_map_lookup_elem(&io_map, &io);
	if (info)
		if (info->crypt_start == 0)
			info->crypt_start = ts;

	t_cry.io_ptr = io;
	t_cry.start_us = ts;

	bpf_map_update_elem(&crypt_con_tmp, &tid, &t_cry, BPF_ANY);

	return 0;

}

SEC("kretprobe/crypt_convert")
int BPF_KRETPROBE(ctypy_convert_exit)
{
	u64 tid = bpf_get_current_pid_tgid();
	u64 now = bpf_ktime_get_ns();
	
	struct thread_crypt *t_cry = bpf_map_lookup_elem(&crypt_con_tmp, &tid);
	if (t_cry) {
		struct crypt_io_info *info = bpf_map_lookup_elem(&io_map, &t_cry->io_ptr);
		if (info) {
			info->crypt_end = now;
			info->pure_crypt_time += (now - t_cry->start_us);
		}
	}
	
	bpf_map_delete_elem(&crypt_con_tmp, &tid);

	return 0;
}

SEC("kprobe/crypt_endio")
int BPF_KPROBE(crypt_endio, struct bio *clone)
{
    // 在克隆 bio 中，bi_private 直接指向 dm_crypt_io
    void *io_ptr = BPF_CORE_READ(clone, bi_private);

    struct crypt_io_info *info = bpf_map_lookup_elem(&io_map, &io_ptr);
    if (info) {
        
        struct crypt_io_info *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
        if (event) {
            *event = *info;
            bpf_ringbuf_submit(event, 0);
        }
        
        bpf_map_delete_elem(&io_map, &io_ptr);
    }
    return 0;
}


char LICENSE[] SEC("license") = "GPL";
