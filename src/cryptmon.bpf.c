// #include "vmlinux.h"
#include "dm_crypt.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 加密函数和加密时间等信息
struct cipher_info {
	char cipher_name[32];		// 加密函数名称
	u64 crypt_start;			// 进入加密时间
	u64 crypt_end;				// 加密结束时间
    u64 pure_crypt_time;        // 纯粹的cpu加密时间
};

// 总体信息，包括加密层和block层
struct io_info {
	u64 submit_entry;			// 提交bio时间
	u64 blk_start;				// 提交到物理磁盘队列
	struct cipher_info cipher;	// 加密信息
	u32 crypt_flag;				// 是否经过加密
	u32 bio_count;				// 记录bio数量 用于判断子bio是否完成
};

// struct bio 和 struct io_info的哈希表 通过bio来定位io_info
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__uint(key_size, sizeof(struct bio *));
	__uint(value_size, sizeof(struct io_info));
} io_map SEC(".maps");

// 用tid来定位加密计算 负责计算纯净加密时间
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(u64));
} crypt_time SEC(".maps");

// ringbuffer
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 记录submit_bio 第一次进入的时间 从这个开始分析时间
SEC("kprobe/submit_bio")
int BPF_KPROBE(submit_bio_entry, struct bio *bio)
{
	struct io_info info = {};

	// 初始化info结构体
	info.submit_entry = bpf_ktime_get_ns();
	info.blk_start = 0;
	info.cipher.crypt_start = 0;
	info.cipher.crypt_end = 0;
	info.cipher.pure_crypt_time = 0;
	info.bio_count = 0;
	info.crypt_flag = false;

	// debug
	// bpf_printk("T0: bio=%p\n", bio);

	bpf_map_update_elem(&io_map, &bio, &info, BPF_ANY);

	return 0;
}

SEC("kprobe/crypt_convert")
int BPF_KPROBE(crypt_convert_entery, struct crypt_config *cc, struct convert_context *dm_ctx)
{	

	// debug
	u64 ctx_addr = (u64)dm_ctx;
	u32 offset = bpf_core_field_offset(struct dm_crypt_io, ctx);
	u64 dm_crypt_io_addr = ctx_addr - offset;
	struct bio *base_bio = NULL;
	bpf_probe_read_kernel(&base_bio, sizeof(base_bio), (void*)(dm_crypt_io_addr + bpf_core_field_offset(struct dm_crypt_io, base_bio))); 



	struct bio *bio_in;
	// bpf_probe_read_kernel(&bio_in, sizeof(bio_in), &dm_ctx->bio_in);
	bio_in = base_bio;

	struct io_info *info = bpf_map_lookup_elem(&io_map, &bio_in);
	if (!info) {
		struct bio* parent;
		bpf_probe_read_kernel(&parent, sizeof(parent), &bio_in->bi_private);
		if (parent)
			info = bpf_map_lookup_elem(&io_map, &parent);
	}

	// 如果找到了
	if (info) {

		// debug
		bpf_printk("find\n");

		u64 now = bpf_ktime_get_ns();
		info->bio_count = info->bio_count + 1;

		if (info->cipher.crypt_start = 0)
			info->cipher.crypt_start = now;

		// 如果是第一次就获取名字
		//if (info->bio_count == 1) {
		if (true) {
			char *crypt_name;

			if (bpf_probe_read_kernel(&crypt_name, sizeof(crypt_name), &cc->cipher_string) < 0) {
				return 0;
			} 
			
			if (crypt_name) {
				bpf_probe_read_kernel_str(info->cipher.cipher_name, sizeof(info->cipher.cipher_name), crypt_name);
			}

		}

	} else bpf_printk("find nothing\n");


    u32 pid = bpf_get_current_pid_tgid() >> 32;
	
    // 在 /sys/kernel/debug/tracing/trace_pipe 中可以看到输出
    bpf_printk("crypt function enterd, called by pid %d\n", pid);
    bpf_printk("cryp: %s\n", info->cipher.cipher_name);
	return 0;
}

SEC("kretprobe/crypt_convert")
int BPF_KRETPROBE(ctypy_convert_exit)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
		
	bpf_printk("crypt function exit, called by pid %d\n", pid);
	return 0;
}

SEC("kprobe/bio_endio")
int BPF_KPROBE(bio_endio, struct bio* bio) {

	struct io_info *info = bpf_map_lookup_elem(&io_map, &bio);
	

}

char LICENSE[] SEC("license") = "GPL";
