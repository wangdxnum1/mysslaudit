// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Yusheng Zheng
//
// Based on mysslaudit from BCC by Adrian Lopez & Mark Drayton.
// 15-Aug-2023   Yusheng Zheng   Created this.
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "mysslaudit.h"

// 添加在头文件包含之后，其他代码之前
// 在头文件包含后添加协议族宏定义
#define AF_INET 2
#define AF_INET6 10

//替换原有的typedef定义
#if defined(bpf_target_x86)
#define SOCKLEN_T unsigned int
#elif defined(bpf_target_arm64)
#define SOCKLEN_T unsigned long
#endif

typedef SOCKLEN_T socklen_t;

// 发送给应用层的消息，例如解密之后的内容，客户端信息等
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} perf_SSL_events SEC(".maps");

#define BASE_EVENT_SIZE ((size_t)(&((struct probe_SSL_data_t *)0)->buf))
#define EVENT_SIZE(X) (BASE_EVENT_SIZE + ((size_t)(X)))
#define MAX_ENTRIES 10240

#define min(x, y)                      \
    ({                                 \
        typeof(x) _min1 = (x);         \
        typeof(y) _min2 = (y);         \
        (void)(&_min1 == &_min2);      \
        _min1 < _min2 ? _min1 : _min2; \
    })

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct probe_SSL_data_t);
} ssl_data SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, __u64);
} start_ns SEC(".maps");

//
// openssl SSL_read,SSL_write传进来的参数
//
struct ssl_read_write_args{
    void *ssl;
    void *buf;
    int num;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct ssl_read_write_args);
} openssl_read_write_args SEC(".maps");

//
// socket accept 传进来的参数
//
struct accept_args {
    int sockfd;
    struct sockaddr *addr; // 替换为内核结构体
    unsigned int addrlen;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct accept_args);
} glibc_accept_args SEC(".maps");

// 添加文件描述符到地址的映射
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, int);
    __type(value, struct sockaddr);
} fd_to_sockaddr SEC(".maps");

struct ssl_key {
    __u64 pid;
    __u64 ssl_ptr;
};

// 更新SSL到fd的映射
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ssl_key);
    __type(value, int);
} ssl_to_fd SEC(".maps");

const volatile pid_t targ_pid = 0;
const volatile uid_t targ_uid = -1;

static __always_inline bool trace_allowed(u32 uid, u32 pid)
{
    /* filters */
    if (targ_pid && targ_pid != pid)
        return false;
    if (targ_uid != -1) {
        if (targ_uid != uid) {
            return false;
        }
    }
    return true;
}


static void do_print_client_info(struct sockaddr *client, const char* funcname){
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    //调试用，通过fd获取客户端信息，输出客户端信息
    if (client) {
        if (client->sa_family == AF_INET) {
            struct sockaddr_in *sockaddr = (struct sockaddr_in *)client;

            uint32_t ip = sockaddr->sin_addr.s_addr;
            uint16_t port = bpf_ntohs(sockaddr->sin_port);

            uint8_t b1 = (ip >> 24) & 0xFF;
            uint8_t b2 = (ip >> 16) & 0xFF;
            uint8_t b3 = (ip >> 8) & 0xFF;
            uint8_t b4 = ip & 0xFF;

            bpf_printk("BPF triggered uretprobe/SSL_read_write_exit [%s] from PID %d, src addr : %d.%d.%d.%d:%d\n", funcname, pid, b4, b3, b2, b1, port);
        }else{
            //struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&args->addr;
            //compact.port = sin6->sin6_port;
            // __builtin_memcpy(compact.addr, sin6->sin6_addr.s6_addr, 16);
            bpf_printk("BPF triggered uretprobe/SSL_read_write_exit from PID %d do not support ipv6 now\n", pid);
        }
    }else{
        bpf_printk("BPF triggered uretprobe/SSL_read_write_exit from PID %d not found client socket address\n", pid);
    }
}

static void print_client_info(struct sockaddr *client, int rw){
    if(rw == 0){
        do_print_client_info(client, "SSL_read");
    }else if(rw == 1){
        do_print_client_info(client, "SSL_write");
    }else if(rw == 2){
        
    }else{

    }
}

// 跟踪glibc的accept函数
SEC("uprobe/accept")
int BPF_UPROBE(probe_accept_enter, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    //bpf_printk("BPF triggered uprobe/accept from PID %d\n", pid);

    struct accept_args args = {0};
    
    // 保存参数
    args.sockfd = sockfd;
    args.addr = addr;

    socklen_t len;
    bpf_probe_read_user(&len, sizeof(len), addrlen);
    args.addrlen = len;
    
    bpf_map_update_elem(&glibc_accept_args, &pid_tgid, &args, BPF_ANY);

    return 0;
}

SEC("uretprobe/accept")
int BPF_URETPROBE(probe_accept_exit)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    //bpf_printk("BPF triggered uretprobe/accept from PID %d\n", pid);

    int new_fd = (int)PT_REGS_RC(ctx);
    if (new_fd < 0) return 0;

    // 获取保存的参数
    struct accept_args *args = bpf_map_lookup_elem(&glibc_accept_args, &pid_tgid);
    if (!args) return 0;

    //bpf_printk("BPF triggered uretprobe/accept from PID %d, sockfd : %d, addr : 0x%x, addrLen : %d\n", pid, args->sockfd, args->addr, args->addrlen);

    struct sockaddr addr = { 0 };
    socklen_t len = min(args->addrlen, (socklen_t)sizeof(args->addr));
    bpf_probe_read_user(&addr, len, args->addr);
    
    do_print_client_info(&addr, "accept");

    // 保存到fd映射
    bpf_map_update_elem(&fd_to_sockaddr, &new_fd, &addr, BPF_ANY);
    bpf_map_delete_elem(&glibc_accept_args, &pid_tgid);

    return 0;
}


SEC("uprobe/SSL_read")
int BPF_UPROBE(probe_SSL_read_enter, void *ssl, void *buf, int num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u32 uid = bpf_get_current_uid_gid();
    u64 ts = bpf_ktime_get_ns();

    if (!trace_allowed(uid, pid)) {
        return 0;
    }

    //bpf_printk("BPF triggered uprobe/SSL_read from PID %d, ssl : 0x%x\n", pid, ssl);

    /* store arg info for later lookup */
    struct ssl_read_write_args args = { 0 };
    args.buf = buf;
    args.ssl = ssl;
    args.num = num;

    bpf_map_update_elem(&openssl_read_write_args, &pid_tgid, &args, BPF_ANY);
    bpf_map_update_elem(&start_ns, &pid_tgid, &ts, BPF_ANY);

    return 0;
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(probe_SSL_write_enter, void *ssl, void *buf, int num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u32 uid = bpf_get_current_uid_gid();
    u64 ts = bpf_ktime_get_ns();

    if (!trace_allowed(uid, pid)) {
        return 0;
    }

    //bpf_printk("BPF triggered uprobe/SSL_write from PID %d, ssl : 0x%x\n", pid, ssl);

    /* store arg info for later lookup */
    struct ssl_read_write_args args = { 0 };
    args.buf = buf;
    args.ssl = ssl;
    args.num = num;
    
    bpf_map_update_elem(&openssl_read_write_args, &pid_tgid, &args, BPF_ANY);
    bpf_map_update_elem(&start_ns, &pid_tgid, &ts, BPF_ANY);

    return 0;
}

SEC("uprobe/SSL_set_fd")
int BPF_UPROBE(probe_SSL_set_fd_enter, void *ssl, int fd) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u32 uid = bpf_get_current_uid_gid();
    u64 ts = bpf_ktime_get_ns();

    if (!trace_allowed(uid, pid)) {
        return 0;
    }

    struct ssl_key key = {
        .pid = pid_tgid,
        .ssl_ptr = (__u64)ssl
    };

    // 存储复合键关联,ssl->fd
    bpf_map_update_elem(&ssl_to_fd, &key, &fd, BPF_ANY);

    return 0;
}

//gnutls_transport_set_int
SEC("uprobe/gnutls_transport_set_ptr")
int BPF_UPROBE(probe_gnutls_transport_set_ptr_enter, void*session, void* fd) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u32 uid = bpf_get_current_uid_gid();
    u64 ts = bpf_ktime_get_ns();

    if (!trace_allowed(uid, pid)) {
        return 0;
    }

    //bpf_printk("BPF triggered uprobe/gnutls_transport_set_ptr from PID %d, session : 0x%x, fd : %d\n", pid, session, (int)(long)fd);
    return 0;
}

static int SSL_read_write_exit(struct pt_regs *ctx, int rw) {
    int ret = 0;
    u32 zero = 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u32 uid = bpf_get_current_uid_gid();
    u64 ts = bpf_ktime_get_ns();

    if (!trace_allowed(uid, pid)) {
        return 0;
    }

    // 检查返回值
    // 实际读取或者写入的长度
    int len = PT_REGS_RC(ctx);
    if (len <= 0)  // no data
        return 0;

    // 获取read或者write传进来的参数，包括ssl和buf
    struct ssl_read_write_args *ssl_args = bpf_map_lookup_elem(&openssl_read_write_args, &pid_tgid);
    if (ssl_args == 0)
        return 0;

    /* store arg info for later lookup */
    u64 *bufp = ssl_args->buf;
    if (bufp == 0)
        return 0;

    u64 *sslp = ssl_args->ssl;
    if (sslp == 0)
        return 0;

    // 根据ssl获取关联的fd
    struct ssl_key key = {
        .pid = pid_tgid,
        .ssl_ptr = (__u64)sslp,
    };
    int *fdp = bpf_map_lookup_elem(&ssl_to_fd, &key);
    if (!fdp) {
        bpf_printk("BPF triggered uretprobe/SSL_read_write_exit from PID : %d TID : %d, ssl : 0x%x not found fdp, rw : %d\n", pid, tid, key.ssl_ptr, rw);
        //bpf_printk("BPF triggered uretprobe/SSL_read_write_exit from PID : %d TID : %d, ssl : 0x%x not found fdp, rw : %d\n", pid, tid, key, rw);
        return 0;
    }

    //调通过fd获取客户端信息，输出客户端信息
    struct sockaddr *sockaddr = bpf_map_lookup_elem(&fd_to_sockaddr, fdp);
   
    // ebpf 程序调试用，输出客户端地址信息，可注释
    print_client_info(sockaddr, rw);

    // 获取发给应用的数据
    struct probe_SSL_data_t *data = bpf_map_lookup_elem(&ssl_data, &zero);
    if (!data)
        return 0;

    u64 *tsp = bpf_map_lookup_elem(&start_ns, &pid_tgid);
    if (!tsp)
        return 0;
    u64 delta_ns = ts - *tsp;

    // 构造发给应用层的数据包
    data->timestamp_ns = ts;
    data->delta_ns = delta_ns;
    data->pid = pid;
    data->tid = tid;
    data->uid = uid;
    data->len = (u32)len;
    data->buf_filled = 0;
    data->rw = rw;
    data->is_handshake = false;
    u32 buf_copy_size = min((size_t)MAX_BUF_SIZE, (size_t)len);

    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    // 读取SSL_read或者SSL_write的buf里面的内容
    // SSL_read解密之后的内容
    // SSL_write是传进来的明文内容
    if (bufp != 0)
        ret = bpf_probe_read_user(&data->buf, buf_copy_size, (char *)bufp);

    // 客户端地址信息
    if(sockaddr){
        __builtin_memcpy(&data->addr, sockaddr, sizeof(struct sockaddr));
    }

    bpf_map_delete_elem(&openssl_read_write_args, &pid_tgid);
    bpf_map_delete_elem(&start_ns, &pid_tgid);

    if (!ret)
        data->buf_filled = 1;
    else
        buf_copy_size = 0;

    // 上报给应用层,包括明文数据，客户端地址信息等
    bpf_perf_event_output(ctx, &perf_SSL_events, BPF_F_CURRENT_CPU, data,
                            EVENT_SIZE(buf_copy_size));
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(probe_SSL_read_exit) {
    return (SSL_read_write_exit(ctx, 0));
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(probe_SSL_write_exit) {
    return (SSL_read_write_exit(ctx, 1));
}

SEC("uprobe/do_handshake")
int BPF_UPROBE(probe_SSL_do_handshake_enter, void *ssl) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u64 ts = bpf_ktime_get_ns();
    u32 uid = bpf_get_current_uid_gid();

    if (!trace_allowed(uid, pid)) {
        return 0;
    }

    /* store arg info for later lookup */
    bpf_map_update_elem(&start_ns, &pid_tgid, &ts, BPF_ANY);
    return 0;
}

SEC("uretprobe/do_handshake")
int BPF_URETPROBE(probe_SSL_do_handshake_exit) {
    u32 zero = 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u32 uid = bpf_get_current_uid_gid();
    u64 ts = bpf_ktime_get_ns();
    int ret = 0;

    /* use kernel terminology here for tgid/pid: */
    u32 tgid = pid_tgid >> 32;

    /* store arg info for later lookup */
    if (!trace_allowed(tgid, pid)) {
        return 0;
    }

    u64 *tsp = bpf_map_lookup_elem(&start_ns, &pid_tgid);
    if (tsp == 0)
        return 0;

    ret = PT_REGS_RC(ctx);
    if (ret <= 0)  // handshake failed
        return 0;

    struct probe_SSL_data_t *data = bpf_map_lookup_elem(&ssl_data, &zero);
    if (!data)
        return 0;

    data->timestamp_ns = ts;
    data->delta_ns = ts - *tsp;
    data->pid = pid;
    data->tid = tid;
    data->uid = uid;
    data->len = ret;
    data->buf_filled = 0;
    data->rw = 2;
    data->is_handshake = true;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_map_delete_elem(&start_ns, &pid_tgid);

    bpf_perf_event_output(ctx, &perf_SSL_events, BPF_F_CURRENT_CPU, data,
                            EVENT_SIZE(0));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
