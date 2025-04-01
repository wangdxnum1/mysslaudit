// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Yusheng Zheng
//
// Based on mysslaudit from BCC by Adrian Lopez & Mark Drayton.
// 15-Aug-2023   Yusheng Zheng   Created this.
#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <errno.h>
#include <linux/types.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <dirent.h>
#include <fcntl.h>


#include "mysslaudit.skel.h"
#include "mysslaudit.h"

#define INVALID_UID -1
#define INVALID_PID -1
#define DEFAULT_BUFFER_SIZE 8192

#define __ATTACH_UPROBE(skel, binary_path, sym_name, prog_name, is_retprobe)   \
	do {                                                                       \
	  LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, .func_name = #sym_name,        \
				  .retprobe = is_retprobe);                                    \
	  skel->links.prog_name = bpf_program__attach_uprobe_opts(                 \
		  skel->progs.prog_name, env.pid, binary_path, 0, &uprobe_opts);       \
	} while (false)

#define __CHECK_PROGRAM(skel, prog_name)               \
	do {                                               \
	  if (!skel->links.prog_name) {                    \
		perror("no program attached for " #prog_name); \
		return -errno;                                 \
	  }                                                \
	} while (false)

#define __ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name,     \
								is_retprobe)                                \
	do {                                                                    \
	  __ATTACH_UPROBE(skel, binary_path, sym_name, prog_name, is_retprobe); \
	  __CHECK_PROGRAM(skel, prog_name);                                     \
	} while (false)

#define ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name)     \
	__ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, binary_path, sym_name, prog_name)  \
	__ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name, true)

volatile sig_atomic_t exiting = 0;

const char *argp_program_version = "mysslaudit 0.1";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
	"Sniff SSL data.\n"
	"\n"
	"USAGE: mysslaudit [OPTIONS]\n"
	"\n"
	"EXAMPLES:\n"
	"    ./mysslaudit              # sniff OpenSSL and GnuTLS functions\n"
	"    ./mysslaudit -p 181       # sniff PID 181 only\n"
	"    ./mysslaudit -u 1000      # sniff only UID 1000\n"
	"    ./mysslaudit -c curl      # sniff curl command only\n"
	"    ./mysslaudit --no-openssl # don't show OpenSSL calls\n"
	"    ./mysslaudit --no-gnutls  # don't show GnuTLS calls\n"
	"    ./mysslaudit --no-nss     # don't show NSS calls\n"
	"    ./mysslaudit --hexdump    # show data as hex instead of trying to "
	"decode it as UTF-8\n"
	"    ./mysslaudit -x           # show process UID and TID\n"
	"    ./mysslaudit -l           # show function latency\n"
	"    ./mysslaudit -l --handshake  # show SSL handshake latency\n"
	"    ./mysslaudit --extra-lib openssl:/path/libssl.so.1.1 # sniff extra "
	"library\n";

struct env {
	pid_t pid;
	int uid;
	bool extra;
	char *comm;
	bool openssl;
	bool gnutls;
	bool nss;
	bool hexdump;
	bool latency;
	bool handshake;
	char *extra_lib;
	bool mysql;
} env = {
	.uid = INVALID_UID,
	.pid = INVALID_PID,
	.openssl = true,
	.gnutls = true,
	.nss = true,
	.comm = NULL,
	.mysql = true,
};

#define HEXDUMP_KEY 1000
#define HANDSHAKE_KEY 1002
#define EXTRA_LIB_KEY 1003

static const struct argp_option opts[] = {
	{"pid", 'p', "PID", 0, "Sniff this PID only."},
	{"uid", 'u', "UID", 0, "Sniff this UID only."},
	{"extra", 'x', NULL, 0, "Show extra fields (UID, TID)"},
	{"comm", 'c', "COMMAND", 0, "Sniff only commands matching string."},
	{"no-openssl", 'o', NULL, 0, "Do not show OpenSSL calls."},
	{"no-gnutls", 'g', NULL, 0, "Do not show GnuTLS calls."},
	{"no-nss", 'n', NULL, 0, "Do not show NSS calls."},
	{"hexdump", HEXDUMP_KEY, NULL, 0,
	 "Show data as hexdump instead of trying to decode it as UTF-8"},
	{"latency", 'l', NULL, 0, "Show function latency"},
	{"handshake", HANDSHAKE_KEY, NULL, 0,
	 "Show SSL handshake latency, enabled only if latency option is on."},
	{"verbose", 'v', NULL, 0, "Verbose debug output"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static bool verbose = false;

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
	switch (key) {
	case 'p':
		env.pid = atoi(arg);
		break;
	case 'u':
		env.uid = atoi(arg);
		break;
	case 'x':
		env.extra = true;
		break;
	case 'c':
		env.comm = strdup(arg);
		break;
	case 'o':
		env.openssl = false;
		break;
	case 'g':
		env.gnutls = false;
		break;
	case 'n':
		env.nss = false;
		break;
	case 'l':
		env.latency = true;
		break;
	case 'v':
		verbose = true;
		break;
	case HEXDUMP_KEY:
		env.hexdump = true;
		break;
	case HANDSHAKE_KEY:
		env.handshake = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static struct argp argp = {
	opts,
	parse_arg,
	NULL,
	argp_program_doc
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
						   va_list args) {
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static void sig_int(int signo) { 
	exiting = 1;
}

int attach_openssl(struct mysslaudit_bpf *skel, const char *lib) {
	ATTACH_UPROBE_CHECKED(skel, lib, SSL_write, probe_SSL_write_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, SSL_write, probe_SSL_write_exit);
	ATTACH_UPROBE_CHECKED(skel, lib, SSL_read, probe_SSL_read_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, SSL_read, probe_SSL_read_exit);

	ATTACH_UPROBE_CHECKED(skel, lib, SSL_set_fd, probe_SSL_set_fd_enter);

	if (env.latency && env.handshake) {
		// ATTACH_UPROBE_CHECKED(skel, lib, SSL_do_handshake,
		// 					probe_SSL_do_handshake_enter);
		// ATTACH_URETPROBE_CHECKED(skel, lib, SSL_do_handshake,
		// 						probe_SSL_do_handshake_exit);
	}

	return 0;
}

int attach_gnutls(struct mysslaudit_bpf *skel, const char *lib) {
	ATTACH_UPROBE_CHECKED(skel, lib, gnutls_record_send, probe_SSL_write_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, gnutls_record_send, probe_SSL_write_exit);
	ATTACH_UPROBE_CHECKED(skel, lib, gnutls_record_recv, probe_SSL_read_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, gnutls_record_recv, probe_SSL_read_exit);

	ATTACH_UPROBE_CHECKED(skel, lib, gnutls_transport_set_ptr, probe_gnutls_transport_set_ptr_enter);

	return 0;
}

int attach_nss(struct mysslaudit_bpf *skel, const char *lib) {
	ATTACH_UPROBE_CHECKED(skel, lib, PR_Write, probe_SSL_write_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, PR_Write, probe_SSL_write_exit);
	ATTACH_UPROBE_CHECKED(skel, lib, PR_Send, probe_SSL_write_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, PR_Send, probe_SSL_write_exit);
	ATTACH_UPROBE_CHECKED(skel, lib, PR_Read, probe_SSL_read_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, PR_Read, probe_SSL_read_exit);
	ATTACH_UPROBE_CHECKED(skel, lib, PR_Recv, probe_SSL_read_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, PR_Recv, probe_SSL_read_exit);

	return 0;
}

int attach_mysql_openssl(struct mysslaudit_bpf *skel, const char *lib) {
	ATTACH_UPROBE_CHECKED(skel, lib, SSL_write, probe_SSL_write_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, SSL_write, probe_SSL_write_exit);
	ATTACH_UPROBE_CHECKED(skel, lib, SSL_read, probe_SSL_read_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, SSL_read, probe_SSL_read_exit);

	ATTACH_UPROBE_CHECKED(skel, lib, SSL_set_fd, probe_SSL_set_fd_enter);

	if (env.latency && env.handshake) {
		// ATTACH_UPROBE_CHECKED(skel, lib, SSL_do_handshake,
		// 					probe_SSL_do_handshake_enter);
		// ATTACH_URETPROBE_CHECKED(skel, lib, SSL_do_handshake,
		// 						probe_SSL_do_handshake_exit);
	}

	return 0;
}

int attach_glibc_accept(struct mysslaudit_bpf *skel, const char *lib)
{
    // 附加到glibc的accept函数
    ATTACH_UPROBE_CHECKED(skel, lib, accept, probe_accept_enter);
    ATTACH_URETPROBE_CHECKED(skel, lib, accept, probe_accept_exit);
    
    // 可选：附加accept4
    // ATTACH_UPROBE_CHECKED(skel, libc_path, accept4, probe_accept_enter);
    // ATTACH_URETPROBE_CHECKED(skel, libc_path, accept4, probe_accept_exit);
    
    return 0;
}

// static int attach_accept_tracepoints(struct mysslaudit_bpf *skel)
// {
//     // 附加accept4跟踪点
//     skel->links.trace_accept4_enter = bpf_program__attach(skel->progs.trace_accept4_enter);
//     skel->links.trace_accept4_exit = bpf_program__attach(skel->progs.trace_accept4_exit);
    
//     if (!skel->links.trace_accept4_enter || !skel->links.trace_accept4_exit) {
//         fprintf(stderr, "Failed to attach accept tracepoints\n");
//         return -1;
//     }
//     return 0;
// }

/*
 * Find the path of a library using ldconfig.
 */
char *find_library_path(const char *libname) {
	char cmd[128];
	static char path[512];
	FILE *fp;

	// Construct the ldconfig command with grep
	snprintf(cmd, sizeof(cmd), "ldconfig -p | grep %s", libname);

	// Execute the command and read the output
	fp = popen(cmd, "r");
	if (fp == NULL) {
		perror("Failed to run ldconfig");
		return NULL;
	}

	// Read the first line of output which should have the library path
	if (fgets(path, sizeof(path) - 1, fp) != NULL) {
		// Extract the path from the ldconfig output
		char *start = strrchr(path, '>');
		if (start && *(start + 1) == ' ') {
			memmove(path, start + 2, strlen(start + 2) + 1);
			char *end = strchr(path, '\n');
			if (end) {
				*end = '\0';  // Null-terminate the path
			}
			pclose(fp);
			return path;
		}
	}

	pclose(fp);
	return NULL;
}

// 修改find_library_path函数
char *find_library_path2(const char *libname) {
    char cmd[256];
    static char path[512] = {0};
    FILE *fp;

    // 使用精确匹配模式，匹配libc.so后跟数字结尾
    snprintf(cmd, sizeof(cmd), 
           "ldconfig -p | grep -E 'lib%s\\.so\\.([0-9]+)$' | awk 'NR==1 {print $4}'",
           libname);

    if (verbose) printf("Executing: %s\n", cmd); // 调试输出

    fp = popen(cmd, "r");
    if (!fp) {
        perror("Failed to run ldconfig");
        return NULL;
    }

    if (fgets(path, sizeof(path)-1, fp)) {
        // 去除末尾换行符
        char *pos = strchr(path, '\n');
        if (pos) *pos = '\0';
        
        // 验证路径有效性
        if (access(path, F_OK) == -1) {
            if (verbose) printf("Path %s not exists\n", path);
            path[0] = '\0';
        }
    }
    
    pclose(fp);

    // 回退到硬编码路径
    if (path[0] == '\0') {
        const char *fallback = 
#if defined(__x86_64__)
            "/lib/x86_64-linux-gnu/libc.so.6";
#elif defined(__aarch64__)
            "/lib/aarch64-linux-gnu/libc.so.6";
#endif
        if (access(fallback, F_OK) == 0) {
            strncpy(path, fallback, sizeof(path)-1);
        }
    }

    return path[0] ? path : NULL;
}

//
// mysql 3306
//
// 函数用于查找指定端口的监听进程的 PID
pid_t find_pid_by_port(int port) {
    DIR *dir;
    struct dirent *entry;
    char path[1024];
    FILE *fp;
    char line[1024];
    char local_addr[16];
    int local_port;
    char state[3];
    char inode[16];

    // 先收集所有监听指定端口的 inode
    char target_inodes[100][16];
    int target_inode_count = 0;

    // 遍历 /proc/net/tcp 文件
    if ((fp = fopen("/proc/net/tcp", "r")) == NULL) {
        perror("fopen /proc/net/tcp");
        return -1;
    }

    // 跳过第一行标题
    fgets(line, sizeof(line), fp);

    // 逐行读取文件内容
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "%*d: %15[^:]:%x %*[^ ] %2s %*[^ ] %*[^ ] %*[^ ] %*[^ ] %*[^ ] %15s", local_addr, &local_port, state, inode) == 4) {
            if (local_port == port && strcmp(state, "0A") == 0) {
                strcpy(target_inodes[target_inode_count], inode);
                target_inode_count++;
            }
        }
    }
    fclose(fp);

    // 没有找到监听指定端口的 inode
    if (target_inode_count == 0) {
        return -1;
    }

    // 打开 /proc 目录
    if ((dir = opendir("/proc")) == NULL) {
        perror("opendir");
        return -1;
    }

    // 遍历 /proc 目录下的所有进程目录
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && strspn(entry->d_name, "0123456789") == strlen(entry->d_name)) {
            // 构建 /proc/<pid>/fd 目录路径
            snprintf(path, sizeof(path), "/proc/%s/fd", entry->d_name);
            DIR *fd_dir = opendir(path);
            if (fd_dir != NULL) {
                struct dirent *fd_entry;
                while ((fd_entry = readdir(fd_dir)) != NULL) {
                    if (fd_entry->d_type == DT_LNK) {
                        // 构建 /proc/<pid>/fd/<fd> 符号链接路径
                        snprintf(path, sizeof(path), "/proc/%s/fd/%s", entry->d_name, fd_entry->d_name);
                        char link_target[1024];
                        ssize_t len = readlink(path, link_target, sizeof(link_target) - 1);
                        if (len != -1) {
                            link_target[len] = '\0';
                            for (int i = 0; i < target_inode_count; i++) {
                                if (strstr(link_target, target_inodes[i]) != NULL) {
                                    closedir(fd_dir);
                                    closedir(dir);
                                    return atoi(entry->d_name);
                                }
                            }
                        }
                    }
                }
                closedir(fd_dir);
            }
        }
    }
    closedir(dir);
    return -1;
}

// 函数用于获取指定 PID 进程的全路径
char *get_process_path(pid_t pid) {
    char path[1024];
    char *process_path = NULL;
    ssize_t len;

    // 构建 /proc/<pid>/exe 符号链接路径
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);

    // 读取符号链接指向的路径
	char buf[PATH_MAX];
    len = readlink(path, buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
        process_path = strdup(buf);
    }
    return process_path;
}

void find_openssl_libs(const char *program_path, char* libpath, int len) {
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "LD_TRACE_LOADED_OBJECTS=1 \"%s\" 2>/dev/null", program_path);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        perror("Failed to trace library dependencies");
        return;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        // 解析两种格式：
        // 1. libssl.so.3 => /usr/lib/libssl.so.3 (0x00007f8c1a200000)
        // 2. linux-vdso.so.1 (0x00007ffd31bdf000)
        
        char *arrow = strstr(line, "=> ");
        if (arrow) {  // 处理动态链接库
            arrow += 3;
            char *end = strchr(arrow, ' ');
            if (!end) end = strchr(arrow, '(');
            if (end) *end = '\0';
            
            // || strstr(arrow, "libcrypto.so")
            if (strstr(arrow, "libssl.so")) {
                //printf("OpenSSL动态库路径: %s\n", arrow);

				if (realpath(arrow, libpath) != NULL) {
					//printf("Mysql OpenSSL动态库路径: %s\n", libpath);
				} else {
					perror("OpenSSL动态库路径 路径解析失败");
				}
            }
        } else {  // 处理静态或特殊库
            char *libname = strtok(line, " ");
            if (libname && (strstr(libname, "libssl.so") || strstr(libname, "libcrypto.so"))) {
                printf("检测到OpenSSL依赖: %s (可能未找到路径)\n", libname);
            }
        }
    }

    pclose(fp);
}

int find_mysql_openssl_path(char* libpath, int len){
	int port = 3306;
    pid_t pid = find_pid_by_port(port);
    if (pid == -1) {
        printf("No process found listening on port %d.\n", port);
        return 1;
    }

    char *process_path = get_process_path(pid);
	if (process_path == NULL) {
		printf("Failed to get process path for PID %d.\n", pid);
		return 1;
	}

    //printf("Process PID: %d\n", pid);
	//printf("Process Path: %s\n", process_path);

	find_openssl_libs(process_path, libpath, len);

	free(process_path);

	return 0;
}

void buf_to_hex(const uint8_t *buf, size_t len, char *hex_str) {
	for (size_t i = 0; i < len; i++) {
		sprintf(hex_str + 2 * i, "%02x", buf[i]);
	}
}

const char* int_to_ip_v1(uint32_t ip_int) {
    struct in_addr addr;
    addr.s_addr = ip_int; // 直接使用网络字节序
    return inet_ntoa(addr);
}

void hexdump(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i += 16) {  // 每行处理16字节
        // 输出十六进制部分
        for (int j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02X ", data[i + j]);  // 两位十六进制 + 空格
            } else {
                printf("   ");  // 不足16字节用空格填充对齐
            }
        }
        printf("| ");  // 分隔符
        
        // 输出ASCII字符部分
        for (int j = 0; j < 16; j++) {
            if (i + j < len) {
                unsigned char c = data[i + j];
                putchar(isprint(c) ? c : '.');  // 不可见字符替换为.
            } else {
                putchar(' ');  // 填充空格保持对齐
            }
        }
        printf("\n");
    }
}
// Function to print the event from the perf buffer
void print_event(struct probe_SSL_data_t *event, const char *evt) {
	static unsigned long long start =
		0;  // Use static to retain value across function calls
	char buf[MAX_BUF_SIZE + 1] = {0};  // +1 for null terminator
	unsigned int buf_size;

	if (event->len <= MAX_BUF_SIZE) {
		buf_size = event->len;
	} else {
		buf_size = MAX_BUF_SIZE;
	}

	if (event->buf_filled == 1) {
		memcpy(buf, event->buf, buf_size);
	} else {
		buf_size = 0;
	}

	if (env.comm && strcmp(env.comm, event->comm) != 0) {
		return;
	}

	if (start == 0) {
		start = event->timestamp_ns;
	}
	double time_s = (double)(event->timestamp_ns - start) / 1000000000;

	char lat_str[10];
	if (event->delta_ns) {
		snprintf(lat_str, sizeof(lat_str), "%.3f",
				(double)event->delta_ns / 1000000);
	} else {
		strncpy(lat_str, "N/A", sizeof(lat_str));
	}

	struct sockaddr_in *sockaddr = (struct sockaddr_in *)&event->addr;

	if (sockaddr->sin_family == AF_INET) {
		int ip =sockaddr->sin_addr.s_addr;
		const char* ip_addr = int_to_ip_v1(ip);

		printf("\n");
		printf("client addr : %s:%d \n\n",ip_addr, ntohs(sockaddr->sin_port));

    } else if (sockaddr->sin_family == AF_INET6) {
		printf("ipv6 client addr is not support now \n");
    }else{
		printf("unsuported family family : %d\n", sockaddr->sin_family);
	}

	char s_mark[] = "----- DATA -----";
	char e_mark[64] = "----- END DATA -----";
	if (buf_size < event->len) {
		snprintf(e_mark, sizeof(e_mark),
				"----- END DATA (TRUNCATED, %d bytes lost) -----",
				event->len - buf_size);
	}

	char *rw_event[] = {
		"READ/RECV",
		"WRITE/SEND",
		"HANDSHAKE"
	};

#define BASE_FMT "%-12s %-18.9f %-16s %-7d %-6d"
#define EXTRA_FMT " %-7d %-7d"
#define LATENCY_FMT " %-7s"

	if (env.extra && env.latency) {
		printf(BASE_FMT EXTRA_FMT LATENCY_FMT, rw_event[event->rw], 
			time_s, event->comm, event->pid,
			event->len, event->uid, event->tid, lat_str);
	} else if (env.extra) {
		printf(BASE_FMT EXTRA_FMT, rw_event[event->rw], time_s, event->comm, event->pid,
			event->len, event->uid, event->tid);
	} else if (env.latency) {
		printf(BASE_FMT LATENCY_FMT, rw_event[event->rw], time_s, event->comm, event->pid,
			event->len, lat_str);
	} else {
		printf(BASE_FMT, rw_event[event->rw], time_s, event->comm, event->pid,
			event->len);
	}

	if (buf_size != 0) {
		if (env.hexdump) {
			// 2 characters for each byte + null terminator
			char hex_data[MAX_BUF_SIZE * 2 + 1] = {0};  
			buf_to_hex((uint8_t *)buf, buf_size, hex_data);
			
			printf("\n%s\n", s_mark);
			for (size_t i = 0; i < strlen(hex_data); i += 32) {
				printf("%.32s\n", hex_data + i);
			}
			printf("%s\n\n", e_mark);
		} else {
			//printf("\n%s\n%s\n%s\n\n", s_mark, buf, e_mark);
			printf("\n%s\n", s_mark);
			hexdump((const unsigned char*)buf, buf_size);
			printf("\n%s\n\n", e_mark);
		}
	}
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_size) {
	struct probe_SSL_data_t *e = data;
	if (e->is_handshake) {
		print_event(e, "perf_SSL_do_handshake");
	} else {
		print_event(e, "perf_SSL_rw");
	}
}

int main(int argc, char **argv) {
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	struct mysslaudit_bpf *obj = NULL;
	struct perf_buffer *pb = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = mysslaudit_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		goto cleanup;
	}

	obj->rodata->targ_uid = env.uid;
	obj->rodata->targ_pid = env.pid == INVALID_PID ? 0 : env.pid;

	err = mysslaudit_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	// ssl read wite
	if (env.openssl) {
		char *openssl_path = find_library_path("libssl.so");
		printf("OpenSSL path: %s\n", openssl_path);
		attach_openssl(obj, openssl_path);
	}
	if (env.gnutls) {
		char *gnutls_path = find_library_path("libgnutls.so");
		printf("GnuTLS path: %s\n", gnutls_path);
		attach_gnutls(obj, gnutls_path);
	}
	if (env.nss) {
		char *nss_path = find_library_path("libnspr4.so");
		printf("NSS path: %s\n", nss_path);
		attach_nss(obj, nss_path);
	}

	if(env.mysql){
		// mysql openssl path
		//const char* mysql_openssl_path = "/usr/local/mysql/lib/private/libssl.so.3";
		//printf("MySQL OpenSSL path: %s\n", mysql_openssl_path);
		char mysql_openssl_path[512] = {0};
		if(find_mysql_openssl_path(mysql_openssl_path, sizeof(mysql_openssl_path))){
			printf("Failed to find mysql openssl path\n");
		}

		printf("Mysql OpenSSL path: %s\n", mysql_openssl_path);
		attach_mysql_openssl(obj, mysql_openssl_path);
	}

	// glibc accept
	char *libc_path = find_library_path2("libc.so");
	printf("libc path: %s\n", libc_path);
	// 在附加SSL探针后添加
    if (attach_glibc_accept(obj,libc_path) < 0) {
        goto cleanup;
    }

	// // 新增accept跟踪点附加
	// if (attach_accept_tracepoints(obj) < 0) {
	// 	goto cleanup;
	// }

	pb = perf_buffer__new(bpf_map__fd(obj->maps.perf_SSL_events),
							PERF_BUFFER_PAGES, handle_event, handle_lost_events,
							NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	// Print header
	printf("%-12s %-18s %-16s %-7s %-7s", "FUNC", "TIME(s)", "COMM", "PID",
			"LEN");
	if (env.extra) {
		printf(" %-7s %-7s", "UID", "TID");
	}
	if (env.latency) {
		printf(" %-7s", "LAT(ms)");
	}
	printf("\n");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	mysslaudit_bpf__destroy(obj);
	return err != 0;
}
