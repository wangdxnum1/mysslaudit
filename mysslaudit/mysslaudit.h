// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Yusheng Zheng
//
// Based on mysslaudit from BCC by Adrian Lopez & Mark Drayton.
// 15-Aug-2023   Yusheng Zheng   Created this.
#ifndef __mysslaudit_H
#define __mysslaudit_H

#define MAX_BUF_SIZE 8192
#define TASK_COMM_LEN 16

// mysslaudit.h
// struct sockaddr_compact {
//     __u16 family;
//     __u16 port;
//     __u8 addr[16];
// };

struct probe_SSL_data_t {
    __u64 timestamp_ns;
    __u64 delta_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 len;
    int buf_filled;
    int rw;
    struct sockaddr addr;
    char comm[TASK_COMM_LEN];
    __u8 buf[MAX_BUF_SIZE];
    int is_handshake;
};

#endif /* __mysslaudit_H */
