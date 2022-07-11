/* Copyright (c) 2017 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * BPF program to set congestion control to dctcp when both hosts are
 * in the same datacenter (as deteremined by IPv6 prefix).
 *
 * Use load_sock_ops to load this BPF program.
 */

#include <uapi/linux/bpf.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <linux/socket.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define DEBUG 1

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

struct cc_name {
	char n[10];
};

struct bpf_map_def SEC("maps") cc_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct cc_name),
	.max_entries = 1024,
};



SEC("sockops")
int bpf_cong(struct bpf_sock_ops *skops)
{
	char cong[2][10] = {"cubic", "bbr"};
	int rv = 0;
	int op;
    int cc_id = 0;
	__u32 key;
	struct cc_name cc;

	op = (int) skops->op;

    if ((bpf_ntohl(skops->remote_ip4) & 0x00ff0000) == 0x00020000) {
        cc_id = 0;
    } else {
        cc_id = 1;
    }

#ifdef DEBUG
	bpf_printk("BPF command: %d\n", op);
#endif

	/* Check if both hosts are in the same datacenter. For this
	 * example they are if the 1st 5.5 bytes in the IPv6 address
	 * are the same.
	 */
	if (skops->family == AF_INET) {
		switch (op) {
		case BPF_SOCK_OPS_NEEDS_ECN:
			rv = 1;
			break;
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
			rv = bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION,
					    cong[cc_id], sizeof(cong[cc_id]));
            bpf_printk("Set %s for %x\n", cong[cc_id], skops->remote_ip4);
			break;
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			rv = bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION,
					    cong[cc_id], sizeof(cong[cc_id]));
            bpf_printk("Set %s for %x\n", cong[cc_id], skops->remote_ip4);
			break;
		default:
			rv = -1;
		}
	} else {
		rv = -1;
	}
#ifdef DEBUG
	bpf_printk("Returning %d\n", rv);
#endif
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
