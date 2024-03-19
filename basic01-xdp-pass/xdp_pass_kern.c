//go:build ignore
/* SPDX-FileCopyrightText: ©  2019 Jesper Dangaard Brouer <https://github.com/netoptimizer> and XDP-Project contrinbutors */
/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
	return XDP_PASS;
}
