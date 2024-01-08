// SPDX-License-Identifier: GPL-2.0-or-later
/* Declarations and definitions for netlink public files
 * Copyright (C) 2024 Nvidia, Inc.
 */
#ifndef KERNEL_NETLINK_PUBLIC_H_
#define KERNEL_NETLINK_PUBLIC_H_

/*
 * Vty/cli apis
 */
extern int netlink_config_write_helper(struct vty *vty);

/*
 * Configure size of the batch buffer and sending threshold. If 'unset', reset
 * to default value.
 */
extern void netlink_set_batch_buffer_size(uint32_t size, uint32_t threshold,
					  bool set);

#endif
