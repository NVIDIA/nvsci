/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved. 
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _NVSCI_MM_H
#define _NVSCI_MM_H
#include <linux/ioctl.h>
#include <linux/types.h>

#define NVSCI_MM_DEV_NODE "/dev/nvsci_mm"

#define NVSCI_MM_MAJOR_VERSION (1U)
#define NVSCI_MM_MINOR_VERSION (0U)

struct nvsci_mm_check_compat_data {
    __u64 header;
    __u32 result;
};

struct nvsci_mm_allocation_data {
    __u64 header;
    __u64 len;
    __s32 fd;
    __u32 fd_flags;
};

struct nvsci_mm_get_sciipcid_data{
    __u64 header;
    __s32 fd;
    __u32 fd_flags;
    __u64 auth_token;
    __u64 sci_ipc_id;
};

#define NVSCI_MM_HEADER_VERSIONBITS    16
#define NVSCI_MM_HEADER_SIZEBITS     32
#define NVSCI_MM_HEADER_VERSIONMASK    ((1U << NVSCI_MM_HEADER_VERSIONBITS) - 1)

#define NVSCI_MM_SET_HEADER(data) \
    (((__u64)sizeof(data) << NVSCI_MM_HEADER_SIZEBITS) | \
    (NVSCI_MM_MAJOR_VERSION << NVSCI_MM_HEADER_VERSIONBITS) | (NVSCI_MM_MINOR_VERSION))

#define GET_MINOR_FROM_HEADER(header) \
    ((__u32)((header) & NVSCI_MM_HEADER_VERSIONMASK))

#define GET_MAJOR_FROM_HEADER(header) \
    ((__u32)(((header) >> NVSCI_MM_HEADER_VERSIONBITS) & NVSCI_MM_HEADER_VERSIONMASK))

#define GET_SIZE_FROM_HEADER(header) \
    ((__u32)((header) >> NVSCI_MM_HEADER_SIZEBITS))

#define NVSCI_MM_SET_DEFAULT_CHECK_COMPAT_DATA(data) \
    do { \
        (data).header = NVSCI_MM_SET_HEADER(data); \
        (data).result = (0); \
    } while (1 == 0)

#define NVSCI_MM_SET_DEFAULT_ALLOCATION_DATA(data) \
    do { \
        (data).header = NVSCI_MM_SET_HEADER(data); \
        (data).len = (0); \
        (data).fd = (-1); \
        (data).fd_flags = (0); \
    } while (1 == 0)

#define NVSCI_MM_SET_DEFAULT_SCIIPCID_DATA(data) \
    do { \
        (data).header = NVSCI_MM_SET_HEADER(data); \
        (data).fd = (-1); \
        (data).fd_flags = (0); \
        (data).auth_token = (0); \
        (data).sci_ipc_id = (0); \
    } while (1 == 0)

#define NVSCI_MM_IOC_MAGIC      'H'
#define NVSCI_MM_IOCTL_CHECK_COMPAT   _IOWR(NVSCI_MM_IOC_MAGIC, 0x0, struct nvsci_mm_check_compat_data)
#define NVSCI_MM_IOCTL_ALLOC    _IOWR(NVSCI_MM_IOC_MAGIC, 0x1, struct nvsci_mm_allocation_data)
#define NVSCI_MM_IOCTL_GET_SCIIPCID   _IOWR(NVSCI_MM_IOC_MAGIC, 0x2, struct nvsci_mm_get_sciipcid_data)
#define NVSCI_MM_IOCTL_FD_FROM_SCIIPCID   _IOWR(NVSCI_MM_IOC_MAGIC, 0x3, struct nvsci_mm_get_sciipcid_data)

#endif /* _NVSCI_MM_H */
