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

#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched/signal.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/dma-buf.h>
#include <linux/highmem.h>
#include <linux/cdev.h>
#include <linux/nospec.h>

#include "uapi/linux/nvsci_mm.h"
#include "nvsciipc_interface.h"

atomic_t nvsci_mm_call_level = ATOMIC_INIT(0);

void PrintLevel(void)
{
    int i = 0;
    int level = atomic_read(&nvsci_mm_call_level);
    for (i=0; i<level; i++) pr_cont("|  ");
}

#define PrintLog(fmt, ...)  if (0 != enable_debug) {PrintLevel(); pr_cont("%u:%u "fmt, task_pid_nr(current), task_tgid_nr(current), ##__VA_ARGS__);}
#define EN  PrintLog("%s() Enter\n", __FUNCTION__); atomic_inc(&nvsci_mm_call_level);
#define EX  atomic_dec(&nvsci_mm_call_level); PrintLog("%s() Exit\n", __FUNCTION__);

static uint32_t gid_start = 0;
static uint32_t gid_end = 0;
static uint32_t max_pending_exports = UINT_MAX;
static uint32_t enable_debug = 0;
module_param(gid_start, uint, 0444);
module_param(gid_end, uint, 0444);
module_param(max_pending_exports, uint, 0444);
module_param(enable_debug, uint, 0644);

static unsigned int nvsci_mm_ioctl_cmds[] = {
    NVSCI_MM_IOCTL_CHECK_COMPAT,
    NVSCI_MM_IOCTL_ALLOC,
    NVSCI_MM_IOCTL_GET_SCIIPCID,
    NVSCI_MM_IOCTL_FD_FROM_SCIIPCID,
};

struct nvsci_mm_db {
    struct rb_root root;
    struct mutex lock;
    struct list_head free_sid_list;
};

static struct nvsci_mm_db* nvsci_mm_db_ptr;

struct free_sid_node {
    struct list_head list;
    u64 sid;
};

struct nvsci_mm_db_entry {
    struct rb_node entry;
    void *client;
    struct file *handle;
    u64 sci_ipc_id;
    u64 local_vuid;
    u64 peer_vuid;
    u32 fd_flags;
    u32 refcount;
};

static int dev_ops_open(struct inode *inode, struct file *filp)
{
    pid_t current_gid = current_cred()->gid.val;
    int ret = 0;

    EN;

    PrintLog("Device open\n");
    /* Provide access only to root and user groups within [gid_start, gid_end] */
    if ((current_gid != 0) && ((current_gid < gid_start) || (current_gid > gid_end))) {
        ret = -EACCES;
        goto out;
    }

    nonseekable_open(inode, filp);
out:
    EX;
    return ret;
}

static int dev_ops_release(struct inode *inodep, struct file *filp)
{
    struct nvsci_mm_db_entry *e;
    struct rb_node *n;
    bool deletePresent = false;
    int ret = 0;

    EN;
    PrintLog("Device close\n");
    mutex_lock(&nvsci_mm_db_ptr->lock);

    PrintLog("Checking for export entries from this client\n");
    do {
        deletePresent = false;
        for (n = rb_first(&nvsci_mm_db_ptr->root); n; n = rb_next(n)) {
            e = rb_entry(n, struct nvsci_mm_db_entry, entry);
            if ((struct file *)e->client == filp) {
                deletePresent = true;
                break;
            }
        }

    if (deletePresent) {
        struct free_sid_node *free_node = kzalloc(sizeof(*free_node), GFP_KERNEL);
        if (free_node != NULL) {
                free_node->sid = e->sci_ipc_id;
                list_add_tail(&free_node->list, &nvsci_mm_db_ptr->free_sid_list);
            }
            PrintLog("Deleting entry %p %p %llu %llu %llu %u %u\n", e->client, e->handle,
                    e->sci_ipc_id, e->local_vuid, e->peer_vuid, e->fd_flags, e->refcount);
            fput((struct file*)e->handle);
            rb_erase(&e->entry, &nvsci_mm_db_ptr->root);
            kfree(e);
        }
    } while(deletePresent);
    mutex_unlock(&nvsci_mm_db_ptr->lock);

    EX;
    return ret;
}

struct nvsci_mm_buffer {
    struct dma_buf *dmabuf;
    size_t size;

    void *priv_virt;
    struct mutex lock;
    int vmap_cnt;
    void *vaddr;
    pgoff_t pagecount;
    struct page **pages;
    struct list_head attachments;

    void (*free)(struct nvsci_mm_buffer *buffer);
};

static void buffer_free(struct nvsci_mm_buffer *buffer)
{
    pgoff_t pg = 0;
    EN;

    for (pg = 0; pg < buffer->pagecount; pg++) {
        __free_page(buffer->pages[pg]);
    }

    kfree(buffer->pages);
    PrintLog("Buffer pointer %p\n", buffer);
    kfree(buffer);
    EX;
}

struct buffer_attachment {
    struct device *dev;
    struct sg_table table;
    struct list_head list;
};

static struct sg_table *buffer_ops_map_dma_buf(struct dma_buf_attachment *attachment,
                                      enum dma_data_direction direction)
{
    int nents;
    struct buffer_attachment *a = attachment->priv;
    struct sg_table *table = &(a->table);
    struct sg_table *ret = NULL;

    EN;

    nents = dma_map_sg(attachment->dev, table->sgl, table->nents, direction);
    if (nents < 0) {
        ret = ERR_PTR(-EINVAL);
        goto out;
    }

    table->nents = nents;
    ret = table;

out:
    EX;
    return ret;
}

static void buffer_ops_unmap_dma_buf(struct dma_buf_attachment *attachment,
                                   struct sg_table *table,
                                   enum dma_data_direction direction)
{
    EN;
    dma_unmap_sg(attachment->dev, table->sgl, table->nents, direction);
    EX;
}

void * dma_heap_dma_buf_map (struct dma_buf *dmabuf)
{
    EN;
    EX;
    return NULL;
}

static vm_fault_t buffer_vm_ops_fault(struct vm_fault *vmf)
{
    struct nvsci_mm_buffer *buffer = vmf->vma->vm_private_data;
    static vm_fault_t ret = 0;
    EN;

    if (vmf->pgoff > buffer->pagecount) {
        ret = VM_FAULT_SIGBUS;
        goto out;
    }

    vmf->page = buffer->pages[vmf->pgoff];
    get_page(vmf->page);

out:
    EX;
    return ret;
}

static const struct vm_operations_struct buffer_vm_ops = {
    .fault = buffer_vm_ops_fault,
};

static int buffer_ops_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
    int ret = 0;

    EN;

    if ((vma->vm_flags & (VM_SHARED | VM_MAYSHARE)) == 0) {
        ret =  -EINVAL;
        goto out;
    }

    vma->vm_ops = &buffer_vm_ops;
    vma->vm_private_data = dmabuf->priv;

out:
    EX;
    return ret;
}

static void buffer_ops_release(struct dma_buf *dmabuf)
{
    struct nvsci_mm_buffer *buffer = dmabuf->priv;
    EN;

    if (buffer->vmap_cnt > 0) {
        WARN(1, "%s: buffer still mapped in the kernel\n", __func__);
        vunmap(buffer->vaddr);
    }

    buffer->free(buffer);
    EX;
}

static int buffer_ops_attach(struct dma_buf *dmabuf, struct dma_buf_attachment *attachment)
{
    struct buffer_attachment *a;
    struct nvsci_mm_buffer *buffer = dmabuf->priv;
    int ret = 0;
    EN;

    a = kzalloc(sizeof(*a), GFP_KERNEL);
    if (!a) {
        ret = -ENOMEM;
        goto out;
    }

    ret = sg_alloc_table_from_pages(&a->table, buffer->pages,
                                    buffer->pagecount, 0,
                                    buffer->pagecount << PAGE_SHIFT,
                                    GFP_KERNEL);
    if (ret) {
        kfree(a);
        goto out;
    }

    a->dev = attachment->dev;
    INIT_LIST_HEAD(&a->list);

    attachment->priv = a;

    mutex_lock(&buffer->lock);
    list_add(&a->list, &buffer->attachments);
    mutex_unlock(&buffer->lock);

out:
    EX;
    return ret;
}

static void buffer_ops_detach(struct dma_buf *dmabuf,
                            struct dma_buf_attachment *attachment)
{
    struct buffer_attachment *a = attachment->priv;
    struct nvsci_mm_buffer *buffer = dmabuf->priv;
    EN;

    mutex_lock(&buffer->lock);
    list_del(&a->list);
    mutex_unlock(&buffer->lock);

    sg_free_table(&a->table);
    kfree(a);
    EX;
}

static int buffer_ops_begin_cpu_access(struct dma_buf *dmabuf,
                                             enum dma_data_direction direction)
{
    struct nvsci_mm_buffer *buffer = dmabuf->priv;
    struct buffer_attachment *a = NULL;
    int ret = 0;
    EN;

    mutex_lock(&buffer->lock);

    if (buffer->vmap_cnt) {
        invalidate_kernel_vmap_range(buffer->vaddr, buffer->size);
    }

    list_for_each_entry(a, &buffer->attachments, list) {
        dma_sync_sg_for_cpu(a->dev, a->table.sgl, a->table.nents,
                            direction);
    }
    mutex_unlock(&buffer->lock);

    EX;
    return ret;
}

static int dma_heap_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
                                           enum dma_data_direction direction)
{
    struct nvsci_mm_buffer *buffer = dmabuf->priv;
    struct buffer_attachment *a = NULL;
    EN;

    mutex_lock(&buffer->lock);

    if (buffer->vmap_cnt) {
        flush_kernel_vmap_range(buffer->vaddr, buffer->size);
    }

    list_for_each_entry(a, &buffer->attachments, list) {
        dma_sync_sg_for_device(a->dev, a->table.sgl, a->table.nents, direction);
    }

    mutex_unlock(&buffer->lock);

    EX;
    return 0;
}

static void *buffer_ops_vmap(struct dma_buf *dmabuf)
{
    struct nvsci_mm_buffer *buffer = dmabuf->priv;
    void *vaddr;
    EN;

    mutex_lock(&buffer->lock);
    if (buffer->vmap_cnt) {
        buffer->vmap_cnt++;
        vaddr = buffer->vaddr;
        goto out;
    }

    vaddr = vmap(buffer->pages, buffer->pagecount, VM_MAP, PAGE_KERNEL);
    if (!vaddr) {
        vaddr = ERR_PTR(-ENOMEM);
        goto out;
    }

    buffer->vaddr = vaddr;
    buffer->vmap_cnt++;

out:
    mutex_unlock(&buffer->lock);
    EX;
    return vaddr;
}

static void buffer_ops_vunmap(struct dma_buf *dmabuf, void *vaddr)
{
    struct nvsci_mm_buffer *buffer = dmabuf->priv;
    EN;

    mutex_lock(&buffer->lock);

    if (!--buffer->vmap_cnt) {
        vunmap(buffer->vaddr);
        buffer->vaddr = NULL;
    }

    mutex_unlock(&buffer->lock);
    EX;
}

static void *buffer_ops_map(struct dma_buf *buf, unsigned long page_num)
{
    struct nvsci_mm_buffer *buffer = buf->priv;
    struct page *page = buffer->pages[page_num];
    EN;
    EX;
    return kmap(page);
}

static void buffer_ops_unmap(struct dma_buf *buf, unsigned long page_num,
                       void *vaddr)
{
    EN;
    kunmap(vaddr);
    EX;
}

const struct dma_buf_ops buffer_ops = {
    .map_dma_buf = buffer_ops_map_dma_buf,
    .unmap_dma_buf = buffer_ops_unmap_dma_buf,
    .mmap = buffer_ops_mmap,
    .release = buffer_ops_release,
    .attach = buffer_ops_attach,
    .detach = buffer_ops_detach,
    .begin_cpu_access = buffer_ops_begin_cpu_access,
    .end_cpu_access = dma_heap_dma_buf_end_cpu_access,
    .vmap = buffer_ops_vmap,
    .vunmap = buffer_ops_vunmap,
    .map = buffer_ops_map,
    .unmap = buffer_ops_unmap,
};

static int buffer_allocate(unsigned long len,
                                unsigned long fd_flags)
{
    struct nvsci_mm_buffer *buffer_data;
    struct dma_buf *dmabuf;
    int ret = -ENOMEM;
    pgoff_t pg;
    DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

    EN;

    buffer_data = kzalloc(sizeof(*buffer_data), GFP_KERNEL);
    if (!buffer_data) {
        ret = -ENOMEM;
        goto out;
    }

    buffer_data->priv_virt = NULL;
    mutex_init(&buffer_data->lock);
    buffer_data->vmap_cnt = 0;
    buffer_data->vaddr = NULL;
    buffer_data->pagecount = 0;
    buffer_data->pages = NULL;
    INIT_LIST_HEAD(&buffer_data->attachments);
    buffer_data->free = buffer_free;
    buffer_data->size = len;

    buffer_data->pagecount = len / PAGE_SIZE;
    buffer_data->pages = kmalloc_array(buffer_data->pagecount, sizeof(*buffer_data->pages), GFP_KERNEL);
    if (!buffer_data->pages) {
        ret = -ENOMEM;
        goto err0;
    }

    for (pg = 0; pg < buffer_data->pagecount; pg++) {
        if (fatal_signal_pending(current)) {
            goto err1;
        }

        buffer_data->pages[pg] = alloc_page(GFP_KERNEL | __GFP_ZERO);
        if (!buffer_data->pages[pg])
            goto err1;
    }

    exp_info.owner = THIS_MODULE;
    exp_info.ops = &buffer_ops;
    exp_info.size = buffer_data->size;
    exp_info.flags = fd_flags;
    exp_info.priv = buffer_data;

    dmabuf = dma_buf_export(&exp_info);
    if (IS_ERR(dmabuf)) {
        ret = PTR_ERR(dmabuf);
        goto err1;
    }

    buffer_data->dmabuf = dmabuf;

    ret = dma_buf_fd(dmabuf, fd_flags);
    if (ret < 0) {
        dma_buf_put(dmabuf);
        goto out;
    }

    PrintLog("Buffer pointer %p\n", buffer_data);
    PrintLog("dma Buffer pointer %p\n", dmabuf);
    PrintLog("dma Buffer file pointer %p\n", dmabuf->file);
    PrintLog("dma Buffer file refCount %llu\n", dmabuf->file->f_count.counter);
    PrintLog("dma Buffer fd %d\n", ret);

    goto out;

err1:
    while (pg > 0)
        __free_page(buffer_data->pages[--pg]);
    kfree(buffer_data->pages);
err0:
    kfree(buffer_data);
out:
    EX;
    return ret;
}

static long nvsci_mm_ioctl_check_compat(struct file *file, void *data)
{
    struct nvsci_mm_check_compat_data *compat_data = data;
    uint32_t umajorVer = GET_MAJOR_FROM_HEADER(compat_data->header);
    uint32_t uminorVer = GET_MINOR_FROM_HEADER(compat_data->header);
    long ret = 0;

    EN;

    PrintLog("Userspace major %u\n", umajorVer);
    PrintLog("Userspace minor %u\n", uminorVer);
    PrintLog("Kernel major %u\n", NVSCI_MM_MAJOR_VERSION);
    PrintLog("Kernel minor %u\n", NVSCI_MM_MINOR_VERSION);

    compat_data->result = (NVSCI_MM_MAJOR_VERSION == umajorVer);

    PrintLog("Compatiblity result %u\n", compat_data->result);

    EX;
    return ret;
}

static long nvsci_mm_ioctl_allocate(struct file *file, void *data)
{
    struct nvsci_mm_allocation_data *alloc_data = data;
    int fd;
    long ret = 0;
    size_t len = 0;
    EN;

    if ((NVSCI_MM_MAJOR_VERSION != GET_MAJOR_FROM_HEADER(alloc_data->header)) ||
        (alloc_data->fd >= 0) ||
        (alloc_data->len == 0) ||
        (alloc_data->fd_flags > O_RDWR)) {
        ret = -EINVAL;
        goto out;
    }

    len = PAGE_ALIGN(alloc_data->len);

    fd = buffer_allocate(len, alloc_data->fd_flags);
    if (fd < 0) {
        ret = fd;
        goto out;
    }

    alloc_data->fd = fd;
    PrintLog("Requested size %llu\n", alloc_data->len);
    PrintLog("Requested fd_flags %x\n", alloc_data->fd_flags);
    PrintLog("Allocated size %lu\n", len);

out:
    EX;
    return ret;
}

static NvSciError nvsci_mm_get_validate_map_vuid(
    NvSciIpcEndpointAuthToken authToken,
    NvSciIpcEndpointVuid *lu_vuid,
    NvSciIpcEndpointVuid *pr_vuid)
{
    NvSciIpcTopoId pr_topoid;

    NvSciError (*ValidateAuthToken)(
            NvSciIpcEndpointAuthToken authToken,
            NvSciIpcEndpointVuid *localUserVuid);

    NvSciError (*MapVuid)(
            NvSciIpcEndpointVuid localUserVuid,
            NvSciIpcTopoId *peerTopoId,
            NvSciIpcEndpointVuid *peerUserVuid);
    NvSciError sciErr = NvSciError_Success;

    EN;

    ValidateAuthToken = symbol_get(NvSciIpcEndpointValidateAuthTokenLinuxCurrent);
    MapVuid = symbol_get(NvSciIpcEndpointMapVuid);

    if (ValidateAuthToken && MapVuid) {
        sciErr = ValidateAuthToken(authToken, lu_vuid);
        if (sciErr == NvSciError_Success) {
            sciErr = MapVuid(*lu_vuid, &pr_topoid, pr_vuid);
        }

        symbol_put(NvSciIpcEndpointValidateAuthTokenLinuxCurrent);
        symbol_put(NvSciIpcEndpointMapVuid);
    } else {
        /* Fall back to non-secure sharing */
        memset(lu_vuid, 0x0, sizeof(NvSciIpcEndpointVuid));
        memset(pr_vuid, 0x0, sizeof(NvSciIpcEndpointVuid));
    }

    EX;
    return sciErr;
}

static long nvsci_mm_ioctl_get_sciipcid(struct file *file, void *data)
{
    struct nvsci_mm_get_sciipcid_data *get_sciipcid_data = data;
    NvSciIpcEndpointVuid pr_vuid;
    NvSciIpcEndpointVuid lu_vuid;
    NvSciError sciErr = NvSciError_Success;
    struct nvsci_mm_db_entry *entry = NULL;
    struct nvsci_mm_db_entry *temp = NULL;
    struct rb_node *parent = NULL;
    struct rb_node *node = NULL;
    struct rb_node **link = NULL;
    struct fd f = {0};
    struct file *fd_file = NULL;
    long ret = 0;
    static atomic_t unq_id = { 0 };
    uint32_t current_pending_exports = 0U;

    EN;

    if (NVSCI_MM_MAJOR_VERSION != GET_MAJOR_FROM_HEADER(get_sciipcid_data->header) ||
        (get_sciipcid_data->fd_flags > O_RDWR)) {
        ret = -EINVAL;
        goto out;
    }

    f = fdget(get_sciipcid_data->fd);
    if (f.file == NULL) {
        ret = -EINVAL;
        goto out;
    }
    fd_file = f.file;

    sciErr = nvsci_mm_get_validate_map_vuid(get_sciipcid_data->auth_token, &lu_vuid, &pr_vuid);
    if (sciErr != NvSciError_Success) {
        ret = -EINVAL;
        goto put_file;
    }

    PrintLog("Peer vuid %llu\n", pr_vuid);
    PrintLog("Local vuid %llu\n", lu_vuid);

    mutex_lock(&nvsci_mm_db_ptr->lock);

    for (node = rb_first(&nvsci_mm_db_ptr->root); node; node = rb_next(node)) {
        entry = rb_entry(node, struct nvsci_mm_db_entry, entry);
        if (file == entry->client) {
            current_pending_exports += entry->refcount;
        }
    }
    if (max_pending_exports <= current_pending_exports) {
        ret = -EINVAL;
        goto unlock;
    }

    for (node = rb_first(&nvsci_mm_db_ptr->root); node; node = rb_next(node)) {
        entry = rb_entry(node, struct nvsci_mm_db_entry, entry);
        if ((entry != NULL) &&
            (file == entry->client) &&
            (fd_file == entry->handle) &&
            (lu_vuid == entry->local_vuid) &&
            (pr_vuid == entry->peer_vuid) &&
            (get_sciipcid_data->fd_flags == entry->fd_flags)) {
            break;
        }
        entry = NULL;
    }

    if (entry) {
        entry->refcount++;
        get_sciipcid_data->sci_ipc_id = entry->sci_ipc_id;
        PrintLog("Found exsisting entry %p %p %llu %llu %llu %u %u\n", entry->client,
                entry->handle, entry->sci_ipc_id, entry->local_vuid, entry->peer_vuid,
                entry->fd_flags, entry->refcount);
        goto unlock;
    } else {
        if (!list_empty(&nvsci_mm_db_ptr->free_sid_list)) {
            struct free_sid_node *fnode = list_first_entry(
                    &nvsci_mm_db_ptr->free_sid_list, struct free_sid_node, list);
            get_sciipcid_data->sci_ipc_id = fnode->sid;
            list_del(&fnode->list);
            kfree(fnode);
            PrintLog("Reusing sid %llu\n", get_sciipcid_data->sci_ipc_id);
        } else {
            get_sciipcid_data->sci_ipc_id = atomic_add_return(2, &unq_id);
            PrintLog("Generated new sid %llu\n", get_sciipcid_data->sci_ipc_id);
        }

        entry = kzalloc(sizeof(*entry), GFP_KERNEL);
        if (entry == NULL) {
            ret = -ENOMEM;
            goto unlock;
        }

        get_file(fd_file);

        entry->client = file;
        entry->handle = fd_file;
        entry->local_vuid = lu_vuid;
        entry->peer_vuid = pr_vuid;
        entry->fd_flags = get_sciipcid_data->fd_flags;
        entry->sci_ipc_id = get_sciipcid_data->sci_ipc_id;
        entry->refcount = 1;

        link = &nvsci_mm_db_ptr->root.rb_node;

        while(*link) {
            parent = *link;
            temp = rb_entry(parent, struct nvsci_mm_db_entry, entry);
            link = (temp->sci_ipc_id > get_sciipcid_data->sci_ipc_id) ?
                    (&parent->rb_left) : (&parent->rb_right);
        }
        rb_link_node(&entry->entry, parent, link);
        rb_insert_color(&entry->entry, &nvsci_mm_db_ptr->root);
        PrintLog("Added entry %p %p %llu %llu %llu %u %u\n", entry->client, entry->handle,
                entry->sci_ipc_id, entry->local_vuid, entry->peer_vuid, entry->fd_flags,
                entry->refcount);
    }

    PrintLog("dma Buffer file pointer %p\n", fd_file);
    PrintLog("dma Buffer file refCount %d\n", (int)fd_file->f_count.counter);

unlock:
    mutex_unlock(&nvsci_mm_db_ptr->lock);
put_file:
    fdput(f);
out:
    EX;
    return ret;
}

static long nvsci_mm_ioctl_fd_from_sci_ipc_id(struct file *file, void *data)
{
    struct nvsci_mm_get_sciipcid_data *get_sciipcid_data = data;
    NvSciIpcEndpointVuid pr_vuid;
    NvSciIpcEndpointVuid lu_vuid;
    NvSciError sciErr = NvSciError_Success;
    struct nvsci_mm_db_entry *entry = NULL;
    struct file* filp = NULL;
    struct rb_node *node = NULL;
    struct free_sid_node *free_node = NULL;
    int ret = 0;

    EN;

    if (NVSCI_MM_MAJOR_VERSION != GET_MAJOR_FROM_HEADER(get_sciipcid_data->header)) {
        ret = -EINVAL;
        goto out;
    }

    if (get_sciipcid_data->fd_flags > O_RDWR) {
        ret = -EINVAL;
        goto out;

    }

    sciErr = nvsci_mm_get_validate_map_vuid(get_sciipcid_data->auth_token, &lu_vuid, &pr_vuid);
    if (sciErr != NvSciError_Success) {
        ret = -EINVAL;
        goto out;
    }

    PrintLog("Peer vuid %llu\n", pr_vuid);
    PrintLog("Local vuid %llu\n", lu_vuid);

    mutex_lock(&nvsci_mm_db_ptr->lock);

    for (node = rb_first(&nvsci_mm_db_ptr->root); node; node = rb_next(node)) {
        entry = rb_entry(node, struct nvsci_mm_db_entry, entry);
        if ((entry != NULL) &&
            (entry->sci_ipc_id == get_sciipcid_data->sci_ipc_id)) {
            break;
        }
        entry = NULL;
    }

    if (entry == NULL || (lu_vuid != entry->peer_vuid) ||
            (pr_vuid != entry->local_vuid) ||
            (get_sciipcid_data->fd_flags != entry->fd_flags)) {
        ret = -EINVAL;
        PrintLog("No entry for %p %p %llu %llu %llu %u %u\n", NULL, NULL,
                get_sciipcid_data->sci_ipc_id, pr_vuid, lu_vuid, 0x00, 0x00);
        goto unlock;
    }

    filp = (struct file*)entry->handle;
    get_sciipcid_data->fd = get_unused_fd_flags(entry->fd_flags);
    if (get_sciipcid_data->fd < 0) {
        ret = -EFAULT;
        goto unlock;
    }

    PrintLog("Found entry %p %p %llu %llu %llu %u %u\n", entry->client, entry->handle,
            entry->sci_ipc_id, entry->local_vuid, entry->peer_vuid, entry->fd_flags,
            entry->refcount);
    fd_install(get_sciipcid_data->fd, filp);
    get_file(filp);
    entry->refcount--;
    if (entry->refcount == 0) {
        fput(filp);
        rb_erase(&entry->entry, &nvsci_mm_db_ptr->root);
        PrintLog("Deleted entry %p %p %llu %llu %llu %u %u\n", entry->client, entry->handle,
                entry->sci_ipc_id, entry->local_vuid, entry->peer_vuid, entry->fd_flags,
                entry->refcount);
        free_node = kzalloc(sizeof(*free_node), GFP_KERNEL);
        if (free_node == NULL) {
            ret = -ENOMEM;
            kfree(entry);
            goto unlock;
        }

        free_node->sid = entry->sci_ipc_id;
        list_add_tail(&free_node->list, &nvsci_mm_db_ptr->free_sid_list);
        PrintLog("Recycling sid %llu\n", get_sciipcid_data->sci_ipc_id);
        kfree(entry);
    }

    PrintLog("dma Buffer file pointer %p\n", filp);
    PrintLog("dma Buffer file refCount %d\n", (int)filp->f_count.counter);

unlock:
    mutex_unlock(&nvsci_mm_db_ptr->lock);
out:
    EX;
    return ret;
}

static long dev_ops_ioctl(struct file *filp, unsigned int ucmd, unsigned long arg)
{
    long ret = 0;
    char stack_kdata[128];
    unsigned int kcmd;
    int nr = _IOC_NR(ucmd);
    char *kdata = stack_kdata;
    unsigned int in_size, out_size, drv_size, ksize;

    EN;

    if (nr >= ARRAY_SIZE(nvsci_mm_ioctl_cmds)) {
        ret = -EINVAL;
        goto out;
    }

    nr = array_index_nospec(nr, ARRAY_SIZE(nvsci_mm_ioctl_cmds));
    /* Get the kernel ioctl cmd that matches */
    kcmd = nvsci_mm_ioctl_cmds[nr];

    /* Figure out the delta between user cmd size and kernel cmd size */
    drv_size = _IOC_SIZE(kcmd);
    out_size = _IOC_SIZE(ucmd);
    in_size = out_size;
    if ((ucmd & kcmd & IOC_IN) == 0)
        in_size = 0;
    if ((ucmd & kcmd & IOC_OUT) == 0)
        out_size = 0;
    ksize = max(max(in_size, out_size), drv_size);

    /* If necessary, allocate buffer for ioctl argument */
    if (ksize > sizeof(stack_kdata)) {
        kdata = kmalloc(ksize, GFP_KERNEL);
        if (!kdata) {
            ret = -ENOMEM;
            goto out;
        }
    }

    if (copy_from_user(kdata, (void __user *)arg, in_size) != 0) {
        ret = -EFAULT;
        goto err;
    }

    /* zero out any difference between the kernel/user structure size */
    if (ksize > in_size)
        memset(kdata + in_size, 0, ksize - in_size);

    switch (ucmd) {
    case NVSCI_MM_IOCTL_CHECK_COMPAT:
        ret = nvsci_mm_ioctl_check_compat(filp, kdata);
        break;
    case NVSCI_MM_IOCTL_ALLOC:
        ret = nvsci_mm_ioctl_allocate(filp, kdata);
        break;
    case NVSCI_MM_IOCTL_GET_SCIIPCID:
        ret = nvsci_mm_ioctl_get_sciipcid(filp, kdata);
        break;
    case NVSCI_MM_IOCTL_FD_FROM_SCIIPCID:
        ret = nvsci_mm_ioctl_fd_from_sci_ipc_id(filp, kdata);
        break;
    default:
        ret = -ENOTTY;
        goto err;
    }

    if (copy_to_user((void __user *)arg, kdata, out_size) != 0) {
        ret = -EFAULT;
        goto err;
    }

err:
    if (kdata != stack_kdata)
        kfree(kdata);
out:
    EX;
    return ret;
}

static ssize_t dev_ops_write(struct file *filp, const char __user *buf,
               size_t len, loff_t *ppos)
{
    EN;
    PrintLog("Device write\n");
    EX;
    return len;
}

static ssize_t dev_ops_read(struct file *filp, char __user *buf,
                    size_t count, loff_t *f_pos)
{
    struct rb_node *node = NULL;
    struct nvsci_mm_db_entry *entry;
    struct free_sid_node *fnode, *temp;
    ssize_t ret = 0;

    EN;

    PrintLog("Device read\n");
    PrintLog("Module refCount %d\n", module_refcount(THIS_MODULE));
    PrintLog("Module filePointer %p\n", filp);
    PrintLog("Module file refCount %d\n", (int)filp->f_count.counter);

    mutex_lock(&nvsci_mm_db_ptr->lock);
    PrintLog("DB\n");
    for (node = rb_first(&nvsci_mm_db_ptr->root); node; node = rb_next(node)) {
        entry = rb_entry(node, struct nvsci_mm_db_entry, entry);
        PrintLog("%p %p %llu %llu %llu %u %u\n", entry->client, entry->handle,
            entry->sci_ipc_id, entry->local_vuid, entry->peer_vuid, entry->fd_flags, entry->refcount);
    }

    PrintLog("Free sids\n");
    list_for_each_entry_safe(fnode, temp, &nvsci_mm_db_ptr->free_sid_list, list) {
        PrintLog("%llu\n", fnode->sid);
    }

    mutex_unlock(&nvsci_mm_db_ptr->lock);

    EX;
    return ret;
}

static const struct file_operations nvsci_mm_dev_fops = {
    .owner          = THIS_MODULE,
    .open           = dev_ops_open,
    .release        = dev_ops_release,
    .unlocked_ioctl = dev_ops_ioctl,
    .write          = dev_ops_write,
    .read           = dev_ops_read,
    .llseek         = no_llseek,
};

struct {
    struct cdev cdev;
    dev_t dev;
    struct class *dev_class;
    struct device *device;
} nvsci_mm_dev;

static int nvsci_mm_db_init(void)
{
    int ret = 0;
    EN;

    nvsci_mm_db_ptr = kzalloc(sizeof(*nvsci_mm_db_ptr), GFP_KERNEL);
    if (nvsci_mm_db_ptr == NULL) {
        ret = -ENOMEM;
        goto out;
    }

    nvsci_mm_db_ptr->root = RB_ROOT;
    INIT_LIST_HEAD(&nvsci_mm_db_ptr->free_sid_list);
    mutex_init(&nvsci_mm_db_ptr->lock);

out:
    EX;
    return ret;
}

static void nvsci_mm_db_deinit(void)
{
    struct nvsci_mm_db_entry *e;
    struct free_sid_node *fnode, *temp;
    struct rb_node *n;
    EN;

    mutex_lock(&nvsci_mm_db_ptr->lock);
    while ((n = rb_first(&nvsci_mm_db_ptr->root))) {
        e = rb_entry(n, struct nvsci_mm_db_entry, entry);
        rb_erase(&e->entry, &nvsci_mm_db_ptr->root);
        kfree(e);
    }

    list_for_each_entry_safe(fnode, temp, &nvsci_mm_db_ptr->free_sid_list, list) {
        list_del(&fnode->list);
        kfree(fnode);
    }

    mutex_unlock(&nvsci_mm_db_ptr->lock);
    kfree(nvsci_mm_db_ptr);
    nvsci_mm_db_ptr = NULL;

    EX;
}

static char *nvsci_mm_devnode(struct device *dev, umode_t *mode)
{
    char *ret = NULL;

    if (!mode) {
        goto out;
    }

    *mode = 0444;

out:
    return ret;
}

static int __init nvsci_mm_init(void)
{
    int devno = 0;
    int err = 0;

    EN;

    memset(&nvsci_mm_dev, 0x0, sizeof(nvsci_mm_dev));

    err = alloc_chrdev_region(&nvsci_mm_dev.dev, 0, 1, "nvsci_mm");
    if (err < 0) {
        pr_err("alloc_chrdev_region failed  %d\n", err);
        goto out;
    }

    devno = MKDEV(MAJOR(nvsci_mm_dev.dev), MINOR(nvsci_mm_dev.dev));

    cdev_init(&nvsci_mm_dev.cdev, &nvsci_mm_dev_fops);

    nvsci_mm_dev.cdev.owner = THIS_MODULE;
    nvsci_mm_dev.cdev.ops = &nvsci_mm_dev_fops;

    err = cdev_add(&nvsci_mm_dev.cdev, devno, 1);
    if (err) {
        pr_err("cdev_add failed  %d\n", err);
        goto free_chrdev;
    }

    nvsci_mm_dev.dev_class = class_create(THIS_MODULE, "nvsci_mm");
    if (IS_ERR_OR_NULL(nvsci_mm_dev.dev_class)) {
        err = PTR_ERR(nvsci_mm_dev.dev_class);
        pr_err("class_create failed  %d\n", err);
        goto free_cdev;
    }

    nvsci_mm_dev.dev_class->devnode = nvsci_mm_devnode;

    nvsci_mm_dev.device = device_create(nvsci_mm_dev.dev_class,
            NULL, nvsci_mm_dev.dev, NULL, "nvsci_mm");
    if (IS_ERR(nvsci_mm_dev.device)) {
        err = PTR_ERR(nvsci_mm_dev.device);
        pr_err("device_create failed  %d\n", err);
        goto free_class;
    }

    err = nvsci_mm_db_init();
    if (err) {
        pr_err("db init failed  %d\n", err);
        goto free_device;
    }

    PrintLog("DB init passedi\n");

    goto out;

free_device:
    device_del(nvsci_mm_dev.device);
    device_destroy(nvsci_mm_dev.dev_class, nvsci_mm_dev.dev);
    nvsci_mm_dev.device = NULL;

free_class:
    class_destroy(nvsci_mm_dev.dev_class);
    nvsci_mm_dev.dev_class = NULL;

free_cdev:
    cdev_del(&nvsci_mm_dev.cdev);

free_chrdev:
    unregister_chrdev_region(nvsci_mm_dev.dev, 1);

out:
    EX;
    return err;
}

static void __exit nvsci_mm_exit(void)
{
    EN;

    nvsci_mm_db_deinit();
    device_del(nvsci_mm_dev.device);
    device_destroy(nvsci_mm_dev.dev_class, nvsci_mm_dev.dev);
    class_destroy(nvsci_mm_dev.dev_class);
    cdev_del(&nvsci_mm_dev.cdev);
    unregister_chrdev_region(nvsci_mm_dev.dev, 1);
    memset(&nvsci_mm_dev, 0x0, sizeof(nvsci_mm_dev));

    PrintLog("DB deinit passed\n");

    EX;
}

module_init(nvsci_mm_init);
module_exit(nvsci_mm_exit);

MODULE_DESCRIPTION("NVIDIA NvSci Memory Management Driver");
MODULE_AUTHOR("Nvidia Corporation");
MODULE_LICENSE("GPL v2");
