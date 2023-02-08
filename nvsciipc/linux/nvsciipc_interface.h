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

#ifndef __NVSCIIPC_INTERFACE_H__
#define __NVSCIIPC_INTERFACE_H__

/** Invalid VUID definition */
#define NVSCIIPC_ENDPOINT_VUID_INVALID      0U
/** Invalid authentication token definition */
#define NVSCIIPC_ENDPOINT_AUTHTOKEN_INVALID 0U
/** current self SOC ID */
#define NVSCIIPC_SELF_SOCID 0xFFFFFFFFU
/** current self VM ID */
#define NVSCIIPC_SELF_VMID  0xFFFFFFFFU

typedef enum NvSciErrorRec {
    /* Range 0x00000000 - 0x00FFFFFF : Common errors
     * This range is used for errors common to all NvSci libraries.
     */

    /** [EOK] No error */
    NvSciError_Success                  = 0x00000000,

    /** Unidentified error with no additional info */
    NvSciError_Unknown                  = 0x00000001,

    /* Generic errors */
    /** [ENOSYS] Feature is not implemented */
    NvSciError_NotImplemented           = 0x00000010,
    /** [ENOTSUP] Feature is not supported */
    NvSciError_NotSupported             = 0x00000011,
    /** [EACCES] Access to resource denied */
    NvSciError_AccessDenied             = 0x00000020,
    /** [EPERM] No permission to perform operation */
    NvSciError_NotPermitted             = 0x00000021,
    /** Resource is in wrong state to perform operation */
    NvSciError_InvalidState             = 0x00000022,
    /** Requested operation is not legal */
    NvSciError_InvalidOperation         = 0x00000023,
    /** Required resource is not initialized */
    NvSciError_NotInitialized           = 0x00000024,
    /** [ENOMEM] Not enough memory */
    NvSciError_InsufficientMemory       = 0x00000030,
    /** Not enough (non-memory) resources */
    NvSciError_InsufficientResource     = 0x00000031,
    /** Resource failed */
    NvSciError_ResourceError            = 0x00000032,

    /* Function parameter errors */
    /** [EINVAL] Invalid parameter value */
    NvSciError_BadParameter             = 0x00000100,
    /** [EFAULT] Invalid address */
    NvSciError_BadAddress               = 0x00000101,
    /** [E2BIG] Parameter list too long */
    NvSciError_TooBig                   = 0x00000102,
    /** [EOVERFLOW] Value too large for data type */
    NvSciError_Overflow                 = 0x00000103,

    /* Timing/temporary errors */
    /** [ETIMEDOUT] Operation timed out*/
    NvSciError_Timeout                  = 0x00000200,
    /** [EAGAIN] Resource unavailable. Try again. */
    NvSciError_TryItAgain               = 0x00000201,
    /** [EBUSY] Resource is busy */
    NvSciError_Busy                     = 0x00000202,
    /** [EINTR] An interrupt ocurred */
    NvSciError_InterruptedCall          = 0x00000203,

    /* Device errors */
    /** [ENODEV] No such device */
    NvSciError_NoSuchDevice             = 0x00001000,
    /** [ENOSPC] No space left on device */
    NvSciError_NoSpace                  = 0x00001001,
    /** [ENXIO] No such device or address */
    NvSciError_NoSuchDevAddr            = 0x00001002,
    /** [EIO] Input/output error */
    NvSciError_IO                       = 0x00001003,
    /** [ENOTTY] Inappropriate I/O control operation */
    NvSciError_InvalidIoctlNum          = 0x00001004,

    /* File system errors */
    /** [ENOENT] No such file or directory*/
    NvSciError_NoSuchEntry              = 0x00001100,
    /** [EBADF] Bad file descriptor */
    NvSciError_BadFileDesc              = 0x00001101,
    /** [EBADFSYS] Corrupted file system detected */
    NvSciError_CorruptedFileSys         = 0x00001102,
    /** [EEXIST] File already exists */
    NvSciError_FileExists               = 0x00001103,
    /** [EISDIR] File is a directory */
    NvSciError_IsDirectory              = 0x00001104,
    /** [EROFS] Read-only file system */
    NvSciError_ReadOnlyFileSys          = 0x00001105,
    /** [ETXTBSY] Text file is busy */
    NvSciError_TextFileBusy             = 0x00001106,
    /** [ENAMETOOLONG] File name is too long */
    NvSciError_FileNameTooLong          = 0x00001107,
    /** [EFBIG] File is too large */
    NvSciError_FileTooBig               = 0x00001108,
    /** [ELOOP] Too many levels of symbolic links */
    NvSciError_TooManySymbolLinks       = 0x00001109,
    /** [EMFILE] Too many open files in process*/
    NvSciError_TooManyOpenFiles         = 0x0000110A,
    /** [ENFILE] Too many open files in system */
    NvSciError_FileTableOverflow        = 0x0000110B,
    /** End of file reached */
    NvSciError_EndOfFile                = 0x0000110C,


    /* Communication errors */
    /** [ECONNRESET] Connection was closed or lost */
    NvSciError_ConnectionReset          = 0x00001200,
    /** [EALREADY] Pending connection is already in progress */
    NvSciError_AlreadyInProgress        = 0x00001201,
    /** [ENODATA] No message data available */
    NvSciError_NoData                   = 0x00001202,
    /** [ENOMSG] No message of the desired type available*/
    NvSciError_NoDesiredMessage         = 0x00001203,
    /** [EMSGSIZE] Message is too large */
    NvSciError_MessageSize              = 0x00001204,
    /** [ENOREMOTE] Remote node doesn't exist */
    NvSciError_NoRemote                 = 0x00001205,

    /* Process/thread errors */
    /** [ESRCH] No such process */
    NvSciError_NoSuchProcess            = 0x00002000,

    /* Mutex errors */
    /** [ENOTRECOVERABLE] Mutex damaged by previous owner's death */
    NvSciError_MutexNotRecoverable      = 0x00002100,
    /** [EOWNERDEAD] Previous owner died while holding mutex */
    NvSciError_LockOwnerDead            = 0x00002101,
    /** [EDEADLK] Taking ownership would cause deadlock */
    NvSciError_ResourceDeadlock         = 0x00002102,

    /** End of range for common error codes */
    NvSciError_CommonEnd                = 0x00FFFFFF,

    /* Range 0x04000000 - 0x04FFFFFF : NvSciIpc errors */
    /** Unidentified NvSciIpc error with no additional info */
    NvSciError_NvSciIpcUnknown          = 0x04000000,
    /** End of range for NvSciIpc errors */
    NvSciError_NvSciIpcEnd              = 0x04FFFFFF,
} NvSciError;

/**
 * @brief Handle to the IPC endpoint.
 */
typedef uint64_t NvSciIpcEndpoint;


/**
 * @brief VUID(VM unique ID) of the IPC endpoint.
 */
typedef uint64_t NvSciIpcEndpointVuid;

/**
 * @brief authentication token of the IPC endpoint.
 */
typedef uint64_t NvSciIpcEndpointAuthToken;

/**
 * @brief Defines topology ID of the IPC endpoint.
 */
typedef struct {
	/*! Holds SOC ID */
	uint32_t SocId;
	/*! Holds VMID */
	uint32_t VmId;
} NvSciIpcTopoId;

/**********************************************************************/
/*********************** Function Definitions *************************/
/**********************************************************************/
NvSciError NvSciIpcEndpointGetAuthToken(NvSciIpcEndpoint handle,
		NvSciIpcEndpointAuthToken *authToken);

NvSciError NvSciIpcEndpointValidateAuthTokenLinuxCurrent(
		NvSciIpcEndpointAuthToken authToken,
		NvSciIpcEndpointVuid *localUserVuid);

NvSciError NvSciIpcEndpointMapVuid(NvSciIpcEndpointVuid localUserVuid,
		NvSciIpcTopoId *peerTopoId, NvSciIpcEndpointVuid *peerUserVuid);

NvSciError NvSciIpcEndpointGetVuid(NvSciIpcEndpoint handle,
		NvSciIpcEndpointVuid *vuid);

#endif /* __NVSCIIPC_INTERFACE_H__ */
