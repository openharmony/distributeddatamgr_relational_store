/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file linux/ashmem.h
 *
 * @brief Host product only: provides the ashmem ioctl command definitions as a
 * compile-time placeholder so that <ashmem.h> from c_utils can be compiled on a
 * host product build, where the kernel header <linux/ashmem.h> is unavailable.
 *
 * The host kernel does not implement the ashmem capability, so these commands
 * are never exercised at runtime; they exist only to let host product builds
 * compile. This shim is put on the include path only when is_host_product is
 * true, so device builds still resolve <linux/ashmem.h> to the real kernel
 * header.
 */

#ifndef RELATIONAL_STORE_HOST_LINUX_ASHMEM_H
#define RELATIONAL_STORE_HOST_LINUX_ASHMEM_H

#define ASHMEM_SET_NAME 0
#define ASHMEM_SET_SIZE 1
#define ASHMEM_SET_PROT_MASK 2
#define ASHMEM_GET_SIZE 3
#define ASHMEM_GET_PROT_MASK 4
#define ASHMEM_NAME_LEN 32

#endif // RELATIONAL_STORE_HOST_LINUX_ASHMEM_H
