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
 * @brief Compile-time placeholder for the ashmem ioctl command definitions.
 * <ashmem.h> from c_utils unconditionally includes <linux/ashmem.h>, which the
 * host kernel does not provide. Targets that pull in c_utils' ashmem header
 * (the real native_appdatafwk SharedBlock, or the mock IPC message_parcel.h)
 * add this directory to their include path only under is_linux builds so
 * <linux/ashmem.h> resolves to this shim.
 *
 * The host kernel has no ashmem capability, so these commands are never
 * exercised at runtime; the macros exist only so the code compiles. Ohos
 * device builds do not carry this directory, so they keep resolving
 * <linux/ashmem.h> to the real kernel header; mock targets that carry it
 * under is_linux are stubs and never invoke the ioctls, so the placeholder
 * values are harmless.
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
