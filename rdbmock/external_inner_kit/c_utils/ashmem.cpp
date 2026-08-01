/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

// This file is vendored from commonlibrary/c_utils/base/src/ashmem.cpp and is
// compiled only for host product builds. On host product the upstream c_utils
// excludes ashmem.cpp from its build (and its header unconditionally includes
// <linux/ashmem.h>, which the host kernel does not provide), so the Ashmem
// symbols are missing and relational_store's SharedBlock fails to link. To keep
// the host build self-contained without modifying c_utils, the implementation is
// duplicated here, compiled under is_host_product only, and the ASHMEM_* ioctl
// macros come from the in-repo shim host_include/linux/ashmem.h instead of the
// kernel header. On device builds (is_host_product == false) this file is not
// compiled, so c_utils remains the single provider of the Ashmem symbols and no
// duplicate-definition conflict occurs. Runtime on host is never exercised: the
// host kernel has no /dev/ashmem, so Ashmem::CreateAshmem returns nullptr and
// callers fall back to error handling.

#include "ashmem.h"

#include <fcntl.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "securec.h"

namespace OHOS {
static pthread_mutex_t g_ashmemLock = PTHREAD_MUTEX_INITIALIZER;

#ifdef UTILS_CXX_RUST
std::shared_ptr<Ashmem> CreateAshmemStd(const char *name, int32_t size)
{
    if ((name == nullptr) || (size <= 0)) {
        return std::shared_ptr<Ashmem>{};
    }

    int fd = AshmemCreate(name, size);
    if (fd < 0) {
        return std::shared_ptr<Ashmem>{};
    }

    return std::make_shared<Ashmem>(fd, size);
}

const c_void* AsVoidPtr(const char* inPtr)
{
    return static_cast<const c_void*>(inPtr);
}

const char* AsCharPtr(const c_void* inPtr)
{
    return static_cast<const char*>(inPtr);
}
#endif

static int AshmemOpenLocked()
{
    int fd = TEMP_FAILURE_RETRY(open("/dev/ashmem", O_RDWR | O_CLOEXEC));
    if (fd < 0) {
        return fd;
    }

    struct stat st;
    int ret = TEMP_FAILURE_RETRY(fstat(fd, &st));
    if (ret < 0) {
        close(fd);
        return ret;
    }

    if (!S_ISCHR(st.st_mode) || !st.st_rdev) {
        close(fd);
        return -1;
    }
    return fd;
}

static int AshmemOpen()
{
    pthread_mutex_lock(&g_ashmemLock);
    int fd = AshmemOpenLocked();
    pthread_mutex_unlock(&g_ashmemLock);
    return fd;
}

/*
 * AshmemCreate - create a new ashmem region and returns the file descriptor
 * fd < 0 means failed
 *
 */
int AshmemCreate(const char *name, size_t size)
{
    int ret;
    int fd = AshmemOpen();
    if (fd < 0) {
        return fd;
    }

    if (name != nullptr) {
        char buf[ASHMEM_NAME_LEN] = {0};
        ret = strcpy_s(buf, sizeof(buf), name);
        if (ret != EOK) {
            close(fd);
            return -1;
        }
        ret = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_NAME, buf));
        if (ret < 0) {
            close(fd);
            return ret;
        }
    }

    ret = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_SIZE, size));
    if (ret < 0) {
        close(fd);
        return ret;
    }
    return fd;
}

int AshmemSetProt(int fd, int prot)
{
    return TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_PROT_MASK, prot));
}

int AshmemGetSize(int fd)
{
    return TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_GET_SIZE, NULL));
}

Ashmem::Ashmem(int fd, int32_t size) : memoryFd_(fd), memorySize_(size), flag_(0), startAddr_(nullptr)
{
}

Ashmem::~Ashmem()
{
    UnmapAshmem();
    CloseAshmem();
}

sptr<Ashmem> Ashmem::CreateAshmem(const char *name, int32_t size)
{
    if ((name == nullptr) || (size <= 0)) {
        return nullptr;
    }

    int fd = AshmemCreate(name, size);
    if (fd < 0) {
        return nullptr;
    }

    return new Ashmem(fd, size);
}

bool Ashmem::SetProtection(int protectionType) const
{
    int result = AshmemSetProt(memoryFd_, protectionType);
    return result >= 0;
}

int Ashmem::GetProtection() const
{
    return TEMP_FAILURE_RETRY(ioctl(memoryFd_, ASHMEM_GET_PROT_MASK));
}

int32_t Ashmem::GetAshmemSize() const
{
    return AshmemGetSize(memoryFd_);
}

#ifdef UTILS_CXX_RUST
void Ashmem::CloseAshmem() const
#else
void Ashmem::CloseAshmem()
#endif
{
    if (memoryFd_ > 0) {
        ::close(memoryFd_);
        memoryFd_ = -1;
    }
    memorySize_ = 0;
    flag_ = 0;
    startAddr_ = nullptr;
}

#ifdef UTILS_CXX_RUST
bool Ashmem::MapAshmem(int mapType) const
#else
bool Ashmem::MapAshmem(int mapType)
#endif
{
    void *startAddr = ::mmap(nullptr, memorySize_, mapType, MAP_SHARED, memoryFd_, 0);
    if (startAddr == MAP_FAILED) {
        return false;
    }

    startAddr_ = startAddr;
    flag_ = mapType;

    return true;
}

#ifdef UTILS_CXX_RUST
bool Ashmem::MapReadAndWriteAshmem() const
#else
bool Ashmem::MapReadAndWriteAshmem()
#endif
{
    return MapAshmem(PROT_READ | PROT_WRITE);
}

#ifdef UTILS_CXX_RUST
bool Ashmem::MapReadOnlyAshmem() const
#else
bool Ashmem::MapReadOnlyAshmem()
#endif
{
    return MapAshmem(PROT_READ);
}

#ifdef UTILS_CXX_RUST
void Ashmem::UnmapAshmem() const
#else
void Ashmem::UnmapAshmem()
#endif
{
    if (startAddr_ != nullptr) {
        ::munmap(startAddr_, memorySize_);
        startAddr_ = nullptr;
    }
    flag_ = 0;
}

#ifdef UTILS_CXX_RUST
bool Ashmem::WriteToAshmem(const void *data, int32_t size, int32_t offset) const
#else
bool Ashmem::WriteToAshmem(const void *data, int32_t size, int32_t offset)
#endif
{
    if (data == nullptr) {
        return false;
    }

    if (!CheckValid(size, offset, PROT_WRITE)) {
        return false;
    }

    auto tmpData = reinterpret_cast<char *>(startAddr_);
    int ret = memcpy_s(tmpData + offset, memorySize_ - offset, reinterpret_cast<const char *>(data), size);
    if (ret != EOK) {
        return false;
    }

    return true;
}

#ifdef UTILS_CXX_RUST
const void *Ashmem::ReadFromAshmem(int32_t size, int32_t offset) const
#else
const void *Ashmem::ReadFromAshmem(int32_t size, int32_t offset)
#endif
{
    if (!CheckValid(size, offset, PROT_READ)) {
        return nullptr;
    }

    return reinterpret_cast<const char *>(startAddr_) + offset;
}

bool Ashmem::CheckValid(int32_t size, int32_t offset, int cmd) const
{
    if (startAddr_ == nullptr) {
        return false;
    }
    if ((size < 0) || (size > memorySize_) || (offset < 0) || (offset > memorySize_)) {
        return false;
    }
    if (offset + size > memorySize_) {
        return false;
    }
    if (!(static_cast<uint32_t>(GetProtection()) & static_cast<uint32_t>(cmd)) ||
        !(static_cast<uint32_t>(flag_) & static_cast<uint32_t>(cmd))) {
        return false;
    }

    return true;
}
}
