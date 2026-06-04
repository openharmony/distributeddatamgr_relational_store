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

#ifndef BASE_EVENTHANDLER_FRAMEWORKS_EVENTHANDLER_INCLUDE_LOCK_BASE_H
#define BASE_EVENTHANDLER_FRAMEWORKS_EVENTHANDLER_INCLUDE_LOCK_BASE_H

#include <memory>

namespace OHOS {
namespace AppExecFwk {

class LockBase {
public:
    virtual ~LockBase() = default;
    virtual void lock() = 0;
    virtual void unlock() = 0;
};

class LockGuardBase {
public:
    explicit LockGuardBase(LockBase& lock) : lock_(lock)
    {
        lock_.lock();
    }
    ~LockGuardBase()
    {
        lock_.unlock();
    }

    LockGuardBase(const LockGuardBase&) = delete;
    LockGuardBase& operator=(const LockGuardBase&) = delete;
    LockGuardBase(LockGuardBase&&) = delete;
    LockGuardBase& operator=(LockGuardBase&&) = delete;

private:
    LockBase& lock_;
};

class UniqueLockBase {
public:
    explicit UniqueLockBase(LockBase& lock) : lock_(&lock), owns_lock_(false)
    {
        this->lock();
    }
    
    UniqueLockBase(UniqueLockBase&& other) noexcept
        : lock_(other.lock_), owns_lock_(other.owns_lock_)
    {
        other.lock_ = nullptr;
        other.owns_lock_ = false;
    }
    
    UniqueLockBase& operator=(UniqueLockBase&& other) noexcept
    {
        if (this != &other) {
            if (owns_lock_) {
                unlock();
            }
            lock_ = other.lock_;
            owns_lock_ = other.owns_lock_;
            other.lock_ = nullptr;
            other.owns_lock_ = false;
        }
        return *this;
    }
    
    ~UniqueLockBase()
    {
        if (owns_lock_) {
            unlock();
        }
    }
    
    void lock()
    {
        if (lock_ && !owns_lock_) {
            lock_->lock();
            owns_lock_ = true;
        }
    }
    
    void unlock()
    {
        if (lock_ && owns_lock_) {
            lock_->unlock();
            owns_lock_ = false;
        }
    }

private:
    LockBase* lock_;
    bool owns_lock_;
    
    UniqueLockBase(const UniqueLockBase&) = delete;
    UniqueLockBase& operator=(const UniqueLockBase&) = delete;
};

enum class EventLockType {
    STANDARD,
    PRIORITY_INHERIT
};

} // namespace AppExecFwk
} // namespace OHOS

#endif  // #ifndef BASE_EVENTHANDLER_FRAMEWORKS_EVENTHANDLER_INCLUDE_LOCK_BASE_H