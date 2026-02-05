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

#ifndef OHOS_RELATION_STORE_THREAD_SAFE_BASE_H
#define OHOS_RELATION_STORE_THREAD_SAFE_BASE_H

#include <shared_mutex>
#include <memory>
#include <utility>

namespace OHOS {
namespace RdbTaihe {

template<typename T>
class ThreadSafeBase {
public:
    ThreadSafeBase() = default;
    virtual ~ThreadSafeBase() = default;

    ThreadSafeBase(const ThreadSafeBase&) = delete;
    ThreadSafeBase& operator=(const ThreadSafeBase&) = delete;
    ThreadSafeBase(ThreadSafeBase&&) = delete;
    ThreadSafeBase& operator=(ThreadSafeBase&&) = delete;

protected:
    std::shared_ptr<T> GetResource() const
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return resource_;
    }

    void SetResource(std::shared_ptr<T> resource)
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        resource_ = std::move(resource);
    }

    std::shared_ptr<T> ResetResource()
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto old = std::move(resource_);
        resource_ = nullptr;
        return old;
    }

private:
    std::shared_ptr<T> resource_;
    mutable std::shared_mutex mutex_;
};

} // namespace RdbTaihe
} // namespace OHOS

#endif // OHOS_RELATION_STORE_THREAD_SAFE_BASE_H
