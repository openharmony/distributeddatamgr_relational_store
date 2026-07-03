/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#ifndef NATIVE_RDB_ERR_MSG_STORE_H
#define NATIVE_RDB_ERR_MSG_STORE_H

#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace OHOS::NativeRdb {
class ErrMsgStore {
public:
    static ErrMsgStore &Instance()
    {
        static ErrMsgStore instance;
        return instance;
    }

    std::string Get(const void *obj) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = map_.find({ const_cast<void *>(obj), std::this_thread::get_id() });
        return it != map_.end() ? it->second : "";
    }

    void Set(const void *obj, const std::string &msg)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        map_[{ const_cast<void *>(obj), std::this_thread::get_id() }] = msg;
    }

    void Clear(const void *obj)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        map_.erase({ const_cast<void *>(obj), std::this_thread::get_id() });
    }

    void RemoveAll(const void *obj)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto target = const_cast<void *>(obj);
        for (auto it = map_.begin(); it != map_.end();) {
            if (it->first.obj == target) {
                it = map_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    ErrMsgStore() = default;

    struct Key {
        void *obj;
        std::thread::id tid;
        bool operator==(const Key &other) const
        {
            return obj == other.obj && tid == other.tid;
        }
    };

    struct KeyHash {
        size_t operator()(const Key &k) const
        {
            auto h1 = std::hash<void *>()(k.obj);
            auto h2 = std::hash<std::thread::id>()(k.tid);
            return h1 ^ (h2 << 1);
        }
    };

    std::unordered_map<Key, std::string, KeyHash> map_;
    mutable std::mutex mutex_;
};
} // namespace OHOS::NativeRdb

#endif // NATIVE_RDB_ERR_MSG_STORE_H
