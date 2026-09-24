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

#ifndef NATIVE_RDB_INCLUDE_SQL_TIMEOUT_GUARD_H
#define NATIVE_RDB_INCLUDE_SQL_TIMEOUT_GUARD_H

#include <chrono>
#include <cstdint>
#include <memory>

namespace OHOS {
namespace NativeRdb {
class Connection;

constexpr int64_t MIN_TIMEOUT_MS = 1000;

class TimeoutGuard {
public:
    explicit TimeoutGuard(int64_t timeoutMs = 0);
    ~TimeoutGuard();

    void SetConnection(std::weak_ptr<Connection> conn);

    TimeoutGuard(const TimeoutGuard &) = delete;
    TimeoutGuard &operator=(const TimeoutGuard &) = delete;
    TimeoutGuard(TimeoutGuard &&) = delete;
    TimeoutGuard &operator=(TimeoutGuard &&) = delete;

private:
    std::chrono::steady_clock::time_point deadline_{};
    bool enabled_ = false;
    uint64_t taskId_ = 0;
};
} // namespace NativeRdb
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_INCLUDE_SQL_TIMEOUT_GUARD_H
