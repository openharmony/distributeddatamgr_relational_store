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
class ExecutorPool;
namespace NativeRdb {
class Connection;

constexpr int64_t MIN_TIMEOUT_MS = 1000;
constexpr int64_t INTERRUPT_RETRY_INTERVAL_MS = 50;
constexpr uint64_t INTERRUPT_RETRY_COUNT = 3;

class SqlTimeoutGuard {
public:
    explicit SqlTimeoutGuard(int64_t timeoutMs = 0);
    ~SqlTimeoutGuard();

    void SetConnection(std::weak_ptr<Connection> conn);

    SqlTimeoutGuard(const SqlTimeoutGuard &) = delete;
    SqlTimeoutGuard &operator=(const SqlTimeoutGuard &) = delete;
    SqlTimeoutGuard(SqlTimeoutGuard &&) = delete;
    SqlTimeoutGuard &operator=(SqlTimeoutGuard &&) = delete;

private:
    std::chrono::steady_clock::time_point deadline_{};
    bool enabled_ = false;
    uint64_t taskId_ = 0;
    std::shared_ptr<ExecutorPool> executor_;
};
} // namespace NativeRdb
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_INCLUDE_SQL_TIMEOUT_GUARD_H
