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

#ifndef OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_INCLUDE_SQL_TIMEOUT_GUARD_H
#define OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_INCLUDE_SQL_TIMEOUT_GUARD_H

#include <cstdint>
#include <functional>
#include <memory>
#include <utility>

#include "rdb_types.h"

namespace OHOS {
namespace NativeRdb {
class ConnectionPool;
class Connection;

// Tier2 mid-execution interrupt. Arms a one-shot task on the shared ExecutorPool that calls
// Connection::Interrupt() (sqlite3_interrupt) when the deadline expires. The connection is
// held by weak_ptr only, so a stale timer on a pooled/reused connection is avoided: on
// destruction Remove(taskId, wait=true) either cancels the pending task or waits for an
// in-flight interrupt to finish before the connection is returned to the pool.
class TimeoutGuard {
public:
    TimeoutGuard(std::shared_ptr<Connection> conn, const DeadlineToken &token);
    ~TimeoutGuard();

    TimeoutGuard(const TimeoutGuard &) = delete;
    TimeoutGuard &operator=(const TimeoutGuard &) = delete;
    TimeoutGuard(TimeoutGuard &&other) noexcept;
    TimeoutGuard &operator=(TimeoutGuard &&) = delete;

private:
    std::function<void()> cancel_;
};
} // namespace NativeRdb
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_INCLUDE_SQL_TIMEOUT_GUARD_H
