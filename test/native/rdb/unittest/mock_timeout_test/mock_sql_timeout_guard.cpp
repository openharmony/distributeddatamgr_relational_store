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

#define LOG_TAG "SqlTimeoutGuard"
#include "sql_timeout_guard.h"

#include "connection.h"
#include "logger.h"
#include "task_executor.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

TimeoutGuard::TimeoutGuard(int64_t timeoutMs)
{
    if (timeoutMs <= 0) {
        return;
    }
    enabled_ = true;
    deadline_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
}

void TimeoutGuard::SetConnection(std::weak_ptr<Connection> conn)
{
    if (!enabled_) {
        return;
    }
    auto executor = TaskExecutor::GetInstance().GetExecutor();
    if (executor == nullptr) {
        LOG_WARN("TimeoutGuard: executor unavailable, mid-execution interrupt disabled");
        return;
    }
    auto delay = deadline_ - std::chrono::steady_clock::now();
    auto taskId = executor->Schedule(
        [conn]() {
            auto connection = conn.lock();
            if (connection != nullptr) {
                LOG_WARN("TimeoutGuard: SQL execution exceeded deadline, interrupting connId=%{public}d",
                    connection->GetId());
                connection->Interrupt();
            }
        },
        delay,
        std::chrono::milliseconds(50),
        3);
    cancel_ = [executor, taskId]() { (void)executor->Remove(taskId, true); };
}

TimeoutGuard::~TimeoutGuard()
{
    if (cancel_) {
        cancel_();
    }
}

TimeoutGuard::TimeoutGuard(TimeoutGuard &&other) noexcept
    : deadline_(other.deadline_), enabled_(other.enabled_), cancel_(std::move(other.cancel_))
{
    other.enabled_ = false;
}
} // namespace NativeRdb
} // namespace OHOS
