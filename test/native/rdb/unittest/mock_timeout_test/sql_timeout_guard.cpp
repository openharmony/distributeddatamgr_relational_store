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

SqlTimeoutGuard::SqlTimeoutGuard(int64_t timeoutMs)
{
    if (timeoutMs <= 0) {
        return;
    }
    executor_ = TaskExecutor::GetInstance().GetExecutor();
    if (executor_ == nullptr) {
        return;
    }
    enabled_ = true;
    deadline_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
}

void SqlTimeoutGuard::SetConnection(std::weak_ptr<Connection> conn)
{
    if (!enabled_ || executor_ == nullptr) {
        return;
    }
    auto delay = deadline_ - std::chrono::steady_clock::now();
    if (delay < std::chrono::milliseconds(0)) {
        delay = std::chrono::milliseconds(0);
    }
    taskId_ = executor_->Schedule(
        [conn]() {
            auto connection = conn.lock();
            if (connection != nullptr) {
                connection->Interrupt();
            }
        },
        delay,
        std::chrono::milliseconds(INTERRUPT_RETRY_INTERVAL_MS),
        INTERRUPT_RETRY_COUNT);
}

SqlTimeoutGuard::~SqlTimeoutGuard()
{
    if (!enabled_ || taskId_ == 0 || executor_ == nullptr) {
        return;
    }
    (void)executor_->Remove(taskId_, true);
}
} // namespace NativeRdb
} // namespace OHOS
