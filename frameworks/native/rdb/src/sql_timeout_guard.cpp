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

#include "sql_timeout_guard.h"

#include <chrono>

#include "connection.h"
#include "logger.h"
#include "task_executor.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
TimeoutGuard::TimeoutGuard(std::shared_ptr<Connection> conn, const DeadlineToken &token)
{
    if (conn == nullptr || !token.IsActive() || token.RemainingMs() <= 0) {
        return;
    }
    auto executor = TaskExecutor::GetInstance().GetExecutor();
    if (executor == nullptr) {
        LOG_WARN("TimeoutGuard: executor unavailable, mid-execution interrupt disabled");
        return;
    }
    std::weak_ptr<Connection> weakConn = conn;
    auto delay = std::chrono::milliseconds(token.RemainingMs());
    auto taskId = executor->Schedule(delay, [weakConn]() {
        auto c = weakConn.lock();
        if (c != nullptr) {
            c->Interrupt();
        }
    });
    // Remove(taskId, wait=true): if the task has not fired it is dropped; if it is currently
    // firing (Interrupt in progress) we wait for it to complete, so the connection is never
    // returned to the pool with a stale/pending interrupt. Remove(0) is a no-op.
    cancel_ = [executor, taskId]() { (void)executor->Remove(taskId, true); };
}

TimeoutGuard::~TimeoutGuard()
{
    if (cancel_) {
        cancel_();
    }
}

TimeoutGuard::TimeoutGuard(TimeoutGuard &&other) noexcept : cancel_(std::move(other.cancel_)) {}
} // namespace NativeRdb
} // namespace OHOS
