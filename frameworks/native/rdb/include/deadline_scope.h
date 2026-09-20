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

#ifndef NATIVE_RDB_DEADLINE_SCOPE_H
#define NATIVE_RDB_DEADLINE_SCOPE_H

#include "rdb_types.h"
#include "statement.h"

namespace OHOS::NativeRdb {
// RAII scope that sets a thread-local deadline on Statement for pre-execution timeout checks.
// Statement::deadline_ is the single source of truth; Current() exposes it. The scope saves
// the previous token on construction and restores it on destruction so nested scopes (e.g. a
// config-overload CRUD triggering another timed CRUD on the same thread) do not silently drop
// the outer deadline. An inactive scope (timeoutMs <= 0) never clobbers the outer deadline.
struct DeadlineScope {
    explicit DeadlineScope(int64_t timeoutMs) : token_(DeadlineToken::FromMs(timeoutMs))
    {
        prev_ = Statement::GetDeadline(); // save outer (single source of truth)
        if (token_.IsActive()) {          // only override when active
            Statement::SetDeadline(token_);
        }
    }
    ~DeadlineScope()
    {
        Statement::SetDeadline(prev_); // restore outer, never unconditional clear
    }

    bool IsExhausted() const { return token_.IsExhausted(); }
    const DeadlineToken &Token() const { return token_; }

    // Access the thread-local active token (Statement::deadline_). Valid only while a
    // DeadlineScope is alive on the current thread.
    static DeadlineToken &Current() noexcept
    {
        return Statement::MutableDeadline();
    }

    DeadlineScope(const DeadlineScope &) = delete;
    DeadlineScope &operator=(const DeadlineScope &) = delete;

private:
    DeadlineToken token_;
    DeadlineToken prev_;
};
} // namespace OHOS::NativeRdb

#endif // NATIVE_RDB_DEADLINE_SCOPE_H
