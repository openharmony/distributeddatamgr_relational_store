/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "gdb_errors.h"
#include "gdb_transaction.h"

namespace OHOS::DistributedDataAip {
std::pair<int32_t, std::shared_ptr<Transaction>> Transaction::Create(std::shared_ptr<Connection> conn)
{
    if (creator_ != nullptr) {
        return creator_(std::move(conn));
    }
    return { E_ERROR, nullptr };
}
 
int32_t Transaction::RegisterCreator(Creator creator)
{
    creator_ = std::move(creator);
    return E_OK;
}
} // namespace OHOS::DistributedDataAip
