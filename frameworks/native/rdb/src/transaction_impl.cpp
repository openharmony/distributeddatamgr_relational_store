/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#define LOG_TAG "TransactionImpl"
#include "transaction_impl.h"
#include "logger.h"

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
int32_t TransactionImpl::Commit()
{
    LOG_ERROR("enter");
    return 0;
}
int32_t TransactionImpl::Begin()
{
    LOG_ERROR("enter");
    return 0;
}
int32_t TransactionImpl::Rollback()
{
    LOG_ERROR("enter");
    return 0;
}
int32_t TransactionImpl::Close()
{
    LOG_ERROR("enter");
    return 0;
}
std::pair<int32_t, int64_t> TransactionImpl::Insert(
    const std::string &table, const ValuesBucket &values, ConflictResolution conflictResolution)
{
    LOG_ERROR("enter.table:%{public}s", table.c_str());
    return { 0, 1 };
}
std::pair<int32_t, int64_t> TransactionImpl::Delete(const AbsRdbPredicates &values)
{
    LOG_ERROR("enter");
    return { 0, 1 };
}
std::pair<int32_t, int64_t> TransactionImpl::Update(
    const ValuesBucket &values, const AbsRdbPredicates &predicates, ConflictResolution conflictResolution)
{
    LOG_ERROR("enter");
    return { 0, 1 };
}
std::pair<int32_t, int64_t> TransactionImpl::BatchInsert(
    const std::string &table, const std::vector<ValuesBucket> &values)
{
    LOG_ERROR("enter.table:%{public}s", table.c_str());
    return { 0, 2 };
}
std::shared_ptr<ResultSet> TransactionImpl::QuerySql(const std::string &sql, const std::vector<ValueObject> &args)
{
    LOG_ERROR("enter.sql:%{public}s", sql.c_str());
    return nullptr;
}
std::pair<int32_t, ValueObject> TransactionImpl::Execute(const std::string &sql, const std::vector<ValueObject> &args)
{
    LOG_ERROR("enter.sql:%{public}s", sql.c_str());
    return { 0, "ok" };
}
} // namespace OHOS::NativeRdb