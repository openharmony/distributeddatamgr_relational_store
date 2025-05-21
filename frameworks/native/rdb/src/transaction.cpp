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
#include "transaction.h"

namespace OHOS::NativeRdb {
std::pair<int32_t, std::shared_ptr<Transaction>> Transaction::Create(
    int32_t type, std::shared_ptr<Connection> connection, const std::string &name)
{
    if (creator_ != nullptr) {
        return creator_(type, std::move(connection), name);
    }
    return { E_ERROR, nullptr };
}

int32_t Transaction::RegisterCreator(Creator creator)
{
    creator_ = std::move(creator);
    return E_OK;
}

std::pair<int32_t, int64_t> Transaction::BatchInsert(
    const std::string &table, const RefRows &rows, Resolution resolution)
{
    auto result = BatchInsert(table, rows, { resolution });
    return std::pair<int32_t, int64_t>();
}

ResultType Transaction::BatchInsert(const std::string &table, const RefRows &rows, const SqlOptions &sqlOptions)
{
    return { E_NOT_SUPPORT, -1 };
}
std::pair<int, int> Transaction::Update(
    const std::string &table, const Row &row, const std::string &where, const Values &args, Resolution resolution)

{
    AbsRdbPredicates predicates(table);
    predicates.SetWhereClause(where);
    predicates.SetBindArgs(args);
    return Update(row, predicates, resolution);
}
std::pair<int32_t, int32_t> Transaction::Update(
    const Row &row, const AbsRdbPredicates &predicates, Resolution resolution)
{
    auto result = Update(row, predicates, { resolution, "" });
    return { result.status, result.count };
}
ResultType Transaction::Update(const Row &row, const AbsRdbPredicates &predicates, const SqlOptions &sqlOptions)
{
    return { E_NOT_SUPPORT, -1 };
}

std::pair<int32_t, int32_t> Transaction::Delete(
    const std::string &table, const std::string &whereClause, const Values &args)
{
    AbsRdbPredicates predicates(table);
    predicates.SetWhereClause(whereClause);
    predicates.SetBindArgs(args);
    return Delete(predicates);
}

std::pair<int32_t, int32_t> Transaction::Delete(const AbsRdbPredicates &predicates)
{
    auto result = Delete(predicates, { "" });
    return { result.status, result.count };
}

ResultType Transaction::Delete(const AbsRdbPredicates &predicates, const SqlOptions &sqlOptions)
{
    return { E_NOT_SUPPORT, -1 };
}

ResultType Transaction::Execute(const std::string &sql, const SqlOptions &sqlOptions, const Transaction::Values &args)
{
    return { E_NOT_SUPPORT, -1 };
}
std::pair<int32_t, ValueObject> Transaction::Execute(const std::string &sql, const Transaction::Values &args)
{
    return { E_NOT_SUPPORT, -1 };
}
} // namespace OHOS::NativeRdb
