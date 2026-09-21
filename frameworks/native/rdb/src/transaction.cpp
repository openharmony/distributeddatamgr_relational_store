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
    int32_t type, std::shared_ptr<Connection> connection, const std::string &path)
{
    if (creator_ != nullptr) {
        return creator_(type, std::move(connection), path);
    }
    return { E_ERROR, nullptr };
}

int32_t Transaction::RegisterCreator(Creator creator)
{
    creator_ = std::move(creator);
    return E_OK;
}

std::pair<int32_t, int64_t> Transaction::Insert(
    const std::string &table, const Row &row, Resolution resolution)
{
    // old calls new: the non-config overload delegates to the per-op config canonical entry.
    return Insert(table, row, resolution, InsertConfig{});
}

std::pair<int32_t, int64_t> Transaction::BatchInsert(
    const std::string &table, const RefRows &rows, Resolution resolution)
{
    auto [code, result] = BatchInsert(table, rows, ReturningConfig{}, resolution);
    return { code, result.changed };
}

std::pair<int32_t, Results> Transaction::BatchInsert(const std::string &table, const RefRows &rows,
    const ReturningConfig &config, Resolution resolution)
{
    // old calls new: the ReturningConfig overload delegates to the per-op config canonical entry.
    return BatchInsert(table, rows, resolution, BatchInsertConfig{0, config});
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
    auto [code, result] = Update(row, predicates, ReturningConfig{}, resolution);
    return { code, result.changed };
}

std::pair<int32_t, Results> Transaction::Update(const Row &row, const AbsRdbPredicates &predicates,
    const ReturningConfig &config, Resolution resolution)
{
    // old calls new: the ReturningConfig overload delegates to the per-op config canonical entry.
    return Update(row, predicates, UpdateConfig{0, config}, resolution);
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
    auto [code, result] = Delete(predicates, ReturningConfig{});
    return { code, result.changed };
}

std::pair<int32_t, Results> Transaction::Delete(
    const AbsRdbPredicates &predicates, const ReturningConfig &config)
{
    // old calls new: the ReturningConfig overload delegates to the per-op config canonical entry.
    return Delete(predicates, DeleteConfig{0, config});
}

std::pair<int32_t, ValueObject> Transaction::Execute(const std::string &sql, const Values &args)
{
    // old calls new: the non-config overload delegates to the per-op config canonical entry.
    return Execute(sql, args, ExecuteConfig{});
}

std::pair<int32_t, Results> Transaction::ExecuteExt(const std::string &sql, const Values &args)
{
    // old calls new: the non-config overload delegates to the per-op config canonical entry.
    return ExecuteExt(sql, args, ExecuteConfig{});
}

std::shared_ptr<ResultSet> Transaction::QueryByStep(const std::string &sql, const Values &args, bool preCount)
{
    QueryOptions options{.preCount = preCount, .isGotoNextRowReturnLastError = false};
    return QueryByStep(sql, args, options);
}

std::shared_ptr<ResultSet> Transaction::QueryByStep(
    const AbsRdbPredicates &predicates, const Fields &columns, bool preCount)
{
    QueryOptions options{.preCount = preCount, .isGotoNextRowReturnLastError = false};
    return QueryByStep(predicates, columns, options);
}

std::shared_ptr<ResultSet> Transaction::QueryByStep(
    const std::string &sql, const Values &args, const QueryOptions &options)
{
    // old calls new: the non-config overload delegates to the per-op config canonical entry.
    return QueryByStep(sql, args, options, QueryConfig{});
}

std::shared_ptr<ResultSet> Transaction::QueryByStep(
    const AbsRdbPredicates &predicates, const Fields &columns, const QueryOptions &options)
{
    // old calls new: the non-config overload delegates to the per-op config canonical entry.
    return QueryByStep(predicates, columns, options, QueryConfig{});
}

// Per-op config canonical entries: subclasses MUST override these to provide CRUD with timeout.
// The base defaults terminate the delegation chain so old-overload callers receive E_NOT_SUPPORT
// (or nullptr) when the subclass does not implement the per-op config overload, instead of
// silently dropping the timeout by delegating back to the old overloads.
std::pair<int32_t, int64_t> Transaction::Insert(
    const std::string &table, const Row &row, Resolution resolution, const InsertConfig &config)
{
    return { E_NOT_SUPPORT, -1 };
}

std::pair<int32_t, Results> Transaction::BatchInsert(const std::string &table, const RefRows &rows,
    Resolution resolution, const BatchInsertConfig &config)
{
    return { E_NOT_SUPPORT, -1 };
}

std::pair<int32_t, Results> Transaction::Update(const Row &row, const AbsRdbPredicates &predicates,
    const UpdateConfig &config, Resolution resolution)
{
    return { E_NOT_SUPPORT, -1 };
}

std::pair<int32_t, Results> Transaction::Delete(
    const AbsRdbPredicates &predicates, const DeleteConfig &config)
{
    return { E_NOT_SUPPORT, -1 };
}

std::shared_ptr<ResultSet> Transaction::QueryByStep(const std::string &sql, const Values &args,
    const QueryOptions &options, const QueryConfig &config)
{
    return nullptr;
}

std::shared_ptr<ResultSet> Transaction::QueryByStep(
    const AbsRdbPredicates &predicates, const Fields &columns, const QueryOptions &options,
    const QueryConfig &config)
{
    return nullptr;
}

std::pair<int32_t, ValueObject> Transaction::Execute(
    const std::string &sql, const Values &args, const ExecuteConfig &config)
{
    return { E_NOT_SUPPORT, ValueObject() };
}

std::pair<int32_t, Results> Transaction::ExecuteExt(
    const std::string &sql, const Values &args, const ExecuteConfig &config)
{
    return { E_NOT_SUPPORT, -1 };
}
} // namespace OHOS::NativeRdb
