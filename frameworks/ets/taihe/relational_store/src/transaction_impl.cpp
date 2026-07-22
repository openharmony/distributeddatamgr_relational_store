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

#define LOG_TAG "TransactionImpl"
#include "transaction_impl.h"

#include "lite_result_set_impl.h"
#include "ohos.data.relationalStore.impl.h"
#include "ohos.data.relationalStore.proj.hpp"
#include "rdb_predicates_impl.h"
#include "result_set_impl.h"

namespace OHOS {
namespace RdbTaihe {

TransactionImpl::TransactionImpl()
{
}
TransactionImpl::TransactionImpl(std::shared_ptr<OHOS::NativeRdb::Transaction> transaction)
{
    SetResource(transaction);
}

void TransactionImpl::CommitSync()
{
    auto transaction = GetResource();
    ASSERT_THROW_INNER_ERROR(
        transaction != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "nativeTransaction_ is nullptr", RDB_DO_NOTHING);
    auto errCode = transaction->Commit();
    CHECK_ERRCODE_THROW_INNER_ERROR(errCode, transaction->GetLastErrorMsg(), RDB_DO_NOTHING);
}

void TransactionImpl::RollbackSync()
{
    auto transaction = GetResource();
    ASSERT_THROW_INNER_ERROR(
        transaction != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "nativeTransaction_ is nullptr", RDB_DO_NOTHING);
    auto errCode = transaction->Rollback();
    CHECK_ERRCODE_THROW_INNER_ERROR(errCode, transaction->GetLastErrorMsg(), RDB_DO_NOTHING);
}

int64_t TransactionImpl::InsertSync(
    string_view table, map_view<::taihe::string, ValueType> values, optional_view<ConflictResolution> conflict)
{
    auto transaction = GetResource();
    ASSERT_THROW_INNER_ERROR(
        transaction != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "nativeTransaction_ is nullptr", ERR_NULL);
    ConflictResolution conflictResolution = ConflictResolution::key_t::ON_CONFLICT_NONE;
    if (conflict.has_value()) {
        conflictResolution = conflict.value().get_key();
    }
    OHOS::NativeRdb::ValuesBucket bucket = ani_rdbutils::MapValuesToNative(values);
    auto nativeConflictValue = (OHOS::NativeRdb::ConflictResolution)conflictResolution.get_key();
    auto [errCode, output] = transaction->Insert(std::string(table), bucket, nativeConflictValue);
    CHECK_ERRCODE_THROW_INNER_ERROR(errCode, transaction->GetLastErrorMsg(), output);
    return output;
}

int64_t TransactionImpl::BatchInsertSync(string_view table, array_view<map<string, ValueType>> values)
{
    auto transaction = GetResource();
    ASSERT_THROW_INNER_ERROR(
        transaction != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "nativeTransaction_ is nullptr", ERR_NULL);
    OHOS::NativeRdb::ValuesBuckets buckets = ani_rdbutils::BucketValuesToNative(values);
    ASSERT_THROW_PARAM_ERROR(
        !ani_rdbutils::HasDuplicateAssets(buckets), "Duplicate assets are not allowed", "", ERR_NULL);
    auto [errCode, output] = transaction->BatchInsert(std::string(table), buckets);
    CHECK_ERRCODE_THROW_INNER_ERROR(errCode, transaction->GetLastErrorMsg(), output);
    return output;
}

int64_t TransactionImpl::UpdateSync(
    map_view<string, ValueType> values, weak::RdbPredicates predicates, optional_view<ConflictResolution> conflict)
{
    auto transaction = GetResource();
    ASSERT_THROW_INNER_ERROR(
        transaction != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "nativeTransaction_ is nullptr", ERR_NULL);
    ConflictResolution conflictResolution = ConflictResolution::key_t::ON_CONFLICT_NONE;
    if (conflict.has_value()) {
        conflictResolution = conflict.value().get_key();
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    ASSERT_THROW_INNER_ERROR(rdbPredicateNative != nullptr, OHOS::NativeRdb::E_ERROR, "", ERR_NULL);
    OHOS::NativeRdb::ValuesBucket bucket = ani_rdbutils::MapValuesToNative(values);
    auto nativeConflictValue = (OHOS::NativeRdb::ConflictResolution)conflictResolution.get_key();
    auto [errCode, rows] = transaction->Update(bucket, *rdbPredicateNative, nativeConflictValue);
    CHECK_ERRCODE_THROW_INNER_ERROR(errCode, transaction->GetLastErrorMsg(), rows);
    return rows;
}

int64_t TransactionImpl::DeleteSync(weak::RdbPredicates predicates)
{
    auto transaction = GetResource();
    ASSERT_THROW_INNER_ERROR(
        transaction != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "nativeTransaction_ is nullptr", ERR_NULL);
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    ASSERT_THROW_INNER_ERROR(rdbPredicateNative != nullptr, OHOS::NativeRdb::E_ERROR, "", ERR_NULL);
    auto [errCode, rows] = transaction->Delete(*rdbPredicateNative);
    CHECK_ERRCODE_THROW_INNER_ERROR(errCode, transaction->GetLastErrorMsg(), rows);
    return rows;
}

ResultSet TransactionImpl::QuerySync(weak::RdbPredicates predicates, optional_view<array<string>> columns)
{
    auto transaction = GetResource();
    ASSERT_THROW_INNER_ERROR(transaction != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED,
        "nativeTransaction_ is nullptr", (make_holder<ResultSetImpl, ResultSet>()));
    std::vector<std::string> stdcolumns;
    if (columns.has_value()) {
        stdcolumns = std::vector<std::string>(columns.value().begin(), columns.value().end());
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    ASSERT_THROW_INNER_ERROR(
        rdbPredicateNative != nullptr, OHOS::NativeRdb::E_ERROR, "", (make_holder<ResultSetImpl, ResultSet>()));
    auto nativeResultSet = transaction->QueryByStep(*rdbPredicateNative, stdcolumns);
    ASSERT_THROW_INNER_ERROR(nativeResultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED,
        "nativeResultSet is nullptr", (make_holder<ResultSetImpl, ResultSet>()));
    return make_holder<ResultSetImpl, ResultSet>(nativeResultSet);
}

ResultSet TransactionImpl::QuerySqlSync(string_view sql, optional_view<array<ValueType>> args)
{
    auto transaction = GetResource();
    ASSERT_THROW_INNER_ERROR(transaction != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED,
        "nativeTransaction_ is nullptr", (make_holder<ResultSetImpl, ResultSet>()));
    std::vector<OHOS::NativeRdb::ValueObject> para;
    if (args.has_value()) {
        std::transform(args.value().begin(), args.value().end(), std::back_inserter(para),
            [](const ValueType &valueType) { return ani_rdbutils::ValueTypeToNative(valueType); });
    }
    auto nativeResultSet = transaction->QueryByStep(std::string(sql), para);
    ASSERT_THROW_INNER_ERROR(nativeResultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED,
        "nativeResultSet is nullptr", (make_holder<ResultSetImpl, ResultSet>()));
    return make_holder<ResultSetImpl, ResultSet>(nativeResultSet);
}

LiteResultSet TransactionImpl::QueryWithoutRowCountSync(
    weak::RdbPredicates predicates, optional_view<array<string>> columns)
{
    auto transaction = GetResource();
    ASSERT_THROW_INNER_ERROR(transaction != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED,
        "nativeTransaction_ is nullptr", (make_holder<LiteResultSetImpl, LiteResultSet>()));
    std::vector<std::string> columnNames;
    if (columns.has_value()) {
        columnNames = std::vector<std::string>(columns.value().begin(), columns.value().end());
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    ASSERT_THROW_INNER_ERROR(rdbPredicateNative != nullptr, OHOS::NativeRdb::E_ERROR, "",
        (make_holder<LiteResultSetImpl, LiteResultSet>()));
    DistributedRdb::QueryOptions options{ .preCount = false, .isGotoNextRowReturnLastError = true };
    auto nativeResultSet = transaction->QueryByStep(*rdbPredicateNative, columnNames, options);
    ASSERT_THROW_INNER_ERROR(nativeResultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED,
        "nativeResultSet is nullptr", (make_holder<LiteResultSetImpl, LiteResultSet>()));
    return make_holder<LiteResultSetImpl, LiteResultSet>(nativeResultSet);
}

LiteResultSet TransactionImpl::QuerySqlWithoutRowCountSync(string_view sql, optional_view<array<ValueType>> args)
{
    auto transaction = GetResource();
    ASSERT_THROW_INNER_ERROR(transaction != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED,
        "nativeTransaction_ is nullptr", (make_holder<LiteResultSetImpl, LiteResultSet>()));
    ASSERT_THROW_INNER_ERROR(
        !sql.empty(), OHOS::NativeRdb::E_INVALID_ARGS_NEW, "", (make_holder<LiteResultSetImpl, LiteResultSet>()));
    std::vector<OHOS::NativeRdb::ValueObject> para;
    if (args.has_value()) {
        para.resize(args.value().size());
        std::transform(args.value().begin(), args.value().end(), para.begin(),
            [](const ValueType &valueType) { return ani_rdbutils::ValueTypeToNative(valueType); });
    }
    DistributedRdb::QueryOptions options{ .preCount = false, .isGotoNextRowReturnLastError = true };
    auto nativeResultSet = transaction->QueryByStep(std::string(sql), para, options);
    ASSERT_THROW_INNER_ERROR(nativeResultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED,
        "nativeResultSet is nullptr", (make_holder<LiteResultSetImpl, LiteResultSet>()));
    return make_holder<LiteResultSetImpl, LiteResultSet>(nativeResultSet);
}

ValueType TransactionImpl::ExecuteSync(string_view sql, optional_view<array<ValueType>> args)
{
    ValueType aniValue = ::ohos::data::relationalStore::ValueType::make_EMPTY();
    auto transaction = GetResource();
    ASSERT_THROW_INNER_ERROR(
        transaction != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "nativeTransaction_ is nullptr", aniValue);
    std::vector<OHOS::NativeRdb::ValueObject> para;
    if (args.has_value()) {
        para.resize(args.value().size());
        std::transform(args.value().begin(), args.value().end(), para.begin(),
            [](const ValueType &valueType) { return ani_rdbutils::ValueTypeToNative(valueType); });
    }
    auto [errCode, nativeValue] = transaction->Execute(std::string(sql), para);
    CHECK_ERRCODE_THROW_INNER_ERROR(errCode, transaction->GetLastErrorMsg(), aniValue);
    return ani_rdbutils::ValueObjectToAni(nativeValue);
}

Result TransactionImpl::BatchInsertWithReturningSync(string_view table, array_view<ValuesBucket> values,
    ReturningConfig const &config, optional_view<ConflictResolution> conflict)
{
    return BatchInsertWithReturning(GetResource(), table, values, config, conflict);
}

Result TransactionImpl::UpdateWithReturningSync(ValuesBucket values, weak::RdbPredicates predicates,
    ReturningConfig const &config, optional_view<ConflictResolution> conflict)
{
    return UpdateWithReturning(GetResource(), values, predicates, config, conflict);
}

Result TransactionImpl::DeleteWithReturningSync(weak::RdbPredicates predicates, ReturningConfig const &config)
{
    return DeleteWithReturning(GetResource(), predicates, config);
}

int64_t TransactionImpl::BatchInsertWithConflictResolutionSync(taihe::string_view table,
    taihe::array_view<ohos::data::relationalStore::ValuesBucket> values,
    ohos::data::relationalStore::ConflictResolution conflict)
{
    auto transaction = GetResource();
    ASSERT_THROW_INNER_ERROR(
        transaction != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "nativeTransaction_ is nullptr", ERR_NULL);
    OHOS::NativeRdb::ValuesBuckets buckets;
    for (const auto &valuesBucket : values) {
        buckets.Put(ani_rdbutils::MapValuesToNative(
            valuesBucket.get_ref<ohos::data::relationalStore::ValuesBucket::tag_t::VALUESBUCKET>()));
    }
    ASSERT_THROW_PARAM_ERROR(
        !ani_rdbutils::HasDuplicateAssets(buckets), "Duplicate assets are not allowed", "", ERR_NULL);
    ConflictResolution conflictResolution = ConflictResolution::key_t::ON_CONFLICT_NONE;
    conflictResolution = conflict.get_key();
    auto [errCode, insertRows] =
        transaction->BatchInsert(std::string(table), buckets, ani_rdbutils::ConflictResolutionToNative(conflict));
    CHECK_ERRCODE_THROW_INNER_ERROR(errCode, transaction->GetLastErrorMsg(), insertRows);
    return insertRows;
}
} // namespace RdbTaihe
} // namespace OHOS
