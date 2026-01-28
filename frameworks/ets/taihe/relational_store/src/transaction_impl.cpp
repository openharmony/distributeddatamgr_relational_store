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
#include "lite_result_set_impl.h"
#include "ohos.data.relationalStore.impl.h"
#include "ohos.data.relationalStore.proj.hpp"
#include "rdb_predicates_impl.h"
#include "result_set_impl.h"
#include "transaction_impl.h"

namespace OHOS {
namespace RdbTaihe {

TransactionImpl::TransactionImpl()
{
}
TransactionImpl::TransactionImpl(std::shared_ptr<OHOS::NativeRdb::Transaction> transaction)
{
    nativeTransaction_ = transaction;
}

void TransactionImpl::CommitSync()
{
    ASSERT_RETURN_THROW_ERROR(nativeTransaction_ != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED,
            "nativeTransaction_ is nullptr"), RDB_DO_NOTHING);
    auto errCode = nativeTransaction_->Commit();
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void TransactionImpl::RollbackSync()
{
    ASSERT_RETURN_THROW_ERROR(nativeTransaction_ != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED,
            "nativeTransaction_ is nullptr"), RDB_DO_NOTHING);
    auto errCode = nativeTransaction_->Rollback();
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

int64_t TransactionImpl::InsertSync(
    string_view table, map_view<::taihe::string, ValueType> values, optional_view<ConflictResolution> conflict)
{
    ASSERT_RETURN_THROW_ERROR(nativeTransaction_ != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED,
            "nativeTransaction_ is nullptr"), ERR_NULL);
    ConflictResolution conflictResolution = ConflictResolution::key_t::ON_CONFLICT_NONE;
    if (conflict.has_value()) {
        conflictResolution = conflict.value().get_key();
    }
    OHOS::NativeRdb::ValuesBucket bucket = ani_rdbutils::MapValuesToNative(values);
    auto nativeConflictValue = (OHOS::NativeRdb::ConflictResolution)conflictResolution.get_key();
    auto [errCode, output] = nativeTransaction_->Insert(std::string(table), bucket, nativeConflictValue);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return output;
    }
    return output;
}

int64_t TransactionImpl::BatchInsertSync(string_view table, array_view<map<string, ValueType>> values)
{
    ASSERT_RETURN_THROW_ERROR(nativeTransaction_ != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED,
            "nativeTransaction_ is nullptr"), ERR_NULL);
    OHOS::NativeRdb::ValuesBuckets buckets = ani_rdbutils::BucketValuesToNative(values);
    if (ani_rdbutils::HasDuplicateAssets(buckets)) {
        ThrowParamError("Duplicate assets are not allowed");
        return ERR_NULL;
    }
    auto [errCode, output] = nativeTransaction_->BatchInsert(std::string(table), buckets);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return output;
    }
    return output;
}

int64_t TransactionImpl::UpdateSync(
    map_view<string, ValueType> values, weak::RdbPredicates predicates, optional_view<ConflictResolution> conflict)
{
    ASSERT_RETURN_THROW_ERROR(nativeTransaction_ != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED,
            "nativeTransaction_ is nullptr"), ERR_NULL);
    ConflictResolution conflictResolution = ConflictResolution::key_t::ON_CONFLICT_NONE;
    if (conflict.has_value()) {
        conflictResolution = conflict.value().get_key();
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return ERR_NULL;
    }
    OHOS::NativeRdb::ValuesBucket bucket = ani_rdbutils::MapValuesToNative(values);
    auto nativeConflictValue = (OHOS::NativeRdb::ConflictResolution)conflictResolution.get_key();
    auto [errCode, rows] = nativeTransaction_->Update(bucket, *rdbPredicateNative, nativeConflictValue);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return rows;
    }
    return rows;
}

int64_t TransactionImpl::DeleteSync(weak::RdbPredicates predicates)
{
    ASSERT_RETURN_THROW_ERROR(nativeTransaction_ != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED,
            "nativeTransaction_ is nullptr"), ERR_NULL);
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return ERR_NULL;
    }
    auto [errCode, rows] = nativeTransaction_->Delete(*rdbPredicateNative);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return rows;
    }
    return rows;
}

ResultSet TransactionImpl::QuerySync(weak::RdbPredicates predicates, optional_view<array<string>> columns)
{
    ASSERT_RETURN_THROW_ERROR(nativeTransaction_ != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED,
            "nativeTransaction_ is nullptr"), (make_holder<ResultSetImpl, ResultSet>()));
    std::vector<std::string> stdcolumns;
    if (columns.has_value()) {
        stdcolumns = std::vector<std::string>(columns.value().begin(), columns.value().end());
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return make_holder<ResultSetImpl, ResultSet>();
    }
    auto nativeResultSet = nativeTransaction_->QueryByStep(*rdbPredicateNative, stdcolumns);
    if (nativeResultSet == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return make_holder<ResultSetImpl, ResultSet>();
    }
    return make_holder<ResultSetImpl, ResultSet>(nativeResultSet);
}

ResultSet TransactionImpl::QuerySqlSync(string_view sql, optional_view<array<ValueType>> args)
{
    ASSERT_RETURN_THROW_ERROR(nativeTransaction_ != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED,
            "nativeTransaction_ is nullptr"), (make_holder<ResultSetImpl, ResultSet>()));
    std::vector<OHOS::NativeRdb::ValueObject> para;
    if (args.has_value()) {
        std::transform(args.value().begin(), args.value().end(), std::back_inserter(para),
            [](const ValueType &valueType) { return ani_rdbutils::ValueTypeToNative(valueType); });
    }
    auto nativeResultSet = nativeTransaction_->QueryByStep(std::string(sql), para);
    if (nativeResultSet == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return make_holder<ResultSetImpl, ResultSet>();
    }
    return make_holder<ResultSetImpl, ResultSet>(nativeResultSet);
}

LiteResultSet TransactionImpl::QueryWithoutRowCountSync(weak::RdbPredicates predicates,
    optional_view<array<string>> columns)
{
    ASSERT_RETURN_THROW_ERROR(nativeTransaction_ != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED,
            "nativeTransaction_ is nullptr"), (make_holder<LiteResultSetImpl, LiteResultSet>()));
    std::vector<std::string> columnNames;
    if (columns.has_value()) {
        columnNames = std::vector<std::string>(columns.value().begin(), columns.value().end());
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return make_holder<LiteResultSetImpl, LiteResultSet>();
    }
    DistributedRdb::QueryOptions options{.preCount = false, .isGotoNextRowReturnLastError = true};
    auto nativeResultSet = nativeTransaction_->QueryByStep(*rdbPredicateNative, columnNames, options);
    if (nativeResultSet == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return make_holder<LiteResultSetImpl, LiteResultSet>();
    }
    return make_holder<LiteResultSetImpl, LiteResultSet>(nativeResultSet);
}

LiteResultSet TransactionImpl::QuerySqlWithoutRowCountSync(string_view sql, optional_view<array<ValueType>> args)
{
    ASSERT_RETURN_THROW_ERROR(nativeTransaction_ != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED,
            "nativeTransaction_ is nullptr"), (make_holder<LiteResultSetImpl, LiteResultSet>()));
    if (sql.empty()) {
        LOG_ERROR("sql is empty");
        ThrowInnerError(OHOS::NativeRdb::E_INVALID_ARGS_NEW);
        return make_holder<LiteResultSetImpl, LiteResultSet>();
    }
    std::vector<OHOS::NativeRdb::ValueObject> para;
    if (args.has_value()) {
        para.resize(args.value().size());
        std::transform(args.value().begin(), args.value().end(), para.begin(),
            [](const ValueType &valueType) { return ani_rdbutils::ValueTypeToNative(valueType); });
    }
    DistributedRdb::QueryOptions options{.preCount = false, .isGotoNextRowReturnLastError = true};
    auto nativeResultSet = nativeTransaction_->QueryByStep(std::string(sql), para, options);
    if (nativeResultSet == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return make_holder<LiteResultSetImpl, LiteResultSet>();
    }
    return make_holder<LiteResultSetImpl, LiteResultSet>(nativeResultSet);
}

ValueType TransactionImpl::ExecuteSync(string_view sql, optional_view<array<ValueType>> args)
{
    ValueType aniValue = ::ohos::data::relationalStore::ValueType::make_EMPTY();
    ASSERT_RETURN_THROW_ERROR(nativeTransaction_ != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED,
            "nativeTransaction_ is nullptr"), aniValue);
    std::vector<OHOS::NativeRdb::ValueObject> para;
    if (args.has_value()) {
        para.resize(args.value().size());
        std::transform(args.value().begin(), args.value().end(), para.begin(),
            [](const ValueType &valueType) { return ani_rdbutils::ValueTypeToNative(valueType); });
    }
    auto [errCode, nativeValue] = nativeTransaction_->Execute(std::string(sql), para);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return aniValue;
    }
    return ani_rdbutils::ValueObjectToAni(nativeValue);
}

Result TransactionImpl::BatchInsertWithReturningSync(string_view table, array_view<ValuesBucket> values,
    ReturningConfig const &config, optional_view<ConflictResolution> conflict)
{
    return BatchInsertWithReturning(nativeTransaction_, table, values, config, conflict);
}

Result TransactionImpl::UpdateWithReturningSync(ValuesBucket values, weak::RdbPredicates predicates,
    ReturningConfig const &config, optional_view<ConflictResolution> conflict)
{
    return UpdateWithReturning(nativeTransaction_, values, predicates, config, conflict);
}

Result TransactionImpl::DeleteWithReturningSync(weak::RdbPredicates predicates, ReturningConfig const &config)
{
    return DeleteWithReturning(nativeTransaction_, predicates, config);
}

int64_t TransactionImpl::BatchInsertWithConflictResolutionSync(taihe::string_view table,
    taihe::array_view<ohos::data::relationalStore::ValuesBucket> values,
    ohos::data::relationalStore::ConflictResolution conflict)
{
    ASSERT_RETURN_THROW_ERROR(nativeTransaction_ != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED,
            "nativeTransaction_ is nullptr"), ERR_NULL);
    OHOS::NativeRdb::ValuesBuckets buckets;
    for (const auto &valuesBucket : values) {
        buckets.Put(ani_rdbutils::MapValuesToNative(
            valuesBucket.get_ref<ohos::data::relationalStore::ValuesBucket::tag_t::VALUESBUCKET>()));
    }
    if (ani_rdbutils::HasDuplicateAssets(buckets)) {
        ThrowParamError("Duplicate assets are not allowed");
        return ERR_NULL;
    }
    ConflictResolution conflictResolution = ConflictResolution::key_t::ON_CONFLICT_NONE;
    conflictResolution = conflict.get_key();
    auto [errCode, insertRows] = nativeTransaction_->BatchInsert(std::string(table),
        buckets, ani_rdbutils::ConflictResolutionToNative(conflict));
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return ERR_NULL;
    }
    return insertRows;
}
}
}