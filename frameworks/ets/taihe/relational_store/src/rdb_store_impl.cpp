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

#define LOG_TAG "RdbStoreImpl"
#include "rdb_store_impl.h"

#include <future>
#include <memory>

#include "ani.h"
#include "ani_async_call.h"
#include "ani_rdb_utils.h"
#include "ani_utils.h"
#include "datashare_abs_predicates.h"
#include "lite_result_set_impl.h"
#include "napi_rdb_error.h"
#include "ohos.data.relationalStore.impl.h"
#include "ohos.data.relationalStore.proj.hpp"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_perfStat.h"
#include "rdb_predicates_impl.h"
#include "rdb_result_set_bridge.h"
#include "rdb_sql_log.h"
#include "rdb_sql_statistic.h"
#include "rdb_store_config.h"
#include "rdb_utils.h"
#include "result_set_impl.h"
#include "taihe_log_observer.h"
#include "taihe_rdb_store_observer.h"
#include "taihe_sql_observer.h"
#include "taihe_sync_observer.h"
#include "transaction_impl.h"

namespace OHOS {
namespace RdbTaihe {
static constexpr int WAIT_TIME_DEFAULT = 2;
static constexpr int WAIT_TIME_MIN = 1;
static constexpr int WAIT_TIME_MAX = 300;

class DefaultOpenCallback : public OHOS::NativeRdb::RdbOpenCallback {
public:
    int OnCreate(OHOS::NativeRdb::RdbStore &rdbStore) override
    {
        return OHOS::NativeRdb::E_OK;
    }
    int OnUpgrade(OHOS::NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override
    {
        return OHOS::NativeRdb::E_OK;
    }
};

RdbStoreImpl::RdbStoreImpl()
{
}

RdbStoreImpl::RdbStoreImpl(ani_object context, StoreConfig const &config)
{
    ani_env *env = get_env();
    OHOS::AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig = ani_rdbutils::AniGetRdbConfig(config);
    auto configRet = ani_rdbutils::AniGetRdbStoreConfig(env, context, rdbConfig);
    isSystemApp_ = rdbConfig.isSystemApp;
    DefaultOpenCallback callback;
    int errCode = OHOS::AppDataMgrJsKit::JSUtils::OK;
    if (!configRet.first) {
        LOG_ERROR("AniGetRdbStoreConfig failed, use default config");
        std::string dir = "/data/storage/el2/database/rdb";
        std::string path = dir + "/" + std::string(config.name);
        OHOS::NativeRdb::RdbStoreConfig storeConfig(path);
        OHOS::NativeRdb::RdbSqlUtils::CreateDirectory(dir);
        nativeRdbStore_ = OHOS::NativeRdb::RdbHelper::GetRdbStore(storeConfig, -1, callback, errCode);
    } else {
        nativeRdbStore_ = OHOS::NativeRdb::RdbHelper::GetRdbStore(configRet.second, -1, callback, errCode);
    }
    if (errCode != OHOS::AppDataMgrJsKit::JSUtils::OK) {
        ThrowInnerError(errCode);
        nativeRdbStore_ = nullptr;
        LOG_ERROR("GetRdbStore failed");
        return;
    }
    LOG_INFO("GetRdbStore success");
}

int32_t RdbStoreImpl::GetVersion()
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return ERR_NULL;
    }
    int32_t version = 0;
    int errCode = nativeRdbStore_->GetVersion(version);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
    return version;
}

void RdbStoreImpl::SetVersion(int32_t veriosn)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    int errCode = nativeRdbStore_->SetVersion(veriosn);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

RebuildType RdbStoreImpl::GetRebuilt()
{
    OHOS::NativeRdb::RebuiltType rebuilt = OHOS::NativeRdb::RebuiltType::NONE;
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return (RebuildType::key_t)rebuilt;
    }
    int errCode = nativeRdbStore_->GetRebuilt(rebuilt);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
    return (RebuildType::key_t)rebuilt;
}

void RdbStoreImpl::SetRebuilt(RebuildType type)
{
    TH_THROW(std::runtime_error, "setRebuilt not implemented");
}

int64_t RdbStoreImpl::InsertWithConflict(string_view table, map_view<string, ValueType> values,
    ConflictResolution conflict)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return ERR_NULL;
    }

    int64_t int64Output = 0;
    OHOS::NativeRdb::ValuesBucket bucket = ani_rdbutils::MapValuesToNative(values);
    if (ani_rdbutils::HasDuplicateAssets(bucket)) {
        ThrowParamError("Duplicate assets are not allowed");
        return ERR_NULL;
    }

    int errCode = nativeRdbStore_->InsertWithConflictResolution(
        int64Output, std::string(table), bucket, (OHOS::NativeRdb::ConflictResolution)conflict.get_key());
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return 0;
    }
    return int64Output;
}

int64_t RdbStoreImpl::InsertWithValue(string_view table, map_view<string, ValueType> values)
{
    return InsertWithConflict(table, values, ConflictResolution::key_t::ON_CONFLICT_NONE);
}

int64_t RdbStoreImpl::InsertSync(
    string_view table, map_view<string, ValueType> values, optional_view<ConflictResolution> conflict)
{
    ConflictResolution conflictResolution = ConflictResolution::key_t::ON_CONFLICT_NONE;
    if (conflict.has_value()) {
        conflictResolution = conflict.value().get_key();
    }
    return InsertWithConflict(table, values, conflictResolution);
}

int64_t RdbStoreImpl::BatchInsertSync(string_view table, array_view<map<string, ValueType>> values)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return ERR_NULL;
    }
    OHOS::NativeRdb::ValuesBuckets buckets = ani_rdbutils::BucketValuesToNative(values);
    if (ani_rdbutils::HasDuplicateAssets(buckets)) {
        ThrowParamError("Duplicate assets are not allowed");
        return ERR_NULL;
    }
    auto [errCode, output] = nativeRdbStore_->BatchInsert(std::string(table), buckets);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return output;
    }
    return output;
}

int64_t RdbStoreImpl::UpdateWithPredicate(map_view<string, ValueType> values, weak::RdbPredicates predicates)
{
    optional<ConflictResolution> emptyConflict;
    return UpdateSync(values, predicates, emptyConflict);
}

int64_t RdbStoreImpl::UpdateSync(
    map_view<string, ValueType> values, weak::RdbPredicates predicates, optional_view<ConflictResolution> conflict)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return ERR_NULL;
    }
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
    int output = 0;
    int errCode = nativeRdbStore_->UpdateWithConflictResolution(output, rdbPredicateNative->GetTableName(), bucket,
        rdbPredicateNative->GetWhereClause(), rdbPredicateNative->GetBindArgs(), nativeConflictValue);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return ERR_NULL;
    }
    return output;
}

int64_t RdbStoreImpl::UpdateDataShareSync(
    ::taihe::string_view table, ::ohos::data::relationalStore::ValuesBucket const &values, uintptr_t predicates)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return ERR_NULL;
    }
    if (!isSystemApp_) {
        ThrowNonSystemError();
        return ERR_NULL;
    }
    ani_env *env = get_env();
    ani_object object = reinterpret_cast<ani_object>(predicates);
    OHOS::DataShare::DataShareAbsPredicates *holder =
        ani_utils::AniObjectUtils::Unwrap<OHOS::DataShare::DataShareAbsPredicates>(env, object);
    if (holder == nullptr) {
        LOG_ERROR("UpdateDataShareSync, holder is nullptr");
        return 0;
    }
    auto rdbPredicates = OHOS::RdbDataShareAdapter::RdbUtils::ToPredicates(*holder, std::string(table));
    OHOS::NativeRdb::ValuesBucket bucket = ani_rdbutils::MapValuesToNative(values.get_VALUESBUCKET_ref());

    int output = 0;
    int errCode = nativeRdbStore_->UpdateWithConflictResolution(output, rdbPredicates.GetTableName(), bucket,
        rdbPredicates.GetWhereClause(), rdbPredicates.GetBindArgs(),
        OHOS::NativeRdb::ConflictResolution::ON_CONFLICT_NONE);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return ERR_NULL;
    }
    return output;
}

int64_t RdbStoreImpl::DeleteSync(weak::RdbPredicates predicates)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return ERR_NULL;
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return ERR_NULL;
    }
    int output = 0;
    int errCode = nativeRdbStore_->Delete(output, *rdbPredicateNative);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return 0;
    }
    return output;
}

int64_t RdbStoreImpl::DeleteDataShareSync(::taihe::string_view table, uintptr_t predicates)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return ERR_NULL;
    }
    if (!isSystemApp_) {
        ThrowNonSystemError();
        return ERR_NULL;
    }
    ani_env *env = get_env();
    ani_object object = reinterpret_cast<ani_object>(predicates);
    OHOS::DataShare::DataShareAbsPredicates *holder =
        ani_utils::AniObjectUtils::Unwrap<OHOS::DataShare::DataShareAbsPredicates>(env, object);
    if (holder == nullptr) {
        LOG_ERROR("DeleteDataShareSync, holder is nullptr");
        return 0;
    }
    auto rdbPredicates = OHOS::RdbDataShareAdapter::RdbUtils::ToPredicates(*holder, std::string(table));
    int output = 0;
    int errCode = nativeRdbStore_->Delete(output, rdbPredicates);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return 0;
    }
    return output;
}

ResultSet RdbStoreImpl::QueryWithPredicate(weak::RdbPredicates predicates)
{
    optional_view<array<string>> empty;
    return QuerySync(predicates, empty);
}

ResultSet RdbStoreImpl::QueryWithColumn(weak::RdbPredicates predicates, array_view<string> columns)
{
    return QuerySync(predicates, optional<array<string>>::make(columns));
}

ResultSet RdbStoreImpl::QueryWithOptionalColumn(weak::RdbPredicates predicates, optional_view<array<string>> columns)
{
    return QuerySync(predicates, columns);
}

ResultSet RdbStoreImpl::QuerySync(weak::RdbPredicates predicates, optional_view<array<string>> columns)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return make_holder<ResultSetImpl, ResultSet>();
    }
    std::vector<std::string> stdcolumns;
    if (columns.has_value()) {
        stdcolumns = std::vector<std::string>(columns.value().begin(), columns.value().end());
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return make_holder<ResultSetImpl, ResultSet>();
    }
    auto nativeResultSet = nativeRdbStore_->Query(*rdbPredicateNative, stdcolumns);
    return make_holder<ResultSetImpl, ResultSet>(nativeResultSet);
}

LiteResultSet RdbStoreImpl::QueryWithoutRowCountSync(weak::RdbPredicates predicates,
    optional_view<array<string>> columns)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return make_holder<LiteResultSetImpl, LiteResultSet>();
    }
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
    auto nativeResultSet = nativeRdbStore_->QueryByStep(*rdbPredicateNative, columnNames, options);
    return make_holder<LiteResultSetImpl, LiteResultSet>(nativeResultSet);
}

LiteResultSet RdbStoreImpl::QuerySqlWithoutRowCountSync(string_view sql, optional_view<array<ValueType>> bindArgs)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return taihe::make_holder<LiteResultSetImpl, LiteResultSet>();
    }
    if (sql.empty()) {
        LOG_ERROR("sql is empty");
        ThrowInnerError(OHOS::NativeRdb::E_INVALID_ARGS_NEW);
        return make_holder<LiteResultSetImpl, LiteResultSet>();
    }
    std::vector<OHOS::NativeRdb::ValueObject> para;
    if (bindArgs.has_value()) {
        para.resize(bindArgs.value().size());
        std::transform(bindArgs.value().begin(), bindArgs.value().end(), para.begin(),
            [](const ValueType &valueType) { return ani_rdbutils::ValueTypeToNative(valueType); });
    }
    std::shared_ptr<OHOS::NativeRdb::ResultSet> nativeResultSet = nullptr;
    DistributedRdb::QueryOptions options{.preCount = false, .isGotoNextRowReturnLastError = true};
    nativeResultSet = nativeRdbStore_->QueryByStep(std::string(sql), para, options);
    return make_holder<LiteResultSetImpl, LiteResultSet>(nativeResultSet);
}

ResultSet RdbStoreImpl::QueryDataShareSync(::taihe::string_view table, uintptr_t predicates)
{
    if (!isSystemApp_) {
        ThrowNonSystemError();
        return taihe::make_holder<ResultSetImpl, ResultSet>();
    }
    optional_view<array<::taihe::string>> empty;
    return QueryDataShareWithColumnSync(table, predicates, empty);
}

ResultSet RdbStoreImpl::QueryDataShareWithColumnSync(
    string_view table, uintptr_t predicates, optional_view<array<::taihe::string>> columns)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return taihe::make_holder<ResultSetImpl, ResultSet>();
    }
    if (!isSystemApp_) {
        ThrowNonSystemError();
        return taihe::make_holder<ResultSetImpl, ResultSet>();
    }
    ani_env *env = get_env();
    ani_object object = reinterpret_cast<ani_object>(predicates);
    OHOS::DataShare::DataShareAbsPredicates *holder =
        ani_utils::AniObjectUtils::Unwrap<OHOS::DataShare::DataShareAbsPredicates>(env, object);
    if (holder == nullptr) {
        LOG_ERROR("QueryDataShareSync, holder is nullptr");
        return taihe::make_holder<ResultSetImpl, ResultSet>();
    }
    std::vector<std::string> stdcolumns;
    if (columns.has_value()) {
        stdcolumns = std::vector<std::string>(columns.value().begin(), columns.value().end());
    }
    auto rdbPredicates = OHOS::RdbDataShareAdapter::RdbUtils::ToPredicates(*holder, std::string(table));
    auto nativeResultSet = nativeRdbStore_->Query(rdbPredicates, stdcolumns);
    return taihe::make_holder<ResultSetImpl, ResultSet>(nativeResultSet);
}

ResultSet RdbStoreImpl::QuerySqlWithSql(string_view sql)
{
    optional_view<array<ValueType>> empty;
    return QuerySqlSync(sql, empty);
}

ResultSet RdbStoreImpl::QuerySqlWithArgs(string_view sql, array_view<ValueType> bindArgs)
{
    return QuerySqlSync(sql, optional<array<ValueType>>::make(bindArgs));
}

ResultSet RdbStoreImpl::QuerySqlSync(string_view sql, optional_view<array<ValueType>> bindArgs)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return taihe::make_holder<ResultSetImpl, ResultSet>();
    }
    std::vector<OHOS::NativeRdb::ValueObject> para;
    if (bindArgs.has_value()) {
        std::transform(bindArgs.value().begin(), bindArgs.value().end(), std::back_inserter(para),
            [](const ValueType &valueType) { return ani_rdbutils::ValueTypeToNative(valueType); });
    }
    std::shared_ptr<OHOS::NativeRdb::ResultSet> nativeResultSet = nullptr;
    if (nativeRdbStore_->GetDbType() == OHOS::NativeRdb::DB_VECTOR) {
        nativeResultSet = nativeRdbStore_->QueryByStep(std::string(sql), para);
    } else {
#if defined(CROSS_PLATFORM)
        nativeResultSet = nativeRdbStore_->QueryByStep(std::string(sql), para);
#else
        nativeResultSet = nativeRdbStore_->QuerySql(std::string(sql), para);
#endif
    }
    return make_holder<ResultSetImpl, ResultSet>(nativeResultSet);
}

ModifyTime RdbStoreImpl::GetModifyTimeSync(
    string_view table, string_view columnName, array_view<PRIKeyType> primaryKeys)
{
    ModifyTime result = ModifyTime::make_MODIFYTIME();
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return result;
    }
    // Convert parameters to the types required by nativeRdbStore_
    std::string nativeTable(table);
    std::string nativeColumnName(columnName);
    std::vector<OHOS::DistributedRdb::RdbStoreObserver::PrimaryKey> nativePrimaryKeys;

    std::transform(
        primaryKeys.begin(), primaryKeys.end(), std::back_inserter(nativePrimaryKeys), [](const PRIKeyType &c) {
            OHOS::DistributedRdb::RdbStoreObserver::PrimaryKey obj = ani_rdbutils::PRIKeyToNative(c);
            return obj;
        });
    // Assume that nativeRdbStore_ has a GetModifyTime method
    // Replace it with the actual method name and parameters
    std::map<OHOS::NativeRdb::RdbStore::PRIKey, OHOS::NativeRdb::RdbStore::Date> mapResult =
        nativeRdbStore_->GetModifyTime(nativeTable, nativeColumnName, nativePrimaryKeys);
    if (mapResult.empty()) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return result;
    }
    return ani_rdbutils::ToAniModifyTime(mapResult);
}

void RdbStoreImpl::CleanDirtyDataWithCursor(string_view table, uint64_t cursor)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    std::string nativeTable(table);
    int32_t errCode = nativeRdbStore_->CleanDirtyData(nativeTable, cursor);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::CleanDirtyDataWithTable(string_view table)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    std::string nativeTable(table);
    int32_t errCode = nativeRdbStore_->CleanDirtyData(nativeTable, 0);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::CleanDirtyDataWithOptionCursor(string_view table, optional_view<uint64_t> cursor)
{
    if (cursor.has_value()) {
        CleanDirtyDataWithCursor(table, cursor.value());
    } else {
        CleanDirtyDataWithTable(table);
    }
}

ResultSet RdbStoreImpl::QuerySharingResourceWithOptionColumn(weak::RdbPredicates predicates,
    optional_view<array<string>> columns)
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(errCode);
        return make_holder<ResultSetImpl, ResultSet>();
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return make_holder<ResultSetImpl, ResultSet>();
    }
    OHOS::NativeRdb::RdbStore::Fields fields;
    if (columns.has_value()) {
        for (const auto &column : columns.value()) {
            fields.push_back(std::string(column));
        }
    }
    auto status = OHOS::NativeRdb::E_ERROR;
    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSetNative;
    std::tie(status, resultSetNative) = nativeRdbStore_->QuerySharingResource(*rdbPredicateNative, fields);
    if (status != OHOS::NativeRdb::E_OK || resultSetNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
    }
    return make_holder<ResultSetImpl, ResultSet>(resultSetNative);
}

ResultSet RdbStoreImpl::QuerySharingResourceWithPredicate(weak::RdbPredicates predicates)
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(errCode);
        return make_holder<ResultSetImpl, ResultSet>();
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return make_holder<ResultSetImpl, ResultSet>();
    }
    OHOS::NativeRdb::RdbStore::Fields fields;
    auto status = OHOS::NativeRdb::E_ERROR;
    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSetNative;
    std::tie(status, resultSetNative) = nativeRdbStore_->QuerySharingResource(*rdbPredicateNative, fields);
    if (status != OHOS::NativeRdb::E_OK || resultSetNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
    }
    return make_holder<ResultSetImpl, ResultSet>(resultSetNative);
}

ResultSet RdbStoreImpl::QuerySharingResourceWithColumn(weak::RdbPredicates predicates, array_view<string> columns)
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(errCode);
        return make_holder<ResultSetImpl, ResultSet>();
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return make_holder<ResultSetImpl, ResultSet>();
    }
    OHOS::NativeRdb::RdbStore::Fields fields;
    for (const auto &column : columns) {
        fields.push_back(std::string(column));
    }
    auto status = OHOS::NativeRdb::E_ERROR;
    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSetNative;
    std::tie(status, resultSetNative) = nativeRdbStore_->QuerySharingResource(*rdbPredicateNative, fields);
    if (status != OHOS::NativeRdb::E_OK || resultSetNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
    }
    return make_holder<ResultSetImpl, ResultSet>(resultSetNative);
}

void RdbStoreImpl::ExecuteSqlWithSql(string_view sql)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    int errCode = nativeRdbStore_->ExecuteSql(std::string(sql));
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::ExecuteSqlWithArgs(string_view sql, array_view<ValueType> bindArgs)
{
    ExecuteSqlWithOptionArgs(sql, optional<array<ValueType>>::make(bindArgs));
}

void RdbStoreImpl::ExecuteSqlWithOptionArgs(string_view sql, optional_view<array<ValueType>> bindArgs)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    if (!bindArgs.has_value()) {
        int errCode = nativeRdbStore_->ExecuteSql(std::string(sql));
        if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
        return;
    }
    array<ValueType> const &value = bindArgs.value();
    std::vector<OHOS::NativeRdb::ValueObject> para;
    std::transform(value.begin(), value.end(), std::back_inserter(para),
        [](const ValueType &valueType) { return ani_rdbutils::ValueTypeToNative(valueType); });
    if (ani_rdbutils::HasDuplicateAssets(para)) {
        ThrowParamError("Duplicate assets are not allowed");
        return;
    }
    int errCode = nativeRdbStore_->ExecuteSql(std::string(sql), para);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

ValueType RdbStoreImpl::ExecuteWithOptionArgs(string_view sql, optional_view<array<ValueType>> args)
{
    ValueType aniValue = ::ohos::data::relationalStore::ValueType::make_EMPTY();
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return aniValue;
    }
    return ExecuteWithTxId(sql, 0, args);
}

ValueType RdbStoreImpl::ExecuteWithTxId(string_view sql, int64_t txId, optional_view<array<ValueType>> args)
{
    ValueType aniValue = ::ohos::data::relationalStore::ValueType::make_EMPTY();
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return aniValue;
    }
    std::vector<OHOS::NativeRdb::ValueObject> nativeValues;
    if (args.has_value()) {
        array_view<ValueType> const &arrayView = args.value();
        nativeValues = ani_rdbutils::ArrayValuesToNative(arrayView);
    }
    if (ani_rdbutils::HasDuplicateAssets(nativeValues)) {
        ThrowParamError("Duplicate assets are not allowed");
        return aniValue;
    }
    auto [errCode, sqlExeOutput] = nativeRdbStore_->Execute(std::string(sql), nativeValues, txId);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return aniValue;
    }
    return ani_rdbutils::ValueObjectToAni(sqlExeOutput);
}

ValueType RdbStoreImpl::ExecuteSync(string_view sql, optional_view<array<ValueType>> args)
{
    return ExecuteWithTxId(sql, 0, args);
}

void RdbStoreImpl::BeginTransaction()
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    int errCode = nativeRdbStore_->BeginTransaction();
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

int64_t RdbStoreImpl::BeginTransSync()
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return ERR_NULL;
    }
    auto [errCode, rxid] = nativeRdbStore_->BeginTrans();
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return 0;
    }
    return rxid;
}

void RdbStoreImpl::Commit()
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    int errCode = nativeRdbStore_->Commit();
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::CommitWithTxId(int64_t txId)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    int errCode = nativeRdbStore_->Commit(txId);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::RollBack()
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    int errCode = nativeRdbStore_->RollBack();
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::RollbackSync(int64_t txId)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    int errCode = nativeRdbStore_->RollBack(txId);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::BackupSync(string_view destName)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    int errCode = nativeRdbStore_->Backup(std::string(destName));
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::RestoreWithSrcName(string_view srcName)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    int errCode = nativeRdbStore_->Restore(std::string(srcName));
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::RestoreWithVoid()
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    int errCode = nativeRdbStore_->Restore("");
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::SetDistributedTablesWithTables(array_view<string> tables)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    int errCode = nativeRdbStore_->SetDistributedTables(std::vector<std::string>(tables.begin(), tables.end()));
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::SetDistributedTablesWithType(array_view<string> tables, DistributedType type)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    int errCode = nativeRdbStore_->SetDistributedTables(
        std::vector<std::string>(tables.begin(), tables.end()), (OHOS::NativeRdb::DistributedType)type.get_key());
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::SetDistributedTablesWithConfig(
    array_view<string> tables, DistributedType type, DistributedConfig const &config)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto nativeConfig = ani_rdbutils::DistributedConfigToNative(config);
    int errCode = nativeRdbStore_->SetDistributedTables(std::vector<std::string>(tables.begin(), tables.end()),
        (OHOS::NativeRdb::DistributedType)type.get_key(), nativeConfig);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::SetDistributedTablesWithOptionConfig(
    array_view<string> tables, optional_view<DistributedType> type, optional_view<DistributedConfig> config)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    std::vector<std::string> tableList(tables.begin(), tables.end());
    OHOS::NativeRdb::DistributedType nativeType = OHOS::NativeRdb::DistributedType::RDB_DEVICE_COLLABORATION;
    OHOS::DistributedRdb::DistributedConfig nativeConfig = { true };
    
    if (type.has_value()) {
        nativeType = static_cast<OHOS::NativeRdb::DistributedType>(type.value().get_key());
    }
    if (config.has_value()) {
        nativeConfig = ani_rdbutils::DistributedConfigToNative(config.value());
    }
    int errCode = nativeRdbStore_->SetDistributedTables(tableList, nativeType, nativeConfig);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

string RdbStoreImpl::ObtainDistributedTableNameSync(string_view device, string_view table)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return "";
    }
    std::string deviceStr(device);
    std::string tableStr(table);
    int errCode;
    std::string distributedTableName = nativeRdbStore_->ObtainDistributedTableName(deviceStr, tableStr, errCode);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return "";
    }
    return distributedTableName;
}

void RdbStoreImpl::Sync(
    SyncMode mode, weak::RdbPredicates predicates, uintptr_t callback, ani_object &promise)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return;
    }
    auto nativeMode = ani_rdbutils::SyncModeToNative(mode);
    if (nativeMode != OHOS::DistributedRdb::SyncMode::PUSH && nativeMode != OHOS::DistributedRdb::SyncMode::PULL) {
        ThrowParamError("mode must be a SyncMode of device.");
        return;
    }
    OHOS::DistributedRdb::SyncOption option{ nativeMode, false };
    std::shared_ptr<AniContext> context = std::make_shared<AniContext>();
    if (!context->Init(callback)) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return;
    }
    promise = context->promise_;
    auto nativeSyncCallback = [context](const OHOS::DistributedRdb::SyncResult &data) {
        {
            ::taihe::env_guard gurd;
            ani_object object = {};
            ani_status status = ani_utils::Convert2AniValue(gurd.get_env(), data, object);
            context->result_ = static_cast<ani_ref>(object);
            if (status != ANI_OK || context->result_ == nullptr) {
                context->error_ = std::make_shared<InnerError>(NativeRdb::E_ERROR);
            }
        }
        AniAsyncCall::ReturnResult(context);
    };
    int errCode = nativeRdbStore_->Sync(option, *rdbPredicateNative, nativeSyncCallback);
    if (errCode != OHOS::NativeRdb::E_OK) {
        context->error_ = std::make_shared<InnerError>(errCode);
        AniAsyncCall::ReturnResult(context);
        return;
    }
}

void RdbStoreImpl::SyncAsync(SyncMode mode, weak::RdbPredicates predicates, uintptr_t callback)
{
    ani_object promise = nullptr;
    Sync(mode, predicates, callback, promise);
}

uintptr_t RdbStoreImpl::SyncPromise(SyncMode mode, weak::RdbPredicates predicates)
{
    ani_object promise = nullptr;
    Sync(mode, predicates, 0, promise);
    return reinterpret_cast<uintptr_t>(promise);
}

void RdbStoreImpl::CloudSyncWithProgress(SyncMode mode, callback_view<void(ProgressDetails const &)> progress)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    OHOS::DistributedRdb::SyncOption option {
        .mode = ani_rdbutils::SyncModeToNative(mode),
        .isBlock = false
    };
    callback<void(ProgressDetails const &)> holder = progress;
    auto nativeProgressCallback =
        [holder](std::map<std::string, OHOS::DistributedRdb::ProgressDetail> &&nativeProgressMap) {
            for (auto &[key, nativeProgress] : nativeProgressMap) {
                auto taiheProgress = ani_rdbutils::ProgressDetailToTaihe(nativeProgress);
                holder(taiheProgress);
            }
        };
    std::vector<std::string> nativeTables;
    int errCode = nativeRdbStore_->Sync(option, nativeTables, nativeProgressCallback);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::CloudSyncWithTable(
    SyncMode mode, array_view<string> tables, callback_view<void(ProgressDetails const &)> progress)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    OHOS::DistributedRdb::SyncOption option {
        .mode = ani_rdbutils::SyncModeToNative(mode),
        .isBlock = false
    };
    std::vector<std::string> nativeTables(tables.begin(), tables.end());
    callback<void(ProgressDetails const &)> holder = progress;
    auto nativeProgressCallback =
        [holder](std::map<std::string, OHOS::DistributedRdb::ProgressDetail> &&nativeProgressMap) {
            for (auto &[key, nativeProgress] : nativeProgressMap) {
                auto taiheProgress = ani_rdbutils::ProgressDetailToTaihe(nativeProgress);
                holder(taiheProgress);
            }
        };
    int errCode = nativeRdbStore_->Sync(option, nativeTables, nativeProgressCallback);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::CloudSyncWithPredicates(
    SyncMode mode, weak::RdbPredicates predicates, callback_view<void(ProgressDetails const &)> progress)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    OHOS::DistributedRdb::SyncOption option {
        .mode = ani_rdbutils::SyncModeToNative(mode),
        .isBlock = false
    };
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return;
    }
    callback<void(ProgressDetails const &)> holder = progress;
    auto nativeProgressCallback =
        [holder](std::map<std::string, OHOS::DistributedRdb::ProgressDetail> &&nativeProgressMap) {
            for (auto &[key, nativeProgress] : nativeProgressMap) {
                auto taiheProgress = ani_rdbutils::ProgressDetailToTaihe(nativeProgress);
                holder(taiheProgress);
            }
        };
    int errCode = nativeRdbStore_->Sync(option, *rdbPredicateNative, nativeProgressCallback);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

ResultSet RdbStoreImpl::RemoteQuerySync(
    string_view device, string_view table, weak::RdbPredicates predicates, array_view<string> columns)
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(errCode);
        return make_holder<ResultSetImpl, ResultSet>();
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return make_holder<ResultSetImpl, ResultSet>();
    }
    OHOS::NativeRdb::RdbStore::Fields fields;
    for (const auto &column : columns) {
        fields.push_back(std::string(column));
    }
    errCode = OHOS::NativeRdb::E_ERROR;
    auto resultSetNative = nativeRdbStore_->RemoteQuery(std::string(device), *rdbPredicateNative, fields, errCode);
    if (resultSetNative == nullptr) {
        ThrowInnerError(errCode);
    }
    return make_holder<ResultSetImpl, ResultSet>(resultSetNative);
}

void RdbStoreImpl::OnDataChangeWithChangeInfo(ohos::data::relationalStore::SubscribeType type,
    taihe::callback_view<void(taihe::array_view<::ohos::data::relationalStore::ChangeInfo> info)> callback,
    uintptr_t opq)
{
    OnDataChangeCommon(ani_rdbutils::SubscribeTypeToMode(type), callback, opq);
}

void RdbStoreImpl::OnDataChangeWithDevices(ohos::data::relationalStore::SubscribeType type,
    taihe::callback_view<void(taihe::array_view<::taihe::string> info)> callback,
    uintptr_t opq)
{
    OnDataChangeCommon(ani_rdbutils::SubscribeTypeToMode(type), callback, opq);
}

void RdbStoreImpl::OffDataChangeInner(ohos::data::relationalStore::SubscribeType type,
    taihe::optional_view<uintptr_t> opq)
{
    OffDataChangeCommon(ani_rdbutils::SubscribeTypeToMode(type), opq);
}

void RdbStoreImpl::OnAutoSyncProgressInner(
    taihe::callback_view<void(ohos::data::relationalStore::ProgressDetails const& info)> callback, uintptr_t opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto subscribeFunc = [this](std::shared_ptr<ani_rdbutils::TaiheSyncObserver> observer)->int32_t {
        auto errCode = nativeRdbStore_->RegisterAutoSyncCallback(observer);
        if (errCode == OHOS::NativeRdb::E_OK) {
            LOG_INFO("RegisterAutoSyncCallback success.");
        } else {
            LOG_ERROR("RegisterAutoSyncCallback failed, %{public}d.", errCode);
        }
        return errCode;
    };
    auto result = rdbObserversData_.OnAutoSyncProgress(callback, opq, subscribeFunc);
    if (result != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("OnAutoSyncProgress failed, %{public}d.", result);
        ThrowInnerError(result);
    }
}

void RdbStoreImpl::OffAutoSyncProgressInner(optional_view<uintptr_t> opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto unSubscribeFunc = [this](std::shared_ptr<ani_rdbutils::TaiheSyncObserver> observer)->int32_t {
        auto errCode = nativeRdbStore_->UnregisterAutoSyncCallback(observer);
        if (errCode == OHOS::NativeRdb::E_OK) {
            LOG_INFO("UnregisterAutoSyncCallback success.");
        } else {
            LOG_ERROR("UnregisterAutoSyncCallback failed, %{public}d.", errCode);
        }
        return errCode;
    };
    std::optional<uintptr_t> opqNative;
    if (opq.has_value()) {
        opqNative = opq.value();
    }
    auto result = rdbObserversData_.OffAutoSyncProgress(opqNative, unSubscribeFunc);
    if (result != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("OffAutoSyncProgress failed, %{public}d.", result);
        ThrowInnerError(result);
    }
}

void RdbStoreImpl::OnStatisticsInner(
    taihe::callback_view<void(ohos::data::relationalStore::SqlExecutionInfo const& info)> callback, uintptr_t opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto subscribeFunc = [this](std::shared_ptr<ani_rdbutils::TaiheSqlObserver> observer)->int32_t {
        auto errCode = DistributedRdb::SqlStatistic::Subscribe(observer);
        if (errCode == OHOS::NativeRdb::E_OK) {
            LOG_INFO("Subscribe success.");
        } else {
            LOG_ERROR("Subscribe failed, %{public}d.", errCode);
        }
        return errCode;
    };
    auto result = rdbObserversData_.OnStatistics(callback, opq, subscribeFunc);
    if (result != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("OnStatistics failed, %{public}d.", result);
        ThrowInnerError(result);
    }
}

void RdbStoreImpl::OffStatisticsInner(optional_view<uintptr_t> opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto unSubscribeFunc = [this](std::shared_ptr<ani_rdbutils::TaiheSqlObserver> observer)->int32_t {
        auto errCode = DistributedRdb::SqlStatistic::Unsubscribe(observer);
        if (errCode == OHOS::NativeRdb::E_OK) {
            LOG_INFO("Unsubscribe success.");
        } else {
            LOG_ERROR("Unsubscribe failed, %{public}d.", errCode);
        }
        return errCode;
    };
    std::optional<uintptr_t> opqNative;
    if (opq.has_value()) {
        opqNative = opq.value();
    }
    auto result = rdbObserversData_.OffStatistics(opqNative, unSubscribeFunc);
    if (result != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("OffStatistics failed, %{public}d.", result);
        ThrowInnerError(result);
    }
}

void RdbStoreImpl::OnCommon(taihe::string_view event, bool interProcess,
    taihe::callback_view<void()> callback, uintptr_t opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto eventNative = std::string(event);
    if (event.empty()) {
        ThrowError(std::make_shared<ParamError>("event", "a not empty string."));
        return;
    }
    auto subscribeMode = OHOS::DistributedRdb::SubscribeMode::LOCAL;
    if (interProcess) {
        subscribeMode = OHOS::DistributedRdb::SubscribeMode::LOCAL_SHARED;
    }
    auto subscribeFunc = [subscribeMode, &eventNative, this](
        std::shared_ptr<ani_rdbutils::TaiheRdbStoreObserver> observer)->int32_t {
        OHOS::DistributedRdb::SubscribeOption option;
        option.mode = subscribeMode;
        option.event = eventNative;
        auto errCode = nativeRdbStore_->Subscribe(option, observer);
        if (errCode == OHOS::NativeRdb::E_OK) {
            LOG_INFO("Subscribe success.");
        } else {
            LOG_ERROR("Subscribe failed, %{public}d.", errCode);
        }
        return errCode;
    };
    auto result = rdbObserversData_.OnCommon(eventNative, subscribeMode, callback, opq, subscribeFunc);
    if (result != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("OnCommon failed, %{public}d.", result);
        ThrowInnerError(result);
    }
}

void RdbStoreImpl::OffCommon(taihe::string_view event, bool interProcess, optional_view<uintptr_t> opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto eventNative = std::string(event);
    if (event.empty()) {
        ThrowError(std::make_shared<ParamError>("event", "a not empty string."));
        return;
    }
    auto subscribeMode = OHOS::DistributedRdb::SubscribeMode::LOCAL;
    if (interProcess) {
        subscribeMode = OHOS::DistributedRdb::SubscribeMode::LOCAL_SHARED;
    }
    auto unSubscribeFunc = [subscribeMode, &eventNative, this](
        std::shared_ptr<ani_rdbutils::TaiheRdbStoreObserver> observer)->int32_t {
        OHOS::DistributedRdb::SubscribeOption option;
        option.mode = subscribeMode;
        option.event = eventNative;
        auto errCode = nativeRdbStore_->UnsubscribeObserver(option, observer);
        if (errCode == OHOS::NativeRdb::E_OK) {
            LOG_INFO("UnsubscribeObserver success.");
        } else {
            LOG_ERROR("UnsubscribeObserver failed, %{public}d.", errCode);
        }
        return errCode;
    };
    std::optional<uintptr_t> opqNative;
    if (opq.has_value()) {
        opqNative = opq.value();
    }
    auto result = rdbObserversData_.OffCommon(eventNative, subscribeMode, opqNative, unSubscribeFunc);
    if (result != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("OffCommon failed, %{public}d.", result);
        ThrowInnerError(result);
    }
}

void RdbStoreImpl::OnSqliteErrorOccurredInner(
    taihe::callback_view<void(ohos::data::relationalStore::ExceptionMessage const& info)> observer, uintptr_t opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    if (nativeRdbStore_->GetDbType() != NativeRdb::DB_SQLITE) {
        ThrowInnerError(OHOS::NativeRdb::E_NOT_SUPPORT);
        return;
    }
    auto subscribeFunc = [this](std::shared_ptr<ani_rdbutils::TaiheLogObserver> observer)->int32_t {
        auto errCode = NativeRdb::SqlLog::Subscribe(nativeRdbStore_->GetPath(), observer);
        if (errCode == OHOS::NativeRdb::E_OK) {
            LOG_INFO("Subscribe success.");
        } else {
            LOG_ERROR("Subscribe failed, %{public}d.", errCode);
        }
        return errCode;
    };
    auto result = rdbObserversData_.OnSqliteErrorOccurred(observer, opq, subscribeFunc);
    if (result != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("OnSqliteErrorOccurred failed, %{public}d.", result);
        ThrowInnerError(result);
    }
}

void RdbStoreImpl::OffSqliteErrorOccurredInner(taihe::optional_view<uintptr_t> opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    if (nativeRdbStore_->GetDbType() != NativeRdb::DB_SQLITE) {
        ThrowInnerError(OHOS::NativeRdb::E_NOT_SUPPORT);
        return;
    }
    auto unSubscribeFunc = [this](std::shared_ptr<ani_rdbutils::TaiheLogObserver> observer)->int32_t {
        auto errCode = NativeRdb::SqlLog::Unsubscribe(nativeRdbStore_->GetPath(), observer);
        if (errCode == OHOS::NativeRdb::E_OK) {
            LOG_INFO("Unsubscribe success.");
        } else {
            LOG_ERROR("Unsubscribe failed, %{public}d.", errCode);
        }
        return errCode;
    };
    std::optional<uintptr_t> opqNative;
    if (opq.has_value()) {
        opqNative = opq.value();
    }
    auto result = rdbObserversData_.OffSqliteErrorOccurred(opqNative, unSubscribeFunc);
    if (result != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("OffSqliteErrorOccurred failed, %{public}d.", result);
        ThrowInnerError(result);
    }
}

void RdbStoreImpl::OnPerfStatInner(
    taihe::callback_view<void(ohos::data::relationalStore::SqlExecutionInfo const& info)> observer, uintptr_t opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    if (nativeRdbStore_->GetDbType() != NativeRdb::DB_SQLITE) {
        ThrowInnerError(OHOS::NativeRdb::E_NOT_SUPPORT);
        return;
    }
    auto subscribeFunc = [this](std::shared_ptr<ani_rdbutils::TaiheSqlObserver> observer)->int32_t {
        auto errCode = DistributedRdb::PerfStat::Subscribe(nativeRdbStore_->GetPath(), observer);
        if (errCode == OHOS::NativeRdb::E_OK) {
            LOG_INFO("Subscribe success.");
        } else {
            LOG_ERROR("Subscribe failed, %{public}d.", errCode);
        }
        return errCode;
    };
    auto result = rdbObserversData_.OnPerfStat(observer, opq, subscribeFunc);
    if (result != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("OnPerfStat failed, %{public}d.", result);
        ThrowInnerError(result);
    }
}

void RdbStoreImpl::OffPerfStatInner(::taihe::optional_view<uintptr_t> opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    if (nativeRdbStore_->GetDbType() != NativeRdb::DB_SQLITE) {
        ThrowInnerError(OHOS::NativeRdb::E_NOT_SUPPORT);
        return;
    }
    auto unSubscribeFunc = [this](std::shared_ptr<ani_rdbutils::TaiheSqlObserver> observer)->int32_t {
        auto errCode = DistributedRdb::PerfStat::Unsubscribe(nativeRdbStore_->GetPath(), observer);
        if (errCode == OHOS::NativeRdb::E_OK) {
            LOG_INFO("Unsubscribe success.");
        } else {
            LOG_ERROR("Unsubscribe failed, %{public}d.", errCode);
        }
        return errCode;
    };
    std::optional<uintptr_t> opqNative;
    if (opq.has_value()) {
        opqNative = opq.value();
    }
    auto result = rdbObserversData_.OffPerfStat(opqNative, unSubscribeFunc);
    if (result != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("OffPerfStat failed, %{public}d.", result);
        ThrowInnerError(result);
    }
}

void RdbStoreImpl::Emit(string_view event)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    int errCode = nativeRdbStore_->Notify(std::string(event));
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::CloseSync()
{
    LOG_INFO("closeSync");
    if (nativeRdbStore_ == nullptr) {
        LOG_ERROR("nativeRdbStore_ is nullptr");
        return;
    }
    UnRegisterAll();
    nativeRdbStore_ = nullptr;
}

int32_t RdbStoreImpl::AttachWithWaitTime(string_view fullPath, string_view attachName,
    taihe::optional_view<int32_t> waitTime)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return 0;
    }
    std::string fullPathStr(fullPath);
    std::string attachNameStr(attachName);
    int32_t waitTimeNative = WAIT_TIME_DEFAULT;
    if (waitTime.has_value()) {
        waitTimeNative = waitTime.value();
        if (waitTimeNative < WAIT_TIME_MIN || waitTimeNative > WAIT_TIME_MAX) {
            ThrowInnerError(OHOS::NativeRdb::E_ERROR);
            return 0;
        }
    }
    OHOS::NativeRdb::RdbStoreConfig config(fullPathStr);
    auto [errCode, output] = nativeRdbStore_->Attach(config, attachNameStr, waitTimeNative);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return 0;
    }
    return output;
}

int32_t RdbStoreImpl::AttachWithContext(
    uintptr_t context, StoreConfig const &config, string_view attachName, optional_view<int32_t> waitTime)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return 0;
    }

    ani_env *env = get_env();
    OHOS::AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig = ani_rdbutils::AniGetRdbConfig(config);
    auto configRet = ani_rdbutils::AniGetRdbStoreConfig(env, reinterpret_cast<ani_object>(context), rdbConfig);
    if (!configRet.first) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return 0;
    }
    OHOS::NativeRdb::RdbStoreConfig nativeConfig = configRet.second;

    std::string attachNameStr(attachName);
    int32_t waitTimeValue = WAIT_TIME_DEFAULT;
    if (waitTime.has_value()) {
        waitTimeValue = waitTime.value();
        if (waitTimeValue < WAIT_TIME_MIN || waitTimeValue > WAIT_TIME_MAX) {
            ThrowInnerError(OHOS::NativeRdb::E_ERROR);
            return 0;
        }
    }

    auto [errCode, output] = nativeRdbStore_->Attach(nativeConfig, attachNameStr, waitTimeValue);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return 0;
    }
    return output;
}

int32_t RdbStoreImpl::DetachSync(string_view attachName, optional_view<int32_t> waitTime)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return ERR_NULL;
    }
    if (waitTime.has_value()) {
        int32_t waitTimeValue = waitTime.value();
        auto [errCode, output] = nativeRdbStore_->Detach(std::string(attachName), waitTimeValue);
        if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
            return 0;
        }
        return output;
    } else {
        auto [errCode, output] = nativeRdbStore_->Detach(std::string(attachName));
        if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
            return 0;
        }
        return output;
    }
}

void RdbStoreImpl::LockRowSync(weak::RdbPredicates predicates)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return;
    }
    if (rdbPredicateNative.get() != nullptr) {
        int errCode = nativeRdbStore_->ModifyLockStatus(*rdbPredicateNative, true);
        if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
    } else {
        LOG_ERROR("rdbPredicateNative.get() is nullptr");
    }
}

void RdbStoreImpl::UnlockRowSync(weak::RdbPredicates predicates)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return;
    }
    if (rdbPredicateNative.get() != nullptr) {
        int errCode = nativeRdbStore_->ModifyLockStatus(*rdbPredicateNative, false);
        if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
    } else {
        LOG_ERROR("rdbPredicateNative.get() is nullptr");
    }
}

ResultSet RdbStoreImpl::QueryLockedRowSync(weak::RdbPredicates predicates, optional_view<array<string>> columns)
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(errCode);
        return make_holder<ResultSetImpl, ResultSet>();
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return make_holder<ResultSetImpl, ResultSet>();
    }
    rdbPredicateNative->BeginWrap()->EqualTo(OHOS::NativeRdb::AbsRdbPredicates::LOCK_STATUS,
        OHOS::NativeRdb::AbsRdbPredicates::LOCKED)->Or();
    rdbPredicateNative->EqualTo(OHOS::NativeRdb::AbsRdbPredicates::LOCK_STATUS,
        OHOS::NativeRdb::AbsRdbPredicates::LOCK_CHANGED)->EndWrap();
    OHOS::NativeRdb::RdbStore::Fields fields;
    if (columns.has_value()) {
        for (const auto &column : columns.value()) {
            fields.push_back(std::string(column));
        }
    }
    auto resultSetNative = nativeRdbStore_->QueryByStep(*rdbPredicateNative, fields);
    if (resultSetNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
    }
    return make_holder<ResultSetImpl, ResultSet>(resultSetNative);
}

uint32_t RdbStoreImpl::LockCloudContainerSync()
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return ERR_NULL;
    }
    auto [errCode, output] = nativeRdbStore_->LockCloudContainer();
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return 0;
    }
    return output;
}

void RdbStoreImpl::UnlockCloudContainerSync()
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    int errCode = nativeRdbStore_->UnlockCloudContainer();
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

Transaction RdbStoreImpl::CreateTransactionSync(
    optional_view<::ohos::data::relationalStore::TransactionOptions> options)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return make_holder<TransactionImpl, Transaction>();
    }
    int32_t transactionType = 0;
    if (options.has_value()) {
        auto optType = options.value();
        if (optType.transactionType.has_value()) {
            transactionType = (int)(optType.transactionType.value());
        }
    }
    auto [errCode, transaction] = nativeRdbStore_->CreateTransaction(transactionType);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return make_holder<TransactionImpl, Transaction>();
    }
    return make_holder<TransactionImpl, Transaction>(transaction);
}

Result RdbStoreImpl::BatchInsertWithReturningSync(string_view table, array_view<ValuesBucket> values,
    ReturningConfig const &config, optional_view<ConflictResolution> conflict)
{
    return BatchInsertWithReturning(nativeRdbStore_, table, values, config, conflict);
}

Result RdbStoreImpl::UpdateWithReturningSync(ValuesBucket values, weak::RdbPredicates predicates,
    ReturningConfig const &config, optional_view<ConflictResolution> conflict)
{
    return UpdateWithReturning(nativeRdbStore_, values, predicates, config, conflict);
}

Result RdbStoreImpl::DeleteWithReturningSync(weak::RdbPredicates predicates, ReturningConfig const &config)
{
    return DeleteWithReturning(nativeRdbStore_, predicates, config);
}

int64_t RdbStoreImpl::BatchInsertWithConflictResolutionSync(taihe::string_view table,
    taihe::array_view<ohos::data::relationalStore::ValuesBucket> values,
    ohos::data::relationalStore::ConflictResolution conflict)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return ERR_NULL;
    }
    OHOS::NativeRdb::ValuesBuckets buckets;
    for (const auto &valuesBucket : values) {
        buckets.Put(ani_rdbutils::MapValuesToNative(
            valuesBucket.get_ref<ohos::data::relationalStore::ValuesBucket::tag_t::VALUESBUCKET>()));
    }
    auto conflictResolution = ani_rdbutils::ConflictResolutionToNative(conflict);
    auto [errCode, output] = nativeRdbStore_->BatchInsert(std::string(table), buckets, conflictResolution);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return ERR_NULL;
    }
    return output;
}

void RdbStoreImpl::RekeySync(taihe::optional_view<ohos::data::relationalStore::CryptoParam> cryptoParam)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    NativeRdb::RdbStoreConfig::CryptoParam cryptoParamNative;
    if (cryptoParam.has_value()) {
        cryptoParamNative = ani_rdbutils::CryptoParamToNative(cryptoParam.value());
    }
    if (!cryptoParamNative.IsValid()) {
        ThrowInnerError(NativeRdb::E_INVALID_ARGS_NEW);
        return;
    }
    auto errCode = nativeRdbStore_->Rekey(cryptoParamNative);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::RekeyExSync(ohos::data::relationalStore::CryptoParam const& cryptoParam)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto cryptoParamNative = ani_rdbutils::CryptoParamToNative(cryptoParam);
    if (!cryptoParamNative.IsValid()) {
        ThrowInnerError(NativeRdb::E_INVALID_ARGS_NEW);
        return;
    }
    auto errCode = nativeRdbStore_->RekeyEx(cryptoParamNative);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::SetLocaleSync(taihe::string_view locale)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto localeNative = std::string(locale);
    if (localeNative.empty()) {
        ThrowInnerError(NativeRdb::E_INVALID_ARGS_NEW);
        return;
    }
    auto errCode = nativeRdbStore_->ConfigLocale(localeNative);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

template<class FuncType>
void RdbStoreImpl::OnDataChangeCommon(OHOS::DistributedRdb::SubscribeMode subscribeMode,
    FuncType callback, uintptr_t opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    if (subscribeMode < 0 || subscribeMode >= DistributedRdb::SubscribeMode::SUBSCRIBE_MODE_MAX) {
        ThrowError(std::make_shared<ParamError>("type", "SubscribeType"));
        return;
    }
    auto subscribeFunc = [subscribeMode, this](
        std::shared_ptr<ani_rdbutils::TaiheRdbStoreObserver> observer)->int32_t {
        OHOS::DistributedRdb::SubscribeOption option;
        option.mode = subscribeMode;
        option.event = ani_rdbutils::EVENT_DATA_CHANGE;
        if (option.mode == OHOS::DistributedRdb::SubscribeMode::LOCAL_DETAIL) {
            auto errCode = nativeRdbStore_->SubscribeObserver(option, observer);
            if (errCode == OHOS::NativeRdb::E_OK) {
                LOG_INFO("SubscribeObserver success.");
            } else {
                LOG_ERROR("SubscribeObserver failed, %{public}d.", errCode);
            }
            return errCode;
        } else {
            auto errCode = nativeRdbStore_->Subscribe(option, observer);
            if (errCode == OHOS::NativeRdb::E_OK) {
                LOG_INFO("Subscribe success.");
            } else {
                LOG_ERROR("Subscribe failed, %{public}d.", errCode);
            }
            return errCode;
        }
    };
    auto result = rdbObserversData_.OnDataChange(subscribeMode, callback, opq, subscribeFunc);
    if (result != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("OnDataChange failed, %{public}d.", result);
        ThrowInnerError(result);
    }
}

void RdbStoreImpl::OffDataChangeCommon(OHOS::DistributedRdb::SubscribeMode subscribeMode,
    taihe::optional_view<uintptr_t> opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    if (subscribeMode < 0 || subscribeMode >= DistributedRdb::SubscribeMode::SUBSCRIBE_MODE_MAX) {
        ThrowError(std::make_shared<ParamError>("type", "SubscribeType"));
        return;
    }
    auto unSubscribeFunc = [subscribeMode, this](
        std::shared_ptr<ani_rdbutils::TaiheRdbStoreObserver> observer)->int32_t {
        OHOS::DistributedRdb::SubscribeOption option;
        option.mode = subscribeMode;
        option.event = ani_rdbutils::EVENT_DATA_CHANGE;
        if (option.mode == OHOS::DistributedRdb::SubscribeMode::LOCAL_DETAIL) {
            auto errCode = nativeRdbStore_->UnsubscribeObserver(option, observer);
            if (errCode == OHOS::NativeRdb::E_OK) {
                LOG_INFO("UnsubscribeObserver success.");
            } else {
                LOG_ERROR("UnsubscribeObserver failed, %{public}d.", errCode);
            }
            return errCode;
        } else {
            auto errCode = nativeRdbStore_->UnSubscribe(option, observer);
            if (errCode == OHOS::NativeRdb::E_OK) {
                LOG_INFO("UnSubscribe success.");
            } else {
                LOG_ERROR("UnSubscribe failed, %{public}d.", errCode);
            }
            return errCode;
        }
    };
    std::optional<uintptr_t> opqNative;
    if (opq.has_value()) {
        opqNative = opq.value();
    }
    auto result = rdbObserversData_.OffDataChange(subscribeMode, opqNative, unSubscribeFunc);
    if (result != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("OffDataChange failed, %{public}d.", result);
        ThrowInnerError(result);
    }
}

void RdbStoreImpl::UnRegisterAll()
{
    std::unique_lock<std::mutex> locker(rdbObserversData_.rdbObserversMutex_);
    UnRegisterDataChange();
    for (auto &obs : rdbObserversData_.syncObservers_) {
        nativeRdbStore_->UnregisterAutoSyncCallback(obs);
    }
    rdbObserversData_.syncObservers_.clear();
    for (auto &obs : rdbObserversData_.statisticses_) {
        DistributedRdb::SqlStatistic::Unsubscribe(obs);
    }
    rdbObserversData_.statisticses_.clear();
    for (auto &obs : rdbObserversData_.logObservers_) {
        NativeRdb::SqlLog::Unsubscribe(nativeRdbStore_->GetPath(), obs);
    }
    rdbObserversData_.logObservers_.clear();
}

void RdbStoreImpl::UnRegisterDataChange()
{
    for (int32_t mode = DistributedRdb::SubscribeMode::REMOTE;
        mode < DistributedRdb::SubscribeMode::LOCAL; mode++) {
        for (auto &obs : rdbObserversData_.observers_[mode]) {
            if (obs == nullptr) {
                continue;
            }
            nativeRdbStore_->UnSubscribe({ static_cast<DistributedRdb::SubscribeMode>(mode) }, obs);
        }
        rdbObserversData_.observers_[mode].clear();
    }
    for (auto &obs : rdbObserversData_.observers_[DistributedRdb::SubscribeMode::LOCAL_DETAIL]) {
        if (obs == nullptr) {
            continue;
        }
        nativeRdbStore_->UnsubscribeObserver({ DistributedRdb::SubscribeMode::LOCAL_DETAIL }, obs);
    }
    rdbObserversData_.observers_[DistributedRdb::SubscribeMode::LOCAL_DETAIL].clear();
    for (const auto &[event, observers] : rdbObserversData_.localObservers_) {
        for (const auto &obs : observers) {
            if (obs == nullptr) {
                continue;
            }
            nativeRdbStore_->UnSubscribe(
                { static_cast<DistributedRdb::SubscribeMode>(DistributedRdb::LOCAL), event }, obs);
        }
    }
    rdbObserversData_.localObservers_.clear();
    for (const auto &[event, observers] : rdbObserversData_.localSharedObservers_) {
        for (const auto &obs : observers) {
            if (obs == nullptr) {
                continue;
            }
            nativeRdbStore_->UnSubscribe(
                { static_cast<DistributedRdb::SubscribeMode>(DistributedRdb::LOCAL_SHARED), event }, obs);
        }
    }
    rdbObserversData_.localSharedObservers_.clear();
}
}
}