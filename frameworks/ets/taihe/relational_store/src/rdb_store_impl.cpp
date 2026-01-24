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
#include "ani_rdb_utils.h"
#include "ani_utils.h"
#include "datashare_abs_predicates.h"
#include "lite_result_set_impl.h"
#include "ohos.data.relationalStore.impl.h"
#include "ohos.data.relationalStore.proj.hpp"
#include "result_set_impl.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_predicates_impl.h"
#include "rdb_store_config.h"
#include "rdb_store_impl.h"
#include "rdb_sql_log.h"
#include "rdb_sql_statistic.h"
#include "rdb_perfStat.h"
#include "rdb_result_set_bridge.h"
#include "rdb_utils.h"
#include "transaction_impl.h"

#include <future>

namespace OHOS {
namespace RdbTaihe {
constexpr size_t RESULT_INIT_SIZE = 5;
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
    auto [result, nativeType] = ani_rdbutils::DistributedTableTypeToNative(type);
    if (!result) {
        ThrowParamError("type must be a DistributedTableType.");
        return;
    }
    int errCode =
        nativeRdbStore_->SetDistributedTables(std::vector<std::string>(tables.begin(), tables.end()), nativeType);
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
    auto [res, nativeType] = ani_rdbutils::DistributedTableTypeToNative(type);
    if (!res) {
        ThrowParamError("type must be a DistributedTableType.");
        return;
    }
    auto [ret, nativeConfig] = ani_rdbutils::DistributedConfigToNative(config, nativeType);
    if (!ret) {
        ThrowParamError("config must be a DistributedConfig.");
        return;
    }
    if (nativeType == NativeDistributedTableType::DISTRIBUTED_CLOUD &&
        nativeConfig.tableType == NativeDistributedTableMode::DEVICE_COLLABORATION) {
        ThrowError(std::make_shared<InnerError>(
            OHOS::NativeRdb::E_NOT_SUPPORT, "The CloudDistributedTable is not support DEVICE_COLLABORATION."));
        return;
    }

    int errCode = nativeRdbStore_->SetDistributedTables(
        std::vector<std::string>(tables.begin(), tables.end()), nativeType, nativeConfig);
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
    NativeDistributedTableType nativeType = NativeDistributedTableType::DISTRIBUTED_DEVICE;
    NativeDistributedConfig nativeConfig = {true};
    if (type.has_value()) {
        auto [res, nativeTypeTemp] = ani_rdbutils::DistributedTableTypeToNative(type.value());
        if (!res) {
            ThrowParamError("type must be a DistributedTableType.");
            return;
        }
        nativeType = nativeTypeTemp;
    }
    if (config.has_value()) {
        auto [ret, nativeConfigTemp] = ani_rdbutils::DistributedConfigToNative(config.value(), nativeType);
        if (!ret) {
            ThrowParamError("config must be a DistributedConfig.");
            return;
        }
        nativeConfig = std::move(nativeConfigTemp);
    } else {
        nativeConfig.tableType = nativeType == NativeDistributedTableType::DISTRIBUTED_DEVICE
                                     ? NativeDistributedTableMode::DEVICE_COLLABORATION
                                     : NativeDistributedTableMode::SINGLE_VERSION;
    }
    if (nativeType == NativeDistributedTableType::DISTRIBUTED_CLOUD &&
        nativeConfig.tableType == NativeDistributedTableMode::DEVICE_COLLABORATION) {
        ThrowError(std::make_shared<InnerError>(
            OHOS::NativeRdb::E_NOT_SUPPORT, "The CloudDistributedTable is not support DEVICE_COLLABORATION."));
        return;
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

array<map<string, int32_t>> RdbStoreImpl::SyncSync(SyncMode mode, weak::RdbPredicates predicates)
{
    taihe::array<taihe::map<taihe::string, int32_t>> taiheResult(RESULT_INIT_SIZE);
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return taiheResult;
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return taiheResult;
    }
    OHOS::DistributedRdb::SyncOption option{ static_cast<OHOS::DistributedRdb::SyncMode>(mode.get_value()), true };
    std::promise<OHOS::DistributedRdb::SyncResult> promise;
    std::future<OHOS::DistributedRdb::SyncResult> future = promise.get_future();
    auto nativeSyncCallback = [&promise](const OHOS::DistributedRdb::SyncResult &data) {
        promise.set_value(data);
    };
    int errCode = nativeRdbStore_->Sync(option, *rdbPredicateNative, nativeSyncCallback);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return taiheResult;
    }
    auto result = future.get();
    if (result.size() == 0) {
        return taiheResult;
    }
    map<string, int32_t> aniMap;
    for (const auto &[key, value] : result) {
        aniMap.emplace(taihe::string(key), value);
    }
    std::vector<map<string, int32_t>> retResult = { aniMap };
    return array<map<string, int32_t>>(retResult);
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
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto rdbSubscribeType = ani_rdbutils::SubscribeTypeToMode(type);
    ani_rdbutils::VarCallbackType varcb = callback;
    RegisterListener(std::string(ani_rdbutils::EVENT_DATA_CHANGE), rdbSubscribeType, varcb, opq);
}

void RdbStoreImpl::OnDataChangeWithDevices(ohos::data::relationalStore::SubscribeType type,
    taihe::callback_view<void(taihe::array_view<::taihe::string> info)> callback,
    uintptr_t opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto rdbSubscribeType = ani_rdbutils::SubscribeTypeToMode(type);
    ani_rdbutils::VarCallbackType varcb = callback;
    RegisterListener(std::string(ani_rdbutils::EVENT_DATA_CHANGE), rdbSubscribeType, varcb, opq);
}


void RdbStoreImpl::OffDataChangeInner(ohos::data::relationalStore::SubscribeType type,
    taihe::optional_view<uintptr_t> opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto rdbSubscribeType = ani_rdbutils::SubscribeTypeToMode(type);
    bool isUpdated = false;
    UnregisterListener(std::string(ani_rdbutils::EVENT_DATA_CHANGE), rdbSubscribeType, opq, isUpdated);
}

void RdbStoreImpl::OnAutoSyncProgressInner(
    taihe::callback_view<void(ohos::data::relationalStore::ProgressDetails const& info)> callback, uintptr_t opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto mode = OHOS::DistributedRdb::SubscribeMode::LOCAL_SHARED;
    ani_rdbutils::VarCallbackType varcb = callback;
    RegisterListener(std::string(ani_rdbutils::EVENT_SYNC_PROGRESS), mode, varcb, opq);
}

void RdbStoreImpl::OffAutoSyncProgressInner(optional_view<uintptr_t> opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    auto mode = OHOS::DistributedRdb::SubscribeMode::LOCAL_SHARED;
    bool isUpdated = false;
    UnregisterListener(std::string(ani_rdbutils::EVENT_SYNC_PROGRESS), mode, opq, isUpdated);
}

void RdbStoreImpl::OnStatisticsInner(
    taihe::callback_view<void(ohos::data::relationalStore::SqlExecutionInfo const& info)> callback, uintptr_t opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    // assume mode is LOCAL_SHARED
    OHOS::DistributedRdb::SubscribeMode mode = OHOS::DistributedRdb::SubscribeMode::LOCAL_SHARED;
    ani_rdbutils::VarCallbackType varcb = callback;
    RegisterListener(std::string(ani_rdbutils::EVENT_STATISTICS), mode, varcb, opq);
}

void RdbStoreImpl::OffStatisticsInner(optional_view<uintptr_t> opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    // assume mode is LOCAL_SHARED
    OHOS::DistributedRdb::SubscribeMode mode = OHOS::DistributedRdb::SubscribeMode::LOCAL_SHARED;
    bool isUpdated = false;
    // define SUBSCRIBE_MODE_MAX when no input SubscribeType
    UnregisterListener(std::string(ani_rdbutils::EVENT_STATISTICS), mode, opq, isUpdated);
}

void RdbStoreImpl::OnCommon(taihe::string_view event, bool interProcess,
    taihe::callback_view<void()> callback, uintptr_t opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    OHOS::DistributedRdb::SubscribeMode mode = OHOS::DistributedRdb::SubscribeMode::LOCAL;
    if (interProcess) {
        mode = OHOS::DistributedRdb::SubscribeMode::LOCAL_SHARED;
    }
    ani_rdbutils::VarCallbackType varcb = callback;
    RegisterListener(std::string(event), mode, varcb, opq);
}

void RdbStoreImpl::OffCommon(taihe::string_view event, bool interProcess, optional_view<uintptr_t> opq)
{
    if (nativeRdbStore_ == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
        return;
    }
    OHOS::DistributedRdb::SubscribeMode mode = OHOS::DistributedRdb::SubscribeMode::LOCAL;
    if (interProcess) {
        mode = OHOS::DistributedRdb::SubscribeMode::LOCAL_SHARED;
    }
    bool isUpdated = false;
    UnregisterListener(std::string(event), mode, opq, isUpdated);
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

void RdbStoreImpl::RegisterListener(std::string const &event, OHOS::DistributedRdb::SubscribeMode &mode,
    ani_rdbutils::VarCallbackType &cb, uintptr_t opq)
{
    std::lock_guard<std::recursive_mutex> lock(cbMapMutex_);
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_ref callbackRef;
    ani_env *env = taihe::get_env();
    if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        LOG_ERROR("Failed to register %{public}s", event.c_str());
        return;
    }
    auto &cbVec = jsCbMap_[event];
    bool isDuplicate = std::any_of(
        cbVec.begin(), cbVec.end(), [env, callbackRef](std::shared_ptr<ani_rdbutils::DataObserver> &obj) {
            ani_boolean isEqual = false;
            return (ANI_OK == env->Reference_StrictEquals(callbackRef, obj->jsCallbackRef_, &isEqual)) && isEqual;
        });
    if (isDuplicate) {
        env->GlobalReference_Delete(callbackRef);
        LOG_WARN("%{public}s is already registered", event.c_str());
        return;
    }
    // start to execute different register function
    int status = OHOS::NativeRdb::E_OK;
    if (event == std::string(ani_rdbutils::EVENT_DATA_CHANGE)) {
        status = RegisterDataChangeObserver(mode, cb, callbackRef);
    } else if (event == std::string(ani_rdbutils::EVENT_SYNC_PROGRESS)) {
        status = RegisterSyncProgressObserver(cb, callbackRef);
    } else if (event == std::string(ani_rdbutils::EVENT_STATISTICS)) {
        status = RegisterStatisticObserver(cb, callbackRef);
    } else {
        // call back function would has not input parameter
        status = RegisterCommonEventObserver(event, mode, cb, callbackRef);
    }
    if (status != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("RegisterListener, SubscribeObserver failed, %{public}d", status);
        ThrowInnerError(status);
        return;
    }
    LOG_INFO("RegisterListener success type: %{public}s", event.c_str());
}
// for dataChange event register
int RdbStoreImpl::RegisterDataChangeObserver(
    OHOS::DistributedRdb::SubscribeMode &type, ani_rdbutils::VarCallbackType &cb, ani_ref callbackRef)
{
    std::lock_guard<std::recursive_mutex> lock(cbMapMutex_);
    auto &cbVec = jsCbMap_[std::string(ani_rdbutils::EVENT_DATA_CHANGE)];
    auto observer = ani_rdbutils::DataObserver::Create(cb, callbackRef);
    // the 'observer' object would be used to get jsCallback pointer
    if ((type == OHOS::DistributedRdb::SubscribeMode::CLOUD_DETAIL) ||
        (type == OHOS::DistributedRdb::SubscribeMode::LOCAL_DETAIL)) {
        observer->SetNotifyDataChangeInfoFunc(
            [](ani_rdbutils::DataObserver *observer, const OHOS::DistributedRdb::Origin &origin,
                const OHOS::DistributedRdb::RdbStoreObserver::PrimaryFields &fields,
                const OHOS::DistributedRdb::RdbStoreObserver::ChangeInfo &changeInfo) {
                // need two input parameters, return value will be one array
                auto jsChangeInfo = ani_rdbutils::RdbChangeInfoToTaihe(origin, changeInfo);
                if (std::holds_alternative<ani_rdbutils::JsChangeInfoCallbackType>(observer->jsCallback_)) {
                    auto &jsfunc = std::get<ani_rdbutils::JsChangeInfoCallbackType>(observer->jsCallback_);
                    jsfunc(jsChangeInfo);
                } else {
                    LOG_ERROR("Js function type error.");
                }
            });
    } else {
        observer->SetNotifyDataChangeArrFunc(
            [](ani_rdbutils::DataObserver *observer, const std::vector<std::string> &devices) {
                // js function will convert input parameters
                auto jsDevices = ani_rdbutils::VectorToTaiheArray(devices);
                auto &jsfunc = std::get<ani_rdbutils::JsDevicesCallbackType>(observer->jsCallback_);
                jsfunc(jsDevices);
            });
    }
    OHOS::DistributedRdb::SubscribeOption option;
    option.mode = type;
    option.event = std::string(ani_rdbutils::EVENT_DATA_CHANGE);
    int status = OHOS::NativeRdb::E_OK;
    if (option.mode == OHOS::DistributedRdb::SubscribeMode::LOCAL_DETAIL) {
        status = nativeRdbStore_->SubscribeObserver(option, observer);
    } else {
        status = nativeRdbStore_->Subscribe(option, observer);
    }
    if (status != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("RegisterDataChangeObserver, SubscribeObserver failed, %{public}d", status);
        return status;
    }
    cbVec.emplace_back(std::move(observer));
    LOG_INFO("RegisterDataChangeObserver success");
    return OHOS::NativeRdb::E_OK;
}
// for autoSyncProgress event register
int RdbStoreImpl::RegisterSyncProgressObserver(ani_rdbutils::VarCallbackType &cb, ani_ref callbackRef)
{
    std::lock_guard<std::recursive_mutex> lock(cbMapMutex_);
    auto &cbVec = jsCbMap_[std::string(ani_rdbutils::EVENT_SYNC_PROGRESS)];
    auto observer = ani_rdbutils::DataObserver::Create(cb, callbackRef);
    observer->SetNotifyProcessFunc(
        [](ani_rdbutils::DataObserver *observer, const OHOS::DistributedRdb::Details &details) {
            if (std::holds_alternative<ani_rdbutils::JsProgressDetailsCallbackType>(observer->jsCallback_)) {
                auto &jsfunc = std::get<ani_rdbutils::JsProgressDetailsCallbackType>(observer->jsCallback_);
                for (auto it = details.begin(); it != details.end(); ++it) {
                    auto jspara = ani_rdbutils::ProgressDetailToTaihe(it->second);
                    jsfunc(jspara);
                }
            } else {
                LOG_ERROR("Js function type error.");
            }
        });
    int status = nativeRdbStore_->RegisterAutoSyncCallback(observer);
    if (status != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("RegisterSyncProgressObserver, RegisterAutoSyncCallback failed, %{public}d", status);
        return status;
    }
    cbVec.emplace_back(std::move(observer));
    LOG_INFO("RegisterSyncProgressObserver success");
    return OHOS::NativeRdb::E_OK;
}
// for statistics event
int RdbStoreImpl::RegisterStatisticObserver(ani_rdbutils::VarCallbackType &cb, ani_ref callbackRef)
{
    std::lock_guard<std::recursive_mutex> lock(cbMapMutex_);
    auto &cbVec = jsCbMap_[std::string(ani_rdbutils::EVENT_STATISTICS)];
    auto observer = ani_rdbutils::DataObserver::Create(cb, callbackRef);
    // the 'observer' object would be used to get jsCallback pointer
    observer->SetNotifySqlExecutionFunc([](ani_rdbutils::DataObserver *observer,
                                            const OHOS::DistributedRdb::SqlObserver::SqlExecutionInfo &sqlInfo) {
        // js function will convert input parameters

        auto jsSqlInfo = ani_rdbutils::SqlExecutionToTaihe(sqlInfo);
        if (std::holds_alternative<ani_rdbutils::JsSqlExecutionCallbackType>(observer->jsCallback_)) {
            auto &jsfunc = std::get<ani_rdbutils::JsSqlExecutionCallbackType>(observer->jsCallback_);
            LOG_ERROR("Js function type success3.");
            jsfunc(jsSqlInfo);
        } else {
            LOG_ERROR("Js function type error.");
        }
    });
    int status = DistributedRdb::SqlStatistic::Subscribe(observer);
    if (status != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("RegisterStatisticObserver, SubscribeObserver failed, %{public}d", status);
        return status;
    }
    cbVec.emplace_back(std::move(observer));
    LOG_INFO("RegisterStatisticObserver success");
    return OHOS::NativeRdb::E_OK;
}
// for common event
int RdbStoreImpl::RegisterCommonEventObserver(std::string const &event, OHOS::DistributedRdb::SubscribeMode &mode,
    ani_rdbutils::VarCallbackType &cb, ani_ref callbackRef)
{
    std::lock_guard<std::recursive_mutex> lock(cbMapMutex_);
    auto &cbVec = jsCbMap_[event];
    auto observer = ani_rdbutils::DataObserver::Create(cb, callbackRef);
    // the 'observer' object would be used to get jsCallback pointer
    observer->SetNotifyCommonEventFunc([](ani_rdbutils::DataObserver *observer) {
        // js function will convert input parameters
        auto &jsfunc = std::get<ani_rdbutils::JsVoidCallbackType>(observer->jsCallback_);
        jsfunc();
    });
    OHOS::DistributedRdb::SubscribeOption option;
    option.mode = mode;
    option.event = event;
    int status = nativeRdbStore_->Subscribe(option, observer);
    if (status != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("RegisterCommonEventObserver, SubscribeObserver failed, %{public}d", status);
        return status;
    }
    cbVec.emplace_back(std::move(observer));
    LOG_INFO("RegisterCommonEventObserver success.");
    return OHOS::NativeRdb::E_OK;
}
// *********************************************************************
// start unregister function
// *********************************************************************
// for dataChange and autoSyncProgress
// the mode is DistributedRdb::SubscribeMode::SUBSCRIBE_MODE_MAX, need to unregister for mode type.
void RdbStoreImpl::UnregisterListener(std::string const &event, OHOS::DistributedRdb::SubscribeMode &mode,
    ::taihe::optional_view<uintptr_t> opq, bool &isUpdateFlag)
{
    std::lock_guard<std::recursive_mutex> lock(cbMapMutex_);
    const auto iter = jsCbMap_.find(event);
    if (iter == jsCbMap_.end()) {
        LOG_ERROR("%{public}s is not registered", event.c_str());
        return;
    }
    OHOS::DistributedRdb::SubscribeOption option;
    option.event = event;
    int status = OHOS::NativeRdb::E_OK;
    ::taihe::optional<uintptr_t> empty;
    // no input type, need to unregister all type
    if (mode == OHOS::DistributedRdb::SubscribeMode::SUBSCRIBE_MODE_MAX) {
        // will execute several times
        for (uint8_t type = ani_rdbutils::SUBSCRIBE_REMOTE; type < ani_rdbutils::SUBSCRIBE_COUNT; type++) {
            bool updated = false;
            option.mode = static_cast<OHOS::DistributedRdb::SubscribeMode>(type);
            status = UnRegisterObserver(option, opq, updated);
            isUpdateFlag |= updated;
            if (status != OHOS::NativeRdb::E_OK) {
                LOG_ERROR("UnregisterListener failed, type = %{public}d, status%{public}d", type, status);
                return;
            }
        }
    } else {
        bool updated = false;
        option.mode = mode;
        status = UnRegisterObserver(option, opq, updated);
        isUpdateFlag |= updated;
        if (status != OHOS::NativeRdb::E_OK) {
            LOG_ERROR("UnregisterListener failed, type = %{public}d, status%{public}d", mode, status);
            return;
        }
    }

    LOG_INFO("UnregisterListener success type: %{public}s", event.c_str());
}

int RdbStoreImpl::UnRegisterObserver(
    OHOS::DistributedRdb::SubscribeOption &option, ::taihe::optional_view<uintptr_t> opq, bool &isUpdateFlag)
{
    int result = OHOS::NativeRdb::E_OK;
    auto &callbackList = jsCbMap_[option.event];
    // two conditions, opq not exist or opq exist
    if (!opq.has_value()) {
        // oqp not exist
        LOG_INFO("UnRegisterObserver for all item, size %{public}zu, type %{public}d",
            callbackList.size(), option.mode);
        for (auto iter = callbackList.begin(); iter != callbackList.end();) {
            int status = OHOS::NativeRdb::E_OK;
            if ((option.event == std::string(ani_rdbutils::EVENT_DATA_CHANGE)) &&
                (option.mode == OHOS::DistributedRdb::SubscribeMode::LOCAL_DETAIL)) {
                status = nativeRdbStore_->UnsubscribeObserver(option, *iter);
            } else if (option.event == std::string(ani_rdbutils::EVENT_SYNC_PROGRESS)) {
                status = nativeRdbStore_->UnregisterAutoSyncCallback(*iter);
            } else if (option.event == std::string(ani_rdbutils::EVENT_STATISTICS)) {
                status = DistributedRdb::SqlStatistic::Unsubscribe(*iter);
            } else {
                // other dataChange, common event use the same unsubscribe
                status = nativeRdbStore_->UnSubscribe(option, *iter);
            }
            LOG_INFO("UnRegisterObserver status %{public}d", status);
            if (status == OHOS::NativeRdb::E_OK || status == OHOS::NativeRdb::E_ALREADY_CLOSED) {
                isUpdateFlag = true;
                (*iter)->Release();
                iter = callbackList.erase(iter);
            } else {
                LOG_ERROR("RdbStoreImpl UnRegisterObserver failed, status %{public}d", status);
                result = status;
                ++iter;
            }
        }
        if (callbackList.empty()) {
            jsCbMap_.erase(option.event);
        }
        return result;
    }
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        LOG_ERROR("Failed to UnRegisterObserver, env is nullptr");
        return result;
    }
    ani_rdbutils::GlobalRefGuard guard(env, reinterpret_cast<ani_object>(opq.value()));
    if (!guard) {
        LOG_ERROR("Failed to UnRegisterObserver, GlobalRefGuard is false!");
        return result;
    }
    return UnRegisterObserverExistOpq(option, guard.get(), isUpdateFlag);
}

int RdbStoreImpl::UnRegisterObserverExistOpq(
    OHOS::DistributedRdb::SubscribeOption &option, ani_ref jsCallbackRef, bool &isUpdateFlag)
{
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        LOG_ERROR("Failed to UnRegisterObserver, env is nullptr");
        return OHOS::NativeRdb::E_OK;
    }
    auto &callbackList = jsCbMap_[option.event];
    const auto pred = [env, jsCallbackRef](std::shared_ptr<ani_rdbutils::DataObserver> &obj) {
        ani_boolean is_equal = false;
        return (ANI_OK == env->Reference_StrictEquals(jsCallbackRef, obj->jsCallbackRef_, &is_equal)) && is_equal;
    };
    const auto it = std::find_if(callbackList.begin(), callbackList.end(), pred);
    if (it != callbackList.end()) {
        int status = OHOS::NativeRdb::E_OK;
        if ((option.event == std::string(ani_rdbutils::EVENT_DATA_CHANGE)) &&
            (option.mode == OHOS::DistributedRdb::SubscribeMode::LOCAL_DETAIL)) {
            status = nativeRdbStore_->UnsubscribeObserver(option, *it);
        } else if  (option.event == std::string(ani_rdbutils::EVENT_SYNC_PROGRESS)) {
            status = nativeRdbStore_->UnregisterAutoSyncCallback(*it);
        } else {
            // other dataChange, statistics, common event use the same unsubscribe
            status = nativeRdbStore_->UnSubscribe(option, *it);
        }
        LOG_INFO("UnRegisterObserver, status %{public}d", status);
        if (status == OHOS::NativeRdb::E_OK || status == OHOS::NativeRdb::E_ALREADY_CLOSED) {
            isUpdateFlag = true;
            (*it)->Release();
            callbackList.erase(it);
        } else {
            return status;
        }
    }
    if (callbackList.empty()) {
        jsCbMap_.erase(option.event);
    }
    return OHOS::NativeRdb::E_OK;
}

void RdbStoreImpl::UnRegisterAll()
{
    LOG_INFO("RdbStoreImpl UnRegisterAll");
    std::lock_guard<std::recursive_mutex> lock(cbMapMutex_);
    bool isUpdated = false;
    // empty is nullptr
    ::taihe::optional<uintptr_t> empty;
    OHOS::DistributedRdb::SubscribeOption option;
    option.event = std::string(ani_rdbutils::EVENT_DATA_CHANGE);
    for (uint8_t type = ani_rdbutils::SUBSCRIBE_REMOTE; type < ani_rdbutils::SUBSCRIBE_COUNT; type++) {
        option.mode = static_cast<OHOS::DistributedRdb::SubscribeMode>(type);
        UnRegisterObserver(option, empty, isUpdated);
    }
    option.event = std::string(ani_rdbutils::EVENT_SYNC_PROGRESS);
    option.mode = OHOS::DistributedRdb::SubscribeMode::SUBSCRIBE_MODE_MAX;
    UnRegisterObserver(option, empty, isUpdated);
    // statistics
    option.event = std::string(ani_rdbutils::EVENT_STATISTICS);
    UnRegisterObserver(option, empty, isUpdated);
    // common event
    auto map = jsCbMap_;
    for (auto &[event, queue]: map) {
        option.event = event;
        option.mode = OHOS::DistributedRdb::SubscribeMode::LOCAL_SHARED;
        UnRegisterObserver(option, empty, isUpdated);
        LOG_INFO("RdbStoreImpl UnRegisterAll");
    }
    LOG_INFO("RdbStoreImpl UnRegisterAll end");
}
}
}