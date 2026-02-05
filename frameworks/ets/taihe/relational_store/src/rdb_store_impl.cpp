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
#include "error_throw_utils.h"

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
        (void) oldVersion;
        (void) newVersion;
        return OHOS::NativeRdb::E_OK;
    }
};

RdbStoreImpl::RdbStoreImpl()
{
}

RdbStoreImpl::RdbStoreImpl(ani_object context, StoreConfig const &config, ConfigVersion version)
{
    ani_env *env = get_env();
    OHOS::AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig = ani_rdbutils::AniGetRdbConfig(config);
    rdbConfig.version = version;
    auto configRet = ani_rdbutils::AniGetRdbStoreConfig(env, context, rdbConfig);
    isSystemApp_ = rdbConfig.isSystemApp;
    DefaultOpenCallback callback;
    int errCode = OHOS::AppDataMgrJsKit::JSUtils::OK;
    if (configRet.first != OK) {
        LOG_ERROR("AniGetRdbStoreConfig failed, use default config");
        bool isConfigNew = (rdbConfig.version >= ConfigVersion::INVALID_CONFIG_CHANGE_NOT_ALLOWED);
        ThrowInnerErrorExt((isConfigNew && (configRet.first == E_PARAM_ERROR)) ? E_INVALID_ARGS : configRet.first);
    }
    auto nativeRdbStore = OHOS::NativeRdb::RdbHelper::GetRdbStore(configRet.second, -1, callback, errCode);
    SetResource(nativeRdbStore);
    if (errCode != OHOS::AppDataMgrJsKit::JSUtils::OK) {
        ThrowInnerError(errCode);
        ResetResource();
        LOG_ERROR("GetRdbStore failed");
        return;
    }
    LOG_INFO("GetRdbStore success");
}

int32_t RdbStoreImpl::GetVersion()
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), ERR_NULL);
    int32_t version = 0;
    int errCode = store->GetVersion(version);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
    return version;
}

void RdbStoreImpl::SetVersion(int32_t veriosn)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    int errCode = store->SetVersion(veriosn);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

RebuildType RdbStoreImpl::GetRebuilt()
{
    OHOS::NativeRdb::RebuiltType rebuilt = OHOS::NativeRdb::RebuiltType::NONE;
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), (RebuildType::key_t)rebuilt);
    int errCode = store->GetRebuilt(rebuilt);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), ERR_NULL);
    int64_t int64Output = 0;
    OHOS::NativeRdb::ValuesBucket bucket = ani_rdbutils::MapValuesToNative(values);
    if (ani_rdbutils::HasDuplicateAssets(bucket)) {
        ThrowParamError("Duplicate assets are not allowed");
        return ERR_NULL;
    }

    int errCode = store->InsertWithConflictResolution(
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), ERR_NULL);
    OHOS::NativeRdb::ValuesBuckets buckets = ani_rdbutils::BucketValuesToNative(values);
    if (ani_rdbutils::HasDuplicateAssets(buckets)) {
        ThrowParamError("Duplicate assets are not allowed");
        return ERR_NULL;
    }
    auto [errCode, output] = store->BatchInsert(std::string(table), buckets);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), ERR_NULL);
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
    int errCode = store->UpdateWithConflictResolution(output, rdbPredicateNative->GetTableName(), bucket,
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), ERR_NULL);
    if (!isSystemApp_) {
        ThrowNonSystemError();
        return ERR_NULL;
    }
    ani_env *env = get_env();
    ani_object object = reinterpret_cast<ani_object>(predicates);
    OHOS::DataShare::DataShareAbsPredicates *holder =
        ani_utils::AniObjectUtils::Unwrap<OHOS::DataShare::DataShareAbsPredicates>(env, object);
    ASSERT_RETURN_THROW_ERROR(
        holder != nullptr, std::make_shared<ParamError>("predicates", "an DataShare Predicates."), ERR_NULL);
    auto rdbPredicates = OHOS::RdbDataShareAdapter::RdbUtils::ToPredicates(*holder, std::string(table));
    OHOS::NativeRdb::ValuesBucket bucket = ani_rdbutils::MapValuesToNative(values.get_VALUESBUCKET_ref());

    int output = 0;
    int errCode = store->UpdateWithConflictResolution(output, rdbPredicates.GetTableName(), bucket,
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), ERR_NULL);
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return ERR_NULL;
    }
    int output = 0;
    int errCode = store->Delete(output, *rdbPredicateNative);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return 0;
    }
    return output;
}

int64_t RdbStoreImpl::DeleteDataShareSync(::taihe::string_view table, uintptr_t predicates)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), ERR_NULL);
    if (!isSystemApp_) {
        ThrowNonSystemError();
        return ERR_NULL;
    }
    ani_env *env = get_env();
    ani_object object = reinterpret_cast<ani_object>(predicates);
    OHOS::DataShare::DataShareAbsPredicates *holder =
        ani_utils::AniObjectUtils::Unwrap<OHOS::DataShare::DataShareAbsPredicates>(env, object);
    ASSERT_RETURN_THROW_ERROR(
        holder != nullptr, std::make_shared<ParamError>("predicates", "an DataShare Predicates."), ERR_NULL);
    auto rdbPredicates = OHOS::RdbDataShareAdapter::RdbUtils::ToPredicates(*holder, std::string(table));
    int output = 0;
    int errCode = store->Delete(output, rdbPredicates);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), (make_holder<ResultSetImpl, ResultSet>()));
    std::vector<std::string> stdcolumns;
    if (columns.has_value()) {
        stdcolumns = std::vector<std::string>(columns.value().begin(), columns.value().end());
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    ASSERT_RETURN_THROW_ERROR(rdbPredicateNative != nullptr,
        std::make_shared<ParamError>("predicates", "an RdbPredicates."), (make_holder<ResultSetImpl, ResultSet>()));
    auto nativeResultSet = store->Query(*rdbPredicateNative, stdcolumns);
    ASSERT_RETURN_THROW_ERROR(nativeResultSet != nullptr, std::make_shared<InnerError>(NativeRdb::E_ERROR),
        (make_holder<ResultSetImpl, ResultSet>()));
    return make_holder<ResultSetImpl, ResultSet>(nativeResultSet);
}

LiteResultSet RdbStoreImpl::QueryWithoutRowCountSync(weak::RdbPredicates predicates,
    optional_view<array<string>> columns)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED),
        (make_holder<LiteResultSetImpl, LiteResultSet>()));
    std::vector<std::string> columnNames;
    if (columns.has_value()) {
        columnNames = std::vector<std::string>(columns.value().begin(), columns.value().end());
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    ASSERT_RETURN_THROW_ERROR(rdbPredicateNative != nullptr,
        std::make_shared<ParamError>("predicates", "an RdbPredicates."),
        (make_holder<LiteResultSetImpl, LiteResultSet>()));
    DistributedRdb::QueryOptions options{ .preCount = false, .isGotoNextRowReturnLastError = true };
    auto nativeResultSet = store->QueryByStep(*rdbPredicateNative, columnNames, options);
    ASSERT_RETURN_THROW_ERROR(nativeResultSet != nullptr, std::make_shared<InnerError>(NativeRdb::E_ERROR),
        (make_holder<LiteResultSetImpl, LiteResultSet>()));
    return make_holder<LiteResultSetImpl, LiteResultSet>(nativeResultSet);
}

LiteResultSet RdbStoreImpl::QuerySqlWithoutRowCountSync(string_view sql, optional_view<array<ValueType>> bindArgs)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED),
        (make_holder<LiteResultSetImpl, LiteResultSet>()));
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
    DistributedRdb::QueryOptions options{ .preCount = false, .isGotoNextRowReturnLastError = true };
    nativeResultSet = store->QueryByStep(std::string(sql), para, options);
    ASSERT_RETURN_THROW_ERROR(nativeResultSet != nullptr, std::make_shared<InnerError>(NativeRdb::E_ERROR),
        (make_holder<LiteResultSetImpl, LiteResultSet>()));
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), (make_holder<ResultSetImpl, ResultSet>()));
    if (!isSystemApp_) {
        ThrowNonSystemError();
        return taihe::make_holder<ResultSetImpl, ResultSet>();
    }
    ani_env *env = get_env();
    ani_object object = reinterpret_cast<ani_object>(predicates);
    OHOS::DataShare::DataShareAbsPredicates *holder =
        ani_utils::AniObjectUtils::Unwrap<OHOS::DataShare::DataShareAbsPredicates>(env, object);
    ASSERT_RETURN_THROW_ERROR(holder != nullptr, std::make_shared<ParamError>("predicates", "an DataShare Predicates."),
        (make_holder<ResultSetImpl, ResultSet>()));
    std::vector<std::string> stdcolumns;
    if (columns.has_value()) {
        stdcolumns = std::vector<std::string>(columns.value().begin(), columns.value().end());
    }
    auto rdbPredicates = OHOS::RdbDataShareAdapter::RdbUtils::ToPredicates(*holder, std::string(table));
    auto nativeResultSet = store->Query(rdbPredicates, stdcolumns);
    ASSERT_RETURN_THROW_ERROR(nativeResultSet != nullptr, std::make_shared<InnerError>(NativeRdb::E_ERROR),
        (make_holder<ResultSetImpl, ResultSet>()));
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), (make_holder<ResultSetImpl, ResultSet>()));
    std::vector<OHOS::NativeRdb::ValueObject> para;
    if (bindArgs.has_value()) {
        std::transform(bindArgs.value().begin(), bindArgs.value().end(), std::back_inserter(para),
            [](const ValueType &valueType) { return ani_rdbutils::ValueTypeToNative(valueType); });
    }
    std::shared_ptr<OHOS::NativeRdb::ResultSet> nativeResultSet = nullptr;
    if (store->GetDbType() == OHOS::NativeRdb::DB_VECTOR) {
        nativeResultSet = store->QueryByStep(std::string(sql), para);
    } else {
#if defined(CROSS_PLATFORM)
        nativeResultSet = store->QueryByStep(std::string(sql), para);
#else
        nativeResultSet = store->QuerySql(std::string(sql), para);
#endif
    }
    ASSERT_RETURN_THROW_ERROR(nativeResultSet != nullptr, std::make_shared<InnerError>(NativeRdb::E_ERROR),
        (make_holder<ResultSetImpl, ResultSet>()));
    return make_holder<ResultSetImpl, ResultSet>(nativeResultSet);
}

ModifyTime RdbStoreImpl::GetModifyTimeSync(
    string_view table, string_view columnName, array_view<PRIKeyType> primaryKeys)
{
    ModifyTime result = ModifyTime::make_MODIFYTIME();
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), result);
    // Convert parameters to the types required by store
    std::string nativeTable(table);
    std::string nativeColumnName(columnName);
    std::vector<OHOS::DistributedRdb::RdbStoreObserver::PrimaryKey> nativePrimaryKeys;

    std::transform(
        primaryKeys.begin(), primaryKeys.end(), std::back_inserter(nativePrimaryKeys), [](const PRIKeyType &c) {
            OHOS::DistributedRdb::RdbStoreObserver::PrimaryKey obj = ani_rdbutils::PRIKeyToNative(c);
            return obj;
        });
    // Assume that store has a GetModifyTime method
    // Replace it with the actual method name and parameters
    std::map<OHOS::NativeRdb::RdbStore::PRIKey, OHOS::NativeRdb::RdbStore::Date> mapResult =
        store->GetModifyTime(nativeTable, nativeColumnName, nativePrimaryKeys);
    if (mapResult.empty()) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
        return result;
    }
    return ani_rdbutils::ToAniModifyTime(mapResult);
}

void RdbStoreImpl::CleanDirtyDataWithCursor(string_view table, uint64_t cursor)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    std::string nativeTable(table);
    int32_t errCode = store->CleanDirtyData(nativeTable, cursor);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::CleanDirtyDataWithTable(string_view table)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    std::string nativeTable(table);
    int32_t errCode = store->CleanDirtyData(nativeTable, 0);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(errCode), (make_holder<ResultSetImpl, ResultSet>()));
    if (!isSystemApp_) {
        ThrowNonSystemError();
        return make_holder<ResultSetImpl, ResultSet>();
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    ASSERT_RETURN_THROW_ERROR(rdbPredicateNative != nullptr,
        std::make_shared<ParamError>("predicates", "an RdbPredicates."), (make_holder<ResultSetImpl, ResultSet>()));
    OHOS::NativeRdb::RdbStore::Fields fields;
    if (columns.has_value()) {
        for (const auto &column : columns.value()) {
            fields.push_back(std::string(column));
        }
    }
    auto status = OHOS::NativeRdb::E_ERROR;
    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSetNative;
    std::tie(status, resultSetNative) = store->QuerySharingResource(*rdbPredicateNative, fields);
    if (status != OHOS::NativeRdb::E_OK || resultSetNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
    }
    return make_holder<ResultSetImpl, ResultSet>(resultSetNative);
}

ResultSet RdbStoreImpl::QuerySharingResourceWithPredicate(weak::RdbPredicates predicates)
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(errCode), (make_holder<ResultSetImpl, ResultSet>()));
    if (!isSystemApp_) {
        ThrowNonSystemError();
        return make_holder<ResultSetImpl, ResultSet>();
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    ASSERT_RETURN_THROW_ERROR(rdbPredicateNative != nullptr,
        std::make_shared<ParamError>("predicates", "an RdbPredicates."), (make_holder<ResultSetImpl, ResultSet>()));
    OHOS::NativeRdb::RdbStore::Fields fields;
    auto status = OHOS::NativeRdb::E_ERROR;
    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSetNative;
    std::tie(status, resultSetNative) = store->QuerySharingResource(*rdbPredicateNative, fields);
    if (status != OHOS::NativeRdb::E_OK || resultSetNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
    }
    return make_holder<ResultSetImpl, ResultSet>(resultSetNative);
}

ResultSet RdbStoreImpl::QuerySharingResourceWithColumn(weak::RdbPredicates predicates, array_view<string> columns)
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(errCode), (make_holder<ResultSetImpl, ResultSet>()));
    if (!isSystemApp_) {
        ThrowNonSystemError();
        return make_holder<ResultSetImpl, ResultSet>();
    }
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    ASSERT_RETURN_THROW_ERROR(rdbPredicateNative != nullptr,
        std::make_shared<ParamError>("predicates", "an RdbPredicates."), (make_holder<ResultSetImpl, ResultSet>()));
    OHOS::NativeRdb::RdbStore::Fields fields;
    for (const auto &column : columns) {
        fields.push_back(std::string(column));
    }
    auto status = OHOS::NativeRdb::E_ERROR;
    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSetNative;
    std::tie(status, resultSetNative) = store->QuerySharingResource(*rdbPredicateNative, fields);
    if (status != OHOS::NativeRdb::E_OK || resultSetNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
    }
    return make_holder<ResultSetImpl, ResultSet>(resultSetNative);
}

void RdbStoreImpl::ExecuteSqlWithSql(string_view sql)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    int errCode = store->ExecuteSql(std::string(sql));
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    if (!bindArgs.has_value()) {
        int errCode = store->ExecuteSql(std::string(sql));
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
    int errCode = store->ExecuteSql(std::string(sql), para);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

ValueType RdbStoreImpl::ExecuteWithOptionArgs(string_view sql, optional_view<array<ValueType>> args)
{
    ValueType aniValue = ::ohos::data::relationalStore::ValueType::make_EMPTY();
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), aniValue);
    return ExecuteWithTxId(sql, 0, args);
}

ValueType RdbStoreImpl::ExecuteWithTxId(string_view sql, int64_t txId, optional_view<array<ValueType>> args)
{
    ValueType aniValue = ::ohos::data::relationalStore::ValueType::make_EMPTY();
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), aniValue);
    std::vector<OHOS::NativeRdb::ValueObject> nativeValues;
    if (args.has_value()) {
        array_view<ValueType> const &arrayView = args.value();
        nativeValues = ani_rdbutils::ArrayValuesToNative(arrayView);
    }
    if (ani_rdbutils::HasDuplicateAssets(nativeValues)) {
        ThrowParamError("Duplicate assets are not allowed");
        return aniValue;
    }
    auto [errCode, sqlExeOutput] = store->Execute(std::string(sql), nativeValues, txId);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    int errCode = store->BeginTransaction();
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

int64_t RdbStoreImpl::BeginTransSync()
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), ERR_NULL);
    auto [errCode, rxid] = store->BeginTrans();
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return 0;
    }
    return rxid;
}

void RdbStoreImpl::Commit()
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    int errCode = store->Commit();
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::CommitWithTxId(int64_t txId)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    int errCode = store->Commit(txId);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::RollBack()
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    int errCode = store->RollBack();
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::RollbackSync(int64_t txId)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    int errCode = store->RollBack(txId);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::BackupSync(string_view destName)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    int errCode = store->Backup(std::string(destName));
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::RestoreWithSrcName(string_view srcName)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    int errCode = store->Restore(std::string(srcName));
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::RestoreWithVoid()
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    if (!isSystemApp_) {
        ThrowNonSystemError();
        return;
    }
    int errCode = store->Restore("");
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::SetDistributedTablesWithTables(array_view<string> tables)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    int errCode = store->SetDistributedTables(std::vector<std::string>(tables.begin(), tables.end()));
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::SetDistributedTablesWithType(array_view<string> tables, DistributedType type)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    auto [isValidType, nativeTableType] = ani_rdbutils::DistributedTableTypeToNative(type);
    if (!isValidType) {
        ThrowParamError("type must be a DistributedTableType.");
        return;
    }
    int errCode =
        store->SetDistributedTables(std::vector<std::string>(tables.begin(), tables.end()), nativeTableType);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::SetDistributedTablesWithConfig(
    array_view<string> tables, DistributedType type, DistributedConfig const &config)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    auto [isValidType, nativeTableType] = ani_rdbutils::DistributedTableTypeToNative(type);
    if (!isValidType) {
        ThrowParamError("type must be a DistributedTableType.");
        return;
    }
    auto [isValidConfig, nativeConfig] = ani_rdbutils::DistributedConfigToNative(config, nativeTableType);
    if (!isValidConfig) {
        ThrowParamError("config must be a DistributedConfig.");
        return;
    }
    if (nativeTableType == NativeDistributedTableType::DISTRIBUTED_CLOUD &&
        nativeConfig.tableType == NativeDistributedTableMode::DEVICE_COLLABORATION) {
        ThrowError(std::make_shared<InnerError>(
            OHOS::NativeRdb::E_NOT_SUPPORT, "The CloudDistributedTable is not support DEVICE_COLLABORATION."));
        return;
    }

    int errCode = store->SetDistributedTables(
        std::vector<std::string>(tables.begin(), tables.end()), nativeTableType, nativeConfig);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::SetDistributedTablesWithOptionConfig(
    array_view<string> tables, optional_view<DistributedType> type, optional_view<DistributedConfig> config)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    std::vector<std::string> tableList(tables.begin(), tables.end());
    NativeDistributedTableType nativeTableType = NativeDistributedTableType::DISTRIBUTED_DEVICE;
    NativeDistributedConfig nativeConfig = {true};
    if (type.has_value()) {
        auto [isValidType, nativeTableTypeTemp] = ani_rdbutils::DistributedTableTypeToNative(type.value());
        if (!isValidType) {
            ThrowParamError("type must be a DistributedTableType.");
            return;
        }
        nativeTableType = nativeTableTypeTemp;
    }
    if (config.has_value()) {
        auto [isValidConfig, nativeConfigTemp] =
            ani_rdbutils::DistributedConfigToNative(config.value(), nativeTableType);
        if (!isValidConfig) {
            ThrowParamError("config must be a DistributedConfig.");
            return;
        }
        nativeConfig = std::move(nativeConfigTemp);
    } else {
        nativeConfig.tableType = nativeTableType == NativeDistributedTableType::DISTRIBUTED_DEVICE
                                     ? NativeDistributedTableMode::DEVICE_COLLABORATION
                                     : NativeDistributedTableMode::SINGLE_VERSION;
    }
    if (nativeTableType == NativeDistributedTableType::DISTRIBUTED_CLOUD &&
        nativeConfig.tableType == NativeDistributedTableMode::DEVICE_COLLABORATION) {
        ThrowError(std::make_shared<InnerError>(
            OHOS::NativeRdb::E_NOT_SUPPORT, "The CloudDistributedTable is not support DEVICE_COLLABORATION."));
        return;
    }
    int errCode = store->SetDistributedTables(tableList, nativeTableType, nativeConfig);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

string RdbStoreImpl::ObtainDistributedTableNameSync(string_view device, string_view table)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), "");
    std::string deviceStr(device);
    std::string tableStr(table);
    int errCode;
    std::string distributedTableName = store->ObtainDistributedTableName(deviceStr, tableStr, errCode);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return "";
    }
    return distributedTableName;
}

void RdbStoreImpl::Sync(
    SyncMode mode, weak::RdbPredicates predicates, uintptr_t callback, ani_object &promise)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    ASSERT_RETURN_THROW_ERROR(rdbPredicateNative != nullptr,
        std::make_shared<ParamError>("predicates", "an RdbPredicates."), RDB_REVT_NOTHING);
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
    int errCode = store->Sync(option, *rdbPredicateNative, nativeSyncCallback);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
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
    int errCode = store->Sync(option, nativeTables, nativeProgressCallback);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::CloudSyncWithTable(
    SyncMode mode, array_view<string> tables, callback_view<void(ProgressDetails const &)> progress)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
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
    int errCode = store->Sync(option, nativeTables, nativeProgressCallback);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::CloudSyncWithPredicates(
    SyncMode mode, weak::RdbPredicates predicates, callback_view<void(ProgressDetails const &)> progress)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    if (!isSystemApp_) {
        ThrowNonSystemError();
        return;
    }
    OHOS::DistributedRdb::SyncOption option {
        .mode = ani_rdbutils::SyncModeToNative(mode),
        .isBlock = false
    };
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    ASSERT_RETURN_THROW_ERROR(rdbPredicateNative != nullptr,
        std::make_shared<ParamError>("predicates", "an RdbPredicates."), RDB_REVT_NOTHING);
    callback<void(ProgressDetails const &)> holder = progress;
    auto nativeProgressCallback =
        [holder](std::map<std::string, OHOS::DistributedRdb::ProgressDetail> &&nativeProgressMap) {
            for (auto &[key, nativeProgress] : nativeProgressMap) {
                auto taiheProgress = ani_rdbutils::ProgressDetailToTaihe(nativeProgress);
                holder(taiheProgress);
            }
        };
    int errCode = store->Sync(option, *rdbPredicateNative, nativeProgressCallback);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

ResultSet RdbStoreImpl::RemoteQuerySync(
    string_view device, string_view table, weak::RdbPredicates predicates, array_view<string> columns)
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(errCode), (make_holder<ResultSetImpl, ResultSet>()));
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    ASSERT_RETURN_THROW_ERROR(rdbPredicateNative != nullptr,
        std::make_shared<ParamError>("predicates", "an RdbPredicates."), (make_holder<ResultSetImpl, ResultSet>()));
    OHOS::NativeRdb::RdbStore::Fields fields;
    for (const auto &column : columns) {
        fields.push_back(std::string(column));
    }
    errCode = OHOS::NativeRdb::E_ERROR;
    auto resultSetNative = store->RemoteQuery(std::string(device), *rdbPredicateNative, fields, errCode);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    auto subscribeFunc = [this, store](std::shared_ptr<ani_rdbutils::TaiheSyncObserver> observer)->int32_t {
        auto errCode = store->RegisterAutoSyncCallback(observer);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    auto unSubscribeFunc = [this, store](std::shared_ptr<ani_rdbutils::TaiheSyncObserver> observer)->int32_t {
        auto errCode = store->UnregisterAutoSyncCallback(observer);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);

    auto eventNative = std::string(event);
    if (event.empty()) {
        ThrowError(std::make_shared<ParamError>("event", "a not empty string."));
        return;
    }
    auto subscribeMode = OHOS::DistributedRdb::SubscribeMode::LOCAL;
    if (interProcess) {
        subscribeMode = OHOS::DistributedRdb::SubscribeMode::LOCAL_SHARED;
    }
    auto subscribeFunc = [subscribeMode, &eventNative, this, store](
        std::shared_ptr<ani_rdbutils::TaiheRdbStoreObserver> observer)->int32_t {
        OHOS::DistributedRdb::SubscribeOption option;
        option.mode = subscribeMode;
        option.event = eventNative;
        auto errCode = store->Subscribe(option, observer);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    auto eventNative = std::string(event);
    if (event.empty()) {
        ThrowError(std::make_shared<ParamError>("event", "a not empty string."));
        return;
    }
    auto subscribeMode = OHOS::DistributedRdb::SubscribeMode::LOCAL;
    if (interProcess) {
        subscribeMode = OHOS::DistributedRdb::SubscribeMode::LOCAL_SHARED;
    }
    auto unSubscribeFunc = [subscribeMode, &eventNative, this, store](
        std::shared_ptr<ani_rdbutils::TaiheRdbStoreObserver> observer)->int32_t {
        OHOS::DistributedRdb::SubscribeOption option;
        option.mode = subscribeMode;
        option.event = eventNative;
        auto errCode = store->UnsubscribeObserver(option, observer);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    if (store->GetDbType() != NativeRdb::DB_SQLITE) {
        ThrowInnerError(OHOS::NativeRdb::E_NOT_SUPPORT);
        return;
    }
    auto subscribeFunc = [this, store](std::shared_ptr<ani_rdbutils::TaiheLogObserver> observer)->int32_t {
        auto errCode = NativeRdb::SqlLog::Subscribe(store->GetPath(), observer);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    if (store->GetDbType() != NativeRdb::DB_SQLITE) {
        ThrowInnerError(OHOS::NativeRdb::E_NOT_SUPPORT);
        return;
    }
    auto unSubscribeFunc = [this, store](std::shared_ptr<ani_rdbutils::TaiheLogObserver> observer)->int32_t {
        auto errCode = NativeRdb::SqlLog::Unsubscribe(store->GetPath(), observer);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    if (store->GetDbType() != NativeRdb::DB_SQLITE) {
        ThrowInnerError(OHOS::NativeRdb::E_NOT_SUPPORT);
        return;
    }
    auto subscribeFunc = [this, store](std::shared_ptr<ani_rdbutils::TaiheSqlObserver> observer)->int32_t {
        auto errCode = DistributedRdb::PerfStat::Subscribe(store->GetPath(), observer);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    if (store->GetDbType() != NativeRdb::DB_SQLITE) {
        ThrowInnerError(OHOS::NativeRdb::E_NOT_SUPPORT);
        return;
    }
    auto unSubscribeFunc = [this, store](std::shared_ptr<ani_rdbutils::TaiheSqlObserver> observer)->int32_t {
        auto errCode = DistributedRdb::PerfStat::Unsubscribe(store->GetPath(), observer);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    int errCode = store->Notify(std::string(event));
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::CloseSync()
{
    auto store = ResetResource();
    if (store == nullptr) {
        LOG_ERROR("store is nullptr");
        return;
    }
    UnRegisterAll(store);
}

int32_t RdbStoreImpl::AttachWithWaitTime(string_view fullPath, string_view attachName,
    taihe::optional_view<int32_t> waitTime)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), 0);
    std::string fullPathStr(fullPath);
    std::string attachNameStr(attachName);
    int32_t waitTimeNative = WAIT_TIME_DEFAULT;
    if (waitTime.has_value()) {
        waitTimeNative = waitTime.value();
        if (waitTimeNative < WAIT_TIME_MIN || waitTimeNative > WAIT_TIME_MAX) {
            ThrowParamError("waitTime cannot exceed 300s.");
            return 0;
        }
    }
    OHOS::NativeRdb::RdbStoreConfig config(fullPathStr);
    auto [errCode, output] = store->Attach(config, attachNameStr, waitTimeNative);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return 0;
    }
    return output;
}

int32_t RdbStoreImpl::AttachWithContext(
    uintptr_t context, StoreConfig const &config, string_view attachName, optional_view<int32_t> waitTime)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), 0);

    ani_env *env = get_env();
    OHOS::AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig = ani_rdbutils::AniGetRdbConfig(config);
    auto configRet = ani_rdbutils::AniGetRdbStoreConfig(env, reinterpret_cast<ani_object>(context), rdbConfig);
    if (configRet.first != OK) {
        ThrowInnerErrorExt(configRet.first);
        return 0;
    }

    std::string attachNameStr(attachName);
    int32_t waitTimeValue = WAIT_TIME_DEFAULT;
    if (waitTime.has_value()) {
        waitTimeValue = waitTime.value();
        if (waitTimeValue < WAIT_TIME_MIN || waitTimeValue > WAIT_TIME_MAX) {
            ThrowParamError("waitTime cannot exceed 300s.");
            return 0;
        }
    }

    auto [errCode, output] = store->Attach(configRet.second, attachNameStr, waitTimeValue);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return 0;
    }
    return output;
}

int32_t RdbStoreImpl::DetachSync(string_view attachName, optional_view<int32_t> waitTime)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), ERR_NULL);
    if (waitTime.has_value()) {
        int32_t waitTimeValue = waitTime.value();
        auto [errCode, output] = store->Detach(std::string(attachName), waitTimeValue);
        if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
            return 0;
        }
        return output;
    } else {
        auto [errCode, output] = store->Detach(std::string(attachName));
        if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
            return 0;
        }
        return output;
    }
}

void RdbStoreImpl::LockRowSync(weak::RdbPredicates predicates)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    ASSERT_RETURN_THROW_ERROR(rdbPredicateNative != nullptr,
        std::make_shared<ParamError>("predicates", "an RdbPredicates."), RDB_REVT_NOTHING);
    if (rdbPredicateNative.get() != nullptr) {
        int errCode = store->ModifyLockStatus(*rdbPredicateNative, true);
        if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
    } else {
        LOG_ERROR("rdbPredicateNative.get() is nullptr");
    }
}

void RdbStoreImpl::UnlockRowSync(weak::RdbPredicates predicates)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    ASSERT_RETURN_THROW_ERROR(rdbPredicateNative != nullptr,
        std::make_shared<ParamError>("predicates", "an RdbPredicates."), RDB_REVT_NOTHING);
    if (rdbPredicateNative.get() != nullptr) {
        int errCode = store->ModifyLockStatus(*rdbPredicateNative, false);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(errCode), (make_holder<ResultSetImpl, ResultSet>()));
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    ASSERT_RETURN_THROW_ERROR(rdbPredicateNative != nullptr,
        std::make_shared<ParamError>("predicates", "an RdbPredicates."), (make_holder<ResultSetImpl, ResultSet>()));
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
    auto resultSetNative = store->QueryByStep(*rdbPredicateNative, fields);
    if (resultSetNative == nullptr) {
        ThrowInnerError(OHOS::NativeRdb::E_ERROR);
    }
    return make_holder<ResultSetImpl, ResultSet>(resultSetNative);
}

int32_t RdbStoreImpl::LockCloudContainerSync()
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), 0);
    if (!isSystemApp_) {
        ThrowNonSystemError();
        return 0;
    }
    auto [errCode, output] = store->LockCloudContainer();
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return 0;
    }
    return output;
}

void RdbStoreImpl::UnlockCloudContainerSync()
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    if (!isSystemApp_) {
        ThrowNonSystemError();
        return;
    }
    int errCode = store->UnlockCloudContainer();
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

Transaction RdbStoreImpl::CreateTransactionSync(
    optional_view<::ohos::data::relationalStore::TransactionOptions> options)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED),
        (make_holder<TransactionImpl, Transaction>()));
    int32_t transactionType = 0;
    if (options.has_value()) {
        auto optType = options.value();
        if (optType.transactionType.has_value()) {
            transactionType = (int)(optType.transactionType.value());
        }
    }
    auto [errCode, transaction] = store->CreateTransaction(transactionType);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return make_holder<TransactionImpl, Transaction>();
    }
    ASSERT_RETURN_THROW_ERROR(transaction != nullptr, std::make_shared<InnerError>(NativeRdb::E_ERROR),
        (make_holder<TransactionImpl, Transaction>()));
    return make_holder<TransactionImpl, Transaction>(transaction);
}

Result RdbStoreImpl::BatchInsertWithReturningSync(string_view table, array_view<ValuesBucket> values,
    ReturningConfig const &config, optional_view<ConflictResolution> conflict)
{
    auto store = GetResource();
    return BatchInsertWithReturning(store, table, values, config, conflict);
}

Result RdbStoreImpl::UpdateWithReturningSync(ValuesBucket values, weak::RdbPredicates predicates,
    ReturningConfig const &config, optional_view<ConflictResolution> conflict)
{
    auto store = GetResource();
    return UpdateWithReturning(store, values, predicates, config, conflict);
}

Result RdbStoreImpl::DeleteWithReturningSync(weak::RdbPredicates predicates, ReturningConfig const &config)
{
    auto store = GetResource();
    return DeleteWithReturning(store, predicates, config);
}

int64_t RdbStoreImpl::BatchInsertWithConflictResolutionSync(taihe::string_view table,
    taihe::array_view<ohos::data::relationalStore::ValuesBucket> values,
    ohos::data::relationalStore::ConflictResolution conflict)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), ERR_NULL);
    OHOS::NativeRdb::ValuesBuckets buckets;
    for (const auto &valuesBucket : values) {
        buckets.Put(ani_rdbutils::MapValuesToNative(
            valuesBucket.get_ref<ohos::data::relationalStore::ValuesBucket::tag_t::VALUESBUCKET>()));
    }
    auto conflictResolution = ani_rdbutils::ConflictResolutionToNative(conflict);
    auto [errCode, output] = store->BatchInsert(std::string(table), buckets, conflictResolution);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
        return ERR_NULL;
    }
    return output;
}

void RdbStoreImpl::RekeySync(taihe::optional_view<ohos::data::relationalStore::CryptoParam> cryptoParam)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    NativeRdb::RdbStoreConfig::CryptoParam cryptoParamNative;
    if (cryptoParam.has_value()) {
        cryptoParamNative = ani_rdbutils::CryptoParamToNative(cryptoParam.value());
    }
    ASSERT_RETURN_THROW_ERROR(cryptoParamNative.IsValid(),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Illegal CryptoParam."), RDB_REVT_NOTHING);
    auto errCode = store->Rekey(cryptoParamNative);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::RekeyExSync(ohos::data::relationalStore::CryptoParam const& cryptoParam)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    auto cryptoParamNative = ani_rdbutils::CryptoParamToNative(cryptoParam);
    ASSERT_RETURN_THROW_ERROR(cryptoParamNative.IsValid(),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Illegal CryptoParam."), RDB_REVT_NOTHING);
    auto errCode = store->RekeyEx(cryptoParamNative);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

void RdbStoreImpl::SetLocaleSync(taihe::string_view locale)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    auto localeNative = std::string(locale);
    ASSERT_RETURN_THROW_ERROR(!localeNative.empty(),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "locale cannot be empty"), RDB_REVT_NOTHING);
    auto errCode = store->ConfigLocale(localeNative);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
}

template<class FuncType>
void RdbStoreImpl::OnDataChangeCommon(OHOS::DistributedRdb::SubscribeMode subscribeMode,
    FuncType callback, uintptr_t opq)
{
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    if (subscribeMode < 0 || subscribeMode >= DistributedRdb::SubscribeMode::SUBSCRIBE_MODE_MAX) {
        ThrowError(std::make_shared<ParamError>("type", "SubscribeType"));
        return;
    }
    auto subscribeFunc = [subscribeMode, this, store](
        std::shared_ptr<ani_rdbutils::TaiheRdbStoreObserver> observer)->int32_t {
        OHOS::DistributedRdb::SubscribeOption option;
        option.mode = subscribeMode;
        option.event = ani_rdbutils::EVENT_DATA_CHANGE;
        if (option.mode == OHOS::DistributedRdb::SubscribeMode::LOCAL_DETAIL) {
            auto errCode = store->SubscribeObserver(option, observer);
            if (errCode == OHOS::NativeRdb::E_OK) {
                LOG_INFO("SubscribeObserver success.");
            } else {
                LOG_ERROR("SubscribeObserver failed, %{public}d.", errCode);
            }
            return errCode;
        } else {
            auto errCode = store->Subscribe(option, observer);
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
    auto store = GetResource();
    ASSERT_RETURN_THROW_ERROR(store != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), RDB_DO_NOTHING);
    if (subscribeMode < 0 || subscribeMode >= DistributedRdb::SubscribeMode::SUBSCRIBE_MODE_MAX) {
        ThrowError(std::make_shared<ParamError>("type", "SubscribeType"));
        return;
    }
    auto unSubscribeFunc = [subscribeMode, this, store](
        std::shared_ptr<ani_rdbutils::TaiheRdbStoreObserver> observer)->int32_t {
        OHOS::DistributedRdb::SubscribeOption option;
        option.mode = subscribeMode;
        option.event = ani_rdbutils::EVENT_DATA_CHANGE;
        if (option.mode == OHOS::DistributedRdb::SubscribeMode::LOCAL_DETAIL) {
            auto errCode = store->UnsubscribeObserver(option, observer);
            if (errCode == OHOS::NativeRdb::E_OK) {
                LOG_INFO("UnsubscribeObserver success.");
            } else {
                LOG_ERROR("UnsubscribeObserver failed, %{public}d.", errCode);
            }
            return errCode;
        } else {
            auto errCode = store->UnSubscribe(option, observer);
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

void RdbStoreImpl::UnRegisterAll(std::shared_ptr<NativeRdb::RdbStore> store)
{
    if (store == nullptr) {
        return;
    }

    std::unique_lock<std::mutex> locker(rdbObserversData_.rdbObserversMutex_);
    UnRegisterDataChange(store);
    for (auto &obs : rdbObserversData_.syncObservers_) {
        store->UnregisterAutoSyncCallback(obs);
    }
    rdbObserversData_.syncObservers_.clear();
    for (auto &obs : rdbObserversData_.statisticses_) {
        DistributedRdb::SqlStatistic::Unsubscribe(obs);
    }
    rdbObserversData_.statisticses_.clear();
    for (auto &obs : rdbObserversData_.logObservers_) {
        NativeRdb::SqlLog::Unsubscribe(store->GetPath(), obs);
    }
    rdbObserversData_.logObservers_.clear();
}

void RdbStoreImpl::UnRegisterDataChange(std::shared_ptr<NativeRdb::RdbStore> store)
{
    for (int32_t mode = DistributedRdb::SubscribeMode::REMOTE;
        mode < DistributedRdb::SubscribeMode::LOCAL; mode++) {
        for (auto &obs : rdbObserversData_.observers_[mode]) {
            if (obs == nullptr) {
                continue;
            }
            store->UnSubscribe({ static_cast<DistributedRdb::SubscribeMode>(mode) }, obs);
        }
        rdbObserversData_.observers_[mode].clear();
    }
    for (auto &obs : rdbObserversData_.observers_[DistributedRdb::SubscribeMode::LOCAL_DETAIL]) {
        if (obs == nullptr) {
            continue;
        }
        store->UnsubscribeObserver({ DistributedRdb::SubscribeMode::LOCAL_DETAIL }, obs);
    }
    rdbObserversData_.observers_[DistributedRdb::SubscribeMode::LOCAL_DETAIL].clear();
    for (const auto &[event, observers] : rdbObserversData_.localObservers_) {
        for (const auto &obs : observers) {
            if (obs == nullptr) {
                continue;
            }
            store->UnSubscribe(
                { static_cast<DistributedRdb::SubscribeMode>(DistributedRdb::LOCAL), event }, obs);
        }
    }
    rdbObserversData_.localObservers_.clear();
    for (const auto &[event, observers] : rdbObserversData_.localSharedObservers_) {
        for (const auto &obs : observers) {
            if (obs == nullptr) {
                continue;
            }
            store->UnSubscribe(
                { static_cast<DistributedRdb::SubscribeMode>(DistributedRdb::LOCAL_SHARED), event }, obs);
        }
    }
    rdbObserversData_.localSharedObservers_.clear();
}
}
}