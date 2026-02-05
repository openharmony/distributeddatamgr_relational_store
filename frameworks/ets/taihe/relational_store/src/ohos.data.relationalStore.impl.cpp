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
#define LOG_TAG "AniRelationalStoreImpl"
#include "ohos.data.relationalStore.impl.h"

#include "abs_rdb_predicates.h"
#include "ani_rdb_utils.h"
#include "ani_utils.h"
#include "datashare_abs_predicates.h"
#include "js_proxy.h"
#include "lite_result_set_impl.h"
#include "lite_result_set_proxy.h"
#include "logger.h"
#include "napi_rdb_js_utils.h"
#include "ohos.data.relationalStore.impl.hpp"
#include "ohos.data.relationalStore.proj.hpp"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_predicates.h"
#include "rdb_predicates_impl.h"
#include "rdb_result_set_bridge.h"
#include "rdb_sql_utils.h"
#include "rdb_store_config.h"
#include "rdb_store_impl.h"
#include "rdb_types.h"
#include "rdb_utils.h"
#include "result_set_bridge.h"
#include "result_set_impl.h"
#include "result_set_proxy.h"
#include "stdexcept"
#include "taihe/runtime.hpp"
#include "transaction_impl.h"

using namespace taihe;
using namespace ohos::data::relationalStore;
using namespace OHOS::RelationalStoreJsKit;
using RdbSqlUtils = OHOS::NativeRdb::RdbSqlUtils;
namespace OHOS {
namespace RdbTaihe {
using namespace OHOS;
using namespace OHOS::Rdb;
using namespace OHOS::RdbTaihe;
using ValueType = ohos::data::relationalStore::ValueType;
using ValueObject = OHOS::NativeRdb::ValueObject;
using ConfigVersion =  OHOS::NativeRdb::ConfigVersion;

constexpr int32_t PARAM_LENGTH_MAX = 256;
constexpr int32_t VALUESBUCKET_LENGTH_MAX = 1000;

RdbPredicates CreateRdbPredicates(string_view name)
{
    return make_holder<RdbPredicatesImpl, RdbPredicates>(std::string(name));
}

RdbStore GetRdbStoreInner(uintptr_t context, StoreConfig const &config)
{
    return make_holder<RdbStoreImpl, RdbStore>(
        reinterpret_cast<ani_object>(context), config, ConfigVersion::DEFAULT_VERSION);
}

RdbStore GetRdbStoreSync(uintptr_t context, StoreConfig const &config)
{
    return make_holder<RdbStoreImpl, RdbStore>(
        reinterpret_cast<ani_object>(context), config, ConfigVersion::INVALID_CONFIG_CHANGE_NOT_ALLOWED);
}

void DeleteRdbStoreWithName(uintptr_t context, string_view name)
{
    ani_env *env = get_env();
    if (env == nullptr) {
        LOG_ERROR("get_env failed");
        return;
    }
    OHOS::AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig;
    OHOS::NativeRdb::RdbStoreConfig storeConfig
    rdbConfig.name = std::string(name);
    int errorCode =
        ani_rdbutils::AniGetRdbStoreConfig(env, reinterpret_cast<ani_object>(context), rdbConfig, storeConfig);
    if (errorCode != OK) {
        LOG_ERROR("AniGetRdbStoreConfig failed");
        ThrowInnerErrorExt(errorCode);
    }
    storeConfig.SetDBType(OHOS::NativeRdb::DBType::DB_SQLITE);
    int errCodeSqlite = OHOS::NativeRdb::RdbHelper::DeleteRdbStore(storeConfig, false);
    storeConfig.SetDBType(OHOS::NativeRdb::DBType::DB_VECTOR);
    int errCodeVector = OHOS::NativeRdb::RdbHelper::DeleteRdbStore(storeConfig, false);
    LOG_INFO("deleteRdbStoreWithName sqlite %{public}d, vector %{public}d", errCodeSqlite, errCodeVector);
    if (errCodeSqlite != NativeRdb::E_OK || errCodeVector != NativeRdb::E_OK) {
        ThrowInnerError(NativeRdb::E_REMOVE_FILE);
    }
}

void DeleteRdbStoreWithConfig(uintptr_t context, StoreConfig const &config)
{
    ani_env *env = get_env();
    if (env == nullptr) {
        LOG_ERROR("get_env failed");
        return;
    }
    OHOS::AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig = ani_rdbutils::AniGetRdbConfig(config);
    OHOS::NativeRdb::RdbStoreConfig storeConfig;
    int errorCode =
        ani_rdbutils::AniGetRdbStoreConfig(env, reinterpret_cast<ani_object>(context), rdbConfig, storeConfig);
    if (errorCode != OK) {
        LOG_ERROR("AniGetRdbStoreConfig failed");
        ThrowInnerErrorExt(errorCode);
    }

    int errCode = OHOS::NativeRdb::RdbHelper::DeleteRdbStore(storeConfig, false);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
    LOG_INFO("deleteRdbStoreWithConfig errCode %{public}d", errCode);
}

bool IsVectorSupported()
{
    return OHOS::NativeRdb::RdbHelper::IsSupportArkDataDb();
}

bool IsTokenizerSupported(ohos::data::relationalStore::Tokenizer tokenizer)
{
    return OHOS::NativeRdb::RdbHelper::IsSupportedTokenizer(ani_rdbutils::TokenizerToNative(tokenizer));
}

SqlInfo GetInsertSqlInfo(string_view table, ValuesBucket const &values, optional_view<ConflictResolution> conflict)
{
    auto tableNative = std::string(table);
    if (tableNative.size() == 0) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "The table must be not empty string."));
        return SqlInfo{};
    }
    if (tableNative.size() > PARAM_LENGTH_MAX) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Table is too long."));
        return SqlInfo{};
    }
    auto valuesNative = ani_rdbutils::ValueBucketToNative(values);
    if (valuesNative.IsEmpty()) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Bucket must not be empty."));
        return SqlInfo{};
    }
    if (valuesNative.Size() > VALUESBUCKET_LENGTH_MAX) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "ValuesBucket is too long."));
        return SqlInfo{};
    }
    for (const auto &[key, val] : valuesNative.values_) {
        if (key.size() > PARAM_LENGTH_MAX) {
            ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "ValuesBucket is too long."));
            return SqlInfo{};
        }
    }
    auto conflictNative = NativeRdb::ConflictResolution::ON_CONFLICT_NONE;
    if (conflict.has_value()) {
        conflictNative = ani_rdbutils::ConflictResolutionToNative(conflict.value());
    }
    auto [errcode, sqlInfo] = RdbSqlUtils::GetInsertSqlInfo(tableNative, valuesNative, conflictNative);
    if (errcode != NativeRdb::E_OK) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, GetErrorString(errcode)));
    }
    return ani_rdbutils::SqlInfoToTaihe(sqlInfo);
}

SqlInfo GetUpdateSqlInfo(
    weak::RdbPredicates predicates, ValuesBucket const &values, optional_view<ConflictResolution> conflict)
{
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Predicates is empty."));
        return SqlInfo{};
    }
    if (rdbPredicateNative->GetWhereClause().size() > PARAM_LENGTH_MAX) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Columns in predicates is too much."));
        return SqlInfo{};
    }
    auto tableNative = rdbPredicateNative->GetTableName();
    if (tableNative.size() == 0) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "The table must be not empty string."));
        return SqlInfo{};
    }
    if (tableNative.size() > PARAM_LENGTH_MAX) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Table is too long."));
        return SqlInfo{};
    }
    auto valuesNative = ani_rdbutils::ValueBucketToNative(values);
    if (valuesNative.IsEmpty()) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Bucket must not be empty."));
        return SqlInfo{};
    }
    if (valuesNative.Size() > VALUESBUCKET_LENGTH_MAX) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "ValuesBucket is too long."));
        return SqlInfo{};
    }
    for (const auto &[key, val] : valuesNative.values_) {
        if (key.size() > PARAM_LENGTH_MAX) {
            ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "ValuesBucket is too long."));
            return SqlInfo{};
        }
    }
    auto conflictNative = NativeRdb::ConflictResolution::ON_CONFLICT_NONE;
    if (conflict.has_value()) {
        conflictNative = ani_rdbutils::ConflictResolutionToNative(conflict.value());
    }
    auto [errcode, sqlInfo] = RdbSqlUtils::GetUpdateSqlInfo(*rdbPredicateNative, valuesNative, conflictNative);
    if (errcode != NativeRdb::E_OK) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, GetErrorString(errcode)));
    }
    return ani_rdbutils::SqlInfoToTaihe(sqlInfo);
}

SqlInfo GetDeleteSqlInfo(weak::RdbPredicates predicates)
{
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Predicates is empty."));
        return SqlInfo{};
    }
    if (rdbPredicateNative->GetWhereClause().size() > PARAM_LENGTH_MAX) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Columns in predicates is too much."));
        return SqlInfo{};
    }
    auto tableNative = rdbPredicateNative->GetTableName();
    if (tableNative.size() == 0) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "The table must be not empty string."));
        return SqlInfo{};
    }
    if (tableNative.size() > PARAM_LENGTH_MAX) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Table is too long."));
        return SqlInfo{};
    }
    auto [errcode, sqlInfo] = RdbSqlUtils::GetDeleteSqlInfo(*rdbPredicateNative);
    if (errcode != NativeRdb::E_OK) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, GetErrorString(errcode)));
    }
    return ani_rdbutils::SqlInfoToTaihe(sqlInfo);
}

int32_t CheckAndTransfromColumns(const optional_view<array<string>> &columns, std::vector<std::string> &columnsNative)
{
    columnsNative.clear();
    if (columns.has_value()) {
        if (columns.value().size() > VALUESBUCKET_LENGTH_MAX) {
            ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Columns is too long."));
            return NativeRdb::E_ERROR;
        }
        for (const auto &column : columns.value()) {
            if (column.size() > PARAM_LENGTH_MAX) {
                ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Columns is too long."));
                return NativeRdb::E_ERROR;
            } else {
                columnsNative.push_back(std::string(column));
            }
        }
    }
    return NativeRdb::E_OK;
}

SqlInfo GetQuerySqlInfo(weak::RdbPredicates predicates, optional_view<array<string>> columns)
{
    auto rdbPredicateNative = ani_rdbutils::GetNativePredicatesFromTaihe(predicates);
    if (rdbPredicateNative == nullptr) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Predicates is empty."));
        return SqlInfo{};
    }
    if (rdbPredicateNative->GetWhereClause().size() > PARAM_LENGTH_MAX) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Columns in predicates is too much."));
        return SqlInfo{};
    }
    auto tableNative = rdbPredicateNative->GetTableName();
    if (tableNative.size() == 0) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "The table must be not empty string."));
        return SqlInfo{};
    }
    if (tableNative.size() > PARAM_LENGTH_MAX) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Table is too long."));
        return SqlInfo{};
    }
    std::vector<std::string> columnsNative;
    if (CheckAndTransfromColumns(columns, columnsNative) != NativeRdb::E_OK) {
        return SqlInfo{};
    }
    auto [errcode, sqlInfo] = RdbSqlUtils::GetQuerySqlInfo(*rdbPredicateNative, columnsNative);
    if (errcode != NativeRdb::E_OK) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, GetErrorString(errcode)));
    }
    return ani_rdbutils::SqlInfoToTaihe(sqlInfo);
}
} // namespace RdbTaihe
} // namespace OHOS

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateRdbPredicates(OHOS::RdbTaihe::CreateRdbPredicates);
TH_EXPORT_CPP_API_GetRdbStoreInner(OHOS::RdbTaihe::GetRdbStoreInner);
TH_EXPORT_CPP_API_GetRdbStoreSync(OHOS::RdbTaihe::GetRdbStoreSync);
TH_EXPORT_CPP_API_DeleteRdbStoreWithName(OHOS::RdbTaihe::DeleteRdbStoreWithName);
TH_EXPORT_CPP_API_DeleteRdbStoreWithConfig(OHOS::RdbTaihe::DeleteRdbStoreWithConfig);
TH_EXPORT_CPP_API_IsVectorSupported(OHOS::RdbTaihe::IsVectorSupported);
TH_EXPORT_CPP_API_IsTokenizerSupported(OHOS::RdbTaihe::IsTokenizerSupported);
TH_EXPORT_CPP_API_GetInsertSqlInfo(OHOS::RdbTaihe::GetInsertSqlInfo);
TH_EXPORT_CPP_API_GetUpdateSqlInfo(OHOS::RdbTaihe::GetUpdateSqlInfo);
TH_EXPORT_CPP_API_GetDeleteSqlInfo(OHOS::RdbTaihe::GetDeleteSqlInfo);
TH_EXPORT_CPP_API_GetQuerySqlInfo(OHOS::RdbTaihe::GetQuerySqlInfo);
// NOLINTEND
