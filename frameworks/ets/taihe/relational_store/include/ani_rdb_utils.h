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
#ifndef OHOS_RELATION_STORE_ANI_RDB_UTILS_H_
#define OHOS_RELATION_STORE_ANI_RDB_UTILS_H_

#include <functional>
#include <memory>

#include "napi_rdb_js_utils.h"
#include "ohos.data.relationalStore.proj.hpp"
#include "rdb_store.h"
#include "rdb_types.h"
#include "result_set.h"
#include "taihe/runtime.hpp"
#include "value_object.h"

namespace ani_rdbutils {
using namespace OHOS;
using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;
using JsChangeInfoCallbackType = taihe::callback<void(taihe::array_view<ohos::data::relationalStore::ChangeInfo>)>;
using JsDevicesCallbackType = taihe::callback<void(taihe::array_view<taihe::string>)>;
using JsSqlExecutionCallbackType = taihe::callback<void(ohos::data::relationalStore::SqlExecutionInfo const& info)>;
using JsVoidCallbackType = taihe::callback<void()>;
using JsProgressDetailsCallbackType = taihe::callback<void(ohos::data::relationalStore::ProgressDetails const& info)>;
using JsExceptionMessageCallbackType =
    taihe::callback<void(ohos::data::relationalStore::ExceptionMessage const& info)>;
using RdbStoreVarCallbackType = std::variant<JsDevicesCallbackType, JsChangeInfoCallbackType, JsVoidCallbackType>;
using NativeDistributedConfig = OHOS::DistributedRdb::DistributedConfig;
using TaiheDistributedConfig = ohos::data::relationalStore::DistributedConfig;
using NativeDistributedTableType = OHOS::DistributedRdb::DistributedTableType;
using TaiheDistributedType = ohos::data::relationalStore::DistributedType;

constexpr std::string_view EVENT_DATA_CHANGE = "dataChange";

OHOS::NativeRdb::AssetValue::Status AssetStatusToNative(ohos::data::relationalStore::AssetStatus const &assetStatus);
ohos::data::relationalStore::AssetStatus AssetStatusToAni(OHOS::NativeRdb::AssetValue::Status const &status);
OHOS::NativeRdb::AssetValue AssetToNative(::ohos::data::relationalStore::Asset const &asset);
::ohos::data::relationalStore::Asset AssetToAni(OHOS::NativeRdb::AssetValue const &value);
OHOS::NativeRdb::ValueObject ValueTypeToNative(::ohos::data::relationalStore::ValueType const &value);
::ohos::data::relationalStore::ValueType ValueObjectToAni(OHOS::NativeRdb::ValueObject const &valueObj);
ohos::data::relationalStore::ValuesBucket ValuesBucketToAni(OHOS::NativeRdb::ValuesBucket const &valuesBucket);
OHOS::NativeRdb::ValuesBucket MapValuesToNative(
    taihe::map_view<taihe::string, ::ohos::data::relationalStore::ValueType> const &values);
std::vector<OHOS::NativeRdb::ValueObject> ArrayValuesToNative(
    taihe::array_view<::ohos::data::relationalStore::ValueType> const &values);
OHOS::NativeRdb::ValuesBuckets BucketValuesToNative(
    taihe::array_view<taihe::map<taihe::string, ::ohos::data::relationalStore::ValueType>> const &values);
OHOS::NativeRdb::ValuesBuckets ValueBucketsToNative(
    taihe::array_view<::ohos::data::relationalStore::ValuesBucket> const &values);
OHOS::NativeRdb::ValuesBucket ValueBucketToNative(::ohos::data::relationalStore::ValuesBucket const &value);
OHOS::NativeRdb::RdbStoreConfig::CryptoParam CryptoParamToNative(
    ::ohos::data::relationalStore::CryptoParam const &param);
void AniGetRdbConfigAppend(const ohos::data::relationalStore::StoreConfig &storeConfig,
    OHOS::AppDataMgrJsKit::JSUtils::RdbConfig &storeConfigNative);
OHOS::AppDataMgrJsKit::JSUtils::RdbConfig AniGetRdbConfig(
    ::ohos::data::relationalStore::StoreConfig const &storeConfig);
std::pair<bool, OHOS::NativeRdb::RdbStoreConfig> AniGetRdbStoreConfig(
    ani_env *env, ani_object aniValue, OHOS::AppDataMgrJsKit::JSUtils::RdbConfig &rdbConfig);

OHOS::NativeRdb::ReturningConfig ReturningConfigToNative(
    ::ohos::data::relationalStore::ReturningConfig returningConfig);

OHOS::DistributedRdb::SubscribeMode SubscribeTypeToMode(ohos::data::relationalStore::SubscribeType type);
std::pair<bool, NativeDistributedTableType> DistributedTableTypeToNative(TaiheDistributedType type);
std::pair<bool, NativeDistributedConfig> DistributedConfigToNative(
    const TaiheDistributedConfig &config, NativeDistributedTableType &nativeType);
OHOS::DistributedRdb::Reference ReferenceToNative(
    const ohos::data::relationalStore::Reference &reference);
ohos::data::relationalStore::ProgressDetails ProgressDetailToTaihe(
    const OHOS::DistributedRdb::ProgressDetail &OrgDetails);
OHOS::DistributedRdb::RdbStoreObserver::PrimaryKey PRIKeyToNative(
    const ohos::data::relationalStore::PRIKeyType &priKey);
ohos::data::relationalStore::PRIKeyType ToNativePRIKeyType(
    const OHOS::DistributedRdb::RdbStoreObserver::PrimaryKey &priKey);
ohos::data::relationalStore::ModifyTime ToAniModifyTime(
    const std::map<OHOS::NativeRdb::RdbStore::PRIKey, OHOS::NativeRdb::RdbStore::Date> &mapResult);
ohos::data::relationalStore::Origin OriginToTaihe(const OHOS::DistributedRdb::Origin &origin);
ohos::data::relationalStore::ChangeType ToAniChangeType(const OHOS::DistributedRdb::Origin &origin);
::ohos::data::relationalStore::StringOrNumberArray VectorToAniArrayType(
    const std::vector<OHOS::DistributedRdb::RdbStoreObserver::PrimaryKey> &array);
taihe::array<ohos::data::relationalStore::ChangeInfo> RdbChangeInfoToTaihe(
    const OHOS::DistributedRdb::Origin &origin,
    const OHOS::DistributedRdb::RdbStoreObserver::ChangeInfo &changeInfo);
::taihe::array_view<::taihe::string> VectorToTaiheArray(const std::vector<std::string> &vec);
ohos::data::relationalStore::SqlExecutionInfo SqlExecutionToTaihe(
    const OHOS::DistributedRdb::SqlObserver::SqlExecutionInfo &sqlInfo);
ohos::data::relationalStore::Statistic StatisticToTaihe(const OHOS::DistributedRdb::Statistic &statistic);

uintptr_t ColumnTypeToTaihe(const OHOS::DistributedRdb::ColumnType columnType);
OHOS::DistributedRdb::SyncMode SyncModeToNative(ohos::data::relationalStore::SyncMode syncMode);
OHOS::NativeRdb::ConflictResolution ConflictResolutionToNative(
    ohos::data::relationalStore::ConflictResolution conflictResolution);
OHOS::NativeRdb::Tokenizer TokenizerToNative(ohos::data::relationalStore::Tokenizer tokenizer);

ohos::data::relationalStore::SqlInfo SqlInfoToTaihe(const OHOS::NativeRdb::SqlInfo &sqlInfo);
ohos::data::relationalStore::ExceptionMessage ExceptionMessageToTaihe(
    const OHOS::DistributedRdb::SqlErrorObserver::ExceptionMessage &exceptionMessage);

bool HasDuplicateAssets(const OHOS::NativeRdb::ValueObject &value);
bool HasDuplicateAssets(const std::vector<OHOS::NativeRdb::ValueObject> &values);
bool HasDuplicateAssets(const OHOS::NativeRdb::ValuesBucket &value);
bool HasDuplicateAssets(const std::vector<OHOS::NativeRdb::ValuesBucket> &values);
bool HasDuplicateAssets(const OHOS::NativeRdb::ValuesBuckets &values);

std::shared_ptr<OHOS::NativeRdb::RdbPredicates> GetNativePredicatesFromTaihe(
    ohos::data::relationalStore::weak::RdbPredicates predicates);

std::pair<int, std::vector<RowEntity>> GetRows(
    OHOS::NativeRdb::ResultSet &resultSet, int32_t maxCount, int32_t position);
bool WarpDate(double time, ani_object &outObj);
} // namespace ani_rdbutils

#endif