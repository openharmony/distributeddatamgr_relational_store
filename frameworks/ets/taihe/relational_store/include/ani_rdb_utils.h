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
#include "ohos.data.relationalStore.impl.hpp"
#include "ohos.data.relationalStore.proj.hpp"
#include "rdb_store.h"
#include "rdb_types.h"
#include "result_set.h"
#include "taihe/runtime.hpp"
#include "value_object.h"

namespace ani_rdbutils {
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
constexpr std::string_view EVENT_SYNC_PROGRESS = "autoSyncProgress";
constexpr std::string_view EVENT_STATISTICS = "statistics";

enum {
    /* exported js SubscribeType */
    SUBSCRIBE_REMOTE = 0,
    SUBSCRIBE_CLOUD = 1,
    SUBSCRIBE_CLOUD_DETAILS = 2,
    SUBSCRIBE_LOCAL_DETAILS = 3,
    SUBSCRIBE_COUNT = 4
};

class GlobalRefGuard {
    ani_env *env_ = nullptr;
    ani_ref ref_ = nullptr;

public:
    GlobalRefGuard(ani_env *env, ani_object obj) : env_(env)
    {
        if (!env_)
            return;
        if (ANI_OK != env_->GlobalReference_Create(obj, &ref_)) {
            ref_ = nullptr;
        }
    }
    explicit operator bool() const
    {
        return ref_ != nullptr;
    }
    ani_ref get() const
    {
        return ref_;
    }
    ~GlobalRefGuard()
    {
        if (env_ && ref_) {
            env_->GlobalReference_Delete(ref_);
        }
    }

    GlobalRefGuard(const GlobalRefGuard &) = delete;
    GlobalRefGuard &operator=(const GlobalRefGuard &) = delete;
};

class DataObserver :
    public OHOS::DistributedRdb::RdbStoreObserver,
    public OHOS::DistributedRdb::DetailProgressObserver,
    public OHOS::DistributedRdb::SqlObserver,
    public std::enable_shared_from_this<DataObserver> {
public:
    static std::shared_ptr<DataObserver> Create(VarCallbackType cb, ani_ref jsCallbackRef);
    DataObserver(VarCallbackType cb, ani_ref jsCallbackRef);
    ~DataObserver();
    // extends from RdbStoreObserver
    void OnChange() override;
    void OnChange(const std::vector<std::string> &devices) override;
    void OnChange(const OHOS::DistributedRdb::Origin &origin, const PrimaryFields &fields,
        OHOS::DistributedRdb::RdbStoreObserver::ChangeInfo &&changeInfo) override;
    // extends from DetailProgressObserver
    void ProgressNotification(const OHOS::DistributedRdb::Details &details) override;
    // extends from SqlObserver
    void OnStatistic(const OHOS::DistributedRdb::SqlObserver::SqlExecutionInfo &info) override;

    void SetNotifyDataChangeInfoFunc(std::function<void(DataObserver *, const OHOS::DistributedRdb::Origin &,
            const OHOS::DistributedRdb::RdbStoreObserver::PrimaryFields &,
        const OHOS::DistributedRdb::RdbStoreObserver::ChangeInfo &)> func);
    void SetNotifyDataChangeArrFunc(std::function<void(DataObserver *, const std::vector<std::string> &)> func);
    void SetNotifySqlExecutionFunc(std::function<void(DataObserver *,
        const OHOS::DistributedRdb::SqlObserver::SqlExecutionInfo &)> func);
    void SetNotifyProcessFunc(std::function<void(DataObserver *, const OHOS::DistributedRdb::Details &)> func);
    void SetNotifyCommonEventFunc(std::function<void(DataObserver *)> func);
    void Release();

private:
    bool SendEventToMainThread(const std::function<void()> func);
    void OnChangeInMainThread();
    void OnChangeArrInMainThread(const std::vector<std::string> &devices);
    void OnChangeInfoInMainThread(const OHOS::DistributedRdb::Origin &origin,
        const OHOS::DistributedRdb::RdbStoreObserver::PrimaryFields &fields,
        const OHOS::DistributedRdb::RdbStoreObserver::ChangeInfo &changeInfo);
    void OnStatisticInMainThread(const SqlExecutionInfo &info);
    void ProgressNotificationInMainThread(const OHOS::DistributedRdb::Details &details);

public:
    VarCallbackType jsCallback_;
    ani_ref jsCallbackRef_ = nullptr;
private:
    std::recursive_mutex mutex_;
    std::function<void(DataObserver *, const OHOS::DistributedRdb::Origin &,
        const OHOS::DistributedRdb::RdbStoreObserver::PrimaryFields &,
        const OHOS::DistributedRdb::RdbStoreObserver::ChangeInfo &)>
        notifyDataChangeInfoFunc_ = nullptr;
    std::function<void(DataObserver *, const std::vector<std::string> &)> notifyDataChangeArrFunc_ = nullptr;
    std::function<void(DataObserver *, const OHOS::DistributedRdb::SqlObserver::SqlExecutionInfo&)>
        notifySqlExecutionInfoFunc_ = nullptr;
    std::function<void(DataObserver *, const OHOS::DistributedRdb::Details&)> notifyProgressDetailsFunc_ = nullptr;
    std::function<void(DataObserver *)> notifyCommonEventFunc_ = nullptr;

    static std::mutex mainHandlerMutex_;
    static std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_;
};

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

bool HasDuplicateAssets(const OHOS::NativeRdb::ValueObject &value);
bool HasDuplicateAssets(const std::vector<OHOS::NativeRdb::ValueObject> &values);
bool HasDuplicateAssets(const OHOS::NativeRdb::ValuesBucket &value);
bool HasDuplicateAssets(const std::vector<OHOS::NativeRdb::ValuesBucket> &values);
bool HasDuplicateAssets(const OHOS::NativeRdb::ValuesBuckets &values);

std::shared_ptr<OHOS::NativeRdb::RdbPredicates> GetNativePredicatesFromTaihe(
    ohos::data::relationalStore::weak::RdbPredicates predicates);

std::pair<int, std::vector<RowEntity>> GetRows(
    ResultSet &resultSet, int32_t maxCount, int32_t position);
bool WarpDate(double time, ani_object &outObj);
} // namespace ani_rdbutils

#endif