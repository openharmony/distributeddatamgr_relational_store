/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define LOG_TAG "RelationalStore"
#include "relational_store.h"

#include "convertor_error_code.h"
#include "grd_api_manager.h"
#include "handle_manager.h"
#include "logger.h"
#include "modify_time_cursor.h"
#include "oh_data_define.h"
#include "oh_data_utils.h"
#include "raw_data_parser.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_ndk_utils.h"
#include "rdb_predicates.h"
#include "rdb_sql_utils.h"
#include "rdb_store_config.h"
#include "relational_cursor.h"
#include "relational_predicates.h"
#include "relational_predicates_objects.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"
#include "relational_store_inner_types.h"
#include "relational_types_v0.h"
#include "relational_values_bucket.h"
#include "securec.h"
#include "sqlite_global_config.h"
#include "values_buckets.h"
#include "sqlite_utils.h"

using namespace OHOS::RdbNdk;
using namespace OHOS::DistributedRdb;
constexpr int RDB_STORE_CID = 1234560;       // The class id used to uniquely identify the OH_Rdb_Store class.
constexpr int RDB_CONFIG_SIZE_V0 = 41;
constexpr int RDB_CONFIG_SIZE_V1 = 45;
constexpr int RDB_ATTACH_WAIT_TIME_MIN = 1;
constexpr int RDB_ATTACH_WAIT_TIME_MAX = 300;
constexpr int RDB_CONFIG_PLUGINS_MAX = 16;
constexpr int RDB_CONFIG_CUST_DIR_MAX_LEN = 128;

static int g_supportDbTypes[] = { RDB_SQLITE, RDB_CAYLEY };

OH_Rdb_ConfigV2 *OH_Rdb_CreateConfig()
{
    return new (std::nothrow) OH_Rdb_ConfigV2();
}

int OH_Rdb_DestroyConfig(OH_Rdb_ConfigV2 *config)
{
    if (config == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE)) {
        LOG_ERROR("config is null %{public}d or magic num not valid %{public}x when destroy.", (config == nullptr),
            (config == nullptr ? 0 : config->magicNum));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    delete config;
    config = nullptr;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_SetDatabaseDir(OH_Rdb_ConfigV2 *config, const char *dataBaseDir)
{
    if (config == nullptr || dataBaseDir == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE)) {
        LOG_ERROR("config is null %{public}d or dataBaseDir %{public}d magic num not valid %{public}x "
                  "when Set DataBaseDir.",
            (config == nullptr), (dataBaseDir == nullptr), (config == nullptr ? 0 : config->magicNum));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    config->dataBaseDir = std::string(dataBaseDir);
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_SetStoreName(OH_Rdb_ConfigV2 *config, const char *storeName)
{
    if (config == nullptr || storeName == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE)) {
        LOG_ERROR("config is null %{public}d or storeName %{public}d or magic num not ok"
                  "%{public}x When set storeName.",
            (config == nullptr), (storeName == nullptr), (config == nullptr ? 0 : config->magicNum));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    config->storeName = std::string(storeName);
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_SetBundleName(OH_Rdb_ConfigV2 *config, const char *bundleName)
{
    if (config == nullptr || bundleName == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE)) {
        LOG_ERROR("config is null %{public}d or bundleName %{public}d magic num no ok %{public}x when set bundleName.",
            (config == nullptr), (bundleName == nullptr), (config == nullptr ? 0 : config->magicNum));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    config->bundleName = std::string(bundleName);
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_SetModuleName(OH_Rdb_ConfigV2 *config, const char *moduleName)
{
    if (config == nullptr || moduleName == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE)) {
        LOG_ERROR("config is null %{public}d or moduleName %{public}d magic num no ok %{public}x when set moduleName.",
            (config == nullptr), (moduleName == nullptr), (config == nullptr ? 0 : config->magicNum));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    config->moduleName = std::string(moduleName);
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_SetEncrypted(OH_Rdb_ConfigV2 *config, bool isEncrypted)
{
    if (config == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE)) {
        LOG_ERROR("config is null %{public}d or magic num not valid %{public}x when set encrypt.", (config == nullptr),
            (config == nullptr ? 0 : config->magicNum));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    config->isEncrypt = isEncrypted;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_SetSecurityLevel(OH_Rdb_ConfigV2 *config, int securityLevel)
{
    if (config == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE)) {
        LOG_ERROR("config is null %{public}d or magic num not valid %{public}x when set security level.",
            (config == nullptr), (config == nullptr ? 0 : config->magicNum));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    if (securityLevel < S1 || securityLevel > S4) {
        LOG_ERROR("securityLevel value is out of range %{public}d", securityLevel);
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    config->securityLevel = securityLevel;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_SetArea(OH_Rdb_ConfigV2 *config, int area)
{
    if (config == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE)) {
        LOG_ERROR("config is null %{public}d or magic num not valid %{public}x when set area.", (config == nullptr),
            (config == nullptr ? 0 : config->magicNum));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    if (area < RDB_SECURITY_AREA_EL1 || area > RDB_SECURITY_AREA_EL5) {
        LOG_ERROR("area value is out of range %{public}d", area);
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    config->area = area;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_SetSemanticIndex(OH_Rdb_ConfigV2 *config, bool isEnable)
{
    if (config == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE)) {
        LOG_ERROR("config is null %{public}d or magic num not valid %{public}x when set SemanticIndex.",
            (config == nullptr), (config == nullptr ? 0 : config->magicNum));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    config->enableSemanticIndex = isEnable;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_SetDbType(OH_Rdb_ConfigV2 *config, int dbType)
{
    if (config == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE) ||
        (dbType < RDB_SQLITE || dbType > RDB_CAYLEY)) {
        LOG_ERROR("config is null %{public}d or magicNum not valid %{public}d or dbType is out of range %{public}d",
            (config == nullptr), (config == nullptr ? 0 : config->magicNum), dbType);
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    if (dbType == RDB_CAYLEY && !(OHOS::NativeRdb::IsUsingArkData())) {
        return OH_Rdb_ErrCode::RDB_E_NOT_SUPPORTED;
    }
    config->dbType = dbType;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_SetCustomDir(OH_Rdb_ConfigV2 *config, const char *customDir)
{
    if (config == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE) || customDir == nullptr ||
        strlen(customDir) > RDB_CONFIG_CUST_DIR_MAX_LEN) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    config->customDir = customDir;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_SetReadOnly(OH_Rdb_ConfigV2 *config, bool readOnly)
{
    if (config == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE)) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    config->readOnly = readOnly;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_SetPlugins(OH_Rdb_ConfigV2 *config, const char **plugins, int32_t length)
{
    if (config == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE) || plugins == nullptr ||
        length > RDB_CONFIG_PLUGINS_MAX) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    for (int i = 0; i < length; i++) {
        config->pluginLibs.push_back(plugins[i]);
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_SetCryptoParam(OH_Rdb_ConfigV2 *config, const OH_Rdb_CryptoParam *cryptoParam)
{
    if (config == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE) ||
        cryptoParam == nullptr || !cryptoParam->IsValid()) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    config->cryptoParam = cryptoParam->cryptoParam;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_IsTokenizerSupported(Rdb_Tokenizer tokenizer, bool *isSupported)
{
    if (tokenizer < RDB_NONE_TOKENIZER || tokenizer > RDB_CUSTOM_TOKENIZER) {
        LOG_ERROR("token is out of range %{public}d", tokenizer);
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    if (isSupported == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    *isSupported = OHOS::NativeRdb::RdbHelper::IsSupportedTokenizer(static_cast<OHOS::NativeRdb::Tokenizer>(tokenizer));
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_SetTokenizer(OH_Rdb_ConfigV2 *config, Rdb_Tokenizer tokenizer)
{
    if (config == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE) ||
        (tokenizer < RDB_NONE_TOKENIZER || tokenizer > RDB_CUSTOM_TOKENIZER)) {
        LOG_ERROR("config is null %{public}d or magicNum not valid %{public}d or token is out of range %{public}d",
            (config == nullptr), (config == nullptr ? 0 : config->magicNum), tokenizer);
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    if (config->dbType != Rdb_DBType::RDB_SQLITE) {
        LOG_ERROR("ICU Tokenizer only support sqlite db type.");
        return OH_Rdb_ErrCode::RDB_E_NOT_SUPPORTED;
    }
    config->token = tokenizer;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_SetPersistent(OH_Rdb_ConfigV2 *config, bool isPersistent)
{
    if (config == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE)) {
        LOG_ERROR("config is null %{public}d or magicNum not valid %{public}d. isPersistent %{public}d",
            (config == nullptr), (config == nullptr ? 0 : config->magicNum), isPersistent);
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    config->persist = isPersistent;
    return OH_Rdb_ErrCode::RDB_OK;
}

const int *OH_Rdb_GetSupportedDbType(int *numType)
{
    if (numType == nullptr) {
        return nullptr;
    }
    // if use arkData, then numType will be 2 {RDB_SQLITE and RDB_CAYLEY}, otherwise only 1 {RDB_SQLITE}
    *numType = OHOS::NativeRdb::IsUsingArkData() ? 2 : 1;
    return g_supportDbTypes;
}

OH_VObject *OH_Rdb_CreateValueObject()
{
    return new (std::nothrow) RelationalPredicatesObjects();
}

OH_VBucket *OH_Rdb_CreateValuesBucket()
{
    return new (std::nothrow) RelationalValuesBucket();
}

OH_Predicates *OH_Rdb_CreatePredicates(const char *table)
{
    if (table == nullptr) {
        return nullptr;
    }
    return new (std::nothrow) RelationalPredicate(table);
}

OHOS::RdbNdk::RelationalStore::RelationalStore(std::shared_ptr<OHOS::NativeRdb::RdbStore> store) : store_(store)
{
    id = RDB_STORE_CID;
}

int RelationalStore::SubscribeAutoSyncProgress(const Rdb_ProgressObserver *callback)
{
    std::lock_guard<decltype(mutex_)> lock(mutex_);
    bool result = std::any_of(
        callbacks_.begin(), callbacks_.end(), [callback](const auto &observer) { return *observer == callback; });
    if (result) {
        LOG_INFO("duplicate subscribe.");
        return OH_Rdb_ErrCode::RDB_OK;
    }
    auto obs = std::make_shared<NDKDetailProgressObserver>(callback);
    if (store_ == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    int errCode = store_->RegisterAutoSyncCallback(obs);
    if (errCode == NativeRdb::E_OK) {
        LOG_ERROR("subscribe failed.");
        return ConvertorErrorCode::NativeToNdk(errCode);
    }
    callbacks_.push_back(std::move(obs));
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalStore::UnsubscribeAutoSyncProgress(const Rdb_ProgressObserver *callback)
{
    std::lock_guard<decltype(mutex_)> lock(mutex_);
    if (store_ == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    for (auto it = callbacks_.begin(); it != callbacks_.end();) {
        if (callback != nullptr && !(**it == callback)) {
            ++it;
            continue;
        }

        int errCode = store_->UnregisterAutoSyncCallback(*it);
        if (errCode != NativeRdb::E_OK) {
            LOG_ERROR("unsubscribe failed.");
            return ConvertorErrorCode::NativeToNdk(errCode);
        }
        it = callbacks_.erase(it);
        LOG_DEBUG("progress unsubscribe success.");
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

RelationalStore::~RelationalStore()
{
    if (store_ == nullptr || callbacks_.empty()) {
        return;
    }
    for (auto &callback : callbacks_) {
        store_->UnregisterAutoSyncCallback(callback);
    }
}

SyncMode NDKUtils::TransformMode(Rdb_SyncMode &mode)
{
    switch (mode) {
        case RDB_SYNC_MODE_TIME_FIRST:
            return TIME_FIRST;
        case RDB_SYNC_MODE_NATIVE_FIRST:
            return NATIVE_FIRST;
        case RDB_SYNC_MODE_CLOUD_FIRST:
            return CLOUD_FIRST;
        default:
            return static_cast<SyncMode>(-1);
    }
}

OHOS::DistributedRdb::SubscribeMode NDKUtils::GetSubscribeType(Rdb_SubscribeType &type)
{
    switch (type) {
        case Rdb_SubscribeType::RDB_SUBSCRIBE_TYPE_CLOUD:
            return SubscribeMode::CLOUD;
        case Rdb_SubscribeType::RDB_SUBSCRIBE_TYPE_CLOUD_DETAILS:
            return SubscribeMode::CLOUD_DETAIL;
        case Rdb_SubscribeType::RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS:
            return SubscribeMode::LOCAL_DETAIL;
        default:
            return SubscribeMode::SUBSCRIBE_MODE_MAX;
    }
}

class MainOpenCallback : public OHOS::NativeRdb::RdbOpenCallback {
public:
    int OnCreate(OHOS::NativeRdb::RdbStore &rdbStore) override;
    int OnUpgrade(OHOS::NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
};

int MainOpenCallback::OnCreate(OHOS::NativeRdb::RdbStore &rdbStore)
{
    return OH_Rdb_ErrCode::RDB_OK;
}

int MainOpenCallback::OnUpgrade(OHOS::NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion)
{
    return OH_Rdb_ErrCode::RDB_OK;
}

RelationalStore *GetRelationalStore(OH_Rdb_Store *store)
{
    if (store == nullptr || store->id != RDB_STORE_CID) {
        LOG_ERROR("store is invalid. is null %{public}d", (store == nullptr));
        return nullptr;
    }
    return static_cast<RelationalStore *>(store);
}

OH_Rdb_Store *OH_Rdb_GetOrOpen(const OH_Rdb_Config *config, int *errCode)
{
    if (config == nullptr || config->selfSize > RDB_CONFIG_SIZE_V1 || errCode == nullptr) {
        LOG_ERROR("Parameters set error:config is NULL ? %{public}d and config size is %{public}zu or "
                  "errCode is NULL ? %{public}d ",
            (config == nullptr), sizeof(OH_Rdb_Config), (errCode == nullptr));
        return nullptr;
    }

    std::string realPath =
        OHOS::NativeRdb::RdbSqlUtils::GetDefaultDatabasePath(config->dataBaseDir, config->storeName, *errCode);
    if (*errCode != 0) {
        *errCode = ConvertorErrorCode::NativeToNdk(*errCode);
        LOG_ERROR("Get database path failed, ret %{public}d ", *errCode);
        return nullptr;
    }
    OHOS::NativeRdb::RdbStoreConfig rdbStoreConfig(realPath);
    rdbStoreConfig.SetSecurityLevel(OHOS::NativeRdb::SecurityLevel(config->securityLevel));
    rdbStoreConfig.SetEncryptStatus(config->isEncrypt);
    if (config->selfSize > RDB_CONFIG_SIZE_V0) {
        rdbStoreConfig.SetArea(config->area - 1);
    }
    if (config->bundleName != nullptr) {
        rdbStoreConfig.SetBundleName(config->bundleName);
    }
    rdbStoreConfig.SetName(config->storeName);

    MainOpenCallback callback;
    std::shared_ptr<OHOS::NativeRdb::RdbStore> store =
        OHOS::NativeRdb::RdbHelper::GetRdbStore(rdbStoreConfig, -1, callback, *errCode);
    *errCode = ConvertorErrorCode::NativeToNdk(*errCode);
    if (store == nullptr) {
        LOG_ERROR("Get RDB Store fail %{public}s", OHOS::NativeRdb::SqliteUtils::Anonymous(realPath).c_str());
        return nullptr;
    }
    return new (std::nothrow) RelationalStore(store);
}

OH_Rdb_Store *OH_Rdb_CreateOrOpen(const OH_Rdb_ConfigV2 *config, int *errCode)
{
    if (config == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE) || errCode == nullptr) {
        LOG_ERROR("Parameters set error:config is NULL ? %{public}d or magicNum is not valid %{public}d or"
                  " errCode is NULL ? %{public}d ",
            (config == nullptr), (config == nullptr ? 0 : config->magicNum), (errCode == nullptr));
        return nullptr;
    }

    auto [ret, rdbStoreConfig] = RdbNdkUtils::GetRdbStoreConfig(config);
    if (ret != OHOS::NativeRdb::E_OK) {
        *errCode = ConvertorErrorCode::NativeToNdk(ret);
        return nullptr;
    }
    MainOpenCallback callback;
    std::shared_ptr<OHOS::NativeRdb::RdbStore> store =
        OHOS::NativeRdb::RdbHelper::GetRdbStore(rdbStoreConfig, -1, callback, *errCode);
    *errCode = ConvertorErrorCode::NativeToNdk(*errCode);
    if (store == nullptr) {
        LOG_ERROR("Get RDB Store fail %{public}s",
            OHOS::NativeRdb::SqliteUtils::Anonymous(rdbStoreConfig.GetPath()).c_str());
        return nullptr;
    }
    return new (std::nothrow) RelationalStore(store);
}

int OH_Rdb_CloseStore(OH_Rdb_Store *store)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    delete rdbStore;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_DeleteStore(const OH_Rdb_Config *config)
{
    if (config == nullptr || config->dataBaseDir == nullptr || config->storeName == nullptr) {
        LOG_ERROR("Parameters set error:path is NULL ? %{public}d", (config == nullptr));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    int errCode = OHOS::NativeRdb::E_OK;
    std::string realPath =
        OHOS::NativeRdb::RdbSqlUtils::GetDefaultDatabasePath(config->dataBaseDir, config->storeName, errCode);
    if (errCode != OHOS::NativeRdb::E_OK) {
        return ConvertorErrorCode::NativeToNdk(errCode);
    }
    return ConvertorErrorCode::NativeToNdk(OHOS::NativeRdb::RdbHelper::DeleteRdbStore(realPath));
}

int OH_Rdb_DeleteStoreV2(const OH_Rdb_ConfigV2 *config)
{
    if (config == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE)) {
        LOG_ERROR("config is NULL ? %{public}d, config is invalid ? %{public}d", (config == nullptr),
            (config == nullptr ? 0 : config->magicNum));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    int errCode = OHOS::NativeRdb::E_OK;
    std::string realPath =
        OHOS::NativeRdb::RdbSqlUtils::GetDefaultDatabasePath(config->dataBaseDir, config->storeName, errCode);
    if (errCode != OHOS::NativeRdb::E_OK) {
        return ConvertorErrorCode::NativeToNdk(errCode);
    }
    return ConvertorErrorCode::NativeToNdk(OHOS::NativeRdb::RdbHelper::DeleteRdbStore(realPath));
}

int OH_Rdb_Insert(OH_Rdb_Store *store, const char *table, OH_VBucket *valuesBucket)
{
    auto rdbStore = GetRelationalStore(store);
    auto bucket = RelationalValuesBucket::GetSelf(valuesBucket);
    if (rdbStore == nullptr || table == nullptr || bucket == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    int64_t rowId = -1;
    rdbStore->GetStore()->Insert(rowId, table, bucket->Get());
    return rowId >= 0 ? rowId : OH_Rdb_ErrCode::RDB_ERR;
}

int OH_Rdb_BatchInsert(OH_Rdb_Store *store, const char *table,
    const OH_Data_VBuckets *rows, Rdb_ConflictResolution resolution, int64_t *changes)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || table == nullptr || rows == nullptr || changes == nullptr ||
        resolution < RDB_CONFLICT_NONE || resolution > RDB_CONFLICT_REPLACE) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    OHOS::NativeRdb::ValuesBuckets datas;
    for (size_t i = 0; i < rows->rows_.size(); i++) {
        auto valuesBucket = RelationalValuesBucket::GetSelf(const_cast<OH_VBucket *>(rows->rows_[i]));
        if (valuesBucket == nullptr) {
            continue;
        }
        datas.Put(valuesBucket->Get());
    }
    auto [errCode, count] = rdbStore->GetStore()->BatchInsert(table,
        datas, Utils::ConvertConflictResolution(resolution));
    *changes = count;
    if (errCode != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("batch insert fail, errCode=%{public}d count=%{public}" PRId64, errCode, count);
    }
    return ConvertorErrorCode::GetInterfaceCode(errCode);
}

int OH_Rdb_Update(OH_Rdb_Store *store, OH_VBucket *valueBucket, OH_Predicates *predicates)
{
    auto rdbStore = GetRelationalStore(store);
    auto predicate = RelationalPredicate::GetSelf(predicates);
    auto bucket = RelationalValuesBucket::GetSelf(valueBucket);
    if (rdbStore == nullptr || predicate == nullptr || bucket == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    int updatedRows = -1;
    rdbStore->GetStore()->Update(updatedRows, bucket->Get(), predicate->Get());
    return updatedRows >= 0 ? updatedRows : OH_Rdb_ErrCode::RDB_ERR;
}

int OH_Rdb_Delete(OH_Rdb_Store *store, OH_Predicates *predicates)
{
    auto rdbStore = GetRelationalStore(store);
    auto predicate = RelationalPredicate::GetSelf(predicates);
    if (rdbStore == nullptr || predicate == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    int deletedRows = -1;
    rdbStore->GetStore()->Delete(deletedRows, predicate->Get());
    return deletedRows >= 0 ? deletedRows : OH_Rdb_ErrCode::RDB_ERR;
}

OH_Cursor *OH_Rdb_Query(OH_Rdb_Store *store, OH_Predicates *predicates, const char *const *columnNames, int length)
{
    auto rdbStore = GetRelationalStore(store);
    auto predicate = RelationalPredicate::GetSelf(predicates);
    if (rdbStore == nullptr || predicate == nullptr) {
        return nullptr;
    }
    std::vector<std::string> columns;
    if (columnNames != nullptr && length > 0) {
        columns.reserve(length);
        for (int i = 0; i < length; i++) {
            columns.push_back(columnNames[i]);
        }
    }

    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet =
        rdbStore->GetStore()->QueryByStep(predicate->Get(), columns);
    if (resultSet == nullptr) {
        return nullptr;
    }
    return new (std::nothrow) RelationalCursor(std::move(resultSet));
}

OH_Cursor *OH_Rdb_ExecuteQuery(OH_Rdb_Store *store, const char *sql)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || sql == nullptr) {
        return nullptr;
    }
    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet =
        rdbStore->GetStore()->GetDbType() == OHOS::NativeRdb::DB_VECTOR
            ? rdbStore->GetStore()->QueryByStep(sql, std::vector<std::string>{})
            : rdbStore->GetStore()->QuerySql(sql, std::vector<std::string>{});
    if (resultSet == nullptr) {
        return nullptr;
    }
    return new OHOS::RdbNdk::RelationalCursor(std::move(resultSet));
}

int OH_Rdb_Execute(OH_Rdb_Store *store, const char *sql)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || sql == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(
        rdbStore->GetStore()->ExecuteSql(sql, std::vector<OHOS::NativeRdb::ValueObject>{}));
}

int OH_Rdb_ExecuteByTrxId(OH_Rdb_Store *store, int64_t trxId, const char *sql)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || sql == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(
        (rdbStore->GetStore()->Execute(sql, std::vector<OHOS::NativeRdb::ValueObject>{}, trxId)).first);
}

int OH_Rdb_BeginTransaction(OH_Rdb_Store *store)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(rdbStore->GetStore()->BeginTransaction());
}

int OH_Rdb_RollBack(OH_Rdb_Store *store)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(rdbStore->GetStore()->RollBack());
}

int OH_Rdb_Commit(OH_Rdb_Store *store)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(rdbStore->GetStore()->Commit());
}

int OH_Rdb_BeginTransWithTrxId(OH_Rdb_Store *store, int64_t *trxId)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || trxId == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    std::pair<int, int64_t> res = rdbStore->GetStore()->BeginTrans();
    *trxId = res.second;
    return ConvertorErrorCode::NativeToNdk(res.first);
}

int OH_Rdb_RollBackByTrxId(OH_Rdb_Store *store, int64_t trxId)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(rdbStore->GetStore()->RollBack(trxId));
}

int OH_Rdb_CommitByTrxId(OH_Rdb_Store *store, int64_t trxId)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(rdbStore->GetStore()->Commit(trxId));
}

int OH_Rdb_Backup(OH_Rdb_Store *store, const char *databasePath)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || databasePath == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(rdbStore->GetStore()->Backup(databasePath));
}

int OH_Rdb_Restore(OH_Rdb_Store *store, const char *databasePath)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || databasePath == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(rdbStore->GetStore()->Restore(databasePath));
}

int OH_Rdb_GetVersion(OH_Rdb_Store *store, int *version)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || version == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(rdbStore->GetStore()->GetVersion(*version));
}

int OH_Rdb_SetVersion(OH_Rdb_Store *store, int version)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(rdbStore->GetStore()->SetVersion(version));
}

static std::pair<int32_t, Rdb_DistributedConfig> Convert(const Rdb_DistributedConfig *config)
{
    std::pair<int32_t, Rdb_DistributedConfig> result = { OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, {} };
    auto &[errCode, cfg] = result;
    switch (config->version) {
        case DISTRIBUTED_CONFIG_V0: {
            const auto *realCfg = reinterpret_cast<const DistributedConfigV0 *>(config);
            cfg.version = realCfg->version;
            cfg.isAutoSync = realCfg->isAutoSync;
            errCode = OH_Rdb_ErrCode::RDB_OK;
            break;
        }
        default:
            break;
    }
    return result;
}

int OH_Rdb_SetDistributedTables(OH_Rdb_Store *store, const char *tables[], uint32_t count, Rdb_DistributedType type,
    const Rdb_DistributedConfig *config)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || type != Rdb_DistributedType::RDB_DISTRIBUTED_CLOUD || (count > 0 && tables == nullptr)) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    auto [errCode, cfg] = Convert(config);
    if (errCode != OH_Rdb_ErrCode::RDB_OK) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    std::vector<std::string> tableNames;
    tableNames.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        if (tables[i] == nullptr) {
            return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
        }
        tableNames.emplace_back(tables[i]);
    }
    return ConvertorErrorCode::NativeToNdk(rdbStore->GetStore()->SetDistributedTables(
        tableNames, DistributedTableType::DISTRIBUTED_CLOUD, { cfg.isAutoSync }));
}

OH_Cursor *OH_Rdb_FindModifyTime(OH_Rdb_Store *store, const char *tableName, const char *columnName, OH_VObject *values)
{
    auto rdbStore = GetRelationalStore(store);
    auto selfObjects = RelationalPredicatesObjects::GetSelf(values);
    if (rdbStore == nullptr || selfObjects == nullptr || tableName == nullptr) {
        return nullptr;
    }
    std::vector<ValueObject> objects = selfObjects->Get();
    std::vector<OHOS::NativeRdb::RdbStore::PRIKey> keys;
    keys.reserve(objects.size());
    for (auto &object : objects) {
        OHOS::NativeRdb::RdbStore::PRIKey priKey;
        OHOS::NativeRdb::RawDataParser::Convert(std::move(object.value), priKey);
        keys.push_back(std::move(priKey));
    }
    auto results = rdbStore->GetStore()->GetModifyTime(tableName, columnName, keys);
    return new (std::nothrow) ModifyTimeCursor(std::move(results));
}

int OH_Rdb_Subscribe(OH_Rdb_Store *store, Rdb_SubscribeType type, const Rdb_DataObserver *observer)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || observer == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->DoSubScribe(type, observer);
}

int OH_Rdb_Unsubscribe(OH_Rdb_Store *store, Rdb_SubscribeType type, const Rdb_DataObserver *observer)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->DoUnsubScribe(type, observer);
}

int RelationalStore::DoSubScribe(Rdb_SubscribeType type, const Rdb_DataObserver *observer)
{
    if (store_ == nullptr || type < RDB_SUBSCRIBE_TYPE_CLOUD || type > RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS ||
        observer == nullptr || observer->callback.briefObserver == nullptr ||
        observer->callback.detailsObserver == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    std::lock_guard<decltype(mutex_)> lock(mutex_);
    auto result = std::any_of(dataObservers_[type].begin(), dataObservers_[type].end(),
        [observer](const std::shared_ptr<NDKStoreObserver> &item) { return *item.get() == observer; });
    if (result) {
        LOG_INFO("duplicate subscribe.");
        return OH_Rdb_ErrCode::RDB_OK;
    }
    auto subscribeOption = SubscribeOption{ .mode = NDKUtils::GetSubscribeType(type), .event = "data_change" };
    auto ndkObserver = std::make_shared<NDKStoreObserver>(observer, type);
    int subscribeResult = (type == RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS)
                              ? store_->SubscribeObserver(subscribeOption, ndkObserver)
                              : store_->Subscribe(subscribeOption, ndkObserver);
    if (subscribeResult != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("subscribe failed.");
    } else {
        dataObservers_[type].emplace_back(std::move(ndkObserver));
    }
    return ConvertorErrorCode::NativeToNdk(subscribeResult);
}

int RelationalStore::DoUnsubScribe(Rdb_SubscribeType type, const Rdb_DataObserver *observer)
{
    if (store_ == nullptr || type < RDB_SUBSCRIBE_TYPE_CLOUD || type > RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    std::lock_guard<decltype(mutex_)> lock(mutex_);
    for (auto it = dataObservers_[type].begin(); it != dataObservers_[type].end();) {
        if (observer != nullptr && !(**it == observer)) {
            ++it;
            continue;
        }
        auto subscribeOption = SubscribeOption{ .mode = NDKUtils::GetSubscribeType(type), .event = "data_change" };
        int errCode = (type == RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS) ? store_->UnsubscribeObserver(subscribeOption, *it)
                                                                 : store_->UnSubscribe(subscribeOption, *it);
        if (errCode != NativeRdb::E_OK) {
            LOG_ERROR("unsubscribe failed.");
            return ConvertorErrorCode::NativeToNdk(errCode);
        }
        it = dataObservers_[type].erase(it);
        LOG_DEBUG("data observer unsubscribe success.");
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

namespace {
struct RelationalProgressDetails : public Rdb_ProgressDetails {
    Rdb_TableDetails *details_ = nullptr;
    explicit RelationalProgressDetails(const ProgressDetail &detail);
    ~RelationalProgressDetails();

    Rdb_TableDetails *GetTableDetails(int paraVersion);
    void DestroyTableDetails();

private:
    uint8_t *ResizeBuff(size_t size);

    TableDetails tableDetails_;
    size_t size_ = 0;
    uint8_t *buffer_ = nullptr;
};

void RelationalProgressDetails::DestroyTableDetails()
{
    delete[] details_;
    details_ = nullptr;
}

RelationalProgressDetails::RelationalProgressDetails(const ProgressDetail &detail)
{
    version = DISTRIBUTED_PROGRESS_DETAIL_VERSION;
    schedule = detail.progress;
    code = detail.code;
    tableLength = (int32_t)detail.details.size();
    tableDetails_ = detail.details;
}

RelationalProgressDetails::~RelationalProgressDetails()
{
    if (buffer_ != nullptr) {
        free(buffer_);
    }
    buffer_ = nullptr;
}

Rdb_TableDetails *RelationalProgressDetails::GetTableDetails(int paraVersion)
{
    switch (paraVersion) {
        case TABLE_DETAIL_V0: {
            auto length = sizeof(TableDetailsV0) * (tableLength + 1);
            auto *detailsV0 = (TableDetailsV0 *)ResizeBuff(length);
            if (detailsV0 == nullptr) {
                return nullptr;
            }
            auto result = memset_s(detailsV0, length, 0, length);
            if (result != EOK) {
                LOG_ERROR("memset_s failed, error code is %{public}d", result);
            }
            int index = 0;
            for (const auto &pair : tableDetails_) {
                detailsV0[index].table = pair.first.c_str();
                detailsV0[index].upload = StatisticV0{
                    .total = (int)pair.second.upload.total,
                    .successful = (int)pair.second.upload.success,
                    .failed = (int)pair.second.upload.failed,
                    .remained = (int)pair.second.upload.untreated,
                };
                detailsV0[index].download = StatisticV0{
                    .total = (int)pair.second.download.total,
                    .successful = (int)pair.second.download.success,
                    .failed = (int)pair.second.download.failed,
                    .remained = (int)pair.second.download.untreated,
                };
                index++;
            }
            return reinterpret_cast<Rdb_TableDetails *>(reinterpret_cast<uint8_t *>(detailsV0));
        }
        default:
            return nullptr;
    }
}

uint8_t *RelationalProgressDetails::ResizeBuff(size_t size)
{
    if (size_ >= size) {
        return buffer_;
    }
    if (buffer_ != nullptr) {
        free(buffer_);
    }
    buffer_ = (uint8_t *)malloc(size);
    return buffer_;
}
} // namespace

static std::pair<int, RelationalProgressDetails *> GetDetails(Rdb_ProgressDetails *progress)
{
    if (progress->version != DISTRIBUTED_PROGRESS_DETAIL_VERSION) {
        return { -1, nullptr };
    }
    return { 0, (RelationalProgressDetails *)progress };
}

Rdb_TableDetails *OH_Rdb_GetTableDetails(Rdb_ProgressDetails *progress, int32_t version)
{
    auto [errCode, details] = GetDetails(progress);
    if (errCode == -1 || details == nullptr) {
        return nullptr;
    }
    return details->GetTableDetails(version);
}

int OH_Rdb_CloudSync(
    OH_Rdb_Store *store, Rdb_SyncMode mode, const char *tables[], uint32_t count, const Rdb_ProgressObserver *observer)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || mode < RDB_SYNC_MODE_TIME_FIRST || mode > RDB_SYNC_MODE_CLOUD_FIRST ||
        observer == nullptr || observer->callback == nullptr || (count > 0 && tables == nullptr)) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    SyncOption syncOption{ .mode = NDKUtils::TransformMode(mode), .isBlock = false };
    std::vector<std::string> tableNames;
    for (uint32_t i = 0; i < count; ++i) {
        if (tables[i] == nullptr) {
            return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
        }
        tableNames.emplace_back(tables[i]);
    }

    auto progressCallback = [cxt = (*observer).context, cb = (*observer).callback](Details &&details) {
        if (details.size() > 1) {
            LOG_ERROR("Not support edge to edge detail notify.");
            return;
        }
        if (details.empty()) {
            LOG_ERROR("No device or cloud synced.");
            return;
        }
        for (auto &[device, detail] : details) {
            RelationalProgressDetails cloudDetail(detail);
            cb(cxt, &cloudDetail);
            break;
        }
    };
    return ConvertorErrorCode::NativeToNdk(rdbStore->GetStore()->Sync(syncOption, tableNames, progressCallback));
}

int OH_Rdb_SubscribeAutoSyncProgress(OH_Rdb_Store *store, const Rdb_ProgressObserver *callback)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || callback == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(rdbStore->SubscribeAutoSyncProgress(callback));
}

int OH_Rdb_UnsubscribeAutoSyncProgress(OH_Rdb_Store *store, const Rdb_ProgressObserver *callback)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(rdbStore->UnsubscribeAutoSyncProgress(callback));
}

int OH_Rdb_LockRow(OH_Rdb_Store *store, OH_Predicates *predicates)
{
    auto rdbStore = GetRelationalStore(store);
    auto predicate = RelationalPredicate::GetSelf(predicates);
    if (rdbStore == nullptr || predicate == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(rdbStore->GetStore()->ModifyLockStatus(predicate->Get(), true));
}

int OH_Rdb_UnlockRow(OH_Rdb_Store *store, OH_Predicates *predicates)
{
    auto rdbStore = GetRelationalStore(store);
    auto predicate = RelationalPredicate::GetSelf(predicates);
    if (rdbStore == nullptr || predicate == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(rdbStore->GetStore()->ModifyLockStatus(predicate->Get(), false));
}

OH_Cursor *OH_Rdb_QueryLockedRow(
    OH_Rdb_Store *store, OH_Predicates *predicates, const char *const *columnNames, int length)
{
    auto rdbStore = GetRelationalStore(store);
    auto predicate = RelationalPredicate::GetSelf(predicates);
    if (rdbStore == nullptr || predicate == nullptr) {
        return nullptr;
    }
    std::vector<std::string> columns;
    if (columnNames != nullptr && length > 0) {
        columns.reserve(length);
        for (int i = 0; i < length; i++) {
            columns.push_back(columnNames[i]);
        }
    }
    predicate->Get().BeginWrap();
    predicate->Get().EqualTo(OHOS::NativeRdb::AbsRdbPredicates::LOCK_STATUS, OHOS::NativeRdb::AbsRdbPredicates::LOCKED);
    predicate->Get().Or();
    predicate->Get().EqualTo(
        OHOS::NativeRdb::AbsRdbPredicates::LOCK_STATUS, OHOS::NativeRdb::AbsRdbPredicates::LOCK_CHANGED);
    predicate->Get().EndWrap();
    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet =
        rdbStore->GetStore()->QueryByStep(predicate->Get(), columns);
    if (resultSet == nullptr) {
        return nullptr;
    }
    return new OHOS::RdbNdk::RelationalCursor(std::move(resultSet));
}

int OH_Rdb_CreateTransaction(OH_Rdb_Store *store, const OH_RDB_TransOptions *options, OH_Rdb_Transaction **trans)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || trans == nullptr || options == nullptr || !options->IsValid()) {
        LOG_ERROR("params exist nullptr or invalid options.");
        return RDB_E_INVALID_ARGS;
    }
    OH_Rdb_Transaction *transaction = new (std::nothrow) OH_Rdb_Transaction();
    if (transaction == nullptr) {
        LOG_ERROR("new OH_Rdb_Transaction failed.");
        return RDB_E_ERROR;
    }
    auto [ret, tmpTrans] = rdbStore->GetStore()->CreateTransaction(static_cast<int>(options->type_));
    transaction->trans_ = tmpTrans;
    *trans = transaction;
    return ConvertorErrorCode::NativeToNdk(ret);
}

int OH_Rdb_ExecuteV2(OH_Rdb_Store *store, const char *sql, const OH_Data_Values *args, OH_Data_Value **result)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || sql == nullptr || (args != nullptr && !args->IsValid())) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    std::vector<ValueObject> datas;
    if (args != nullptr) {
        for (auto arg : args->values_) {
            if (!arg.IsValid()) {
                return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
            }
            datas.push_back(arg.value_);
        }
    }
    auto innerStore = rdbStore->GetStore();
    if (innerStore == nullptr) {
        LOG_ERROR("store is nullptr");
        return OH_Rdb_ErrCode::RDB_E_ALREADY_CLOSED;
    }
    auto [errCode, valueObj] = innerStore->Execute(sql, datas);
    if (errCode != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("execute fail, errCode=%{public}d", errCode);
        return ConvertorErrorCode::GetInterfaceCode(errCode);
    }
    if (result != nullptr) {
        OH_Data_Value *value = OH_Value_Create();
        if (value == nullptr) {
            return RDB_E_ERROR;
        }
        value->value_ = valueObj;
        *result = value;
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

OH_Cursor *OH_Rdb_ExecuteQueryV2(OH_Rdb_Store *store, const char *sql, const OH_Data_Values *args)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || sql == nullptr || (args != nullptr && !args->IsValid())) {
        return nullptr;
    }
    std::vector<ValueObject> datas;
    if (args != nullptr) {
        for (auto arg : args->values_) {
            if (!arg.IsValid()) {
                LOG_ERROR("args is invalid");
                return nullptr;
            }
            datas.push_back(arg.value_);
        }
    }
    auto innerStore = rdbStore->GetStore();
    if (innerStore == nullptr) {
        LOG_ERROR("store is nullptr");
        return nullptr;
    }
    auto resultSet = innerStore->QueryByStep(sql, datas);
    if (resultSet == nullptr) {
        return nullptr;
    }
    return new (std::nothrow) RelationalCursor(std::move(resultSet));
}

NDKDetailProgressObserver::NDKDetailProgressObserver(const Rdb_ProgressObserver *callback) : callback_(callback)
{
}

void NDKDetailProgressObserver::ProgressNotification(const Details &details)
{
    if (callback_ == nullptr || details.empty()) {
        return;
    }
    RelationalProgressDetails progressDetails = RelationalProgressDetails(details.begin()->second);
    (*(callback_->callback))(callback_->context, &progressDetails);
    progressDetails.DestroyTableDetails();
}

bool NDKDetailProgressObserver::operator==(const Rdb_ProgressObserver *callback)
{
    return callback == callback_;
}

NDKCorruptHandler::NDKCorruptHandler(
    OH_Rdb_ConfigV2 *config, void *context, Rdb_CorruptedHandler *handler, std::weak_ptr<NativeRdb::RdbStore> store)
    : config_(config), context_(context), handler_(handler), store_(std::move(store))
{
    config_ = config;
}

Rdb_Tokenizer NDKCorruptHandler::ConvertTokenizer2Ndk(OHOS::NativeRdb::Tokenizer token)
{
    if (token == OHOS::NativeRdb::Tokenizer::NONE_TOKENIZER) {
        return Rdb_Tokenizer::RDB_NONE_TOKENIZER;
    } else if (token == OHOS::NativeRdb::Tokenizer::ICU_TOKENIZER) {
        return Rdb_Tokenizer::RDB_ICU_TOKENIZER;
    }
    return Rdb_Tokenizer::RDB_CUSTOM_TOKENIZER;
}

OH_Rdb_ConfigV2 *NDKCorruptHandler::GetOHRdbConfig(const OHOS::NativeRdb::RdbStoreConfig &rdbConfig)
{
    OH_Rdb_ConfigV2 *config = OH_Rdb_CreateConfig();
    if (config == nullptr) {
        LOG_ERROR("Failed to create OH_Rdb_ConfigV2");
        return nullptr;
    }

    config->persist = (rdbConfig.GetStorageMode() == OHOS::NativeRdb::StorageMode::MODE_DISK);

    const std::string &realPath = rdbConfig.GetPath();
    config->dataBaseDir = OHOS::NativeRdb::RdbSqlUtils::GetDataBaseDirFromRealPath(realPath, config->persist);
    config->securityLevel = static_cast<int32_t>(rdbConfig.GetSecurityLevel());
    config->isEncrypt = rdbConfig.IsEncrypt();
    config->area = rdbConfig.GetArea() + 1;
    config->dbType = rdbConfig.IsVector() ? RDB_CAYLEY : RDB_SQLITE;
    config->bundleName = rdbConfig.GetBundleName();
    config->storeName = rdbConfig.GetName();
    config->token = ConvertTokenizer2Ndk(rdbConfig.GetTokenizer());
    config->customDir = rdbConfig.GetCustomDir();
    config->readOnly = rdbConfig.IsReadOnly();
    config->pluginLibs = rdbConfig.GetPluginLibs();
    config->cryptoParam = rdbConfig.GetCryptoParam();
    config->enableSemanticIndex = rdbConfig.GetEnableSemanticIndex();
    return config;
}

void NDKCorruptHandler::OnCorruptHandler(const OHOS::NativeRdb::RdbStoreConfig &config)
{
    if (handler_ == nullptr) {
        return;
    }
    if (!isExecuting.exchange(true)) {
        OH_Rdb_Store *store = nullptr;
        auto storePtr = store_.lock();
        if (storePtr != nullptr) {
            store = new (std::nothrow) RelationalStore(storePtr);
        }
        OH_Rdb_ConfigV2* rdbConfig = GetOHRdbConfig(config);
        (*handler_)(rdbConfig, context_, store);
        delete store;
        OH_Rdb_DestroyConfig(rdbConfig);
        isExecuting.store(false);
    }
}

void NDKCorruptHandler::SetStore(std::weak_ptr<OHOS::NativeRdb::RdbStore> store)
{
    store_ = store;
}

NDKStoreObserver::NDKStoreObserver(const Rdb_DataObserver *observer, int mode) : mode_(mode), observer_(observer)
{
}

void NDKStoreObserver::OnChange(const std::vector<std::string> &devices)
{
    if (mode_ == Rdb_SubscribeType::RDB_SUBSCRIBE_TYPE_CLOUD) {
        auto count = devices.size();
        std::unique_ptr<const char *[]> deviceIds = std::make_unique<const char *[]>(count);
        for (uint32_t i = 0; i < count; ++i) {
            deviceIds[i] = devices[i].c_str();
        }
        (*observer_->callback.briefObserver)(observer_->context, deviceIds.get(), count);
    }
}

size_t NDKStoreObserver::GetKeyInfoSize(RdbStoreObserver::ChangeInfo &&changeInfo)
{
    size_t size = 0;
    for (auto it = changeInfo.begin(); it != changeInfo.end(); ++it) {
        size += it->second[RdbStoreObserver::CHG_TYPE_INSERT].size() * sizeof(Rdb_KeyInfo::Rdb_KeyData);
        size += it->second[RdbStoreObserver::CHG_TYPE_UPDATE].size() * sizeof(Rdb_KeyInfo::Rdb_KeyData);
        size += it->second[RdbStoreObserver::CHG_TYPE_DELETE].size() * sizeof(Rdb_KeyInfo::Rdb_KeyData);
    }
    return size;
}

int32_t NDKStoreObserver::GetKeyDataType(std::vector<RdbStoreObserver::PrimaryKey> &primaryKey)
{
    if (primaryKey.size() == 0) {
        return OH_ColumnType::TYPE_NULL;
    }
    if (std::holds_alternative<int64_t>(primaryKey[0]) || std::holds_alternative<double>(primaryKey[0])) {
        return OH_ColumnType::TYPE_INT64;
    }
    if (std::holds_alternative<std::string>(primaryKey[0])) {
        return OH_ColumnType::TYPE_TEXT;
    }
    return OH_ColumnType::TYPE_NULL;
}

void NDKStoreObserver::OnChange(
    const Origin &origin, const RdbStoreObserver::PrimaryFields &fields, RdbStoreObserver::ChangeInfo &&changeInfo)
{
    uint32_t count = changeInfo.size();
    if (count == 0) {
        LOG_ERROR("No any infos.");
        return;
    }

    if (mode_ == Rdb_SubscribeType::RDB_SUBSCRIBE_TYPE_CLOUD_DETAILS ||
        mode_ == Rdb_SubscribeType::RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS) {
        size_t size = count * (sizeof(Rdb_ChangeInfo *) + sizeof(Rdb_ChangeInfo)) +
                      GetKeyInfoSize(std::forward<RdbStoreObserver::ChangeInfo &&>(changeInfo));
        std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(size);
        Rdb_ChangeInfo **infos = (Rdb_ChangeInfo **)(buffer.get());
        if (infos == nullptr) {
            LOG_ERROR("Failed to allocate memory for Rdb_ChangeInfo.");
            return;
        }

        Rdb_ChangeInfo *details = (Rdb_ChangeInfo *)(infos + count);
        Rdb_KeyInfo::Rdb_KeyData *data = (Rdb_KeyInfo::Rdb_KeyData *)(details + count);

        int index = 0;
        for (auto it = changeInfo.begin(); it != changeInfo.end(); ++it) {
            infos[index] = &details[index];
            infos[index]->version = DISTRIBUTED_CHANGE_INFO_VERSION;
            infos[index]->tableName = it->first.c_str();
            infos[index]->ChangeType = origin.dataType;
            infos[index]->inserted.count = static_cast<int>(it->second[RdbStoreObserver::CHG_TYPE_INSERT].size());
            infos[index]->inserted.type = GetKeyDataType(it->second[RdbStoreObserver::CHG_TYPE_INSERT]);
            infos[index]->updated.count = static_cast<int>(it->second[RdbStoreObserver::CHG_TYPE_UPDATE].size());
            infos[index]->updated.type = GetKeyDataType(it->second[RdbStoreObserver::CHG_TYPE_UPDATE]);
            infos[index]->deleted.count = static_cast<int>(it->second[RdbStoreObserver::CHG_TYPE_DELETE].size());
            infos[index]->deleted.type = GetKeyDataType(it->second[RdbStoreObserver::CHG_TYPE_DELETE]);
            ConvertKeyInfoData(data, it->second[RdbStoreObserver::CHG_TYPE_INSERT]);
            infos[index]->inserted.data = data;
            ConvertKeyInfoData(data + infos[index]->inserted.count, it->second[RdbStoreObserver::CHG_TYPE_UPDATE]);
            infos[index]->updated.data = data + infos[index]->inserted.count;
            ConvertKeyInfoData(data + infos[index]->inserted.count + infos[index]->updated.count,
                it->second[RdbStoreObserver::CHG_TYPE_DELETE]);
            infos[index]->deleted.data = data + infos[index]->inserted.count + infos[index]->updated.count;
            index++;
        }

        (*observer_->callback.detailsObserver)(observer_->context, const_cast<const Rdb_ChangeInfo **>(infos), count);
    }
}

void NDKStoreObserver::OnChange()
{
    RdbStoreObserver::OnChange();
}

void NDKStoreObserver::ConvertKeyInfoData(
    Rdb_KeyInfo::Rdb_KeyData *keyInfoData, std::vector<RdbStoreObserver::PrimaryKey> &primaryKey)
{
    if (keyInfoData == nullptr || primaryKey.empty()) {
        LOG_WARN("no data, keyInfoData is nullptr:%{public}d", keyInfoData == nullptr);
        return;
    }

    for (size_t i = 0; i < primaryKey.size(); ++i) {
        const auto &key = primaryKey[i];
        if (auto val = std::get_if<double>(&key)) {
            keyInfoData[i].real = *val;
        } else if (auto val = std::get_if<int64_t>(&key)) {
            keyInfoData[i].integer = *val;
        } else if (auto val = std::get_if<std::string>(&key)) {
            keyInfoData[i].text = val->c_str();
        } else {
            LOG_ERROR("Not support the data type.");
            return;
        }
    }
}

bool NDKStoreObserver::operator==(const Rdb_DataObserver *other)
{
    if (other == nullptr || observer_ == nullptr) {
        return false;
    }
    return other->context == observer_->context && &(other->callback) == &(observer_->callback);
}

int OH_Rdb_InsertWithConflictResolution(OH_Rdb_Store *store, const char *table, OH_VBucket *row,
    Rdb_ConflictResolution resolution, int64_t *rowId)
{
    auto rdbStore = GetRelationalStore(store);
    auto bucket = RelationalValuesBucket::GetSelf(row);
    if (rdbStore == nullptr || table == nullptr || bucket == nullptr || rowId == nullptr ||
        resolution < RDB_CONFLICT_NONE || resolution > RDB_CONFLICT_REPLACE) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto [errCode, count] = rdbStore->GetStore()->Insert(table, bucket->Get(),
        Utils::ConvertConflictResolution(resolution));
    *rowId = count;
    return ConvertorErrorCode::GetInterfaceCode(errCode);
}

int OH_Rdb_UpdateWithConflictResolution(OH_Rdb_Store *store, OH_VBucket *row, OH_Predicates *predicates,
    Rdb_ConflictResolution resolution, int64_t *changes)
{
    auto rdbStore = GetRelationalStore(store);
    auto bucket = RelationalValuesBucket::GetSelf(row);
    auto predicate = RelationalPredicate::GetSelf(predicates);
    if (rdbStore == nullptr || bucket == nullptr || predicate == nullptr || changes == nullptr ||
        resolution < RDB_CONFLICT_NONE || resolution > RDB_CONFLICT_REPLACE) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    int changedRows = 0;
    auto errCode = rdbStore->GetStore()->UpdateWithConflictResolution(changedRows,
        predicate->Get().GetTableName(), bucket->Get(), predicate->Get().GetWhereClause(),
        predicate->Get().GetBindArgs(), Utils::ConvertConflictResolution(resolution));
    *changes = changedRows;
    return ConvertorErrorCode::GetInterfaceCode(errCode);
}

int OH_Rdb_Attach(OH_Rdb_Store *store, const OH_Rdb_ConfigV2 *config, const char *attachName, int64_t waitTime,
    size_t *attachedNumber)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || config == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE) ||
        attachName == nullptr || waitTime < RDB_ATTACH_WAIT_TIME_MIN || waitTime > RDB_ATTACH_WAIT_TIME_MAX ||
        attachedNumber == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto [ret, rdbStoreConfig] = RdbNdkUtils::GetRdbStoreConfig(config);
    if (ret != OHOS::NativeRdb::E_OK) {
        return ConvertorErrorCode::NativeToNdk(ret);
    }
    auto [errCode, size] = rdbStore->GetStore()->Attach(rdbStoreConfig, attachName, static_cast<int32_t>(waitTime));
    *attachedNumber = size;
    return ConvertorErrorCode::GetInterfaceCode(errCode);
}

int OH_Rdb_Detach(OH_Rdb_Store *store, const char *attachName, int64_t waitTime, size_t *attachedNumber)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || attachName == nullptr ||
        waitTime < RDB_ATTACH_WAIT_TIME_MIN || waitTime > RDB_ATTACH_WAIT_TIME_MAX || attachedNumber == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto [errCode, size] = rdbStore->GetStore()->Detach(attachName, static_cast<int32_t>(waitTime));
    *attachedNumber = size;
    return ConvertorErrorCode::GetInterfaceCode(errCode);
}

int OH_Rdb_SetLocale(OH_Rdb_Store *store, const char *locale)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || locale == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto errCode = rdbStore->GetStore()->ConfigLocale(locale);
    return ConvertorErrorCode::GetInterfaceCode(errCode);
}

int OH_Rdb_RegisterCorruptedHandler(OH_Rdb_ConfigV2 *config, void *context, Rdb_CorruptedHandler *handler)
{
    if (config == nullptr || handler == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE)) {
        LOG_ERROR("Parameters set error:config is NULL ? %{public}d or magicNum is not valid %{public}d or",
            (config == nullptr), (config == nullptr ? 0 : config->magicNum));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    auto [ret, rdbStoreConfig] = RdbNdkUtils::GetRdbStoreConfig(config);
    if (ret != OHOS::NativeRdb::E_OK) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    std::shared_ptr<OHOS::NativeRdb::RdbStore> store = OHOS::NativeRdb::RdbHelper::GetRdb(rdbStoreConfig);
    auto ndkHandler = std::make_shared<NDKCorruptHandler>(config, context, handler, store);
    auto errCode = OHOS::NativeRdb::HandleManager::GetInstance().Register(rdbStoreConfig, ndkHandler);
    return ConvertorErrorCode::GetInterfaceCode(errCode);
}

int OH_Rdb_UnRegisterCorruptedHandler(OH_Rdb_ConfigV2 *config)
{
    if (config == nullptr || (config->magicNum != RDB_CONFIG_V2_MAGIC_CODE)) {
        LOG_ERROR("Parameters set error:config is NULL ? %{public}d or magicNum is not valid %{public}d",
            (config == nullptr), (config == nullptr ? 0 : config->magicNum));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    auto [ret, rdbStoreConfig] = RdbNdkUtils::GetRdbStoreConfig(config);
    if (ret != OHOS::NativeRdb::E_OK) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    auto errCode = OHOS::NativeRdb::HandleManager::GetInstance().Unregister(rdbStoreConfig);
    return ConvertorErrorCode::GetInterfaceCode(errCode);
}