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

#include "logger.h"
#include "modify_time_cursor.h"
#include "raw_data_parser.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_predicates.h"
#include "rdb_sql_utils.h"
#include "relational_cursor.h"
#include "relational_predicates.h"
#include "relational_predicates_objects.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"
#include "relational_types_v0.h"
#include "relational_values_bucket.h"
#include "securec.h"
#include "sqlite_global_config.h"
#include "convertor_error_code.h"

using namespace OHOS::RdbNdk;
using namespace OHOS::DistributedRdb;
constexpr int RDB_STORE_CID = 1234560; // The class id used to uniquely identify the OH_Rdb_Store class.
constexpr int RDB_CONFIG_SIZE_V0 = 41;
constexpr int RDB_CONFIG_SIZE_V1 = 45;
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
    std::lock_guard<decltype(mutex_)> lock(mutex_) ;
    bool result = std::any_of(callbacks_.begin(), callbacks_.end(), [callback](const auto &observer) {
        return *observer == callback;
    });
    if (result) {
        LOG_INFO("duplicate subscribe");
        return OH_Rdb_ErrCode::RDB_OK;
    }
    auto obs = std::make_shared<NDKDetailProgressObserver>(callback);
    int errCode = store_->RegisterAutoSyncCallback(obs);
    if (errCode == NativeRdb::E_OK) {
        LOG_ERROR("subscribe failed");
        return ConvertorErrorCode::NativeToNdk(errCode);
    }
    callbacks_.push_back(std::move(obs));
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalStore::UnsubscribeAutoSyncProgress(const Rdb_ProgressObserver *callback)
{
    std::lock_guard<decltype(mutex_)> lock(mutex_) ;
    for (auto it = callbacks_.begin(); it != callbacks_.end();) {
        if (callback != nullptr && !(**it == callback)) {
            ++it;
            continue;
        }

        int errCode = store_->UnregisterAutoSyncCallback(*it);
        if (errCode != NativeRdb::E_OK) {
            LOG_ERROR("unsubscribe failed");
            return ConvertorErrorCode::NativeToNdk(errCode);
        }
        it = callbacks_.erase(it);
        LOG_DEBUG("progress unsubscribe success");
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
        rdbStoreConfig.SetArea(config->area);
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
        LOG_ERROR("Get RDB Store fail %{public}s", realPath.c_str());
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
        rdbStore->GetStore()->QuerySql(sql, std::vector<std::string>{});
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
    return ConvertorErrorCode::NativeToNdk(rdbStore->GetStore()->SetDistributedTables(tableNames,
        DistributedTableType::DISTRIBUTED_CLOUD, { cfg.isAutoSync }));
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
    if (rdbStore == nullptr) {
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
                              [observer](const std::shared_ptr<NDKStoreObserver> &item) {
                                  return *item.get() == observer;
                              });
    if (result) {
        LOG_INFO("duplicate subscribe");
        return OH_Rdb_ErrCode::RDB_OK;
    }
    auto subscribeOption = SubscribeOption{ .mode = NDKUtils::GetSubscribeType(type), .event = "data_change" };
    auto ndkObserver = std::make_shared<NDKStoreObserver>(observer, type);
    int subscribeResult = (type == RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS) ?
        store_->SubscribeObserver(subscribeOption, ndkObserver) : store_->Subscribe(subscribeOption, ndkObserver.get());
    if (subscribeResult != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("subscribe failed");
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
        int errCode = (type == RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS) ?
            store_->UnsubscribeObserver(subscribeOption, *it) : store_->UnSubscribe(subscribeOption, it->get());
        if (errCode != NativeRdb::E_OK) {
            LOG_ERROR("unsubscribe failed");
            return ConvertorErrorCode::NativeToNdk(errCode);
        }
        it = dataObservers_[type].erase(it);
        LOG_DEBUG("data observer unsubscribe success");
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
            (void)memset_s(detailsV0, length, 0, length);
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

int OH_Rdb_CloudSync(OH_Rdb_Store *store, Rdb_SyncMode mode, const char *tables[], uint32_t count,
                     const Rdb_ProgressObserver *observer)
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
            LOG_ERROR("Not support edge to edge detail notify");
            return;
        }
        if (details.empty()) {
            LOG_ERROR("No device or cloud synced");
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
        LOG_ERROR("rdbStore or predicate is nullptr.");
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

NDKDetailProgressObserver::NDKDetailProgressObserver(const Rdb_ProgressObserver *callback):callback_(callback)
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

NDKStoreObserver::NDKStoreObserver(const Rdb_DataObserver *observer, int mode) : mode_(mode), observer_(observer) {}

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

void NDKStoreObserver::OnChange(const Origin &origin, const RdbStoreObserver::PrimaryFields &fields,
                                RdbStoreObserver::ChangeInfo &&changeInfo)
{
    uint32_t count = changeInfo.size();
    if (count == 0) {
        LOG_ERROR("No any infos");
        return;
    }

    if (mode_ == Rdb_SubscribeType::RDB_SUBSCRIBE_TYPE_CLOUD_DETAILS ||
        mode_ == Rdb_SubscribeType::RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS) {
        size_t size = count * (sizeof(Rdb_ChangeInfo *) + sizeof(Rdb_ChangeInfo)) +
                      GetKeyInfoSize(std::forward<RdbStoreObserver::ChangeInfo &&>(changeInfo));
        std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(size);
        Rdb_ChangeInfo **infos = (Rdb_ChangeInfo **)(buffer.get());
        if (infos == nullptr) {
            LOG_ERROR("Failed to allocate memory for Rdb_ChangeInfo");
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
            ConvertKeyInfoData(data+infos[index]->inserted.count, it->second[RdbStoreObserver::CHG_TYPE_UPDATE]);
            infos[index]->updated.data = data+infos[index]->inserted.count;
            ConvertKeyInfoData(data+infos[index]->inserted.count+infos[index]->updated.count,
                               it->second[RdbStoreObserver::CHG_TYPE_DELETE]);
            infos[index]->deleted.data = data+infos[index]->inserted.count+infos[index]->updated.count;
            index++;
        }

        (*observer_->callback.detailsObserver)(observer_->context, const_cast<const Rdb_ChangeInfo**>(infos), count);
    }
}

void NDKStoreObserver::OnChange()
{
    RdbStoreObserver::OnChange();
}

void NDKStoreObserver::ConvertKeyInfoData(Rdb_KeyInfo::Rdb_KeyData *keyInfoData,
                                          std::vector<RdbStoreObserver::PrimaryKey> &primaryKey)
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
            LOG_ERROR("Not support the data type");
            return;
        }
    }
}

bool NDKStoreObserver::operator==(const Rdb_DataObserver *other)
{
    if (other == nullptr) {
        return false;
    }
    return other->context == observer_->context && &(other->callback) == &(observer_->callback);
}