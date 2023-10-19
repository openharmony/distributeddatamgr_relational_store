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

#include "relational_store.h"

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_predicates.h"
#include "rdb_sql_utils.h"
#include "relational_cursor.h"
#include "relational_predicates.h"
#include "relational_predicates_objects.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"
#include "relational_values_bucket.h"
#include "sqlite_global_config.h"
#include "raw_data_parser.h"

using namespace OHOS::RdbNdk;
using namespace OHOS::DistributedRdb;
constexpr int RDB_STORE_CID = 1234560; // The class id used to uniquely identify the OH_Rdb_Store class.
constexpr int RDB_DISTRIBUTED_CONFIG_V0 = 1;
constexpr int RDB_PROGRESS_DETAILS_V0 = 1;
constexpr int RDB_TABLE_DETAILS_V0 = 1;
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

SubscribeMode RelationalStore::GetSubscribeType(Rdb_SubscribeType &type)
{
    switch (type) {
        case Rdb_SubscribeType::RDB_SUBSCRIBE_TYPE_CLOUD:
            return SubscribeMode::CLOUD;
        case Rdb_SubscribeType::RDB_SUBSCRIBE_TYPE_CLOUD_DETAILS:
            return SubscribeMode::CLOUD_DETAIL;
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
    return OHOS::NativeRdb::E_OK;
}

int MainOpenCallback::OnUpgrade(OHOS::NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion)
{
    return OHOS::NativeRdb::E_OK;
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
    if (config == nullptr || config->selfSize != sizeof(OH_Rdb_Config) || errCode == nullptr) {
        LOG_ERROR("Parameters set error:config is NULL ? %{public}d and config size is %{public}zu or "
                  "errCode is NULL ? %{public}d ",
            (config == nullptr), sizeof(OH_Rdb_Config), (errCode == nullptr));
        return nullptr;
    }

    std::string realPath =
        OHOS::NativeRdb::RdbSqlUtils::GetDefaultDatabasePath(config->dataBaseDir, config->storeName, *errCode);
    if (*errCode != 0) {
        LOG_ERROR("Get database path failed, ret %{public}d ", *errCode);
        return nullptr;
    }
    OHOS::NativeRdb::RdbStoreConfig rdbStoreConfig(realPath);
    rdbStoreConfig.SetSecurityLevel(OHOS::NativeRdb::SecurityLevel(config->securityLevel));
    rdbStoreConfig.SetEncryptStatus(config->isEncrypt);
    rdbStoreConfig.SetArea(config->area);
    if (config->bundleName != nullptr) {
        rdbStoreConfig.SetBundleName(config->bundleName);
    }
    rdbStoreConfig.SetName(config->storeName);

    MainOpenCallback callback;
    std::shared_ptr<OHOS::NativeRdb::RdbStore> store =
        OHOS::NativeRdb::RdbHelper::GetRdbStore(rdbStoreConfig, -1, callback, *errCode);
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
        return errCode;
    }
    return OHOS::NativeRdb::RdbHelper::DeleteRdbStore(realPath);
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
    return rdbStore->GetStore()->ExecuteSql(sql, std::vector<OHOS::NativeRdb::ValueObject>{});
}

int OH_Rdb_BeginTransaction(OH_Rdb_Store *store)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->GetStore()->BeginTransaction();
}

int OH_Rdb_RollBack(OH_Rdb_Store *store)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->GetStore()->RollBack();
}

int OH_Rdb_Commit(OH_Rdb_Store *store)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->GetStore()->Commit();
}

int OH_Rdb_Backup(OH_Rdb_Store *store, const char *databasePath)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || databasePath == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->GetStore()->Backup(databasePath);
}

int OH_Rdb_Restore(OH_Rdb_Store *store, const char *databasePath)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || databasePath == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->GetStore()->Restore(databasePath);
}

int OH_Rdb_GetVersion(OH_Rdb_Store *store, int *version)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || version == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->GetStore()->GetVersion(*version);
}

int OH_Rdb_SetVersion(OH_Rdb_Store *store, int version)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->GetStore()->SetVersion(version);
}

std::pair<int32_t, DistributedConfig> Convert(const Rdb_DistributedConfig *config)
{
    if (config->version < RDB_DISTRIBUTED_CONFIG_V0) {
        return { -1, {} };
    }
    switch (config->version) {
        case RDB_DISTRIBUTED_CONFIG_V0:
            return { 0, DistributedConfig{ .autoSync = config->isAutoSync } };
        default:
            return { -1, {} };
    }
}

int OH_Rdb_SetDistributedTables(OH_Rdb_Store *store, const char *tables[], uint32_t count, Rdb_DistributedType type,
    const Rdb_DistributedConfig *config)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || type != Rdb_DistributedType::RDB_DISTRIBUTED_CLOUD) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto ret = Convert(config);
    if (ret.first < 0) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto distributedConfig = ret.second;
    std::vector<std::string> tableNames;
    tableNames.reserve(count);
    for (int i = 0; i < count; i++) {
        tableNames.emplace_back(tables[i]);
    }
    return rdbStore->GetStore()->SetDistributedTables(tableNames, DistributedTableType::DISTRIBUTED_CLOUD,
        distributedConfig);
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
    for (const auto &object : objects) {
        OHOS::NativeRdb::RdbStore::PRIKey priKey;
        OHOS::NativeRdb::RawDataParser::Convert(object.value, priKey);
        keys.push_back(priKey);
    }
    auto results = rdbStore->GetStore()->GetModifyTime(tableName, columnName, keys);
    return new (std::nothrow) RelationalCursor(std::move(results));
}

int OH_Rdb_Subscribe(OH_Rdb_Store *store, Rdb_SubscribeType type, Rdb_DataObserver *observer)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || type < RDB_SUBSCRIBE_TYPE_CLOUD || type > RDB_SUBSCRIBE_TYPE_CLOUD_DETAILS ||
        observer->callback->briefObserver == nullptr || observer->callback->detailsObserver == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto subscribeOption = SubscribeOption{ .mode = RelationalStore::GetSubscribeType(type), .event = "data_change" };
    auto ndkObserver = NDKStoreObserver(store, observer, type);
    auto subscribeResult = rdbStore->GetStore()->Subscribe(subscribeOption, &ndkObserver);
    if (subscribeResult != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("subscribe failed");
    }
    return (OH_Rdb_ErrCode)subscribeResult;
}

int OH_Rdb_Unsubscribe(OH_Rdb_Store *store, Rdb_SubscribeType type, Rdb_DataObserver *observer)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || type < RDB_SUBSCRIBE_TYPE_CLOUD || type > RDB_SUBSCRIBE_TYPE_CLOUD_DETAILS) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto subscribeOption = SubscribeOption{ .mode = RelationalStore::GetSubscribeType(type), .event = "data_change" };
    auto ndkObserver = NDKStoreObserver(store, observer, type);
    auto unsubscribeResult = rdbStore->GetStore()->UnSubscribe(subscribeOption, &ndkObserver);
    if (unsubscribeResult != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("subscribe failed, mode is %{public}d", type);
    }
    return (OH_Rdb_ErrCode)unsubscribeResult;
}

NDKStoreObserver::NDKChangeInfo::NDKChangeInfo(const NDKStoreObserver::Origin &origin, ChangeInfo ::iterator info)
    : table(info->first), type(origin.dataType), inserted(std::move(info->second[CHG_TYPE_INSERT])),
      updated(std::move(info->second[CHG_TYPE_UPDATE])), deleted(std::move(info->second[CHG_TYPE_DELETE]))
{
}

NDKStoreObserver::NDKStoreObserver(OH_Rdb_Store *store, Rdb_DataObserver *callback, int mode)
    : store_(store), mode_(mode), observer_(callback)
{
}

void NDKStoreObserver::OnChange(const std::vector<std::string> &devices)
{
    if (mode_ == Rdb_SubscribeType::RDB_SUBSCRIBE_TYPE_CLOUD) {
        RelationalPredicatesObjects objects;
        std::copy(devices.begin(), devices.end(), objects.Get().begin());
        (*observer_->callback->briefObserver)(observer_->context, &objects, devices.size());
    }
}

void NDKStoreObserver::OnChange(const Origin &origin, const RdbStoreObserver::PrimaryFields &fields,
    RdbStoreObserver::ChangeInfo &&changeInfo)
{
    if (mode_ == Rdb_SubscribeType::RDB_SUBSCRIBE_TYPE_CLOUD_DETAILS) {
        std::vector<Rdb_ChangeInfo> changeInfos;
        for (auto &info : changeInfo) {
            Rdb_ChangeInfo rdbChangeInfo;
            rdbChangeInfo.tableName = info.first.c_str();
            rdbChangeInfo.ChangeType = (Rdb_ChangeType)origin.dataType;
            TransformData(rdbChangeInfo.inserted, info.second[CHG_TYPE_INSERT]);
            TransformData(rdbChangeInfo.updated, info.second[CHG_TYPE_UPDATE]);
            TransformData(rdbChangeInfo.deleted, info.second[CHG_TYPE_DELETE]);
            changeInfos.emplace_back(rdbChangeInfo);
        }
        (*observer_->callback->detailsObserver)(observer_->context, changeInfos.data(), changeInfos.size());
    }
}

void NDKStoreObserver::OnChange() {}

void NDKStoreObserver::TransformData(Rdb_KeyInfo &keyInfo, std::vector<PrimaryKey> &primaryKey)
{
    keyInfo.count = (int)primaryKey.size();
    keyInfo.type = (OH_ColumnType)primaryKey.begin()->index();
    if (keyInfo.type == TYPE_NULL || keyInfo.type > TYPE_TEXT) {
        return;
    }
    union Rdb_KeyInfo::Rdb_KeyData keyData[keyInfo.count];
    auto it = primaryKey.begin();
    if (keyInfo.type == TYPE_REAL) {
        for (int i = 0; i < keyInfo.count; ++i) {
            keyData[i].real = *std::get_if<double>(it.base());
            it++;
        }
    } else if (keyInfo.type == TYPE_INT64) {
        for (int i = 0; i < keyInfo.count; ++i) {
            keyData[i].integer = *std::get_if<int64_t>(it.base());
            it++;
        }
    } else if (keyInfo.type == TYPE_TEXT) {
        for (int i = 0; i < keyInfo.count; ++i) {
            keyData[i].text = (*std::get_if<std::string>(it.base())).c_str();
            it++;
        }
    }
    keyInfo.data = keyData;
}

SyncMode NDKStoreObserver::TransformMode(Rdb_SyncMode &mode)
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

struct RelationalTableDetails : public Rdb_TableDetails {
};

struct RelationalProgressDetails : public Rdb_ProgressDetails {
    TableDetails tableDetails_;
    explicit RelationalProgressDetails(const ProgressDetail &detail);
    Rdb_TableDetails *GetTableDetails(int version);
};

RelationalProgressDetails::RelationalProgressDetails(const ProgressDetail &detail) : Rdb_ProgressDetails()
{
    version = RDB_TABLE_DETAILS_V0;
    schedule = detail.progress;
    code = detail.code;
    tableLength = (int32_t)detail.details.size();
    tableDetails_ = detail.details;
}

Rdb_TableDetails *RelationalProgressDetails::GetTableDetails(int version)
{
    switch (version) {
        case RDB_TABLE_DETAILS_V0: {
            auto *ret = (Rdb_TableDetails *)malloc(sizeof(Rdb_TableDetails) * (tableLength + 1));
            int index = 0;
            for (const auto &pair : tableDetails_) {
                ret[index].table = pair.first.c_str();
                ret[index].upload = Rdb_Statistic{
                    .total = (int)pair.second.upload.total,
                    .successful = (int)pair.second.upload.success,
                    .failed = (int)pair.second.upload.failed,
                    .remained = (int)pair.second.upload.untreated,
                };
                ret[index].download = Rdb_Statistic{
                    .total = (int)pair.second.download.total,
                    .successful = (int)pair.second.download.success,
                    .failed = (int)pair.second.download.failed,
                    .remained = (int)pair.second.download.untreated,
                };
                index++;
            }
        }
        default:
            return nullptr;
    }
}

std::pair<int, RelationalProgressDetails *> GetDetails(Rdb_ProgressDetails *progress, int32_t version)
{
    switch (version) {
        case RDB_PROGRESS_DETAILS_V0:
            return { 0, (RelationalProgressDetails *)progress };
        default:
            return { -1, {} };
    }
}

Rdb_TableDetails *OH_Rdb_GetTableDetails(Rdb_ProgressDetails *progress, int32_t version)
{
    auto pair = GetDetails(progress, version);
    if (pair.first == -1) {
        return nullptr;
    }
    return pair.second->GetTableDetails(version);
}

int OH_Rdb_CloudSync(OH_Rdb_Store *store, Rdb_SyncMode mode, const char *tables[], uint32_t count,
    Rdb_SyncCallback *callback)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || mode < RDB_SYNC_MODE_TIME_FIRST || mode > RDB_SYNC_MODE_CLOUD_FIRST ||
        callback == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    SyncOption syncOption{ .mode = NDKStoreObserver::TransformMode(mode), .isBlock = false };
    std::vector<std::string> tableNames;
    for (int i = 0; i < count; ++i) {
        tableNames.emplace_back(tables[i]);
    }
    auto progressCallback = [&callback](Details &&details) {
        RelationalProgressDetails progressDetails = RelationalProgressDetails(details.begin()->second);
        (*callback)(&progressDetails);
    };
    return rdbStore->GetStore()->Sync(syncOption, tableNames, progressCallback);
}
