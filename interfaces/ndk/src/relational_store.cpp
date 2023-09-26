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
#include "traits.h"

using namespace OHOS::RdbNdk;
using namespace OHOS::DistributedRdb;
constexpr int RDB_STORE_CID = 1234560; // The class id used to uniquely identify the OH_Rdb_Store class.
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

    std::string realPath = OHOS::NativeRdb::RdbSqlUtils::GetDefaultDatabasePath(config->dataBaseDir,
        config->storeName, *errCode);
    if (*errCode != 0) {
        LOG_ERROR("Get database path failed, ret %{public}d ", *errCode);
        return nullptr;
    }
    OHOS::NativeRdb::RdbStoreConfig rdbStoreConfig(realPath);
    rdbStoreConfig.SetSecurityLevel(OHOS::NativeRdb::SecurityLevel(config->securityLevel));
    rdbStoreConfig.SetEncryptStatus(config->isEncrypt);
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
    std::string realPath = OHOS::NativeRdb::RdbSqlUtils::GetDefaultDatabasePath(config->dataBaseDir,
        config->storeName, errCode);
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

int OH_Rdb_SetDistributedTables(OH_Rdb_Store *store, const char *tables[], uint32_t count, OH_Rdb_DistributedType type,
    const OH_Rdb_DistributedConfig *config)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || type != OH_Rdb_DistributedType::DISTRIBUTED_CLOUD ||
        config->version != DISTRIBUTED_CONFIG_VERSION) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    std::vector<std::string> tableNames;
    tableNames.reserve(count);
    for (int i = 0; i < count; i++) {
        tableNames.emplace_back(tables[i]);
    }
    auto distributedConfig = DistributedConfig{ .autoSync = config->isAutoSync };
    return rdbStore->GetStore()->SetDistributedTables(tableNames, type, distributedConfig);
}
OHOS::NativeRdb::RdbStore::PRIKey TransformToPK(const ValueObject &valueObject)
{
    OHOS::NativeRdb::RdbStore::PRIKey priKey;
    auto stringValue = OHOS::Traits::get_if<std::string>(&valueObject.value);
    if (stringValue != nullptr && !(*stringValue).empty()) {
        priKey = stringValue->c_str();
        return priKey;
    }
    auto intValue = OHOS::Traits::get_if<int64_t>(&valueObject.value);
    if (intValue != nullptr) {
        priKey = *intValue;
        return priKey;
    }
    auto doubleValue = OHOS::Traits::get_if<double>(&valueObject.value);
    if (doubleValue != nullptr) {
        priKey = *doubleValue;
        return priKey;
    }
    priKey = std::monostate();
    return priKey;
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
        keys.push_back(TransformToPK(object));
    }
    auto results = rdbStore->GetStore()->GetModifyTimeCursor(tableName, columnName, keys);
    if (results == nullptr) {
        return nullptr;
    }
    return new (std::nothrow) RelationalCursor(std::move(results));
}

SubscribeMode GetSubscribeType(int type)
{
    switch (type) {
        case OH_Rdb_SubscribeType::SUBSCRIBE_TYPE_CLOUD:
            return SubscribeMode::CLOUD;
        case OH_Rdb_SubscribeType::SUBSCRIBE_TYPE_CLOUD_DETAILS:
            return SubscribeMode::CLOUD_DETAIL;
        default:
            return SubscribeMode::SUBSCRIBE_MODE_MAX;
    }
}
int RelationalStore::DoSubscribe(SubscribeMode mode, OH_Rdb_SubscribeCallback *observer)
{
    std::lock_guard<decltype(mutex_)> lockGuard(mutex_);
    auto result = std::any_of(observers_[mode].begin(), observers_[mode].end(),
        [observer](const std::shared_ptr<NDKStoreObserver> &element) {
            return element->Get() == observer;
        });
    if (result) {
        LOG_INFO("duplicate subscribe");
        return OH_Rdb_ErrCode::RDB_OK;
    }
    auto subscribeOption = SubscribeOption{ .mode = mode, .event = "data_change" };
    auto ndkObserver = std::make_shared<NDKStoreObserver>(this, observer, mode);
    auto subscribeResult = store_->Subscribe(subscribeOption, ndkObserver.get());
    if (subscribeResult != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("subscribe failed");
        return subscribeResult;
    }
    observers_[mode].emplace_back(ndkObserver);
    return subscribeResult;
}

int OH_Rdb_Subscribe(OH_Rdb_Store *store, OH_Rdb_SubscribeType type, OH_Rdb_SubscribeCallback *observer)
{
    auto rdbStore = GetRelationalStore(store);
    auto rdbMode = GetSubscribeType(type);
    if (rdbStore == nullptr || type < SUBSCRIBE_TYPE_CLOUD || type > SUBSCRIBE_TYPE_CLOUD_DETAILS ||
        observer == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->DoSubscribe(rdbMode, observer);
}

int RelationalStore::DoUnsubscribe(SubscribeMode mode, OH_Rdb_SubscribeCallback *observer)
{
    std::lock_guard<decltype(mutex_)> lockGuard(mutex_);
    auto subscribeResult = OHOS::NativeRdb::E_OK;
    auto subscribeOption = SubscribeOption{ .mode = mode, .event = "data_change" };
    for (auto it = observers_[mode].begin(); it != observers_[mode].end();) {
        if (*it == nullptr) {
            it = observers_[mode].erase(it);
            continue;
        }
        if ((*it)->Get() != observer) {
            ++it;
            continue;
        }
        subscribeResult = store_->UnSubscribe(subscribeOption, it->get());
        if (subscribeResult != OHOS::NativeRdb::E_OK) {
            LOG_ERROR("subscribe failed, mode is %{public}d", mode);
            return subscribeResult;
        }
        it = observers_[mode].erase(it);
    }
    return subscribeResult;
}

int OH_Rdb_Unsubscribe(OH_Rdb_Store *store, OH_Rdb_SubscribeType type, OH_Rdb_SubscribeCallback *observer)
{
    auto rdbStore = GetRelationalStore(store);
    auto rdbMode = GetSubscribeType(type);
    if (rdbStore == nullptr || type < SUBSCRIBE_TYPE_CLOUD || type > SUBSCRIBE_TYPE_CLOUD_DETAILS) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->DoUnsubscribe(rdbMode, observer);
}

NDKStoreObserver::NDKChangeInfo::NDKChangeInfo(const NDKStoreObserver::Origin &origin, ChangeInfo ::iterator info)
    : table(info->first), type(origin.dataType), inserted(std::move(info->second[CHG_TYPE_INSERT])),
      updated(std::move(info->second[CHG_TYPE_UPDATE])), deleted(std::move(info->second[CHG_TYPE_DELETE]))
{
}

NDKStoreObserver::NDKStoreObserver(OH_Rdb_Store *store, OH_Rdb_SubscribeCallback *callback, int mode)
    : store_(store), callback_(callback), mode_(mode)
{
}

void NDKStoreObserver::OnChange(const std::vector<std::string> &devices)
{
    if (mode_ == OH_Rdb_SubscribeType::SUBSCRIBE_TYPE_CLOUD) {
        RelationalPredicatesObjects *objects;
        std::copy(devices.begin(), devices.end(), objects->Get().begin());
        (*callback_->cloudObserver)(store_, objects, devices.size());
    }
}

void NDKStoreObserver::OnChange(const Origin &origin, const RdbStoreObserver::PrimaryFields &fields,
    RdbStoreObserver::ChangeInfo &&changeInfo)
{
    if (mode_ == OH_Rdb_SubscribeType::SUBSCRIBE_TYPE_CLOUD_DETAILS) {
        std::vector<OH_Rdb_ChangeInfo> changeInfos;
        for (auto &info : changeInfo) {
            OH_Rdb_ChangeInfo rdbChangeInfo;
            rdbChangeInfo.tableName = info.first.c_str();
            rdbChangeInfo.ChangeType = (OH_Rdb_ChangeType)origin.dataType;
            TransformData(rdbChangeInfo.inserted, info.second[CHG_TYPE_INSERT]);
            TransformData(rdbChangeInfo.updated, info.second[CHG_TYPE_UPDATE]);
            TransformData(rdbChangeInfo.deleted, info.second[CHG_TYPE_DELETE]);
            changeInfos.emplace_back(rdbChangeInfo);
        }
        (*callback_->cloudDetailsObserver)(store_, changeInfos.data(), changeInfos.size());
    }
}

void NDKStoreObserver::OnChange() {}

void NDKStoreObserver::TransformData(OH_Rdb_KeyInfo &keyInfo, std::vector<PrimaryKey> &primaryKey)
{
    keyInfo.count = (int)primaryKey.size();
    keyInfo.type = (OH_ColumnType)primaryKey.begin()->index();
    if (keyInfo.type == TYPE_NULL || keyInfo.type > TYPE_TEXT) {
        return;
    }
    union OH_Rdb_KeyInfo::OH_Rdb_KeyData keyData[keyInfo.count];
    auto it = primaryKey.begin();
    if (keyInfo.type == TYPE_REAL) {
        for (int i = 0; i < keyInfo.count; ++i) {
            keyData[i].doubleData = *OHOS::Traits::get_if<double>(it.base());
            it++;
        }
    } else if (keyInfo.type == TYPE_INT64) {
        for (int i = 0; i < keyInfo.count; ++i) {
            keyData[i].intData = *OHOS::Traits::get_if<int64_t>(it.base());
            it++;
        }
    } else if (keyInfo.type == TYPE_TEXT) {
        for (int i = 0; i < keyInfo.count; ++i) {
            keyData[i].textData = (*OHOS::Traits::get_if<std::string>(it.base())).c_str();
            it++;
        }
    }
    keyInfo.data = keyData;
}

SyncMode NDKStoreObserver::TransformMode(OH_SyncMode &mode)
{
    switch (mode) {
        case SYNC_MODE_TIME_FIRST:
            return TIME_FIRST;
        case SYNC_MODE_NATIVE_FIRST:
            return NATIVE_FIRST;
        case SYNC_MODE_CLOUD_FIRST:
            return CLOUD_FIRST;
        default:
            return static_cast<SyncMode>(-1);
    }
}

OH_Rdb_SubscribeCallback *NDKStoreObserver::Get()
{
    return callback_;
}

int OH_Rdb_CloudSync(OH_Rdb_Store *store, OH_SyncMode mode, const char *tables[], uint32_t count,
    OH_Rdb_SyncCallback *progress)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || mode < SYNC_MODE_TIME_FIRST || mode > SYNC_MODE_CLOUD_FIRST || progress == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    SyncOption syncOption{ .mode = NDKStoreObserver::TransformMode(mode), .isBlock = false };
    std::vector<std::string> tableNames;
    for (int i = 0; i < count; ++i) {
        tableNames.emplace_back(tables[i]);
    }
    auto callback = [&progress](Details &&details) {
        auto tableDetails = details.begin()->second;
        OH_ProgressDetails progressDetails{ .version = DISTRIBUTED_PROGRESS_DETAIL_VERSION,
            .schedule = (OH_Rdb_Progress)tableDetails.progress,
            .code = (OH_Rdb_ProgressCode)tableDetails.code,
            .tableLength = (int32_t)tableDetails.details.size() };
        OH_TableDetails ohTableDetails[progressDetails.tableLength];
        int index = 0;
        for (const auto &detail : tableDetails.details) {
            OH_TableDetails tableDetail{ .version = DISTRIBUTED_TABLE_DETAILS_VERSION,
                .table = detail.first.c_str(),
                .upload =
                    OH_Statistic{
                        .version = DISTRIBUTED_STATISTIC_VERSION,
                        .total = (int)detail.second.upload.total,
                        .successful = (int)detail.second.upload.success,
                        .failed = (int)detail.second.upload.failed,
                        .remained = (int)detail.second.upload.untreated,
                    },
                .download = OH_Statistic{
                    .version = DISTRIBUTED_STATISTIC_VERSION,
                    .total = (int)detail.second.download.total,
                    .successful = (int)detail.second.download.success,
                    .failed = (int)detail.second.download.failed,
                    .remained = (int)detail.second.download.untreated,
                } };
            ohTableDetails[index] = tableDetail;
            index++;
        }
        progressDetails.tableDetails = ohTableDetails;
        (*progress)(&progressDetails);
    };
    return rdbStore->GetStore()->Sync(syncOption, tableNames, callback);
}
