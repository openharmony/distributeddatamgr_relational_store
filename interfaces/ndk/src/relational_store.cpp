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

#include "relational_cursor_impl.h"
#include "relational_predicates_impl.h"
#include "relational_store_impl.h"

#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_predicates.h"
#include "relational_values_bucket_impl.h"
#include "relational_error_code.h"

OHOS::NativeRdb::StoreImpl::StoreImpl(std::shared_ptr<OHOS::NativeRdb::RdbStore> store)
{
    id = RDB_STORE_CID;
    store_ = store;
}

std::shared_ptr<OHOS::NativeRdb::RdbStore> OHOS::NativeRdb::StoreImpl::GetStore()
{
    return store_;
}

class MainOpenCallback : public OHOS::NativeRdb::RdbOpenCallback {
public:
    int OnCreate(OHOS::NativeRdb::RdbStore &rdbStore) override;
    int OnUpgrade(OHOS::NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
};

int MainOpenCallback::OnCreate(OHOS::NativeRdb::RdbStore &store)
{
    return OHOS::NativeRdb::E_OK;
}

int MainOpenCallback::OnUpgrade(OHOS::NativeRdb::RdbStore &store, int oldVersion, int newVersion)
{
    return OHOS::NativeRdb::E_OK;
}

void InitConfig(RDB_Config const *config, OHOS::NativeRdb::RdbStoreConfig &rdbStoreConfig)
{
    if (config->storageMode != 0) {
        rdbStoreConfig.SetStorageMode(OHOS::NativeRdb::StorageMode((int )config->storageMode));
    }
    if (config->journalMode != 0) {
        rdbStoreConfig.SetJournalMode(OHOS::NativeRdb::JournalMode((int)config->journalMode));
    }

    if (config->readOnly == true) {
        rdbStoreConfig.SetReadOnly(config->readOnly);
    }
    if (config->storeType != 0) {
        rdbStoreConfig.SetDatabaseFileType(OHOS::NativeRdb::DatabaseFileType((int)config->storeType));
    }

    if (config->distributedType != 0) {
        rdbStoreConfig.SetDistributedType(OHOS::NativeRdb::DistributedType((int)config->distributedType));
    }
    if (config->area != 0) {
        rdbStoreConfig.SetArea(config->area);
    }
    if (config->bundleName != nullptr) {
        rdbStoreConfig.SetBundleName(config->bundleName);
    }
    if (config->moduleName != nullptr) {
        rdbStoreConfig.SetModuleName(config->moduleName);
    }

    if (config->autoCheck == true) {
        rdbStoreConfig.SetAutoCheck(config->autoCheck);
    }
    if (config->journalSize != 0) {
        rdbStoreConfig.SetJournalSize(config->journalSize);
    }
    if (config->pageSize != 0) {
        rdbStoreConfig.SetPageSize(config->pageSize);
    }
    if (config->readConSize != 0) {
        rdbStoreConfig.SetReadConSize(config->readConSize);
    }
    if (config->encryptAlgo != nullptr) {
        rdbStoreConfig.SetEncryptAlgo(config->encryptAlgo);
    }
}
RDB_Store *RDB_GetOrOpen(RDB_Config const *config, int version, int *errCode)
{
    OHOS::NativeRdb::RdbStoreConfig rdbStoreConfig(config->name);
    rdbStoreConfig.SetSecurityLevel(OHOS::NativeRdb::SecurityLevel(config->securityLevel));
    rdbStoreConfig.SetEncryptStatus(config->isEncrypt);
    rdbStoreConfig.SetCreateNecessary(config->isCreateNecessary);
    InitConfig(config, rdbStoreConfig);

    MainOpenCallback callback;

    std::shared_ptr<OHOS::NativeRdb::RdbStore> store =
        OHOS::NativeRdb::RdbHelper::GetRdbStore(rdbStoreConfig, version, callback, *errCode);
    if (store == nullptr) {
        return nullptr;
    }
    return new OHOS::NativeRdb::StoreImpl(store);;
}

int RDB_CloseStore(RDB_Store *store)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    delete tempStore;
    return E_OK;
}

int RDB_DeleteStore(const char *path)
{
    if (path == nullptr) {
        return E_INVALID_ARG;
    }
    int err = OHOS::NativeRdb::RdbHelper::DeleteRdbStore(path);
    if (err != OHOS::NativeRdb::E_OK) {
        return err;
    }
    return err;
}

int RDB_Insert(RDB_Store *store, char const *table, RDB_ValuesBucket *valuesBucket)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return E_INVALID_ARG;
    }
    int64_t rowId;
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    OHOS::NativeRdb::ValuesBucketImpl *valueImpl = static_cast<OHOS::NativeRdb::ValuesBucketImpl *>(valuesBucket);
    int ret = tempStore->GetStore()->Insert(rowId, table, valueImpl->valuesBucket_);
    if (rowId >= 0) {
        return rowId;
    } else {
        return ret;
    }
}

int RDB_Update(RDB_Store *store, RDB_ValuesBucket *valueBucket, RDB_Predicates *predicate)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return E_INVALID_ARG;
    }
    int updatedRows;
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    OHOS::NativeRdb::PredicateImpl *tempPredicate = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    OHOS::NativeRdb::ValuesBucketImpl *valueImpl = static_cast<OHOS::NativeRdb::ValuesBucketImpl *>(valueBucket);

    int ret = tempStore->GetStore()->Update(updatedRows, valueImpl->valuesBucket_, (tempPredicate->GetPredicates()));
    if (updatedRows >= 0) {
        return updatedRows;
    } else {
        return ret;
    }
}

int RDB_Delete(RDB_Store *store, RDB_Predicates *predicate)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return E_INVALID_ARG;
    }
    int deletedRows;
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    OHOS::NativeRdb::PredicateImpl *tempPredicate = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    int ret = tempStore->GetStore()->Delete(deletedRows, (tempPredicate->GetPredicates()));
    if (deletedRows >= 0) {
        return deletedRows;
    } else {
        return ret;
    }
}

RDB_Cursor *RDB_Query(RDB_Store *store, RDB_Predicates *predicate, char const *const *columnNames, int length)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return nullptr;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    OHOS::NativeRdb::PredicateImpl *tempPredicate = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    std::vector<std::string> columns;
    if (columnNames == nullptr) {
        for (int i = 0; i < length; i++) {
            std::string str;
            str.assign(*(columnNames + i), length);
            columns.push_back(move(str));
        }
    }

    std::unique_ptr<OHOS::NativeRdb::ResultSet> resultSet =
        tempStore->GetStore()->QueryByStep(tempPredicate->GetPredicates(), columns);
    if (resultSet == nullptr) {
        return nullptr;
    }
    std::shared_ptr<OHOS::NativeRdb::ResultSet> retParam = std::move(resultSet);
    return new OHOS::NativeRdb::CursorImpl(retParam);
}

RDB_Cursor *RDB_ExecuteQuery(RDB_Store *store, char const *sql)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return nullptr;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    std::unique_ptr<OHOS::NativeRdb::ResultSet> resultSet =
        tempStore->GetStore()->QuerySql(sql, std::vector<std::string>{});
    if (resultSet == nullptr) {
        return nullptr;
    }
    std::shared_ptr<OHOS::NativeRdb::ResultSet> retParam = std::move(resultSet);
    return new OHOS::NativeRdb::CursorImpl(retParam);
}

int RDB_Execute(RDB_Store *store, char const *sql)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    return tempStore->GetStore()->ExecuteSql(sql, std::vector<OHOS::NativeRdb::ValueObject>{});
}

int RDB_Transaction(RDB_Store *store)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    return tempStore->GetStore()->BeginTransaction();
}

int RDB_RollBack(RDB_Store *store)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    return tempStore->GetStore()->RollBack();
}

int RDB_Commit(RDB_Store *store)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    return tempStore->GetStore()->Commit();
}

int RDB_Backup(RDB_Store *store, const char *databasePath, const unsigned char *destEncryptKey)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    std::vector<uint8_t> vec;
    if (destEncryptKey != nullptr) {
        for (size_t i = 0; i < strlen((char *)destEncryptKey); i++) {
            vec.push_back(*(destEncryptKey + i));
        }
    }

    return tempStore->GetStore()->Backup(databasePath, vec);
}

int RDB_Restore(RDB_Store *store, const char *databasePath, const unsigned char *destEncryptKey)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    std::vector<uint8_t> vec;
    if (destEncryptKey != nullptr) {
        for (size_t i = 0; i < strlen((char *)destEncryptKey); i++) {
            vec.push_back(*(destEncryptKey + i));
        }
    }

    return tempStore->GetStore()->Restore(databasePath, vec);
}

int RDB_GetVersion(RDB_Store *store, int *version)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    return tempStore->GetStore()->GetVersion(*version);
}

int RDB_SetVersion(RDB_Store *store, int version)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    return tempStore->GetStore()->SetVersion(version);
}