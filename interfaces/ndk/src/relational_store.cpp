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
    int OnDowngrade(OHOS::NativeRdb::RdbStore  &rdbStore, int oldVersion, int newVersion) override;
    int OnOpen(OHOS::NativeRdb::RdbStore  &rdbStore) override;
    int onCorruption(std::string databaseFile) override;

    OH_Rdb_OpenCallback rdbStoreOpenCallback;
};


int MainOpenCallback::OnCreate(OHOS::NativeRdb::RdbStore &store)
{
    if (rdbStoreOpenCallback.OH_Callback_OnCreate == NULL) {
        return OHOS::NativeRdb::E_OK;
    }
    std::shared_ptr<OHOS::NativeRdb::RdbStore> storeTemp(&store);
    OH_Rdb_Store *rdbStore  = new OHOS::NativeRdb::StoreImpl(storeTemp);
    int ret = rdbStoreOpenCallback.OH_Callback_OnCreate(rdbStore);
    delete rdbStore;
    rdbStore = nullptr;
    return ret;
}

int MainOpenCallback::OnUpgrade(OHOS::NativeRdb::RdbStore &store, int oldVersion, int newVersion)
{
    if (rdbStoreOpenCallback.OH_Callback_OnUpgrade == NULL) {
        return OHOS::NativeRdb::E_OK;
    }
    std::shared_ptr<OHOS::NativeRdb::RdbStore> storeTemp(&store);
    OH_Rdb_Store *rdbStore  = new OHOS::NativeRdb::StoreImpl(storeTemp);
    int ret = rdbStoreOpenCallback.OH_Callback_OnUpgrade(rdbStore, oldVersion, newVersion);
    delete rdbStore;
    rdbStore = nullptr;
    return ret;
}

int MainOpenCallback::OnDowngrade(OHOS::NativeRdb::RdbStore &store, int oldVersion, int newVersion)
{
    if (rdbStoreOpenCallback.OH_Callback_OnDowngrade == NULL) {
        return OHOS::NativeRdb::E_OK;
    }
    std::shared_ptr<OHOS::NativeRdb::RdbStore> storeTemp(&store);
    OH_Rdb_Store *rdbStore  = new OHOS::NativeRdb::StoreImpl(storeTemp);
    int ret = rdbStoreOpenCallback.OH_Callback_OnDowngrade(rdbStore, oldVersion, newVersion);
    delete rdbStore;
    rdbStore = nullptr;
    return ret;
}

int MainOpenCallback::OnOpen(OHOS::NativeRdb::RdbStore &store)
{
    if (rdbStoreOpenCallback.OH_Callback_OnOpen == NULL) {
        return OHOS::NativeRdb::E_OK;
    }
    std::shared_ptr<OHOS::NativeRdb::RdbStore> storeTemp(&store);
    OH_Rdb_Store *rdbStore  = new OHOS::NativeRdb::StoreImpl(storeTemp);
    int ret = rdbStoreOpenCallback.OH_Callback_OnOpen(rdbStore);
    delete rdbStore;
    rdbStore = nullptr;
    return ret;
}

int MainOpenCallback::onCorruption(std::string databaseFile)
{
    if (rdbStoreOpenCallback.OH_Callback_OnCorruption == NULL) {
        return OHOS::NativeRdb::E_OK;
    }
    return rdbStoreOpenCallback.OH_Callback_OnCorruption(databaseFile.c_str());
}

OH_Rdb_Store *OH_Rdb_GetOrOpen(OH_Rdb_Config const *config, int version, OH_Rdb_OpenCallback *openCallback, int *errCode)
{
    OHOS::NativeRdb::RdbStoreConfig rdbStoreConfig(config->path);
    rdbStoreConfig.SetSecurityLevel(OHOS::NativeRdb::SecurityLevel(config->securityLevel));
    rdbStoreConfig.SetEncryptStatus(config->isEncrypt);

    MainOpenCallback callback;
    if (openCallback != nullptr) {
        callback.rdbStoreOpenCallback = *openCallback;
    } else {
        callback.rdbStoreOpenCallback = {NULL, NULL, NULL, NULL, NULL};
    }

    std::shared_ptr<OHOS::NativeRdb::RdbStore> store =
        OHOS::NativeRdb::RdbHelper::GetRdbStore(rdbStoreConfig, version, callback, *errCode);
    if (store == nullptr) {
        return nullptr;
    }
    return new OHOS::NativeRdb::StoreImpl(store);
}

int OH_Rdb_CloseStore(OH_Rdb_Store *store)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    delete tempStore;
    tempStore = nullptr;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_Rdb_ClearCache()
{
    OHOS::NativeRdb::RdbHelper::ClearCache();
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_Rdb_DeleteStore(const char *path)
{
    if (path == nullptr) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    int err = OHOS::NativeRdb::RdbHelper::DeleteRdbStore(path);
    if (err != OHOS::NativeRdb::E_OK) {
        return err;
    }
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_Rdb_Insert(OH_Rdb_Store *store, char const *table, OH_Rdb_ValuesBucket *valuesBucket)
{
    if (store == nullptr || table == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    int64_t rowId = -1;
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    OHOS::NativeRdb::ValuesBucketImpl *valueImpl = static_cast<OHOS::NativeRdb::ValuesBucketImpl *>(valuesBucket);
    int ret = tempStore->GetStore()->Insert(rowId, table, valueImpl->valuesBucket_);
    if (rowId >= 0) {
        return rowId;
    } else {
        return ret;
    }
}

int OH_Rdb_Update(OH_Rdb_Store *store, OH_Rdb_ValuesBucket *valueBucket, OH_Predicates *predicate)
{
    if (store == nullptr || predicate == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    int updatedRows = -1;
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

int OH_Rdb_Delete(OH_Rdb_Store *store, OH_Predicates *predicate)
{
    if (store == nullptr || predicate == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    int deletedRows = -1;
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    OHOS::NativeRdb::PredicateImpl *tempPredicate = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    int ret = tempStore->GetStore()->Delete(deletedRows, (tempPredicate->GetPredicates()));
    if (deletedRows >= 0) {
        return deletedRows;
    } else {
        return ret;
    }
}

OH_Cursor *OH_Rdb_Query(OH_Rdb_Store *store, OH_Predicates *predicate, char const *const *columnNames, int length)
{
    if (store == nullptr || predicate == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return nullptr;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    OHOS::NativeRdb::PredicateImpl *tempPredicate = static_cast<OHOS::NativeRdb::PredicateImpl *>(predicate);
    std::vector<std::string> columns;
    if (columnNames != nullptr) {
        for (int i = 0; i < length; i++) {
            columns.push_back(std::string(columnNames[i]));
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

OH_Cursor *OH_Rdb_ExecuteQuery(OH_Rdb_Store *store, char const *sql)
{
    if (store == nullptr || sql == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
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

int OH_Rdb_Execute(OH_Rdb_Store *store, char const *sql)
{
    if (store == nullptr || sql == nullptr ||store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    return tempStore->GetStore()->ExecuteSql(sql, std::vector<OHOS::NativeRdb::ValueObject>{});
}

int OH_Rdb_Transaction(OH_Rdb_Store *store)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    return tempStore->GetStore()->BeginTransaction();
}

int OH_Rdb_RollBack(OH_Rdb_Store *store)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    return tempStore->GetStore()->RollBack();
}

int OH_Rdb_Commit(OH_Rdb_Store *store)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    return tempStore->GetStore()->Commit();
}

int OH_Rdb_Backup(OH_Rdb_Store *store, const char *databasePath)
{
    if (store == nullptr || databasePath == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    std::vector<uint8_t> vec;

    return tempStore->GetStore()->Backup(databasePath, vec);
}

int OH_Rdb_Restore(OH_Rdb_Store *store, const char *databasePath)
{
    if (store == nullptr || databasePath == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    std::vector<uint8_t> vec;

    return tempStore->GetStore()->Restore(databasePath, vec);
}

int OH_Rdb_GetVersion(OH_Rdb_Store *store, int *version)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    return tempStore->GetStore()->GetVersion(*version);
}

int OH_Rdb_SetVersion(OH_Rdb_Store *store, int version)
{
    if (store == nullptr || store->id != OHOS::NativeRdb::RDB_STORE_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::StoreImpl *tempStore = static_cast<OHOS::NativeRdb::StoreImpl *>(store);
    return tempStore->GetStore()->SetVersion(version);
}