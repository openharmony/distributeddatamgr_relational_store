/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "relational_store_utils.h"
#include "rdb_open_callback.h"
#include "rdb_store_config.h"
#include "rdb_store.h"
#include "rdb_helper.h"
#include "abs_rdb_predicates.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_open_callback.h"
#include "rdb_sql_utils.h"
#include "rdb_store_config.h"
#include "unistd.h"
#include "js_ability.h"
#include "native_log.h"
#include "value_object.h"
#include "rdb_common.h"
#include "native_log.h"
#include "relational_store_impl_rdbstore.h"

#ifndef PATH_SPLIT
#define PATH_SPLIT '/'
#endif

using ContextParam = OHOS::AppDataMgrJsKit::JSUtils::ContextParam;
using RdbConfig = OHOS::AppDataMgrJsKit::JSUtils::RdbConfig;

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {
    RdbStoreObserverImpl::RdbStoreObserverImpl(int64_t id, FuncType type, int32_t mode)
    {
        callbackId = id;
        funcType = type;
        mode_ = mode;
        switch (type) {
            case NoParam: {
                auto cFunc = reinterpret_cast<void(*)()>(callbackId);
                func = CJLambda::Create(cFunc);
                break;
            }
            case ParamArrStr: {
                auto cFunc = reinterpret_cast<void(*)(CArrStr arr)>(callbackId);
                carrStrFunc = [ lambda = CJLambda::Create(cFunc)](const std::vector<std::string> &devices) ->
                    void { lambda(VectorToCArrStr(devices)); };
                break;
            }
            case ParamChangeInfo: {
                auto cFunc = reinterpret_cast<void(*)(CArrRetChangeInfo arr)>(callbackId);
                changeInfoFunc = [ lambda = CJLambda::Create(cFunc)](const DistributedRdb::Origin &origin,
                const PrimaryFields &fields, DistributedRdb::RdbStoreObserver::ChangeInfo &&changeInfo) ->
                    void { lambda(ToCArrRetChangeInfo(origin, fields, std::move(changeInfo))); };
                break;
            }
        }
    }

    SyncObserverImpl::SyncObserverImpl(int64_t id)
    {
        callbackId = id;
        auto cFunc = reinterpret_cast<void(*)(CProgressDetails details)>(callbackId);
        func = [ lambda = CJLambda::Create(cFunc)](const DistributedRdb::Details &details) ->
            void { lambda(ToCProgressDetails(details)); };
    }

    class DefaultOpenCallback : public NativeRdb::RdbOpenCallback {
    public:
        int OnCreate(NativeRdb::RdbStore &rdbStore) override
        {
            return RelationalStoreJsKit::OK;
        }

        int OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override
        {
            return RelationalStoreJsKit::OK;
        }
    };

    RdbStoreImpl::RdbStoreImpl(std::shared_ptr<OHOS::NativeRdb::RdbStore> rdbStore)
    {
        rdbStore_ = rdbStore;
    }

    OHOS::FFI::RuntimeType* RdbStoreImpl::GetClassType()
    {
        static OHOS::FFI::RuntimeType runtimeType = OHOS::FFI::RuntimeType::Create<OHOS::FFI::FFIData>("RdbStoreImpl");
        return &runtimeType;
    }

    NativeRdb::ValuesBucket ConvertFromValueBucket(ValuesBucket valuesBucket)
    {
        int64_t mapSize = valuesBucket.size;
        NativeRdb::ValuesBucket nativeValuesBucket = NativeRdb::ValuesBucket();

        for (int64_t i = 0; i < mapSize; i++) {
            NativeRdb::ValueObject valueObject = ValueTypeToValueObject(valuesBucket.value[i]);
            std::string keyStr = valuesBucket.key[i];
            nativeValuesBucket.Put(keyStr, valueObject);
        }
        return nativeValuesBucket;
    }

    std::shared_ptr<NativeRdb::ResultSet> RdbStoreImpl::Query(RdbPredicatesImpl &predicates, char** column,
        int64_t columnSize)
    {
        std::vector<std::string> columnsVector = std::vector<std::string>();
        for (int64_t i = 0; i < columnSize; i++) {
            columnsVector.push_back(std::string(column[i]));
        }
        auto resultSet = rdbStore_->Query(*(predicates.GetPredicates()), columnsVector);
        return resultSet;
    }

    std::shared_ptr<NativeRdb::ResultSet> RdbStoreImpl::RemoteQuery(char* device, RdbPredicatesImpl &predicates,
        char** column, int64_t columnSize)
    {
        std::vector<std::string> columnsVector;
        for (int64_t i = 0; i < columnSize; i++) {
            columnsVector.push_back(std::string(column[i]));
        }
        int32_t errCode;
        auto resultSet = rdbStore_->RemoteQuery(std::string(device), *(predicates.GetPredicates()), columnsVector,
            errCode);
        return resultSet;
    }

    int32_t RdbStoreImpl::Update(ValuesBucket valuesBucket, RdbPredicatesImpl &predicates,
        NativeRdb::ConflictResolution conflictResolution, int32_t *errCode)
    {
        int32_t affectedRows;
        NativeRdb::ValuesBucket nativeValuesBucket = ConvertFromValueBucket(valuesBucket);
        *errCode = rdbStore_->UpdateWithConflictResolution(affectedRows, predicates.GetPredicates()->GetTableName(),
            nativeValuesBucket, predicates.GetPredicates()->GetWhereClause(), predicates.GetPredicates()->GetBindArgs(),
            conflictResolution);
        return affectedRows;
    }

    int RdbStoreImpl::Delete(RdbPredicatesImpl &predicates, int32_t *errCode)
    {
        int deletedRows = 0;
        *errCode = rdbStore_->Delete(deletedRows, *(predicates.GetPredicates()));
        return deletedRows;
    }

    int32_t RdbStoreImpl::SetDistributedTables(char** tables, int64_t tablesSize)
    {
        std::vector<std::string> tablesVector;
        for (int64_t i = 0; i < tablesSize; i++) {
            tablesVector.push_back(std::string(tables[i]));
        }
        return rdbStore_->SetDistributedTables(tablesVector, DistributedRdb::DISTRIBUTED_DEVICE,
            DistributedRdb::DistributedConfig{false});
    }

    int32_t RdbStoreImpl::SetDistributedTables(char** tables, int64_t tablesSize, int32_t type)
    {
        std::vector<std::string> tablesVector;
        for (int64_t i = 0; i < tablesSize; i++) {
            tablesVector.push_back(std::string(tables[i]));
        }
        return rdbStore_->SetDistributedTables(tablesVector, type, DistributedRdb::DistributedConfig{false});
    }

    int32_t RdbStoreImpl::SetDistributedTables(char** tables, int64_t tablesSize, int32_t type,
        DistributedRdb::DistributedConfig &distributedConfig)
    {
        std::vector<std::string> tablesVector;
        for (int64_t i = 0; i < tablesSize; i++) {
            tablesVector.push_back(std::string(tables[i]));
        }
        return rdbStore_->SetDistributedTables(tablesVector, type, distributedConfig);
    }

    int32_t RdbStoreImpl::RollBack()
    {
        return rdbStore_->RollBack();
    }

    int32_t RdbStoreImpl::Commit()
    {
        return rdbStore_->Commit();
    }

    int32_t RdbStoreImpl::BeginTransaction()
    {
        return rdbStore_->BeginTransaction();
    }

    int32_t RdbStoreImpl::Backup(const char* destName)
    {
        return rdbStore_->Backup(destName, newKey);
    }

    int32_t RdbStoreImpl::Restore(const char* srcName)
    {
        return rdbStore_->Restore(srcName, newKey);
    }

    char* RdbStoreImpl::ObtainDistributedTableName(const char* device, const char* table)
    {
        int errCode = RelationalStoreJsKit::E_INNER_ERROR;
        std::string tableName = rdbStore_->ObtainDistributedTableName(device, table, errCode);
        return MallocCString(tableName);
    }

    int32_t RdbStoreImpl::Emit(const char* event)
    {
        return rdbStore_->Notify(event);
    }

    int64_t RdbStoreImpl::Insert(const char* table, ValuesBucket valuesBucket, int32_t conflict, int32_t *errCode)
    {
        std::string tableName = table;
        int64_t result;
        NativeRdb::ValuesBucket nativeValuesBucket = ConvertFromValueBucket(valuesBucket);
        *errCode = rdbStore_->InsertWithConflictResolution(result, tableName,
            nativeValuesBucket, NativeRdb::ConflictResolution(conflict));
        return result;
    }

    void RdbStoreImpl::ExecuteSql(const char* sql, int32_t *errCode)
    {
        *errCode = rdbStore_->ExecuteSql(sql, bindArgs);
    }


    int32_t RdbStoreImpl::CleanDirtyData(const char* tableName, uint64_t cursor)
    {
        int32_t rtnCode = rdbStore_->CleanDirtyData(tableName, cursor);
        return rtnCode;
    }

    int32_t RdbStoreImpl::BatchInsert(int64_t &insertNum, const char* tableName, ValuesBucket* valuesBuckets,
        int64_t valuesSize)
    {
        std::vector<NativeRdb::ValuesBucket> valuesVector;
        std::string tableNameStr = tableName;
        if (tableNameStr.empty()) {
            return RelationalStoreJsKit::E_PARAM_ERROR;
        }
        for (int64_t i = 0; i < valuesSize; i++) {
            NativeRdb::ValuesBucket nativeValuesBucket = ConvertFromValueBucket(valuesBuckets[i]);
            valuesVector.push_back(nativeValuesBucket);
        }
        int32_t rtnCode = rdbStore_->BatchInsert(insertNum, tableNameStr, valuesVector);
        return rtnCode;
    }

    CArrSyncResult RdbStoreImpl::Sync(int32_t mode, RdbPredicatesImpl &predicates)
    {
        DistributedRdb::SyncOption option;
        option.mode = static_cast<DistributedRdb::SyncMode>(mode);
        option.isBlock = true;
        DistributedRdb::SyncResult resMap;
        rdbStore_->Sync(option, *(predicates.GetPredicates()),
            [&resMap](const DistributedRdb::SyncResult &result) { resMap = result; });
        char** resultStr = static_cast<char**>(malloc(resMap.size() * sizeof(char*)));
        int32_t* resultNum = static_cast<int32_t*>(malloc(resMap.size() * sizeof(int32_t)));
        if (resultStr == nullptr || resultNum == nullptr) {
            free(resultStr);
            free(resultNum);
            return CArrSyncResult{nullptr, nullptr, -1};
        }
        size_t i = 0;
        for (auto it = resMap.begin(); it != resMap.end(); ++it) {
            resultStr[i] = MallocCString(it->first);
            resultNum[i] = it->second;
            i++;
        }
        return CArrSyncResult{resultStr, resultNum, int64_t(resMap.size())};
    }

    std::shared_ptr<NativeRdb::ResultSet> RdbStoreImpl::QuerySql(const char *sql, ValueType *bindArgs, int64_t size)
    {
        std::string tmpSql = sql;
        std::vector<NativeRdb::ValueObject> tmpBindArgs = std::vector<NativeRdb::ValueObject>();
        for (int64_t i = 0; i < size; i++) {
            tmpBindArgs.push_back(ValueTypeToValueObject(bindArgs[i]));
        }
        auto result = rdbStore_->QueryByStep(tmpSql, tmpBindArgs);
        return result;
    }

    void RdbStoreImpl::ExecuteSql(const char* sql, ValueType* bindArgs, int64_t bindArgsSize, int32_t *errCode)
    {
        std::vector<NativeRdb::ValueObject> bindArgsObjects = std::vector<NativeRdb::ValueObject>();
        for (int64_t i = 0; i < bindArgsSize; i++) {
            bindArgsObjects.push_back(ValueTypeToValueObject(bindArgs[i]));
        }
        *errCode = rdbStore_->ExecuteSql(sql, bindArgsObjects);
    }

    int32_t RdbStoreImpl::RegisterObserver(const char *event, bool interProcess, std::function<void()> *callback,
        const std::function<void()>& callbackRef)
    {
        DistributedRdb::SubscribeOption option;
        option.event = event;
        interProcess ? option.mode = DistributedRdb::SubscribeMode::LOCAL_SHARED : option.mode =
            DistributedRdb::SubscribeMode::LOCAL;
        if (option.mode == DistributedRdb::SubscribeMode::LOCAL) {
            return RegisteredObserver(option, localObservers_, callback, callbackRef);
        }
        return RegisteredObserver(option, localSharedObservers_, callback, callbackRef);
    }

    bool isSameFunction(const std::function<void()> *f1, const std::function<void()> *f2)
    {
        return f1 == f2;
    }

    bool RdbStoreImpl::HasRegisteredObserver(
        std::function<void()> *callback,
        std::list<std::shared_ptr<RdbStoreObserverImpl>> &observers)
    {
        for (auto &it : observers) {
            if (isSameFunction(callback, it->GetCallBack())) {
                return true;
            }
        }
        return false;
    }

    RdbStoreObserverImpl::RdbStoreObserverImpl(std::function<void()> *callback,
        const std::function<void()>& callbackRef)
    {
        m_callback = callback;
        m_callbackRef = callbackRef;
    }

    std::function<void()> *RdbStoreObserverImpl::GetCallBack()
    {
        return m_callback;
    }

    int32_t RdbStoreImpl::RegisteredObserver(
        DistributedRdb::SubscribeOption option,
        std::map<std::string, std::list<std::shared_ptr<RdbStoreObserverImpl>>> &observers,
        std::function<void()> *callback, const std::function<void()>& callbackRef)
    {
        observers.try_emplace(option.event);
        if (!HasRegisteredObserver(callback, observers[option.event])) {
            auto localObserver = std::make_shared<RdbStoreObserverImpl>(callback, callbackRef);
            int32_t errCode = rdbStore_->Subscribe(option, localObserver.get());
            if (errCode != NativeRdb::E_OK) {
                return errCode;
            }
            observers[option.event].push_back(localObserver);
            LOGI("subscribe success event: %{public}s", option.event.c_str());
        } else {
            LOGI("duplicate subscribe event: %{public}s", option.event.c_str());
        }
        return RelationalStoreJsKit::OK;
    }

    int32_t RdbStoreImpl::RegisterObserverArrStr(int32_t subscribeType, int64_t callbackId)
    {
        int32_t mode = subscribeType;
        DistributedRdb::SubscribeOption option;
        option.mode = static_cast<DistributedRdb::SubscribeMode>(mode);
        option.event = "dataChange";
        auto observer = std::make_shared<RdbStoreObserverImpl>(callbackId, RdbStoreObserverImpl::ParamArrStr, mode);
        int32_t errCode = NativeRdb::E_OK;
        if (option.mode == DistributedRdb::SubscribeMode::LOCAL_DETAIL) {
            errCode = rdbStore_->SubscribeObserver(option, observer);
        } else {
            errCode = rdbStore_->Subscribe(option, observer.get());
        }
        if (errCode == NativeRdb::E_OK) {
            observers_[mode].push_back(observer);
            LOGI("subscribe success");
        }
        return errCode;
    }

    int32_t RdbStoreImpl::RegisterObserverChangeInfo(int32_t subscribeType, int64_t callbackId)
    {
        int32_t mode = subscribeType;
        DistributedRdb::SubscribeOption option;
        option.mode = static_cast<DistributedRdb::SubscribeMode>(mode);
        option.event = "dataChange";
        auto observer = std::make_shared<RdbStoreObserverImpl>(callbackId, RdbStoreObserverImpl::ParamChangeInfo, mode);
        int32_t errCode = NativeRdb::E_OK;
        if (option.mode == DistributedRdb::SubscribeMode::LOCAL_DETAIL) {
            errCode = rdbStore_->SubscribeObserver(option, observer);
        } else {
            errCode = rdbStore_->Subscribe(option, observer.get());
        }
        if (errCode == NativeRdb::E_OK) {
            observers_[mode].push_back(observer);
            LOGI("subscribe success");
        }
        return errCode;
    }

    int32_t RdbStoreImpl::RegisterObserverProgressDetails(int64_t callbackId)
    {
        auto observer = std::make_shared<SyncObserverImpl>(callbackId);
        int errCode = rdbStore_->RegisterAutoSyncCallback(observer);
        if (errCode == NativeRdb::E_OK) {
            syncObservers_.push_back(observer);
            LOGI("progress subscribe success");
        }
        return errCode;
    }

    int32_t RdbStoreImpl::UnRegisterObserver(const char *event, bool interProcess, std::function<void()> *callback)
    {
        DistributedRdb::SubscribeOption option;
        option.event = event;
        interProcess ? option.mode = DistributedRdb::SubscribeMode::LOCAL_SHARED : option.mode =
            DistributedRdb::SubscribeMode::LOCAL;
        if (option.mode == DistributedRdb::SubscribeMode::LOCAL) {
            return UnRegisteredObserver(option, localObservers_, callback);
        }
        return UnRegisteredObserver(option, localSharedObservers_, callback);
    }

    int32_t RdbStoreImpl::UnRegisteredObserver(DistributedRdb::SubscribeOption option,
        std::map<std::string, std::list<std::shared_ptr<RdbStoreObserverImpl>>> &observers,
        std::function<void()> *callback)
    {
        auto obs = observers.find(option.event);
        if (obs == observers.end()) {
            LOGI("observer not found, event: %{public}s", option.event.c_str());
            return RelationalStoreJsKit::OK;
        }

        auto &list = obs->second;
        for (auto it = list.begin(); it != list.end(); it++) {
            if (isSameFunction(callback, (*it)->GetCallBack())) {
                int errCode = rdbStore_->UnSubscribe(option, it->get());
                if (errCode != RelationalStoreJsKit::OK) {
                    return errCode;
                }
                list.erase(it);
                break;
            }
        }
        if (list.empty()) {
            observers.erase(option.event);
        }
        LOGI("unsubscribe success, event: %{public}s", option.event.c_str());
        return RelationalStoreJsKit::OK;
    }

    int32_t RdbStoreImpl::UnRegisterAllObserver(const char *event, bool interProcess)
    {
        DistributedRdb::SubscribeOption option;
        option.event = event;
        interProcess ? option.mode = DistributedRdb::SubscribeMode::LOCAL_SHARED : option.mode =
            DistributedRdb::SubscribeMode::LOCAL;
        if (option.mode == DistributedRdb::SubscribeMode::LOCAL) {
            return UnRegisteredAllObserver(option, localObservers_);
        }
        return UnRegisteredAllObserver(option, localSharedObservers_);
    }

    int32_t RdbStoreImpl::UnRegisteredAllObserver(DistributedRdb::SubscribeOption option, std::map<std::string,
        std::list<std::shared_ptr<RdbStoreObserverImpl>>> &observers)
    {
        auto obs = observers.find(option.event);
        if (obs == observers.end()) {
            LOGI("observer not found, event: %{public}s", option.event.c_str());
            return RelationalStoreJsKit::OK;
        }

        int errCode = rdbStore_->UnSubscribe(option, nullptr);
        if (errCode != RelationalStoreJsKit::OK) {
            return errCode;
        }
        observers.erase(option.event);
        LOGI("unsubscribe success, event: %{public}s", option.event.c_str());
        return RelationalStoreJsKit::OK;
    }

    int32_t RdbStoreImpl::UnRegisterObserverArrStrChangeInfo(int32_t subscribeType, int64_t callbackId)
    {
        int32_t mode = subscribeType;
        DistributedRdb::SubscribeOption option;
        option.mode = static_cast<DistributedRdb::SubscribeMode>(mode);
        option.event = "dataChange";
        for (auto it = observers_[mode].begin(); it != observers_[mode].end();) {
            if (*it == nullptr) {
                it = observers_[mode].erase(it);
                continue;
            }
            if (((**it).GetCallBackId() != callbackId)) {
                ++it;
                continue;
            }
            int errCode = NativeRdb::E_OK;
            if (option.mode == DistributedRdb::SubscribeMode::LOCAL_DETAIL) {
                errCode = rdbStore_->UnsubscribeObserver(option, *it);
            } else {
                errCode = rdbStore_->UnSubscribe(option, it->get());
            }
            if (errCode != NativeRdb::E_OK) {
                return errCode;
            }
            it = observers_[mode].erase(it);
        }
        return NativeRdb::E_OK;
    }
    
    int32_t RdbStoreImpl::UnRegisterObserverArrStrChangeInfoAll(int32_t subscribeType)
    {
        int32_t mode = subscribeType;
        DistributedRdb::SubscribeOption option;
        option.mode = static_cast<DistributedRdb::SubscribeMode>(mode);
        option.event = "dataChange";
        for (auto it = observers_[mode].begin(); it != observers_[mode].end();) {
            if (*it == nullptr) {
                it = observers_[mode].erase(it);
                continue;
            }
            int errCode = NativeRdb::E_OK;
            if (option.mode == DistributedRdb::SubscribeMode::LOCAL_DETAIL) {
                errCode = rdbStore_->UnsubscribeObserver(option, *it);
            } else {
                errCode = rdbStore_->UnSubscribe(option, it->get());
            }
            if (errCode != NativeRdb::E_OK) {
                return errCode;
            }
            it = observers_[mode].erase(it);
        }
        return NativeRdb::E_OK;
    }

    int32_t RdbStoreImpl::UnRegisterObserverProgressDetails(int64_t callbackId)
    {
        for (auto it = syncObservers_.begin(); it != syncObservers_.end();) {
            if (*it == nullptr) {
                it = syncObservers_.erase(it);
                continue;
            }
            if (((**it).GetCallBackId() != callbackId)) {
                ++it;
                continue;
            }

            int32_t errCode = rdbStore_->UnregisterAutoSyncCallback(*it);
            if (errCode != NativeRdb::E_OK) {
                return errCode;
            }
            it = syncObservers_.erase(it);
        }
        return NativeRdb::E_OK;
    }

    int32_t RdbStoreImpl::UnRegisterObserverProgressDetailsAll()
    {
        for (auto it = syncObservers_.begin(); it != syncObservers_.end();) {
            if (*it == nullptr) {
                it = syncObservers_.erase(it);
                continue;
            }
            int32_t errCode = rdbStore_->UnregisterAutoSyncCallback(*it);
            if (errCode != NativeRdb::E_OK) {
                return errCode;
            }
            it = syncObservers_.erase(it);
        }
        return NativeRdb::E_OK;
    }

    int32_t RdbStoreImpl::CloudSync(int32_t mode, CArrStr tables, int64_t callbackId)
    {
        DistributedRdb::SyncOption option;
        option.mode = static_cast<DistributedRdb::SyncMode>(mode);
        option.isBlock = false;
        std::vector<std::string> arr = CArrStrToVector(tables);
        auto cFunc = reinterpret_cast<void(*)(CProgressDetails details)>(callbackId);
        auto async = [ lambda = CJLambda::Create(cFunc)](const DistributedRdb::Details &details) ->
            void { lambda(ToCProgressDetails(details)); };
        int32_t errCode = rdbStore_->Sync(option, arr, async);
        return errCode;
    }

    int32_t RdbStoreImpl::GetVersion(int32_t& errCode)
    {
        int32_t version = 0;
        errCode = rdbStore_->GetVersion(version);
        return version;
    }

    void RdbStoreImpl::SetVersion(int32_t value, int32_t &errCode)
    {
        errCode = rdbStore_->SetVersion(value);
    }

    ModifyTime RdbStoreImpl::GetModifyTime(char *cTables, char *cColumnName, CArrPRIKeyType &cPrimaryKeys,
        int32_t& errCode)
    {
        std::string tableName = cTables;
        std::string columnName = cColumnName;
        std::vector<NativeRdb::RdbStore::PRIKey> keys = CArrPRIKeyTypeToPRIKeyArray(cPrimaryKeys);
        std::map<NativeRdb::RdbStore::PRIKey, NativeRdb::RdbStore::Date> map =
            rdbStore_->GetModifyTime(tableName, columnName, keys);
        if (map.empty()) {
            errCode = NativeRdb::E_ERROR;
            return ModifyTime{0};
        }
        return MapToModifyTime(map, errCode);
    }

    int32_t GetRealPath(AppDataMgrJsKit::JSUtils::RdbConfig &rdbConfig,
        const AppDataMgrJsKit::JSUtils::ContextParam &param,
        std::shared_ptr<OHOS::AppDataMgrJsKit::Context> abilitycontext)
    {
        if (rdbConfig.name.find(PATH_SPLIT) != std::string::npos) {
            LOGE("Parameter error. The StoreConfig.name must be a file name without path.");
            return RelationalStoreJsKit::E_PARAM_ERROR;
        }

        if (!rdbConfig.customDir.empty()) {
            // determine if the first character of customDir is '/'
            if (rdbConfig.customDir.find_first_of(PATH_SPLIT) == 0) {
                LOGE("Parameter error. The customDir must be a relative directory.");
                return RelationalStoreJsKit::E_PARAM_ERROR;
            }
            // customDir length is limited to 128 bytes
            if (rdbConfig.customDir.length() > 128) {
                LOGE("Parameter error. The customDir length must be less than or equal to 128 bytes.");
                return RelationalStoreJsKit::E_PARAM_ERROR;
            }
        }

        std::string baseDir = param.baseDir;
        if (!rdbConfig.dataGroupId.empty()) {
            if (!param.isStageMode) {
                return RelationalStoreJsKit::E_NOT_STAGE_MODE;
            }
            std::string groupDir;
            int errCode = abilitycontext->GetSystemDatabaseDir(rdbConfig.dataGroupId, groupDir);
            if (errCode != NativeRdb::E_OK && groupDir.empty()) {
                return RelationalStoreJsKit::E_DATA_GROUP_ID_INVALID;
            }
            baseDir = groupDir;
        }

        auto [realPath, errorCode] =
            NativeRdb::RdbSqlUtils::GetDefaultDatabasePath(baseDir, rdbConfig.name, rdbConfig.customDir);
        // realPath length is limited to 1024 bytes
        if (errorCode != NativeRdb::E_OK || realPath.length() > 1024) {
            LOGE("Parameter error. The database path must be a valid path.");
            return RelationalStoreJsKit::E_PARAM_ERROR;
        }
        rdbConfig.path = realPath;
        return NativeRdb::E_OK;
    }

    void initContextParam(AppDataMgrJsKit::JSUtils::ContextParam &param,
        std::shared_ptr<OHOS::AppDataMgrJsKit::Context> abilitycontext)
    {
        param.bundleName = abilitycontext->GetBundleName();
        param.moduleName = abilitycontext->GetModuleName();
        param.baseDir = abilitycontext->GetDatabaseDir();
        param.area = abilitycontext->GetArea();
        param.isSystemApp = abilitycontext->IsSystemAppCalled();
        param.isStageMode = abilitycontext->IsStageMode();
    }

    void initRdbConfig(AppDataMgrJsKit::JSUtils::RdbConfig &rdbConfig, StoreConfig &config)
    {
        rdbConfig.isEncrypt = config.encrypt;
        rdbConfig.isSearchable = config.isSearchable;
        rdbConfig.isAutoClean = config.autoCleanDirtyData;
        rdbConfig.securityLevel = static_cast<NativeRdb::SecurityLevel>(config.securityLevel);
        rdbConfig.dataGroupId = config.dataGroupId;
        rdbConfig.name = config.name;
        rdbConfig.customDir = config.customDir;
    }

    NativeRdb::RdbStoreConfig getRdbStoreConfig(const AppDataMgrJsKit::JSUtils::RdbConfig &rdbConfig,
        const AppDataMgrJsKit::JSUtils::ContextParam &param)
    {
        NativeRdb::RdbStoreConfig rdbStoreConfig(rdbConfig.path);
        rdbStoreConfig.SetEncryptStatus(rdbConfig.isEncrypt);
        rdbStoreConfig.SetSearchable(rdbConfig.isSearchable);
        rdbStoreConfig.SetIsVector(rdbConfig.vector);
        rdbStoreConfig.SetAutoClean(rdbConfig.isAutoClean);
        rdbStoreConfig.SetSecurityLevel(rdbConfig.securityLevel);
        rdbStoreConfig.SetDataGroupId(rdbConfig.dataGroupId);
        rdbStoreConfig.SetName(rdbConfig.name);
        rdbStoreConfig.SetCustomDir(rdbConfig.customDir);
        rdbStoreConfig.SetAllowRebuild(rdbConfig.allowRebuild);

        if (!param.bundleName.empty()) {
            rdbStoreConfig.SetBundleName(param.bundleName);
        }
        rdbStoreConfig.SetModuleName(param.moduleName);
        rdbStoreConfig.SetArea(param.area);
        return rdbStoreConfig;
    }

    int64_t GetRdbStore(OHOS::AbilityRuntime::Context* context, StoreConfig config,
        int32_t *errCode)
    {
        if (context == nullptr) {
            *errCode = -1;
            return -1;
        }
        auto abilitycontext = std::make_shared<AppDataMgrJsKit::Context>(context->shared_from_this());
        AppDataMgrJsKit::JSUtils::ContextParam param;
        initContextParam(param, abilitycontext);
        AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig;
        initRdbConfig(rdbConfig, config);

        *errCode = GetRealPath(rdbConfig, param, abilitycontext);
        if (*errCode != NativeRdb::E_OK) {
            return -1;
        }

        DefaultOpenCallback callback;
        auto rdbStore =
            NativeRdb::RdbHelper::GetRdbStore(getRdbStoreConfig(rdbConfig, param), -1, callback, *errCode);
        if (*errCode != 0) {
            return -1;
        }
        auto nativeRdbStore = FFIData::Create<RdbStoreImpl>(rdbStore);
        if (nativeRdbStore == nullptr) {
            *errCode = -1;
            return -1;
        }
        return nativeRdbStore->GetID();
    }

    void DeleteRdbStore(OHOS::AbilityRuntime::Context* context, const char* name,
        int32_t *errCode)
    {
        if (context == nullptr) {
            *errCode = -1;
            return;
        }
        auto abilitycontext = std::make_shared<AppDataMgrJsKit::Context>(context->shared_from_this());
        AppDataMgrJsKit::JSUtils::ContextParam param;
        initContextParam(param, abilitycontext);
        AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig;
        rdbConfig.name = name;

        *errCode = GetRealPath(rdbConfig, param, abilitycontext);
        if (*errCode != NativeRdb::E_OK) {
            return;
        }
        *errCode = NativeRdb::RdbHelper::DeleteRdbStore(rdbConfig.path);
        return;
    }

    void DeleteRdbStoreConfig(OHOS::AbilityRuntime::Context* context, StoreConfig config,
        int32_t *errCode)
    {
        if (context == nullptr) {
            *errCode = -1;
            return;
        }
        auto abilitycontext = std::make_shared<AppDataMgrJsKit::Context>(context->shared_from_this());
        AppDataMgrJsKit::JSUtils::ContextParam param;
        initContextParam(param, abilitycontext);
        AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig;
        initRdbConfig(rdbConfig, config);

        *errCode = GetRealPath(rdbConfig, param, abilitycontext);
        if (*errCode != NativeRdb::E_OK) {
            return;
        }
        *errCode = NativeRdb::RdbHelper::DeleteRdbStore(rdbConfig.path);
        return;
    }
}
}