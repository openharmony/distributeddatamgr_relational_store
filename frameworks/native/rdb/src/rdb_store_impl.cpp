/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#define LOG_TAG "RdbStoreImpl"
#include "rdb_store_impl.h"

#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <sys/stat.h>
#include <string>

#include "cache_result_set.h"
#include "connection_pool.h"
#include "delay_notify.h"
#include "directory_ex.h"
#include "knowledge_schema_helper.h"
#include "logger.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_fault_hiview_reporter.h"
#include "rdb_local_db_observer.h"
#include "rdb_radar_reporter.h"
#include "rdb_stat_reporter.h"
#include "rdb_security_manager.h"
#include "rdb_sql_log.h"
#include "rdb_sql_statistic.h"
#include "rdb_store.h"
#include "rdb_trace.h"
#include "rdb_types.h"
#include "relational_store_client.h"
#include "sqlite_global_config.h"
#include "sqlite_sql_builder.h"
#include "sqlite_statement.h"
#include "sqlite_utils.h"
#include "step_result_set.h"
#include "task_executor.h"
#include "traits.h"
#include "transaction.h"
#include "values_buckets.h"
#if !defined(CROSS_PLATFORM)
#include "raw_data_parser.h"
#include "rdb_device_manager_adapter.h"
#include "rdb_manager_impl.h"
#include "relational_store_manager.h"
#include "runtime_config.h"
#include "security_policy.h"
#include "sqlite_shared_result_set.h"
#endif

#ifdef WINDOWS_PLATFORM
#define ISFILE(filePath) ((filePath.find("\\") == std::string::npos))
#else
#define ISFILE(filePath) ((filePath.find("/") == std::string::npos))
#endif
#include "rdb_time_utils.h"

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
using namespace std::chrono;
using SqlStatistic = DistributedRdb::SqlStatistic;
using RdbNotifyConfig = DistributedRdb::RdbNotifyConfig;
using Reportor = RdbFaultHiViewReporter;
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
using RdbMgr = DistributedRdb::RdbManagerImpl;
#endif

static constexpr const char *BEGIN_TRANSACTION_SQL = "begin;";
static constexpr const char *COMMIT_TRANSACTION_SQL = "commit;";
static constexpr const char *ROLLBACK_TRANSACTION_SQL = "rollback;";
static constexpr const char *BACKUP_RESTORE = "backup.restore";
constexpr int64_t TIME_OUT = 1500;

void RdbStoreImpl::InitSyncerParam(const RdbStoreConfig &config, bool created)
{
    syncerParam_.bundleName_ = config.GetBundleName();
    syncerParam_.hapName_ = config.GetModuleName();
    syncerParam_.storeName_ = config.GetName();
    syncerParam_.customDir_ = config.GetCustomDir();
    syncerParam_.area_ = config.GetArea();
    syncerParam_.level_ = static_cast<int32_t>(config.GetSecurityLevel());
    syncerParam_.type_ = config.GetDistributedType();
    syncerParam_.isEncrypt_ = config.IsEncrypt();
    syncerParam_.isAutoClean_ = config.GetAutoClean();
    syncerParam_.isSearchable_ = config.IsSearchable();
    syncerParam_.password_ = config.GetEncryptKey();
    syncerParam_.haMode_ = config.GetHaMode();
    syncerParam_.roleType_ = config.GetRoleType();
    syncerParam_.tokenIds_ = config.GetPromiseInfo().tokenIds_;
    syncerParam_.uids_ = config.GetPromiseInfo().uids_;
    syncerParam_.user_ = config.GetPromiseInfo().user_;
    syncerParam_.permissionNames_ = config.GetPromiseInfo().permissionNames_;
    syncerParam_.subUser_ = config.GetSubUser();
    syncerParam_.dfxInfo_.lastOpenTime_ = RdbTimeUtils::GetCurSysTimeWithMs();
    if (created) {
        syncerParam_.infos_ = Connection::Collect(config);
    }
}

int RdbStoreImpl::InnerOpen()
{
    isOpen_ = true;
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    if (isReadOnly_ || isMemoryRdb_ || config_.IsLocalOnly()) {
        return E_OK;
    }
    if (config_.GetKnowledgeProcessing()) {
        SetKnowledgeSchema();
    }
    AfterOpen(syncerParam_);
    if (config_.GetDBType() == DB_VECTOR || (!config_.IsSearchable() && !config_.GetKnowledgeProcessing())) {
        return E_OK;
    }
    int errCode = RegisterDataChangeCallback();
    if (errCode != E_OK) {
        LOG_ERROR("RegisterCallBackObserver is failed, err is %{public}d.", errCode);
    }
#endif
    return E_OK;
}

void RdbStoreImpl::InitReportFunc(const RdbParam &param)
{
#if !defined(CROSS_PLATFORM)
    reportFunc_ = std::make_shared<ReportFunc>([reportParam = param](const DistributedRdb::RdbStatEvent &event) {
        auto [err, service] = RdbMgr::GetInstance().GetRdbService(reportParam);
        if (err != E_OK || service == nullptr) {
            LOG_ERROR("GetRdbService failed, err: %{public}d, storeName: %{public}s.", err,
                SqliteUtils::Anonymous(reportParam.storeName_).c_str());
            return;
        }
        err = service->ReportStatistic(reportParam, event);
        if (err != E_OK) {
            LOG_ERROR("ReportStatistic failed, err: %{public}d, storeName: %{public}s.", err,
                SqliteUtils::Anonymous(reportParam.storeName_).c_str());
        }
        return;
    });
#endif
}

void RdbStoreImpl::Close()
{
    {
        std::unique_lock<decltype(poolMutex_)> lock(poolMutex_);
        if (connectionPool_) {
            connectionPool_->CloseAllConnections();
            connectionPool_.reset();
        }
    }
    {
        std::lock_guard<decltype(mutex_)> guard(mutex_);
        for (auto &it : transactions_) {
            auto trans = it.lock();
            if (trans != nullptr) {
                trans->Close();
            }
        }
        transactions_ = {};
    }
}

std::shared_ptr<ConnectionPool> RdbStoreImpl::GetPool() const
{
    std::shared_lock<decltype(poolMutex_)> lock(poolMutex_);
    return connectionPool_;
}

std::pair<int32_t, std::shared_ptr<Connection>> RdbStoreImpl::GetConn(bool isRead)
{
    auto pool = GetPool();
    if (pool == nullptr) {
        return { E_ALREADY_CLOSED, nullptr };
    }

    auto connection = pool->AcquireConnection(isRead);
    if (connection == nullptr) {
        return { E_DATABASE_BUSY, nullptr };
    }
    return { E_OK, connection };
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
void RdbStoreImpl::AfterOpen(const RdbParam &param, int32_t retry)
{
    auto [err, service] = RdbMgr::GetInstance().GetRdbService(param);
    if (err == E_NOT_SUPPORT) {
        return;
    }
    if (err != E_OK || service == nullptr) {
        LOG_ERROR("GetRdbService failed, err: %{public}d, storeName: %{public}s.", err,
            SqliteUtils::Anonymous(param.storeName_).c_str());
        auto pool = TaskExecutor::GetInstance().GetExecutor();
        if (err == E_SERVICE_NOT_FOUND && pool != nullptr && retry++ < MAX_RETRY_TIMES) {
            pool->Schedule(std::chrono::seconds(RETRY_INTERVAL), [param, retry]() {
                AfterOpen(param, retry);
            });
        }
        return;
    }
    err = service->AfterOpen(param);
    if (err != E_OK) {
        LOG_ERROR("AfterOpen failed, err: %{public}d, storeName: %{public}s.", err,
            SqliteUtils::Anonymous(param.storeName_).c_str());
    }
}

RdbStore::ModifyTime RdbStoreImpl::GetModifyTime(
    const std::string &table, const std::string &columnName, std::vector<PRIKey> &keys)
{
    if (table.empty() || columnName.empty() || keys.empty()) {
        LOG_ERROR("Invalid para.");
        return {};
    }

    auto logTable = DistributedDB::RelationalStoreManager::GetDistributedLogTableName(table);
    if (SqliteUtils::StrToUpper(columnName) == ROW_ID) {
        return GetModifyTimeByRowId(logTable, keys);
    }
    std::vector<ValueObject> hashKeys;
    hashKeys.reserve(keys.size());
    std::map<std::vector<uint8_t>, PRIKey> keyMap;
    std::map<std::string, DistributedDB::Type> tmp;
    for (const auto &key : keys) {
        DistributedDB::Type value;
        RawDataParser::Convert(key, value);
        tmp[columnName] = value;
        auto hashKey = DistributedDB::RelationalStoreManager::CalcPrimaryKeyHash(tmp);
        if (hashKey.empty()) {
            LOG_DEBUG("Hash key fail.");
            continue;
        }
        hashKeys.emplace_back(ValueObject(hashKey));
        keyMap[hashKey] = key;
    }

    std::string sql;
    sql.append("select hash_key as key, timestamp/10000 as modify_time from ");
    sql.append(logTable);
    sql.append(" where hash_key in (");
    sql.append(SqliteSqlBuilder::GetSqlArgs(hashKeys.size()));
    sql.append(")");
    auto resultSet = QueryByStep(sql, hashKeys, true);
    int count = 0;
    if (resultSet == nullptr || resultSet->GetRowCount(count) != E_OK || count <= 0) {
        LOG_ERROR("Get resultSet err.");
        return {};
    }
    return { resultSet, keyMap, false };
}

RdbStore::ModifyTime RdbStoreImpl::GetModifyTimeByRowId(const std::string &logTable, std::vector<PRIKey> &keys)
{
    std::string sql;
    sql.append("select data_key as key, timestamp/10000 as modify_time from ");
    sql.append(logTable);
    sql.append(" where data_key in (");
    sql.append(SqliteSqlBuilder::GetSqlArgs(keys.size()));
    sql.append(")");
    std::vector<ValueObject> args;
    args.reserve(keys.size());
    for (auto &key : keys) {
        ValueObject::Type value;
        RawDataParser::Convert(key, value);
        args.emplace_back(ValueObject(value));
    }
    auto resultSet = QueryByStep(sql, args, true);
    int count = 0;
    if (resultSet == nullptr || resultSet->GetRowCount(count) != E_OK || count <= 0) {
        LOG_ERROR("Get resultSet err.");
        return {};
    }
    return ModifyTime(resultSet, {}, true);
}

int RdbStoreImpl::CleanDirtyData(const std::string &table, uint64_t cursor)
{
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR) || isMemoryRdb_) {
        LOG_ERROR("Not support. table:%{public}s, isRead:%{public}d, dbType:%{public}d, isMemoryRdb:%{public}d.",
            SqliteUtils::Anonymous(table).c_str(), isReadOnly_, config_.GetDBType(), isMemoryRdb_);
        return E_NOT_SUPPORT;
    }
    auto [errCode, conn] = GetConn(false);
    if (errCode != E_OK) {
        LOG_ERROR("The database is busy or closed.");
        return errCode;
    }
    errCode = conn->CleanDirtyData(table, cursor);
    return errCode;
}

std::string RdbStoreImpl::GetLogTableName(const std::string &tableName)
{
    return DistributedDB::RelationalStoreManager::GetDistributedLogTableName(tableName);
}

std::pair<int32_t, std::shared_ptr<ResultSet>> RdbStoreImpl::QuerySharingResource(
    const AbsRdbPredicates &predicates, const Fields &columns)
{
    if (config_.GetDBType() == DB_VECTOR) {
        return { E_NOT_SUPPORT, nullptr };
    }
    auto [errCode, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (errCode != E_OK) {
        return { errCode, nullptr };
    }
    auto [status, resultSet] =
        service->QuerySharingResource(syncerParam_, predicates.GetDistributedPredicates(), columns);
    if (status != E_OK) {
        return { status, nullptr };
    }
    return { status, resultSet };
}

std::shared_ptr<ResultSet> RdbStoreImpl::RemoteQuery(
    const std::string &device, const AbsRdbPredicates &predicates, const Fields &columns, int &errCode)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (config_.GetDBType() == DB_VECTOR || isMemoryRdb_) {
        return nullptr;
    }
    std::vector<std::string> selectionArgs = predicates.GetWhereArgs();
    std::string sql = SqliteSqlBuilder::BuildQueryString(predicates, columns);
    auto [err, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (err == E_NOT_SUPPORT) {
        errCode = err;
        return nullptr;
    }
    if (err != E_OK) {
        LOG_ERROR("RdbStoreImpl::RemoteQuery get service failed.");
        errCode = err;
        return nullptr;
    }
    auto [status, resultSet] = service->RemoteQuery(syncerParam_, device, sql, selectionArgs);
    errCode = status;
    return resultSet;
}

void RdbStoreImpl::NotifyDataChange()
{
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR) || !config_.GetRegisterInfo(RegisterType::CLIENT_OBSERVER)) {
        return;
    }
    config_.SetRegisterInfo(RegisterType::CLIENT_OBSERVER, false);
    int errCode = RegisterDataChangeCallback();
    if (errCode != E_OK) {
        LOG_ERROR("RegisterDataChangeCallback is failed, err is %{public}d.", errCode);
    }
    DistributedRdb::RdbChangedData rdbChangedData;
    if (delayNotifier_ != nullptr) {
        delayNotifier_->UpdateNotify(rdbChangedData, true);
    }
}

int RdbStoreImpl::SetDistributedTables(
    const std::vector<std::string> &tables, int32_t type, const DistributedRdb::DistributedConfig &distributedConfig)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (config_.GetDBType() == DB_VECTOR || isReadOnly_ || isMemoryRdb_) {
        return E_NOT_SUPPORT;
    }
    if (tables.empty()) {
        LOG_WARN("The distributed tables to be set is empty.");
        return E_OK;
    }
    auto [errCode, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (errCode != E_OK) {
        return errCode;
    }
    syncerParam_.asyncDownloadAsset_ = distributedConfig.asyncDownloadAsset;
    syncerParam_.enableCloud_ = distributedConfig.enableCloud;
    int32_t errorCode = service->SetDistributedTables(
        syncerParam_, tables, distributedConfig.references, distributedConfig.isRebuild, type);
    if (errorCode != E_OK) {
        LOG_ERROR("Fail to set distributed tables, error=%{public}d.", errorCode);
        return errorCode;
    }
    if (type == DistributedRdb::DISTRIBUTED_DEVICE && !config_.GetRegisterInfo(RegisterType::CLIENT_OBSERVER)) {
        RegisterDataChangeCallback();
    }
    if (type != DistributedRdb::DISTRIBUTED_CLOUD) {
        return E_OK;
    }

    return HandleCloudSyncAfterSetDistributedTables(tables, distributedConfig);
}

int RdbStoreImpl::HandleCloudSyncAfterSetDistributedTables(
    const std::vector<std::string> &tables, const DistributedRdb::DistributedConfig &distributedConfig)
{
    auto pool = GetPool();
    if (pool == nullptr) {
        return E_ALREADY_CLOSED;
    }
    auto conn = pool->AcquireConnection(false);
    if (conn != nullptr) {
        auto strategy = conn->GenerateExchangeStrategy(slaveStatus_);
        if (strategy == ExchangeStrategy::BACKUP) {
            (void)conn->Backup({}, {}, false, slaveStatus_);
        }
    }
    {
        std::unique_lock<decltype(rwMutex_)> lock(rwMutex_);
        if (distributedConfig.enableCloud && distributedConfig.autoSync) {
            cloudInfo_->AddTables(tables);
        } else {
            cloudInfo_->RmvTables(tables);
            return E_OK;
        }
    }
    auto isRebuilt = RebuiltType::NONE;
    GetRebuilt(isRebuilt);
    if (isRebuilt == RebuiltType::REBUILT) {
        DoCloudSync("");
    }
    return E_OK;
}

std::string RdbStoreImpl::ObtainDistributedTableName(const std::string &device, const std::string &table, int &errCode)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (config_.GetDBType() == DB_VECTOR || isMemoryRdb_) {
        return "";
    }
    std::string uuid;
    DeviceManagerAdaptor::RdbDeviceManagerAdaptor &deviceManager =
        DeviceManagerAdaptor::RdbDeviceManagerAdaptor::GetInstance(syncerParam_.bundleName_);
    errCode = deviceManager.GetEncryptedUuidByNetworkId(device, uuid);
    if (errCode != E_OK) {
        LOG_ERROR("GetUuid is failed.");
        return "";
    }

    auto translateCall = [uuid](const std::string &oriDevId, const DistributedDB::StoreInfo &info) {
        return uuid;
    };
    DistributedDB::RuntimeConfig::SetTranslateToDeviceIdCallback(translateCall);

    return DistributedDB::RelationalStoreManager::GetDistributedTableName(uuid, table);
}

int RdbStoreImpl::Sync(const SyncOption &option, const AbsRdbPredicates &predicate, const AsyncBrief &callback)
{
    if (config_.GetDBType() == DB_VECTOR) {
        return E_NOT_SUPPORT;
    }
    return Sync(option, predicate, [callback](Details &&details) {
        Briefs briefs;
        for (auto &[key, value] : details) {
            briefs.insert_or_assign(key, value.code);
        }
        if (callback != nullptr) {
            callback(briefs);
        }
    });
}

int RdbStoreImpl::Sync(const SyncOption &option, const std::vector<std::string> &tables, const AsyncDetail &async)
{
    return Sync(option, AbsRdbPredicates(tables), async);
}

int RdbStoreImpl::Sync(const SyncOption &option, const AbsRdbPredicates &predicate, const AsyncDetail &async)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (isMemoryRdb_) {
        return E_NOT_SUPPORT;
    }
    DistributedRdb::RdbService::Option rdbOption;
    rdbOption.mode = option.mode;
    rdbOption.isAsync = !option.isBlock;
    RdbRadar ret(Scene::SCENE_SYNC, __FUNCTION__, config_.GetBundleName());
    ret = InnerSync(syncerParam_, rdbOption, predicate.GetDistributedPredicates(), async);
    return ret;
}

int RdbStoreImpl::InnerSync(
    const RdbParam &param, const Options &option, const Memo &predicates, const AsyncDetail &async)
{
    auto [errCode, service] = RdbMgr::GetInstance().GetRdbService(param);
    if (errCode == E_NOT_SUPPORT) {
        return errCode;
    }
    if (errCode != E_OK) {
        LOG_ERROR("GetRdbService is failed, err is %{public}d, bundleName is %{public}s.", errCode,
            param.bundleName_.c_str());
        return errCode;
    }
    errCode = service->Sync(param, option, predicates, async);
    if (errCode != E_OK) {
        LOG_ERROR("Sync is failed, err is %{public}d.", errCode);
        return errCode;
    }
    return E_OK;
}

Uri RdbStoreImpl::GetUri(const std::string &event)
{
    std::string rdbUri;
    if (config_.GetDataGroupId().empty()) {
        rdbUri = SCHEME_RDB + config_.GetBundleName() + "/" + path_ + "/" + event;
    } else {
        rdbUri = SCHEME_RDB + config_.GetDataGroupId() + "/" + path_ + "/" + event;
    }
    return Uri(rdbUri);
}

int RdbStoreImpl::SubscribeLocal(const SubscribeOption &option, RdbStoreObserver *observer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    localObservers_.try_emplace(option.event);
    auto &list = localObservers_.find(option.event)->second;
    for (auto it = list.begin(); it != list.end(); it++) {
        if ((*it)->getObserver() == observer) {
            LOG_ERROR("Duplicate subscribe.");
            return E_OK;
        }
    }

    localObservers_[option.event].push_back(std::make_shared<RdbStoreLocalObserver>(observer));
    return E_OK;
}

int RdbStoreImpl::SubscribeLocalShared(const SubscribeOption &option, RdbStoreObserver *observer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    localSharedObservers_.try_emplace(option.event);
    auto &list = localSharedObservers_.find(option.event)->second;
    for (auto it = list.begin(); it != list.end(); it++) {
        if ((*it)->getObserver() == observer) {
            LOG_ERROR("Duplicate subscribe.");
            return E_OK;
        }
    }

    auto client = OHOS::AAFwk::DataObsMgrClient::GetInstance();
    if (client == nullptr) {
        LOG_ERROR("Failed to get DataObsMgrClient.");
        return E_GET_DATAOBSMGRCLIENT_FAIL;
    }
    sptr<RdbStoreLocalSharedObserver> localSharedObserver(new (std::nothrow) RdbStoreLocalSharedObserver(observer));
    int32_t err = client->RegisterObserver(GetUri(option.event), localSharedObserver);
    if (err != 0) {
        LOG_ERROR("Subscribe failed.");
        return err;
    }
    localSharedObservers_[option.event].push_back(std::move(localSharedObserver));
    return E_OK;
}

int32_t RdbStoreImpl::SubscribeLocalDetail(
    const SubscribeOption &option, const std::shared_ptr<RdbStoreObserver> &observer)
{
    if (observer == nullptr) {
        return E_OK;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = localDetailObservers_.begin(); it != localDetailObservers_.end(); it++) {
        if ((*it)->GetObserver() == observer) {
            LOG_WARN("duplicate subscribe.");
            return E_OK;
        }
    }
    auto localStoreObserver = std::make_shared<RdbStoreLocalDbObserver>(observer);
    auto [errCode, conn] = GetConn(false);
    if (conn == nullptr) {
        return errCode;
    }
    errCode = conn->Subscribe(localStoreObserver);
    if (errCode != E_OK) {
        LOG_ERROR("Subscribe local detail observer failed. db name:%{public}s errCode:%{public}." PRId32,
            SqliteUtils::Anonymous(config_.GetName()).c_str(), errCode);
        return errCode;
    }
    config_.SetRegisterInfo(RegisterType::STORE_OBSERVER, true);
    localDetailObservers_.emplace_back(localStoreObserver);
    return E_OK;
}

int RdbStoreImpl::SubscribeRemote(const SubscribeOption &option, RdbStoreObserver *observer)
{
    auto [errCode, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (errCode != E_OK) {
        return errCode;
    }
    return service->Subscribe(syncerParam_, option, observer);
}

int RdbStoreImpl::Subscribe(const SubscribeOption &option, RdbStoreObserver *observer)
{
    if (config_.GetDBType() == DB_VECTOR) {
        return E_NOT_SUPPORT;
    }
    if (option.mode == SubscribeMode::LOCAL) {
        return SubscribeLocal(option, observer);
    }
    if (isMemoryRdb_) {
        return E_NOT_SUPPORT;
    }
    if (option.mode == SubscribeMode::LOCAL_SHARED) {
        return SubscribeLocalShared(option, observer);
    }
    return SubscribeRemote(option, observer);
}

int RdbStoreImpl::UnSubscribeLocal(const SubscribeOption &option, RdbStoreObserver *observer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto obs = localObservers_.find(option.event);
    if (obs == localObservers_.end()) {
        return E_OK;
    }

    auto &list = obs->second;
    for (auto it = list.begin(); it != list.end();) {
        if (observer == nullptr || (*it)->getObserver() == observer) {
            it = list.erase(it);
            if (observer != nullptr) {
                break;
            }
        } else {
            it++;
        }
    }

    if (list.empty()) {
        localObservers_.erase(option.event);
    }
    return E_OK;
}

int RdbStoreImpl::UnSubscribeLocalShared(const SubscribeOption &option, RdbStoreObserver *observer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto obs = localSharedObservers_.find(option.event);
    if (obs == localSharedObservers_.end()) {
        return E_OK;
    }

    auto client = OHOS::AAFwk::DataObsMgrClient::GetInstance();
    if (client == nullptr) {
        LOG_ERROR("Failed to get DataObsMgrClient.");
        return E_GET_DATAOBSMGRCLIENT_FAIL;
    }

    auto &list = obs->second;
    for (auto it = list.begin(); it != list.end();) {
        if (observer == nullptr || (*it)->getObserver() == observer) {
            int32_t err = client->UnregisterObserver(GetUri(option.event), *it);
            if (err != 0) {
                LOG_ERROR("UnSubscribeLocalShared failed.");
                return err;
            }
            it = list.erase(it);
            if (observer != nullptr) {
                break;
            }
        } else {
            it++;
        }
    }
    if (list.empty()) {
        localSharedObservers_.erase(option.event);
    }
    return E_OK;
}

int32_t RdbStoreImpl::UnsubscribeLocalDetail(
    const SubscribeOption &option, const std::shared_ptr<RdbStoreObserver> &observer)
{
    auto [errCode, conn] = GetConn(false);
    if (conn == nullptr) {
        return errCode;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = localDetailObservers_.begin(); it != localDetailObservers_.end();) {
        if (observer == nullptr || (*it)->GetObserver() == observer) {
            int32_t err = conn->Unsubscribe(*it);
            if (err != 0) {
                LOG_ERROR("Unsubscribe local detail observer failed. db name:%{public}s errCode:%{public}." PRId32,
                    SqliteUtils::Anonymous(config_.GetName()).c_str(), errCode);
                return err;
            }
            it = localDetailObservers_.erase(it);
            if (observer != nullptr) {
                break;
            }
        } else {
            it++;
        }
    }
    return E_OK;
}

int RdbStoreImpl::UnSubscribeRemote(const SubscribeOption &option, RdbStoreObserver *observer)
{
    auto [errCode, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (errCode != E_OK) {
        return errCode;
    }
    return service->UnSubscribe(syncerParam_, option, observer);
}

int RdbStoreImpl::UnSubscribe(const SubscribeOption &option, RdbStoreObserver *observer)
{
    if (config_.GetDBType() == DB_VECTOR) {
        return E_NOT_SUPPORT;
    }
    if (option.mode == SubscribeMode::LOCAL) {
        return UnSubscribeLocal(option, observer);
    }
    if (isMemoryRdb_) {
        return E_NOT_SUPPORT;
    }
    if (option.mode == SubscribeMode::LOCAL_SHARED) {
        return UnSubscribeLocalShared(option, observer);
    }
    return UnSubscribeRemote(option, observer);
}

int RdbStoreImpl::SubscribeObserver(const SubscribeOption &option, const std::shared_ptr<RdbStoreObserver> &observer)
{
    if (config_.GetDBType() == DB_VECTOR || isMemoryRdb_) {
        return E_NOT_SUPPORT;
    }
    return SubscribeLocalDetail(option, observer);
}

int RdbStoreImpl::UnsubscribeObserver(const SubscribeOption &option, const std::shared_ptr<RdbStoreObserver> &observer)
{
    if (config_.GetDBType() == DB_VECTOR || isMemoryRdb_) {
        return E_NOT_SUPPORT;
    }
    return UnsubscribeLocalDetail(option, observer);
}

int RdbStoreImpl::Notify(const std::string &event)
{
    if (config_.GetDBType() == DB_VECTOR) {
        return E_NOT_SUPPORT;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto obs = localObservers_.find(event);
        if (obs != localObservers_.end()) {
            auto &list = obs->second;
            for (auto &it : list) {
                it->OnChange();
            }
        }
    }
    if (isMemoryRdb_) {
        return E_OK;
    }
    auto client = OHOS::AAFwk::DataObsMgrClient::GetInstance();
    if (client == nullptr) {
        LOG_ERROR("Failed to get DataObsMgrClient.");
        return E_GET_DATAOBSMGRCLIENT_FAIL;
    }
    int32_t err = client->NotifyChange(GetUri(event));
    if (err != 0) {
        LOG_ERROR("Notify failed.");
    }
    return E_OK;
}

int RdbStoreImpl::SetSearchable(bool isSearchable)
{
    if (config_.GetDBType() == DB_VECTOR || isMemoryRdb_) {
        return E_NOT_SUPPORT;
    }
    auto [errCode, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (errCode != E_OK || service == nullptr) {
        LOG_ERROR("GetRdbService is failed, err is %{public}d.", errCode);
        return errCode;
    }
    return service->SetSearchable(syncerParam_, isSearchable);
}

int RdbStoreImpl::RegisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer)
{
    if (config_.GetDBType() == DB_VECTOR || isMemoryRdb_) {
        return E_NOT_SUPPORT;
    }
    auto [errCode, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (errCode != E_OK) {
        return errCode;
    }
    return service->RegisterAutoSyncCallback(syncerParam_, observer);
}

int RdbStoreImpl::UnregisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer)
{
    if (config_.GetDBType() == DB_VECTOR || isMemoryRdb_) {
        return E_NOT_SUPPORT;
    }
    auto [errCode, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (errCode != E_OK) {
        return errCode;
    }
    return service->UnregisterAutoSyncCallback(syncerParam_, observer);
}

void RdbStoreImpl::InitDelayNotifier()
{
    if (delayNotifier_ != nullptr) {
        return;
    }
    delayNotifier_ = std::make_shared<DelayNotify>();
    if (delayNotifier_ == nullptr) {
        LOG_ERROR("Init delay notifier failed.");
        return;
    }
    delayNotifier_->SetExecutorPool(TaskExecutor::GetInstance().GetExecutor());
    delayNotifier_->SetTask([param = syncerParam_, helper = GetKnowledgeSchemaHelper()](
        const DistributedRdb::RdbChangedData &rdbChangedData, const RdbNotifyConfig &rdbNotifyConfig) -> int {
        if (IsKnowledgeDataChange(rdbChangedData)) {
            helper->DonateKnowledgeData();
        }
        if (!IsNotifyService(rdbChangedData)) {
            return E_OK;
        }
        auto [errCode, service] = RdbMgr::GetInstance().GetRdbService(param);
        if (errCode == E_NOT_SUPPORT) {
            return errCode;
        }
        if (errCode != E_OK || service == nullptr) {
            LOG_ERROR("GetRdbService is failed, err is %{public}d.", errCode);
            return errCode;
        }
        return service->NotifyDataChange(param, rdbChangedData, rdbNotifyConfig);
    });
}

int RdbStoreImpl::RegisterDataChangeCallback()
{
    InitDelayNotifier();
    auto connPool = GetPool();
    if (connPool == nullptr) {
        return E_ALREADY_CLOSED;
    }

    RegisterDataChangeCallback(delayNotifier_, connPool, 0);
    config_.SetRegisterInfo(RegisterType::CLIENT_OBSERVER, true);
    return E_OK;
}

void RdbStoreImpl::RegisterDataChangeCallback(
    std::shared_ptr<DelayNotify> delayNotifier, std::weak_ptr<ConnectionPool> connPool, int retry)
{
    auto relConnPool = connPool.lock();
    if (relConnPool == nullptr) {
        return;
    }
    auto conn = relConnPool->AcquireConnection(false);
    if (conn == nullptr) {
        relConnPool->Dump(true, "DATACHANGE");
        auto pool = TaskExecutor::GetInstance().GetExecutor();
        if (pool != nullptr && retry++ < MAX_RETRY_TIMES) {
            pool->Schedule(std::chrono::seconds(1),
                [delayNotifier, connPool, retry]() { RegisterDataChangeCallback(delayNotifier, connPool, retry); });
        }
        return;
    }
    auto callBack = [delayNotifier](const DistributedRdb::RdbChangedData &rdbChangedData) {
        if (delayNotifier != nullptr) {
            delayNotifier->UpdateNotify(rdbChangedData);
        }
    };
    auto errCode = conn->SubscribeTableChanges(callBack);
    if (errCode != E_OK) {
        return;
    }
}

int RdbStoreImpl::GetHashKeyForLockRow(const AbsRdbPredicates &predicates, std::vector<std::vector<uint8_t>> &hashKeys)
{
    std::string table = predicates.GetTableName();
    if (table.empty()) {
        return E_EMPTY_TABLE_NAME;
    }
    auto logTable = GetLogTableName(table);
    std::string sql;
    sql.append("SELECT ").append(logTable).append(".hash_key ").append("FROM ").append(logTable);
    sql.append(" INNER JOIN ").append(table).append(" ON ");
    sql.append(table).append(".ROWID = ").append(logTable).append(".data_key");
    auto whereClause = predicates.GetWhereClause();
    if (!whereClause.empty()) {
        sql.append(" WHERE ").append(SqliteUtils::Replace(whereClause, SqliteUtils::REP, logTable + "."));
    }

    auto result = QuerySql(sql, predicates.GetBindArgs());
    if (result == nullptr) {
        return E_ALREADY_CLOSED ;
    }
    int count = 0;
    if (result->GetRowCount(count) != E_OK) {
        return E_NO_ROW_IN_QUERY;
    }

    if (count <= 0) {
        return E_NO_ROW_IN_QUERY;
    }
    while (result->GoToNextRow() == E_OK) {
        std::vector<uint8_t> hashKey;
        if (result->GetBlob(0, hashKey) != E_OK) {
            return E_ERROR;
        }
        hashKeys.push_back(std::move(hashKey));
    }
    return E_OK;
}

int RdbStoreImpl::ModifyLockStatus(const AbsRdbPredicates &predicates, bool isLock)
{
    if (config_.IsVector() || isMemoryRdb_ || isReadOnly_) {
        return E_NOT_SUPPORT;
    }
    std::vector<std::vector<uint8_t>> hashKeys;
    int ret = GetHashKeyForLockRow(predicates, hashKeys);
    if (ret != E_OK) {
        LOG_ERROR("GetHashKeyForLockRow failed, err is %{public}d.", ret);
        return ret;
    }
    SqlLog::Pause();
    auto [err, statement] = GetStatement(GlobalExpr::PRAGMA_VERSION);
    if (statement == nullptr || err != E_OK) {
        return err;
    }
    SqlLog::Resume();
    int errCode = statement->ModifyLockStatus(predicates.GetTableName(), hashKeys, isLock);
    if (errCode == E_WAIT_COMPENSATED_SYNC) {
        LOG_DEBUG("Start compensation sync.");
        DistributedRdb::RdbService::Option option = { DistributedRdb::TIME_FIRST, 0, true, true, true };
        auto memo = AbsRdbPredicates(predicates.GetTableName()).GetDistributedPredicates();
        InnerSync(syncerParam_, option, memo, nullptr);
        return E_OK;
    }
    if (errCode != E_OK) {
        LOG_ERROR("ModifyLockStatus failed, err is %{public}d.", errCode);
    }
    return errCode;
}

std::pair<int32_t, uint32_t> RdbStoreImpl::LockCloudContainer()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (config_.IsVector() || isMemoryRdb_ || isReadOnly_) {
        return { E_NOT_SUPPORT, 0 };
    }
    RdbRadar ret(Scene::SCENE_SYNC, __FUNCTION__, config_.GetBundleName());
    auto [errCode, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (errCode == E_NOT_SUPPORT) {
        LOG_ERROR("not support");
        return { errCode, 0 };
    }
    if (errCode != E_OK) {
        LOG_ERROR("GetRdbService is failed, err is %{public}d, bundleName is %{public}s.", errCode,
            syncerParam_.bundleName_.c_str());
        return { errCode, 0 };
    }
    auto result = service->LockCloudContainer(syncerParam_);
    if (result.first != E_OK) {
        LOG_ERROR("LockCloudContainer failed, err is %{public}d.", result.first);
    }
    return result;
}

int32_t RdbStoreImpl::UnlockCloudContainer()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (config_.IsVector() || isMemoryRdb_ || isReadOnly_) {
        return E_NOT_SUPPORT;
    }
    RdbRadar ret(Scene::SCENE_SYNC, __FUNCTION__, config_.GetBundleName());
    auto [errCode, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (errCode == E_NOT_SUPPORT) {
        LOG_ERROR("not support");
        return errCode;
    }
    if (errCode != E_OK) {
        LOG_ERROR("GetRdbService is failed, err is %{public}d, bundleName is %{public}s.", errCode,
            syncerParam_.bundleName_.c_str());
        return errCode;
    }
    errCode = service->UnlockCloudContainer(syncerParam_);
    if (errCode != E_OK) {
        LOG_ERROR("UnlockCloudContainer failed, err is %{public}d.", errCode);
    }
    return errCode;
}
#endif

RdbStoreImpl::RdbStoreImpl(const RdbStoreConfig &config)
    : isMemoryRdb_(config.IsMemoryRdb()), config_(config), name_(config.GetName()),
      fileType_(config.GetDatabaseFileType())
{
    SqliteGlobalConfig::GetDbPath(config_, path_);
    isReadOnly_ = config.IsReadOnly() || config.GetRoleType() == VISITOR;
}

RdbStoreImpl::RdbStoreImpl(const RdbStoreConfig &config, int &errCode)
    : isMemoryRdb_(config.IsMemoryRdb()), config_(config), name_(config.GetName()),
      fileType_(config.GetDatabaseFileType())
{
    isReadOnly_ = config.IsReadOnly() || config.GetRoleType() == VISITOR;
    SqliteGlobalConfig::GetDbPath(config_, path_);
    bool created = access(path_.c_str(), F_OK) != 0;
    connectionPool_ = ConnectionPool::Create(config_, errCode);
    if (connectionPool_ == nullptr && (errCode == E_SQLITE_CORRUPT || errCode == E_INVALID_SECRET_KEY) &&
        !isReadOnly_) {
        LOG_ERROR("database corrupt, errCode:0x%{public}x, %{public}s, %{public}s", errCode,
            SqliteUtils::Anonymous(name_).c_str(),
            SqliteUtils::FormatDebugInfoBrief(Connection::Collect(config_), "master").c_str());
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
        RdbParam param;
        param.bundleName_ = config_.GetBundleName();
        param.storeName_ = config_.GetName();
        param.subUser_ = config_.GetSubUser();
        auto [err, service] = RdbMgr::GetInstance().GetRdbService(param);
        if (service != nullptr) {
            service->Disable(param);
        }
#endif
        config_.SetIter(0);
        if (config_.IsEncrypt() && config_.GetAllowRebuild()) {
            auto key = config_.GetEncryptKey();
            RdbSecurityManager::GetInstance().RestoreKeyFile(path_, key);
            key.assign(key.size(), 0);
        }
        std::tie(rebuild_, connectionPool_) = ConnectionPool::HandleDataCorruption(config_, errCode);
        created = true;
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
        if (service != nullptr) {
            service->Enable(param);
        }
#endif
    }
    if (connectionPool_ == nullptr || errCode != E_OK) {
        connectionPool_ = nullptr;
        LOG_ERROR("Create connPool failed, err is %{public}d, path:%{public}s", errCode,
            SqliteUtils::Anonymous(path_).c_str());
        return;
    }
    InitSyncerParam(config_, created);
    InitReportFunc(syncerParam_);
    InnerOpen();
}

RdbStoreImpl::~RdbStoreImpl()
{
    connectionPool_ = nullptr;
    trxConnMap_ = {};
    for (auto &trans : transactions_) {
        auto realTrans = trans.lock();
        if (realTrans) {
            (void)realTrans->Close();
        }
    }
    transactions_ = {};
}

const RdbStoreConfig &RdbStoreImpl::GetConfig()
{
    return config_;
}

std::pair<int, int64_t> RdbStoreImpl::Insert(const std::string &table, const Row &row, Resolution resolution)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR)) {
        return { E_NOT_SUPPORT, -1 };
    }
    if (table.empty()) {
        return { E_EMPTY_TABLE_NAME, -1 };
    }

    if (row.IsEmpty()) {
        return { E_EMPTY_VALUES_BUCKET, -1 };
    }

    auto conflictClause = SqliteUtils::GetConflictClause(static_cast<int>(resolution));
    if (conflictClause == nullptr) {
        return { E_INVALID_CONFLICT_FLAG, -1 };
    }
    RdbStatReporter reportStat(RDB_PERF, INSERT, config_, reportFunc_);
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL);
    std::string sql;
    sql.append("INSERT").append(conflictClause).append(" INTO ").append(table).append("(");
    size_t bindArgsSize = row.values_.size();
    std::vector<ValueObject> bindArgs;
    bindArgs.reserve(bindArgsSize);
    const char *split = "";
    for (const auto &[key, val] : row.values_) {
        sql.append(split).append(key);
        if (val.GetType() == ValueObject::TYPE_ASSETS && resolution == ConflictResolution::ON_CONFLICT_REPLACE) {
            return { E_INVALID_ARGS, -1 };
        }
        SqliteSqlBuilder::UpdateAssetStatus(val, AssetValue::STATUS_INSERT);
        bindArgs.push_back(val); // columnValue
        split = ",";
    }

    sql.append(") VALUES (");
    if (bindArgsSize > 0) {
        sql.append(SqliteSqlBuilder::GetSqlArgs(bindArgsSize));
    }

    sql.append(")");
    int64_t rowid = -1;
    auto errCode = ExecuteForLastInsertedRowId(rowid, sql, bindArgs);
    if (errCode == E_OK) {
        DoCloudSync(table);
    }

    return { errCode, rowid };
}

std::pair<int, int64_t> RdbStoreImpl::BatchInsert(const std::string &table, const ValuesBuckets &rows)
{
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR)) {
        return { E_NOT_SUPPORT, -1 };
    }

    if (rows.RowSize() == 0) {
        return { E_OK, 0 };
    }

    RdbStatReporter reportStat(RDB_PERF, BATCHINSERT, config_, reportFunc_);
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL);
    auto pool = GetPool();
    if (pool == nullptr) {
        return { E_ALREADY_CLOSED, -1 };
    }
    auto conn = pool->AcquireConnection(false);
    if (conn == nullptr) {
        return { E_DATABASE_BUSY, -1 };
    }

    auto executeSqlArgs = SqliteSqlBuilder::GenerateSqls(table, rows, conn->GetMaxVariable());
    BatchInsertArgsDfx(static_cast<int>(executeSqlArgs.size()));
    if (executeSqlArgs.empty()) {
        LOG_ERROR("empty, table=%{public}s, values:%{public}zu, max number:%{public}d.", table.c_str(), rows.RowSize(),
            conn->GetMaxVariable());
        return { E_INVALID_ARGS, -1 };
    }
    PauseDelayNotify pauseDelayNotify(delayNotifier_);
    for (const auto &[sql, bindArgs] : executeSqlArgs) {
        auto [errCode, statement] = GetStatement(sql, conn);
        if (statement == nullptr) {
            LOG_ERROR("statement is nullptr, errCode:0x%{public}x, args:%{public}zu, table:%{public}s, "
                "app self can check the SQL", errCode, bindArgs.size(), table.c_str());
            return { E_OK, -1 };
        }
        for (const auto &args : bindArgs) {
            auto errCode = statement->Execute(args);
            if (errCode == E_SQLITE_LOCKED || errCode == E_SQLITE_BUSY) {
                pool->Dump(true, "BATCH");
                return { errCode, -1 };
            }
            if (errCode != E_OK) {
                LOG_ERROR("failed, errCode:%{public}d,args:%{public}zu,table:%{public}s,app self can check the SQL",
                    errCode, bindArgs.size(), table.c_str());
                return { E_OK, -1 };
            }
        }
    }
    conn = nullptr;
    DoCloudSync(table);
    return { E_OK, int64_t(rows.RowSize()) };
}

void RdbStoreImpl::BatchInsertArgsDfx(int argsSize)
{
    if (argsSize > 1) {
        Reportor::ReportFault(RdbFaultEvent(FT_CURD, E_DFX_BATCH_INSERT_ARGS_SIZE, config_.GetBundleName(),
            "BatchInsert executeSqlArgs size[ " + std::to_string(argsSize) + "]"));
    }
}

std::pair<int, int64_t> RdbStoreImpl::BatchInsertWithConflictResolution(
    const std::string &table, const ValuesBuckets &rows, Resolution resolution)
{
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR)) {
        return { E_NOT_SUPPORT, -1 };
    }

    if (rows.RowSize() == 0) {
        return { E_OK, 0 };
    }

    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL);
    auto pool = GetPool();
    if (pool == nullptr) {
        return { E_ALREADY_CLOSED, -1 };
    }
    auto conn = pool->AcquireConnection(false);
    if (conn == nullptr) {
        return { E_DATABASE_BUSY, -1 };
    }

    auto sqlArgs = SqliteSqlBuilder::GenerateSqls(table, rows, conn->GetMaxVariable(), resolution);
    // To ensure atomicity, execute SQL only once
    if (sqlArgs.size() != 1 || sqlArgs.front().second.size() != 1) {
        auto [fields, values] = rows.GetFieldsAndValues();
        LOG_ERROR("invalid args, table=%{public}s, rows:%{public}zu, fields:%{public}zu, max:%{public}d.",
            table.c_str(), rows.RowSize(), fields != nullptr ? fields->size() : 0, conn->GetMaxVariable());
        return { E_INVALID_ARGS, -1 };
    }
    auto &[sql, bindArgs] = sqlArgs.front();
    auto [errCode, statement] = GetStatement(sql, conn);
    if (statement == nullptr) {
        LOG_ERROR("statement is nullptr, errCode:0x%{public}x, args:%{public}zu, table:%{public}s, "
                  "app self can check the SQL", errCode, bindArgs.size(), table.c_str());
        return { errCode, -1 };
    }
    PauseDelayNotify pauseDelayNotify(delayNotifier_);
    auto args = std::ref(bindArgs.front());
    errCode = statement->Execute(args);
    if (errCode == E_SQLITE_LOCKED || errCode == E_SQLITE_BUSY) {
        pool->Dump(true, "BATCH");
        return { errCode, -1 };
    }
    if (errCode != E_OK) {
        LOG_ERROR("failed,errCode:%{public}d,table:%{public}s,args:%{public}zu,resolution:%{public}d.", errCode,
            table.c_str(), args.get().size(), static_cast<int32_t>(resolution));
        return { errCode, errCode == E_SQLITE_CONSTRAINT ? int64_t(statement->Changes()) : -1 };
    }
    conn = nullptr;
    DoCloudSync(table);
    return { E_OK, int64_t(statement->Changes()) };
}

std::pair<int, int> RdbStoreImpl::Update(
    const std::string &table, const Row &row, const std::string &where, const Values &args, Resolution resolution)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR)) {
        return { E_NOT_SUPPORT, -1 };
    }
    if (table.empty()) {
        return { E_EMPTY_TABLE_NAME, -1 };
    }

    if (row.IsEmpty()) {
        return { E_EMPTY_VALUES_BUCKET, -1 };
    }

    auto clause = SqliteUtils::GetConflictClause(static_cast<int>(resolution));
    if (clause == nullptr) {
        return { E_INVALID_CONFLICT_FLAG, -1 };
    }
    RdbStatReporter reportStat(RDB_PERF, UPDATE, config_, reportFunc_);
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL);
    std::string sql;
    sql.append("UPDATE").append(clause).append(" ").append(table).append(" SET ");
    std::vector<ValueObject> tmpBindArgs;
    size_t tmpBindSize = row.values_.size() + args.size();
    tmpBindArgs.reserve(tmpBindSize);
    const char *split = "";
    for (auto &[key, val] : row.values_) {
        sql.append(split);
        if (val.GetType() == ValueObject::TYPE_ASSETS) {
            sql.append(key).append("=merge_assets(").append(key).append(", ?)"); // columnName
        } else if (val.GetType() == ValueObject::TYPE_ASSET) {
            sql.append(key).append("=merge_asset(").append(key).append(", ?)"); // columnName
        } else {
            sql.append(key).append("=?"); // columnName
        }
        tmpBindArgs.push_back(val); // columnValue
        split = ",";
    }

    if (!where.empty()) {
        sql.append(" WHERE ").append(where);
    }

    tmpBindArgs.insert(tmpBindArgs.end(), args.begin(), args.end());

    int64_t changes = 0;
    auto errCode = ExecuteForChangedRowCount(changes, sql, tmpBindArgs);
    if (errCode == E_OK) {
        DoCloudSync(table);
    }
    return { errCode, int32_t(changes) };
}

int RdbStoreImpl::Delete(int &deletedRows, const std::string &table, const std::string &whereClause, const Values &args)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR)) {
        return E_NOT_SUPPORT;
    }
    if (table.empty()) {
        return E_EMPTY_TABLE_NAME;
    }

    RdbStatReporter reportStat(RDB_PERF, DELETE, config_, reportFunc_);
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL);
    std::string sql;
    sql.append("DELETE FROM ").append(table);
    if (!whereClause.empty()) {
        sql.append(" WHERE ").append(whereClause);
    }
    int64_t changes = 0;
    auto errCode = ExecuteForChangedRowCount(changes, sql, args);
    if (errCode != E_OK) {
        return errCode;
    }
    deletedRows = changes;
    DoCloudSync(table);
    return E_OK;
}

std::shared_ptr<AbsSharedResultSet> RdbStoreImpl::QuerySql(const std::string &sql, const Values &bindArgs)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (config_.GetDBType() == DB_VECTOR) {
        return nullptr;
    }
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL);
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    auto start = std::chrono::steady_clock::now();
    auto pool = GetPool();
    if (pool == nullptr) {
        LOG_ERROR("Database already closed.");
        return nullptr;
    }
    return std::make_shared<SqliteSharedResultSet>(start, pool->AcquireRef(true), sql, bindArgs, path_);
#else
    (void)sql;
    (void)bindArgs;
    return nullptr;
#endif
}

std::shared_ptr<ResultSet> RdbStoreImpl::QueryByStep(const std::string &sql, const Values &args, bool preCount)
{
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL);
    auto start = std::chrono::steady_clock::now();
    auto pool = GetPool();
    if (pool == nullptr) {
        LOG_ERROR("Database already closed.");
        return nullptr;
    }
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    return std::make_shared<StepResultSet>(start, connectionPool_->AcquireRef(true), sql, args, preCount);
#else
    return std::make_shared<StepResultSet>(start, connectionPool_->AcquireRef(true), sql, args, false);
#endif
}

int RdbStoreImpl::Count(int64_t &outValue, const AbsRdbPredicates &predicates)
{
    if (config_.GetDBType() == DB_VECTOR) {
        return E_NOT_SUPPORT;
    }
    std::string sql = SqliteSqlBuilder::BuildCountString(predicates);
    return ExecuteAndGetLong(outValue, sql, predicates.GetBindArgs());
}

void WriteToCompareFile(const std::string &dbPath, const std::string &bundleName, const std::string &sql)
{
    auto poolTask = TaskExecutor::GetInstance().GetExecutor();
    if (poolTask != nullptr) {
        poolTask->Execute([dbPath, bundleName, sql]() {
            std::string comparePath = dbPath + "-compare";
            if (SqliteUtils::CleanFileContent(comparePath)) {
                Reportor::ReportFault(
                    RdbFaultEvent(FT_CURD, E_DFX_IS_NOT_EXIST, bundleName, "compare file is deleted"));
            }
            SqliteUtils::WriteSqlToFile(comparePath, sql);
        });
    }
}

void RdbStoreImpl::HandleSchemaDDL(std::shared_ptr<Statement> statement,
    std::shared_ptr<ConnectionPool> pool, const std::string &sql, int32_t &errCode)
{
    statement->Reset();
    statement->Prepare("PRAGMA schema_version");
    auto [err, version] = statement->ExecuteForValue();
    statement = nullptr;
    if (vSchema_ < static_cast<int64_t>(version)) {
        LOG_INFO("db:%{public}s exe DDL schema<%{public}" PRIi64 "->%{public}" PRIi64
                 "> app self can check the SQL.",
            SqliteUtils::Anonymous(name_).c_str(), vSchema_, static_cast<int64_t>(version));
        vSchema_ = version;
        errCode = pool->RestartConns();
        if (!isMemoryRdb_) {
            std::string dbPath = config_.GetPath();
            std::string bundleName = config_.GetBundleName();
            WriteToCompareFile(dbPath, bundleName, sql);
        }
    }
}

int RdbStoreImpl::ExecuteSql(const std::string &sql, const Values &args)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (config_.GetDBType() == DB_VECTOR || isReadOnly_) {
        return E_NOT_SUPPORT;
    }
    int ret = CheckAttach(sql);
    if (ret != E_OK) {
        return ret;
    }
    RdbStatReporter reportStat(RDB_PERF, EXECUTESQL, config_, reportFunc_);
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL);
    auto [errCode, statement] = BeginExecuteSql(sql);
    if (statement == nullptr) {
        return errCode;
    }
    auto pool = GetPool();
    if (pool == nullptr) {
        return E_ALREADY_CLOSED;
    }
    errCode = statement->Execute(args);
    if (errCode != E_OK) {
        LOG_ERROR("failed,error:0x%{public}x app self can check the SQL.", errCode);
        if (errCode == E_SQLITE_LOCKED || errCode == E_SQLITE_BUSY) {
            pool->Dump(true, "EXECUTE");
        }
        return errCode;
    }
    int sqlType = SqliteUtils::GetSqlStatementType(sql);
    if (sqlType == SqliteUtils::STATEMENT_DDL) {
        HandleSchemaDDL(statement, pool, sql, errCode);
    }
    statement = nullptr;
    if (errCode == E_OK && (sqlType == SqliteUtils::STATEMENT_UPDATE || sqlType == SqliteUtils::STATEMENT_INSERT)) {
        DoCloudSync("");
    }
    return errCode;
}

std::pair<int32_t, ValueObject> RdbStoreImpl::Execute(const std::string &sql, const Values &args, int64_t trxId)
{
    ValueObject object;
    if (isReadOnly_) {
        return { E_NOT_SUPPORT, object };
    }

    RdbStatReporter reportStat(RDB_PERF, EXECUTE, config_, reportFunc_);
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL);
    int sqlType = SqliteUtils::GetSqlStatementType(sql);
    if (!SqliteUtils::IsSupportSqlForExecute(sqlType)) {
        LOG_ERROR("Not support the sqlType: %{public}d, app self can check the SQL", sqlType);
        return { E_NOT_SUPPORT_THE_SQL, object };
    }

    if (config_.IsVector() && trxId > 0) {
        return { ExecuteByTrxId(sql, trxId, false, args), ValueObject() };
    }

    auto pool = GetPool();
    if (pool == nullptr) {
        return { E_ALREADY_CLOSED, object };
    }
    auto conn = pool->AcquireConnection(false);
    if (pool == nullptr) {
        return { E_DATABASE_BUSY, object };
    }

    auto [errCode, statement] = GetStatement(sql, conn);
    if (errCode != E_OK) {
        return { errCode, object };
    }

    errCode = statement->Execute(args);
    if (errCode != E_OK) {
        LOG_ERROR("failed,error:0x%{public}x app self can check the SQL.", errCode);
        if (errCode == E_SQLITE_LOCKED || errCode == E_SQLITE_BUSY) {
            pool->Dump(true, "EXECUTE");
        }
        return { errCode, object };
    }

    if (config_.IsVector()) {
        return { errCode, object };
    }

    return HandleDifferentSqlTypes(statement, sql, object, sqlType);
}

std::pair<int32_t, ValueObject> RdbStoreImpl::HandleDifferentSqlTypes(
    std::shared_ptr<Statement> statement, const std::string &sql, const ValueObject &object, int sqlType)
{
    int32_t errCode = E_OK;
    if (sqlType == SqliteUtils::STATEMENT_INSERT) {
        int64_t outValue = statement->Changes() > 0 ? statement->LastInsertRowId() : -1;
        return { errCode, ValueObject(outValue) };
    }

    if (sqlType == SqliteUtils::STATEMENT_UPDATE) {
        int outValue = statement->Changes();
        return { errCode, ValueObject(outValue) };
    }

    if (sqlType == SqliteUtils::STATEMENT_PRAGMA) {
        if (statement->GetColumnCount() == 1) {
            return statement->GetColumn(0);
        }

        if (statement->GetColumnCount() > 1) {
            LOG_ERROR("Not support the sql:app self can check the SQL, column count more than 1");
            return { E_NOT_SUPPORT_THE_SQL, object };
        }
    }

    auto pool = GetPool();
    if (pool == nullptr) {
        return { E_ALREADY_CLOSED, object };
    }

    if (sqlType == SqliteUtils::STATEMENT_DDL) {
        HandleSchemaDDL(statement, pool, sql, errCode);
    }
    return { errCode, object };
}

int RdbStoreImpl::ExecuteAndGetLong(int64_t &outValue, const std::string &sql, const Values &args)
{
    if (config_.GetDBType() == DB_VECTOR) {
        return E_NOT_SUPPORT;
    }
    auto [errCode, statement] = BeginExecuteSql(sql);
    if (statement == nullptr) {
        return errCode;
    }
    auto [err, object] = statement->ExecuteForValue(args);
    if (err != E_OK) {
        LOG_ERROR("failed, app self can check the SQL,  ERROR is %{public}d.", err);
    }
    outValue = object;
    return err;
}

int RdbStoreImpl::ExecuteAndGetString(std::string &outValue, const std::string &sql, const Values &args)
{
    if (config_.GetDBType() == DB_VECTOR) {
        return E_NOT_SUPPORT;
    }
    auto [errCode, statement] = BeginExecuteSql(sql);
    if (statement == nullptr) {
        return errCode;
    }
    ValueObject object;
    std::tie(errCode, object) = statement->ExecuteForValue(args);
    if (errCode != E_OK) {
        LOG_ERROR("failed, app self can check the SQL,  ERROR is %{public}d.", errCode);
    }
    outValue = static_cast<std::string>(object);
    return errCode;
}

int RdbStoreImpl::ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql, const Values &args)
{
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR)) {
        return E_NOT_SUPPORT;
    }
    auto begin = std::chrono::steady_clock::now();
    auto [errCode, statement] = GetStatement(sql, false);
    if (statement == nullptr) {
        return errCode;
    }
    auto beginExec = std::chrono::steady_clock::now();
    errCode = statement->Execute(args);
    if (errCode != E_OK) {
        if (errCode == E_SQLITE_LOCKED || errCode == E_SQLITE_BUSY) {
            auto pool = GetPool();
            if (pool != nullptr) {
                pool->Dump(true, "INSERT");
            }
        }
        return errCode;
    }
    auto beginResult = std::chrono::steady_clock::now();
    outValue = statement->Changes() > 0 ? statement->LastInsertRowId() : -1;
    auto allEnd = std::chrono::steady_clock::now();
    int64_t totalCostTime = std::chrono::duration_cast<std::chrono::milliseconds>(allEnd - begin).count();
    if (totalCostTime >= TIME_OUT) {
        int64_t prepareCost = std::chrono::duration_cast<std::chrono::milliseconds>(beginExec - begin).count();
        int64_t execCost = std::chrono::duration_cast<std::chrono::milliseconds>(beginResult - beginExec).count();
        int64_t resultCost = std::chrono::duration_cast<std::chrono::milliseconds>(allEnd - beginResult).count();
        LOG_WARN("total[%{public}" PRId64 "] stmt[%{public}" PRId64 "] exec[%{public}" PRId64
                 "] result[%{public}" PRId64 "] "
                 "sql[%{public}s]",
            totalCostTime, prepareCost, execCost, resultCost, SqliteUtils::Anonymous(sql).c_str());
    }
    return E_OK;
}

int RdbStoreImpl::ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql, const Values &args)
{
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR)) {
        return E_NOT_SUPPORT;
    }
    auto [errCode, statement] = GetStatement(sql, false);
    if (statement == nullptr) {
        return errCode;
    }
    errCode = statement->Execute(args);
    if (errCode == E_OK) {
        outValue = statement->Changes();
        return E_OK;
    }
    if (errCode == E_SQLITE_LOCKED || errCode == E_SQLITE_BUSY) {
        auto pool = GetPool();
        if (pool != nullptr) {
            pool->Dump(true, "UPG DEL");
        }
    }
    return errCode;
}

int RdbStoreImpl::GetDataBasePath(const std::string &databasePath, std::string &backupFilePath)
{
    if (databasePath.empty()) {
        return E_INVALID_FILE_PATH;
    }

    if (ISFILE(databasePath)) {
        backupFilePath = ExtractFilePath(path_) + databasePath;
    } else {
        // 2 represents two characters starting from the len - 2 position
        if (!PathToRealPath(ExtractFilePath(databasePath), backupFilePath) || databasePath.back() == '/' ||
            databasePath.substr(databasePath.length() - 2, 2) == "\\") {
            LOG_ERROR("Invalid databasePath.");
            return E_INVALID_FILE_PATH;
        }
        backupFilePath = databasePath;
    }

    if (backupFilePath == path_) {
        LOG_ERROR("The backupPath and path should not be same.");
        return E_INVALID_FILE_PATH;
    }

    LOG_INFO("databasePath is %{public}s.", SqliteUtils::Anonymous(backupFilePath).c_str());
    return E_OK;
}

int RdbStoreImpl::GetSlaveName(const std::string &path, std::string &backupFilePath)
{
    std::string suffix(".db");
    std::string slaveSuffix("_slave.db");
    auto pos = path.find(suffix);
    if (pos == std::string::npos) {
        backupFilePath = path + slaveSuffix;
    } else {
        backupFilePath = std::string(path, 0, pos) + slaveSuffix;
    }
    return E_OK;
}

/**
 * Backup a database from a specified encrypted or unencrypted database file.
 */
int RdbStoreImpl::Backup(const std::string &databasePath, const std::vector<uint8_t> &encryptKey)
{
    LOG_INFO("Backup db: %{public}s.", SqliteUtils::Anonymous(config_.GetName()).c_str());
    if (isReadOnly_ || isMemoryRdb_) {
        return E_NOT_SUPPORT;
    }
    std::string backupFilePath;
    if (TryGetMasterSlaveBackupPath(databasePath, backupFilePath)) {
        return InnerBackup(backupFilePath, encryptKey);
    }

    int ret = GetDataBasePath(databasePath, backupFilePath);
    if (ret != E_OK) {
        return ret;
    }

    RdbSecurityManager::KeyFiles keyFiles(path_ + BACKUP_RESTORE);
    keyFiles.Lock();

    auto walFile = backupFilePath + "-wal";
    if (access(walFile.c_str(), F_OK) == E_OK) {
        if (!SqliteUtils::DeleteDirtyFiles(backupFilePath)) {
            keyFiles.Unlock();
            return E_ERROR;
        }
    }
    std::string tempPath = backupFilePath + ".tmp";
    if (access(tempPath.c_str(), F_OK) == E_OK) {
        SqliteUtils::DeleteFile(backupFilePath);
    } else {
        if (access(backupFilePath.c_str(), F_OK) == E_OK && !SqliteUtils::RenameFile(backupFilePath, tempPath)) {
            LOG_ERROR("rename backup file failed, path:%{public}s, errno:%{public}d",
                SqliteUtils::Anonymous(backupFilePath).c_str(), errno);
            keyFiles.Unlock();
            return E_ERROR;
        }
    }
    ret = InnerBackup(backupFilePath, encryptKey);
    if (ret != E_OK || access(walFile.c_str(), F_OK) == E_OK) {
        if (ret == E_DB_NOT_EXIST) {
            Reportor::ReportCorrupted(Reportor::Create(config_, ret, "ErrorType: BackupFailed"));
        }
        if (SqliteUtils::DeleteDirtyFiles(backupFilePath)) {
            SqliteUtils::RenameFile(tempPath, backupFilePath);
        }
    } else {
        SqliteUtils::DeleteFile(tempPath);
    }
    keyFiles.Unlock();
    return ret;
}

std::vector<ValueObject> RdbStoreImpl::CreateBackupBindArgs(
    const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey)
{
    std::vector<ValueObject> bindArgs;
    bindArgs.emplace_back(databasePath);
    if (!destEncryptKey.empty() && !config_.IsEncrypt()) {
        bindArgs.emplace_back(destEncryptKey);
    } else if (config_.IsEncrypt()) {
        std::vector<uint8_t> key = config_.GetEncryptKey();
        bindArgs.emplace_back(key);
        key.assign(key.size(), 0);
    } else {
        bindArgs.emplace_back("");
    }
    return bindArgs;
}

/**
 * Backup a database from a specified encrypted or unencrypted database file.
 */
int RdbStoreImpl::InnerBackup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey)
{
    if (isReadOnly_) {
        return E_NOT_SUPPORT;
    }

    if (config_.GetDBType() == DB_VECTOR) {
        auto [errCode, conn] = GetConn(false);
        return errCode != E_OK ? errCode : conn->Backup(databasePath, destEncryptKey, false, slaveStatus_);
    }

    if (config_.GetHaMode() != HAMode::SINGLE && SqliteUtils::IsSlaveDbName(databasePath)) {
        auto [errCode, conn] = GetConn(false);
        return errCode != E_OK ? errCode : conn->Backup(databasePath, {}, false, slaveStatus_);
    }

    auto [result, conn] = CreateWritableConn();
    if (result != E_OK) {
        return result;
    }

    if (config_.IsEncrypt()) {
        result = SetDefaultEncryptAlgo(conn, config_);
        if (result != E_OK) {
            return result;
        }
    }

    std::vector<ValueObject> bindArgs = CreateBackupBindArgs(databasePath, destEncryptKey);
    SqlLog::Pause();
    auto [errCode, statement] = conn->CreateStatement(GlobalExpr::ATTACH_BACKUP_SQL, conn);
    errCode = statement->Execute(bindArgs);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = statement->Prepare(GlobalExpr::PRAGMA_BACKUP_JOUR_MODE_WAL);
    errCode = statement->Execute();
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = statement->Prepare(GlobalExpr::EXPORT_SQL);
    int ret = statement->Execute();
    errCode = statement->Prepare(GlobalExpr::DETACH_BACKUP_SQL);
    int res = statement->Execute();
    SqlLog::Resume();
    return (res == E_OK) ? ret : res;
}

std::pair<int32_t, RdbStoreImpl::Stmt> RdbStoreImpl::BeginExecuteSql(const std::string &sql)
{
    int type = SqliteUtils::GetSqlStatementType(sql);
    if (SqliteUtils::IsSpecial(type)) {
        return { E_NOT_SUPPORT, nullptr };
    }

    bool assumeReadOnly = SqliteUtils::IsSqlReadOnly(type);
    auto pool = GetPool();
    if (pool == nullptr) {
        return { E_ALREADY_CLOSED, nullptr };
    }
    auto conn = pool->AcquireConnection(assumeReadOnly);
    if (conn == nullptr) {
        return { E_DATABASE_BUSY, nullptr };
    }

    auto [errCode, statement] = conn->CreateStatement(sql, conn);
    if (statement == nullptr) {
        return { errCode, nullptr };
    }

    if (statement->ReadOnly() && conn->IsWriter()) {
        statement = nullptr;
        conn = nullptr;
        return GetStatement(sql, true);
    }

    return { errCode, statement };
}

bool RdbStoreImpl::IsHoldingConnection()
{
    return GetPool() != nullptr;
}

int RdbStoreImpl::SetDefaultEncryptSql(
    const std::shared_ptr<Statement> &statement, std::string sql, const RdbStoreConfig &config)
{
    auto errCode = statement->Prepare(sql);
    if (errCode != E_OK) {
        LOG_ERROR("Prepare failed: %{public}s, %{public}d, %{public}d, %{public}d, %{public}d, %{public}u",
            SqliteUtils::Anonymous(config.GetName()).c_str(), config.GetCryptoParam().iterNum,
            config.GetCryptoParam().encryptAlgo, config.GetCryptoParam().hmacAlgo, config.GetCryptoParam().kdfAlgo,
            config.GetCryptoParam().cryptoPageSize);
        return errCode;
    }
    errCode = statement->Execute();
    if (errCode != E_OK) {
        LOG_ERROR("Execute failed: %{public}s, %{public}d, %{public}d, %{public}d, %{public}d, %{public}u",
            SqliteUtils::Anonymous(config.GetName()).c_str(), config.GetCryptoParam().iterNum,
            config.GetCryptoParam().encryptAlgo, config.GetCryptoParam().hmacAlgo, config.GetCryptoParam().kdfAlgo,
            config.GetCryptoParam().cryptoPageSize);
        return errCode;
    }
    return E_OK;
}

int RdbStoreImpl::SetDefaultEncryptAlgo(const ConnectionPool::SharedConn &conn, const RdbStoreConfig &config)
{
    if (conn == nullptr) {
        return E_DATABASE_BUSY;
    }

    if (!config.GetCryptoParam().IsValid()) {
        LOG_ERROR("Invalid crypto param, name:%{public}s", SqliteUtils::Anonymous(config.GetName()).c_str());
        return E_INVALID_ARGS;
    }

    std::string sql = std::string(GlobalExpr::CIPHER_DEFAULT_ATTACH_CIPHER_PREFIX) +
                      SqliteUtils::EncryptAlgoDescription(config.GetEncryptAlgo()) +
                      std::string(GlobalExpr::ALGO_SUFFIX);
    SqlLog::Pause();
    auto [errCode, statement] = conn->CreateStatement(sql, conn);
    errCode = SetDefaultEncryptSql(statement, sql, config);
    if (errCode != E_OK) {
        return errCode;
    }

    if (config.GetIter() > 0) {
        sql = std::string(GlobalExpr::CIPHER_DEFAULT_ATTACH_KDF_ITER_PREFIX) + std::to_string(config.GetIter());
        errCode = SetDefaultEncryptSql(statement, sql, config);
        if (errCode != E_OK) {
            return errCode;
        }
    }

    sql = std::string(GlobalExpr::CIPHER_DEFAULT_ATTACH_HMAC_ALGO_PREFIX) +
          SqliteUtils::HmacAlgoDescription(config.GetCryptoParam().hmacAlgo) + std::string(GlobalExpr::ALGO_SUFFIX);
    errCode = SetDefaultEncryptSql(statement, sql, config);
    if (errCode != E_OK) {
        return errCode;
    }

    sql = std::string(GlobalExpr::CIPHER_DEFAULT_ATTACH_KDF_ALGO_PREFIX) +
                      SqliteUtils::KdfAlgoDescription(config.GetCryptoParam().kdfAlgo) +
                      std::string(GlobalExpr::ALGO_SUFFIX);
    errCode = SetDefaultEncryptSql(statement, sql, config);
    if (errCode != E_OK) {
        return errCode;
    }

    sql = std::string(GlobalExpr::CIPHER_DEFAULT_ATTACH_PAGE_SIZE_PREFIX) +
          std::to_string(config.GetCryptoParam().cryptoPageSize);
    errCode = SetDefaultEncryptSql(statement, sql, config);
    SqlLog::Resume();
    return errCode;
}

int RdbStoreImpl::AttachInner(const RdbStoreConfig &config, const std::string &attachName, const std::string &dbPath,
    const std::vector<uint8_t> &key, int32_t waitTime)
{
    auto pool = GetPool();
    if (pool == nullptr) {
        return E_ALREADY_CLOSED;
    }
    auto [conn, readers] = pool->AcquireAll(waitTime);
    if (conn == nullptr) {
        return E_DATABASE_BUSY;
    }

    if (!isMemoryRdb_ && conn->GetJournalMode() == static_cast<int32_t>(JournalMode::MODE_WAL)) {
        // close first to prevent the connection from being put back.
        pool->CloseAllConnections();
        conn = nullptr;
        readers.clear();
        auto [err, newConn] = pool->DisableWal();
        if (err != E_OK) {
            return err;
        }
        conn = newConn;
    }
    std::vector<ValueObject> bindArgs;
    bindArgs.emplace_back(ValueObject(dbPath));
    bindArgs.emplace_back(ValueObject(attachName));
    SqlLog::Pause();
    if (!key.empty()) {
        auto ret = SetDefaultEncryptAlgo(conn, config);
        if (ret != E_OK) {
            return ret;
        }
        bindArgs.emplace_back(ValueObject(key));
        auto [errCode, statement] = conn->CreateStatement(GlobalExpr::ATTACH_WITH_KEY_SQL, conn);
        if (statement == nullptr || errCode != E_OK) {
            LOG_ERROR("Attach get statement failed, code is %{public}d", errCode);
            return E_ERROR;
        }
        return statement->Execute(bindArgs);
    }

    auto [errCode, statement] = conn->CreateStatement(GlobalExpr::ATTACH_SQL, conn);
    if (statement == nullptr || errCode != E_OK) {
        LOG_ERROR("Attach get statement failed, code is %{public}d", errCode);
        return errCode;
    }
    errCode = statement->Execute(bindArgs);
    SqlLog::Resume();
    return errCode;
}

/**
 * Attaches a database.
 */
std::pair<int32_t, int32_t> RdbStoreImpl::Attach(
    const RdbStoreConfig &config, const std::string &attachName, int32_t waitTime)
{
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR) || config_.GetHaMode() != HAMode::SINGLE ||
        (config.IsMemoryRdb() && config.IsEncrypt())) {
        return { E_NOT_SUPPORT, 0 };
    }
    std::string dbPath;
    int err = SqliteGlobalConfig::GetDbPath(config, dbPath);
    if (err != E_OK || (access(dbPath.c_str(), F_OK) != E_OK && !config.IsMemoryRdb())) {
        return { E_INVALID_FILE_PATH, 0 };
    }

    // encrypted databases are not supported to attach a non encrypted database.
    if (!config.IsEncrypt() && config_.IsEncrypt()) {
        return { E_NOT_SUPPORT, 0 };
    }

    if (attachedInfo_.Contains(attachName)) {
        return { E_ATTACHED_DATABASE_EXIST, 0 };
    }

    std::vector<uint8_t> key;
    config.Initialize();
    if (config.IsEncrypt()) {
        key = config.GetEncryptKey();
    }
    err = AttachInner(config, attachName, dbPath, key, waitTime);
    key.assign(key.size(), 0);
    if (err == E_SQLITE_ERROR) {
        // only when attachName is already in use, SQLITE-ERROR will be reported here.
        return { E_ATTACHED_DATABASE_EXIST, 0 };
    } else if (err != E_OK) {
        LOG_ERROR("failed, errCode[%{public}d] fileName[%{public}s] attachName[%{public}s] attach fileName"
                  "[%{public}s]",
            err, SqliteUtils::Anonymous(config_.GetName()).c_str(), attachName.c_str(),
            SqliteUtils::Anonymous(config.GetName()).c_str());
        return { err, 0 };
    }
    if (!attachedInfo_.Insert(attachName, dbPath)) {
        return { E_ATTACHED_DATABASE_EXIST, 0 };
    }
    return { E_OK, attachedInfo_.Size() };
}

std::pair<int32_t, int32_t> RdbStoreImpl::Detach(const std::string &attachName, int32_t waitTime)
{
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR)) {
        return { E_NOT_SUPPORT, 0 };
    }
    if (!attachedInfo_.Contains(attachName)) {
        return { E_OK, attachedInfo_.Size() };
    }

    auto pool = GetPool();
    if (pool == nullptr) {
        return { E_ALREADY_CLOSED, 0 };
    }
    auto [connection, readers] = pool->AcquireAll(waitTime);
    if (connection == nullptr) {
        return { E_DATABASE_BUSY, 0 };
    }
    std::vector<ValueObject> bindArgs;
    bindArgs.push_back(ValueObject(attachName));
    SqlLog::Pause();
    auto [errCode, statement] = connection->CreateStatement(GlobalExpr::DETACH_SQL, connection);
    if (statement == nullptr || errCode != E_OK) {
        LOG_ERROR("Detach get statement failed, errCode %{public}d", errCode);
        return { errCode, 0 };
    }
    errCode = statement->Execute(bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("failed, errCode[%{public}d] fileName[%{public}s] attachName[%{public}s] attach", errCode,
            SqliteUtils::Anonymous(config_.GetName()).c_str(), attachName.c_str());
        return { errCode, 0 };
    }
    SqlLog::Resume();
    attachedInfo_.Erase(attachName);
    if (!attachedInfo_.Empty()) {
        return { E_OK, attachedInfo_.Size() };
    }
    statement = nullptr;
    if (!isMemoryRdb_ && connection->GetJournalMode() == static_cast<int32_t>(JournalMode::MODE_WAL)) {
        // close first to prevent the connection from being put back.
        pool->CloseAllConnections();
        connection = nullptr;
        readers.clear();
        errCode = pool->EnableWal();
    }
    return { errCode, 0 };
}

/**
 * Obtains the database version.
 */
int RdbStoreImpl::GetVersion(int &version)
{
    SqlLog::Pause();
    auto [errCode, statement] = GetStatement(GlobalExpr::PRAGMA_VERSION, isReadOnly_);
    if (statement == nullptr) {
        return errCode;
    }
    ValueObject value;
    std::tie(errCode, value) = statement->ExecuteForValue();
    SqlLog::Resume();
    auto val = std::get_if<int64_t>(&value.value);
    if (val != nullptr) {
        version = static_cast<int>(*val);
    }
    return errCode;
}

/**
 * Sets the version of a new database.
 */
int RdbStoreImpl::SetVersion(int version)
{
    if (isReadOnly_) {
        return E_NOT_SUPPORT;
    }
    SqlLog::Pause();
    std::string sql = std::string(GlobalExpr::PRAGMA_VERSION) + " = " + std::to_string(version);
    auto [errCode, statement] = GetStatement(sql);
    if (statement == nullptr) {
        return errCode;
    }
    errCode = statement->Execute();
    SqlLog::Resume();
    return errCode;
}
/**
 * Begins a transaction in EXCLUSIVE mode.
 */
int RdbStoreImpl::BeginTransaction()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto pool = GetPool();
    if (pool == nullptr) {
        return E_ALREADY_CLOSED;
    }
    std::lock_guard<std::mutex> lockGuard(pool->GetTransactionStackMutex());
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR)) {
        return E_NOT_SUPPORT;
    }
    // size + 1 means the number of transactions in process
    RdbStatReporter reportStat(RDB_PERF, BEGINTRANSACTION, config_, reportFunc_);
    size_t transactionId = pool->GetTransactionStack().size() + 1;
    BaseTransaction transaction(pool->GetTransactionStack().size());
    auto [errCode, statement] = GetStatement(transaction.GetTransactionStr());
    if (statement == nullptr) {
        return errCode;
    }
    errCode = statement->Execute();
    if (errCode != E_OK) {
        if (errCode == E_SQLITE_LOCKED || errCode == E_SQLITE_BUSY) {
            pool->Dump(true, "BEGIN");
        }
        LOG_ERROR("transaction id: %{public}zu, storeName: %{public}s, errCode: %{public}d", transactionId,
            SqliteUtils::Anonymous(name_).c_str(), errCode);
        return errCode;
    }
    pool->SetInTransaction(true);
    pool->GetTransactionStack().push(transaction);
    // 1 means the number of transactions in process
    if (transactionId > 1) {
        LOG_WARN("transaction id: %{public}zu, storeName: %{public}s, errCode: %{public}d", transactionId,
            SqliteUtils::Anonymous(name_).c_str(), errCode);
    }

    return E_OK;
}

std::pair<int, int64_t> RdbStoreImpl::BeginTrans()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (!config_.IsVector() || isReadOnly_) {
        return { E_NOT_SUPPORT, 0 };
    }

    int64_t tmpTrxId = 0;
    auto pool = GetPool();
    if (pool == nullptr) {
        return { E_ALREADY_CLOSED, 0 };
    }
    auto [errCode, connection] = pool->CreateTransConn(false);
    if (connection == nullptr) {
        LOG_ERROR("Get null connection, storeName: %{public}s errCode:0x%{public}x.",
            SqliteUtils::Anonymous(name_).c_str(), errCode);
        return { errCode, 0 };
    }

    tmpTrxId = newTrxId_.fetch_add(1);
    trxConnMap_.Insert(tmpTrxId, connection);
    errCode = ExecuteByTrxId(BEGIN_TRANSACTION_SQL, tmpTrxId);
    if (errCode != E_OK) {
        trxConnMap_.Erase(tmpTrxId);
    }
    return { errCode, tmpTrxId };
}

/**
* Begins a transaction in EXCLUSIVE mode.
*/
int RdbStoreImpl::RollBack()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto pool = GetPool();
    if (pool == nullptr) {
        return E_ALREADY_CLOSED;
    }
    std::lock_guard<std::mutex> lockGuard(pool->GetTransactionStackMutex());
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR)) {
        return E_NOT_SUPPORT;
    }
    RdbStatReporter reportStat(RDB_PERF, ROLLBACK, config_, reportFunc_);
    size_t transactionId = pool->GetTransactionStack().size();

    if (pool->GetTransactionStack().empty()) {
        LOG_ERROR("transaction id: %{public}zu, storeName: %{public}s", transactionId,
            SqliteUtils::Anonymous(name_).c_str());
        return E_NO_TRANSACTION_IN_SESSION;
    }
    BaseTransaction transaction = pool->GetTransactionStack().top();
    pool->GetTransactionStack().pop();
    if (transaction.GetType() != TransType::ROLLBACK_SELF && !pool->GetTransactionStack().empty()) {
        pool->GetTransactionStack().top().SetChildFailure(true);
    }
    auto [errCode, statement] = GetStatement(transaction.GetRollbackStr());
    if (statement == nullptr) {
        if (errCode == E_DATABASE_BUSY) {
            Reportor::ReportCorrupted(Reportor::Create(config_, errCode, "ErrorType: RollBusy"));
        }
        // size + 1 means the number of transactions in process
        LOG_ERROR("transaction id: %{public}zu, storeName: %{public}s", transactionId + 1,
            SqliteUtils::Anonymous(name_).c_str());
        return E_DATABASE_BUSY;
    }
    errCode = statement->Execute();
    if (errCode != E_OK) {
        if (errCode == E_SQLITE_BUSY || errCode == E_SQLITE_LOCKED) {
            Reportor::ReportCorrupted(Reportor::Create(config_, errCode, "ErrorType: RollBusy"));
        }
        LOG_ERROR("failed, id: %{public}zu, storeName: %{public}s, errCode: %{public}d", transactionId,
            SqliteUtils::Anonymous(name_).c_str(), errCode);
        return errCode;
    }
    if (pool->GetTransactionStack().empty()) {
        pool->SetInTransaction(false);
    }
    // 1 means the number of transactions in process
    if (transactionId > 1) {
        LOG_WARN("transaction id: %{public}zu, storeName: %{public}s, errCode: %{public}d", transactionId,
            SqliteUtils::Anonymous(name_).c_str(), errCode);
    }
    return E_OK;
}

int RdbStoreImpl::ExecuteByTrxId(
    const std::string &sql, int64_t trxId, bool closeConnAfterExecute, const std::vector<ValueObject> &bindArgs)
{
    if ((!config_.IsVector()) || isReadOnly_) {
        return E_NOT_SUPPORT;
    }
    if (trxId == 0) {
        return E_INVALID_ARGS;
    }

    if (!trxConnMap_.Contains(trxId)) {
        LOG_ERROR("trxId hasn't appeared before %{public}" PRIu64, trxId);
        return E_INVALID_ARGS;
    }
    auto time = static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
    auto result = trxConnMap_.Find(trxId);
    auto connection = result.second;
    if (connection == nullptr) {
        LOG_ERROR("Get null connection, storeName: %{public}s time:%{public}" PRIu64 ".",
            SqliteUtils::Anonymous(name_).c_str(), time);
        return E_ERROR;
    }
    auto [ret, statement] = GetStatement(sql, connection);
    if (ret != E_OK) {
        return ret;
    }
    ret = statement->Execute(bindArgs);
    if (ret != E_OK) {
        LOG_ERROR("transaction id: %{public}" PRIu64 ", storeName: %{public}s, errCode: %{public}d" PRIu64, trxId,
            SqliteUtils::Anonymous(name_).c_str(), ret);
        trxConnMap_.Erase(trxId);
        return ret;
    }
    if (closeConnAfterExecute) {
        trxConnMap_.Erase(trxId);
    }
    return E_OK;
}

int RdbStoreImpl::RollBack(int64_t trxId)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    return ExecuteByTrxId(ROLLBACK_TRANSACTION_SQL, trxId, true);
}

/**
* Begins a transaction in EXCLUSIVE mode.
*/
int RdbStoreImpl::Commit()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto pool = GetPool();
    if (pool == nullptr) {
        return E_ALREADY_CLOSED;
    }
    std::lock_guard<std::mutex> lockGuard(pool->GetTransactionStackMutex());
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR)) {
        return E_NOT_SUPPORT;
    }
    RdbStatReporter reportStat(RDB_PERF, COMMIT, config_, reportFunc_);
    size_t transactionId = pool->GetTransactionStack().size();

    if (pool->GetTransactionStack().empty()) {
        return E_OK;
    }
    BaseTransaction transaction = pool->GetTransactionStack().top();
    std::string sqlStr = transaction.GetCommitStr();
    if (sqlStr.size() <= 1) {
        LOG_WARN("id: %{public}zu, storeName: %{public}s, sql: %{public}s", transactionId,
            SqliteUtils::Anonymous(name_).c_str(), sqlStr.c_str());
        pool->GetTransactionStack().pop();
        return E_OK;
    }
    auto [errCode, statement] = GetStatement(sqlStr);
    if (statement == nullptr) {
        if (errCode == E_DATABASE_BUSY) {
            Reportor::ReportCorrupted(Reportor::Create(config_, errCode, "ErrorType: CommitBusy"));
        }
        LOG_ERROR("id: %{public}zu, storeName: %{public}s, statement error", transactionId,
            SqliteUtils::Anonymous(name_).c_str());
        return E_DATABASE_BUSY;
    }
    errCode = statement->Execute();
    if (errCode != E_OK) {
        if (errCode == E_SQLITE_BUSY || errCode == E_SQLITE_LOCKED) {
            Reportor::ReportCorrupted(Reportor::Create(config_, errCode, "ErrorType: CommitBusy"));
        }
        LOG_ERROR("failed, id: %{public}zu, storeName: %{public}s, errCode: %{public}d", transactionId,
            SqliteUtils::Anonymous(name_).c_str(), errCode);
        return errCode;
    }
    pool->SetInTransaction(false);
    // 1 means the number of transactions in process
    if (transactionId > 1) {
        LOG_WARN("id: %{public}zu, storeName: %{public}s, errCode: %{public}d", transactionId,
            SqliteUtils::Anonymous(name_).c_str(), errCode);
    }
    pool->GetTransactionStack().pop();
    return E_OK;
}

int RdbStoreImpl::Commit(int64_t trxId)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    return ExecuteByTrxId(COMMIT_TRANSACTION_SQL, trxId, true);
}

bool RdbStoreImpl::IsInTransaction()
{
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR)) {
        return false;
    }
    auto pool = GetPool();
    if (pool == nullptr) {
        return false;
    }
    return pool->IsInTransaction();
}

int RdbStoreImpl::CheckAttach(const std::string &sql)
{
    size_t index = sql.find_first_not_of(' ');
    if (index == std::string::npos) {
        return E_OK;
    }

    /* The first 3 characters can determine the type */
    std::string sqlType = sql.substr(index, 3);
    sqlType = SqliteUtils::StrToUpper(sqlType);
    if (sqlType != "ATT") {
        return E_OK;
    }
    SqlLog::Pause();
    auto [errCode, statement] = GetStatement(GlobalExpr::PRAGMA_JOUR_MODE_EXP);
    if (statement == nullptr) {
        return errCode;
    }

    errCode = statement->Execute();
    if (errCode != E_OK) {
        LOG_ERROR("RdbStoreImpl CheckAttach fail to get journal mode : %{public}d", errCode);
        return errCode;
    }
    auto [errorCode, valueObject] = statement->GetColumn(0);
    if (errorCode != E_OK) {
        LOG_ERROR("RdbStoreImpl CheckAttach fail to get journal mode : %{public}d", errorCode);
        return errorCode;
    }
    auto journal = std::get_if<std::string>(&valueObject.value);
    auto journalMode = SqliteUtils::StrToUpper((journal == nullptr) ? "" : *journal);
    if (journalMode == RdbStoreConfig::DB_DEFAULT_JOURNAL_MODE) {
        LOG_ERROR("RdbStoreImpl attach is not supported in WAL mode");
        return E_NOT_SUPPORTED_ATTACH_IN_WAL_MODE;
    }
    SqlLog::Resume();
    return E_OK;
}

bool RdbStoreImpl::IsOpen() const
{
    return isOpen_;
}

std::string RdbStoreImpl::GetPath()
{
    return path_;
}

bool RdbStoreImpl::IsReadOnly() const
{
    return isReadOnly_;
}

bool RdbStoreImpl::IsMemoryRdb() const
{
    return isMemoryRdb_;
}

std::string RdbStoreImpl::GetName()
{
    return name_;
}

void RdbStoreImpl::DoCloudSync(const std::string &table)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    auto needSync = cloudInfo_->Change(table);
    if (!needSync) {
        return;
    }
    auto pool = TaskExecutor::GetInstance().GetExecutor();
    if (pool == nullptr) {
        return;
    }
    auto interval =
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::milliseconds(INTERVAL));
    pool->Schedule(interval, [cloudInfo = std::weak_ptr<CloudTables>(cloudInfo_), param = syncerParam_]() {
        auto changeInfo = cloudInfo.lock();
        if (changeInfo == nullptr) {
            return;
        }
        auto tables = changeInfo->Steal();
        if (tables.empty()) {
            return;
        }
        DistributedRdb::RdbService::Option option = { DistributedRdb::TIME_FIRST, 0, true, true };
        auto memo = AbsRdbPredicates(std::vector<std::string>(tables.begin(), tables.end())).GetDistributedPredicates();
        InnerSync(param, option, memo, nullptr);
    });
#endif
}
std::string RdbStoreImpl::GetFileType()
{
    return fileType_;
}

/**
 * Sets the database locale.
 */
int RdbStoreImpl::ConfigLocale(const std::string &localeStr)
{
    if (!isOpen_) {
        LOG_ERROR("The connection pool has been closed.");
        return E_ALREADY_CLOSED;
    }

    auto pool = GetPool();
    if (pool == nullptr) {
        return E_ALREADY_CLOSED;
    }
    return pool->ConfigLocale(localeStr);
}

int RdbStoreImpl::GetDestPath(const std::string &backupPath, std::string &destPath)
{
    int ret = GetDataBasePath(backupPath, destPath);
    if (ret != E_OK) {
        return ret;
    }
    std::string tempPath = destPath + ".tmp";
    if (access(tempPath.c_str(), F_OK) == E_OK) {
        destPath = tempPath;
    }

    if (access(destPath.c_str(), F_OK) != E_OK) {
        LOG_ERROR("The backupFilePath does not exists.");
        return E_INVALID_FILE_PATH;
    }
    return E_OK;
}

int RdbStoreImpl::Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey)
{
    LOG_INFO("Restore db: %{public}s.", SqliteUtils::Anonymous(config_.GetName()).c_str());
    if (isReadOnly_ || isMemoryRdb_) {
        return E_NOT_SUPPORT;
    }

    auto pool = GetPool();
    if (pool == nullptr || !isOpen_) {
        LOG_ERROR("The pool is: %{public}d, pool is null: %{public}d", isOpen_, pool == nullptr);
        return E_ALREADY_CLOSED;
    }

    RdbSecurityManager::KeyFiles keyFiles(path_ + BACKUP_RESTORE);
    keyFiles.Lock();
    std::string destPath;
    bool isOK = TryGetMasterSlaveBackupPath(backupPath, destPath, true);
    if (!isOK) {
        int ret = GetDestPath(backupPath, destPath);
        if (ret != E_OK) {
            keyFiles.Unlock();
            return ret;
        }
    }
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    auto [err, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (service != nullptr) {
        service->Disable(syncerParam_);
    }
#endif
    bool corrupt = Reportor::IsReportCorruptedFault(path_);
    int errCode = pool->ChangeDbFileForRestore(path_, destPath, newKey, slaveStatus_);
    keyFiles.Unlock();
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    SecurityPolicy::SetSecurityLabel(config_);
    if (service != nullptr) {
        service->Enable(syncerParam_);
        if (errCode == E_OK) {
            auto syncerParam = syncerParam_;
            syncerParam.infos_ = Connection::Collect(config_);
            service->AfterOpen(syncerParam);
            NotifyDataChange();
        }
    }
#endif
    if (errCode == E_OK) {
        ExchangeSlaverToMaster();
        Reportor::ReportRestore(Reportor::Create(config_, E_OK, "ErrorType::RdbStoreImpl::Restore", false), corrupt);
        rebuild_ = RebuiltType::NONE;
    }
    DoCloudSync("");
    return errCode;
}

std::pair<int32_t, std::shared_ptr<Connection>> RdbStoreImpl::CreateWritableConn()
{
    auto config = config_;
    config.SetHaMode(HAMode::SINGLE);
    config.SetCreateNecessary(false);
    auto [result, conn] = Connection::Create(config, true);
    if (result != E_OK || conn == nullptr) {
        LOG_ERROR("create connection failed, err:%{public}d", result);
        return { result, nullptr };
    }
    return { E_OK, conn };
}

std::pair<int32_t, std::shared_ptr<Statement>> RdbStoreImpl::GetStatement(
    const std::string &sql, std::shared_ptr<Connection> conn) const
{
    if (conn == nullptr) {
        return { E_DATABASE_BUSY, nullptr };
    }
    return conn->CreateStatement(sql, conn);
}

std::pair<int32_t, std::shared_ptr<Statement>> RdbStoreImpl::GetStatement(const std::string &sql, bool read) const
{
    auto pool = GetPool();
    if (pool == nullptr) {
        return { E_ALREADY_CLOSED, nullptr };
    }
    auto conn = pool->AcquireConnection(read);
    if (conn == nullptr) {
        return { E_DATABASE_BUSY, nullptr };
    }
    return conn->CreateStatement(sql, conn);
}

int RdbStoreImpl::GetRebuilt(RebuiltType &rebuilt)
{
    rebuilt = static_cast<RebuiltType>(rebuild_);
    return E_OK;
}

int RdbStoreImpl::InterruptBackup()
{
    if (config_.GetHaMode() != HAMode::MANUAL_TRIGGER) {
        return E_NOT_SUPPORT;
    }
    if (slaveStatus_ == SlaveStatus::BACKING_UP) {
        slaveStatus_ = SlaveStatus::BACKUP_INTERRUPT;
        return E_OK;
    }
    return E_CANCEL;
}

int32_t RdbStoreImpl::GetBackupStatus() const
{
    if (config_.GetHaMode() != HAMode::MANUAL_TRIGGER && config_.GetHaMode() != HAMode::MAIN_REPLICA) {
        return SlaveStatus::UNDEFINED;
    }
    return slaveStatus_;
}

bool RdbStoreImpl::TryGetMasterSlaveBackupPath(const std::string &srcPath, std::string &destPath, bool isRestore)
{
    if (!srcPath.empty() || config_.GetHaMode() == HAMode::SINGLE || config_.GetDBType() != DB_SQLITE) {
        return false;
    }
    int ret = GetSlaveName(config_.GetPath(), destPath);
    if (ret != E_OK) {
        destPath = {};
        return false;
    }
    if (isRestore && access(destPath.c_str(), F_OK) != 0) {
        LOG_WARN("The backup path can not access: %{public}s", SqliteUtils::Anonymous(destPath).c_str());
        return false;
    }
    return true;
}

bool RdbStoreImpl::IsSlaveDiffFromMaster() const
{
    std::string slaveDbPath = SqliteUtils::GetSlavePath(config_.GetPath());
    return SqliteUtils::IsSlaveInvalid(config_.GetPath()) || (access(slaveDbPath.c_str(), F_OK) != 0);
}

int32_t RdbStoreImpl::ExchangeSlaverToMaster()
{
    if (isReadOnly_ || rebuild_ != RebuiltType::NONE) {
        return E_OK;
    }
    auto [errCode, conn] = GetConn(false);
    if (errCode != E_OK) {
        return errCode;
    }
    auto strategy = conn->GenerateExchangeStrategy(slaveStatus_);
    if (strategy != ExchangeStrategy::NOT_HANDLE) {
        LOG_WARN("exchange st:%{public}d, %{public}s,", strategy, SqliteUtils::Anonymous(config_.GetName()).c_str());
    }
    int ret = E_OK;
    if (strategy == ExchangeStrategy::RESTORE) {
        conn = nullptr;
        // disable is required before restore
        ret = Restore({}, {});
    } else if (strategy == ExchangeStrategy::BACKUP) {
        // async backup
        ret = conn->Backup({}, {}, true, slaveStatus_);
    }
    return ret;
}

int32_t RdbStoreImpl::GetDbType() const
{
    return config_.GetDBType();
}

std::pair<int32_t, std::shared_ptr<Transaction>> RdbStoreImpl::CreateTransaction(int32_t type)
{
    if (isReadOnly_) {
        return { E_NOT_SUPPORT, nullptr };
    }

    auto pool = GetPool();
    if (pool == nullptr) {
        return { E_ALREADY_CLOSED, nullptr };
    }
    auto [errCode, conn] = pool->CreateTransConn();
    if (conn == nullptr) {
        return { errCode, nullptr };
    }
    std::shared_ptr<Transaction> trans;
    std::tie(errCode, trans) = Transaction::Create(type, conn, config_.GetName());
    if (trans == nullptr) {
        if (errCode == E_SQLITE_LOCKED || errCode == E_SQLITE_BUSY) {
            pool->Dump(true, "TRANS");
        }
        return { errCode, nullptr };
    }

    std::lock_guard<decltype(mutex_)> guard(mutex_);
    for (auto it = transactions_.begin(); it != transactions_.end();) {
        if (it->expired()) {
            it = transactions_.erase(it);
        } else {
            it++;
        }
    }
    transactions_.push_back(trans);
    return { errCode, trans };
}

int RdbStoreImpl::CleanDirtyLog(const std::string &table, uint64_t cursor)
{
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR) || isMemoryRdb_) {
        LOG_ERROR("Not support. table:%{public}s, isRead:%{public}d, dbType:%{public}d, isMemoryRdb:%{public}d.",
            SqliteUtils::Anonymous(table).c_str(), isReadOnly_, config_.GetDBType(), isMemoryRdb_);
        return E_NOT_SUPPORT;
    }
    auto [errCode, conn] = GetConn(false);
    if (errCode != E_OK || conn == nullptr) {
        LOG_ERROR("The database is busy or closed errCode:%{public}d", errCode);
        return errCode;
    }
    return conn->CleanDirtyLog(table, cursor);
}

int32_t RdbStoreImpl::CloudTables::AddTables(const std::vector<std::string> &tables)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto &table : tables) {
        tables_.insert(table);
    }
    return E_OK;
}

int32_t RdbStoreImpl::CloudTables::RmvTables(const std::vector<std::string> &tables)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto &table : tables) {
        tables_.erase(table);
    }
    return E_OK;
}

bool RdbStoreImpl::CloudTables::Change(const std::string &table)
{
    bool needSync = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (tables_.empty() || (!table.empty() && tables_.find(table) == tables_.end())) {
            return needSync;
        }
        // from empty, then need schedule the cloud sync, others only wait the schedule execute
        needSync = changes_.empty();
        if (!table.empty()) {
            changes_.insert(table);
        } else {
            changes_.insert(tables_.begin(), tables_.end());
        }
    }
    return needSync;
}

std::set<std::string> RdbStoreImpl::CloudTables::Steal()
{
    std::set<std::string> result;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        result = std::move(changes_);
    }
    return result;
}

void RdbStoreImpl::SetKnowledgeSchema()
{
    auto [errCode, schema] = GetKnowledgeSchemaHelper()->GetRdbKnowledgeSchema(config_.GetName());
    if (errCode != E_OK) {
        return;
    }
    auto [ret, conn] = GetConn(false);
    if (ret != E_OK) {
        LOG_ERROR("The database is busy or closed when set knowledge schema ret %{public}d.", ret);
        return;
    }
    ret = conn->SetKnowledgeSchema(schema);
    if (ret != E_OK) {
        LOG_ERROR("Set knowledge schema failed %{public}d.", ret);
        return;
    }
    auto helper = GetKnowledgeSchemaHelper();
    helper->Init(config_, schema);
    helper->DonateKnowledgeData();
}

std::shared_ptr<NativeRdb::KnowledgeSchemaHelper> RdbStoreImpl::GetKnowledgeSchemaHelper()
{
    std::lock_guard<std::mutex> autoLock(helperMutex_);
    if (knowledgeSchemaHelper_ == nullptr) {
        knowledgeSchemaHelper_ = std::make_shared<NativeRdb::KnowledgeSchemaHelper>();
    }
    return knowledgeSchemaHelper_;
}

bool RdbStoreImpl::IsKnowledgeDataChange(const DistributedRdb::RdbChangedData &rdbChangedData)
{
    for (const auto &item : rdbChangedData.tableData) {
        if (item.second.isKnowledgeDataChange) {
            return true;
        }
    }
    return false;
}

bool RdbStoreImpl::IsNotifyService(const DistributedRdb::RdbChangedData &rdbChangedData)
{
    for (const auto &item : rdbChangedData.tableData) {
        if (item.second.isP2pSyncDataChange || item.second.isTrackedDataChange) {
            return true;
        }
    }
    return false;
}
} // namespace OHOS::NativeRdb
