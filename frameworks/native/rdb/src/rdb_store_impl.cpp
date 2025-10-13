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

#include <dlfcn.h>
#include <sys/stat.h>
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
#include "rdb_perfStat.h"
#include "rdb_radar_reporter.h"
#include "rdb_stat_reporter.h"
#include "rdb_security_manager.h"
#include "rdb_sql_log.h"
#include "rdb_sql_utils.h"
#include "rdb_sql_statistic.h"
#include "rdb_store.h"
#include "rdb_time_utils.h"
#include "rdb_trace.h"
#include "rdb_types.h"
#include "relational_store_client.h"
#include "sqlite_global_config.h"
#include "sqlite_sql_builder.h"
#include "sqlite_utils.h"
#include "step_result_set.h"
#include "string_utils.h"
#include "suspender.h"
#include "task_executor.h"
#include "traits.h"
#include "transaction.h"
#include "values_buckets.h"
#if !defined(CROSS_PLATFORM)
#include "raw_data_parser.h"
#include "rdb_manager_impl.h"
#include "relational_store_manager.h"
#include "security_policy.h"
#include "sqlite_shared_result_set.h"
#endif

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#include "security_policy.h"
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
using PerfStat = DistributedRdb::PerfStat;
using RdbNotifyConfig = DistributedRdb::RdbNotifyConfig;
using Reportor = RdbFaultHiViewReporter;

#if !defined(CROSS_PLATFORM)
using RdbMgr = DistributedRdb::RdbManagerImpl;
#endif

static constexpr const char *BEGIN_TRANSACTION_SQL = "begin;";
static constexpr const char *COMMIT_TRANSACTION_SQL = "commit;";
static constexpr const char *ROLLBACK_TRANSACTION_SQL = "rollback;";
static constexpr const char *BACKUP_RESTORE = "backup.restore";
static constexpr const char *ASYNC_RESTORE = "-async.restore";
constexpr char const *SUFFIX_BINLOG = "_binlog/";
constexpr int32_t SERVICE_GID = 3012;
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
#if !defined(CROSS_PLATFORM)
    // Only owner mode can store metadata information.
    if (isReadOnly_ || isMemoryRdb_ || config_.IsCustomEncryptParam() || (config_.GetRoleType() != OWNER)) {
        return E_OK;
    }
    if (config_.GetEnableSemanticIndex()) {
        SetKnowledgeSchema();
    }
    AfterOpen(syncerParam_);
    if (config_.GetDBType() == DB_VECTOR || (!config_.IsSearchable() && !config_.GetEnableSemanticIndex())) {
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
    {
        std::lock_guard<decltype(helperMutex_)> autoLock(helperMutex_);
        if (knowledgeSchemaHelper_ != nullptr) {
            knowledgeSchemaHelper_->Close();
        }
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

bool RdbStoreImpl::SetFileGid(const RdbStoreConfig &config, int32_t gid)
{
    bool setDir = SqliteUtils::SetDbDirGid(config.GetPath(), gid, false);
    if (!setDir) {
        LOG_ERROR("SetDbDir fail, bundleName is %{public}s, store is %{public}s.",
            config.GetBundleName().c_str(),
            SqliteUtils::Anonymous(config.GetName()).c_str());
    }
    std::vector<std::string> dbFiles = Connection::GetDbFiles(config);
    bool setDbFile = SqliteUtils::SetDbFileGid(config.GetPath(), dbFiles, gid);
    if (!setDbFile) {
        LOG_ERROR("SetDbFile fail, bundleName is %{public}s, store is %{public}s.",
            config.GetBundleName().c_str(),
            SqliteUtils::Anonymous(config.GetName()).c_str());
    }

    if (config.GetHaMode() == HAMode::SINGLE || config.IsEncrypt() || config.IsMemoryRdb()) {
        return setDir && setDbFile;
    }
    std::string binlogDir = config.GetPath() + SUFFIX_BINLOG;
    bool setBinlog = SqliteUtils::SetDbDirGid(binlogDir, gid, true);
    if (!setBinlog) {
        LOG_ERROR("SetBinlog fail, bundleName is %{public}s, store is %{public}s.",
            config.GetBundleName().c_str(),
            SqliteUtils::Anonymous(config.GetName()).c_str());
    }
    return setDir && setDbFile && setBinlog;
}

#if !defined(CROSS_PLATFORM)
void RdbStoreImpl::AfterOpen(const RdbParam &param, int32_t retry)
{
    auto [err, service] = RdbMgr::GetInstance().GetRdbService(param);
    if (err == E_NOT_SUPPORT) {
        return;
    }
    if (err != E_OK || service == nullptr) {
        if (err != E_INVALID_ARGS) {
            LOG_ERROR("GetRdbService failed, err: %{public}d, storeName: %{public}s.", err,
                SqliteUtils::Anonymous(param.storeName_).c_str());
        }
        auto pool = TaskExecutor::GetInstance().GetExecutor();
        if (err == E_SERVICE_NOT_FOUND && pool != nullptr && retry < MAX_RETRY_TIMES) {
            retry++;
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
    isNeedSetAcl_ = true;
    SetFileGid(config_, SERVICE_GID);
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

int32_t RdbStoreImpl::Rekey(const RdbStoreConfig::CryptoParam &cryptoParam)
{
    if (config_.GetDBType() == DB_VECTOR || isReadOnly_ || isMemoryRdb_) {
        return E_NOT_SUPPORT;
    }
    if (!cryptoParam.IsValid()) {
        LOG_ERROR("Invalid crypto param, name:%{public}s", SqliteUtils::Anonymous(config_.GetName()).c_str());
        return E_INVALID_ARGS_NEW;
    }
    if (!config_.IsEncrypt() || !config_.GetCryptoParam().Equal(cryptoParam) ||
        (config_.IsCustomEncryptParam() == cryptoParam.encryptKey_.empty())) {
        LOG_ERROR("Not supported! name:%{public}s, [%{public}d,%{public}d,%{public}d,%{public}d,%{public}d,%{public}u]"
            "->[%{public}d,%{public}d,%{public}d,%{public}d,%{public}d,%{public}u]",
            SqliteUtils::Anonymous(config_.GetName()).c_str(), config_.GetCryptoParam().encryptKey_.empty(),
            config_.GetCryptoParam().iterNum, config_.GetCryptoParam().encryptAlgo, config_.GetCryptoParam().hmacAlgo,
            config_.GetCryptoParam().kdfAlgo, config_.GetCryptoParam().cryptoPageSize, cryptoParam.encryptKey_.empty(),
            cryptoParam.iterNum, cryptoParam.encryptAlgo, cryptoParam.hmacAlgo,
            cryptoParam.kdfAlgo, cryptoParam.cryptoPageSize);
        return E_NOT_SUPPORT;
    }

    auto pool = GetPool();
    if (pool == nullptr) {
        LOG_ERROR("Database already closed.");
        return E_ALREADY_CLOSED;
    }

#if !defined(CROSS_PLATFORM)
    auto [err, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (service != nullptr) {
        service->Disable(syncerParam_);
    }
#endif
    LOG_INFO("Start rekey, name:%{public}s, IsCustomEncrypt:%{public}d. ",
        SqliteUtils::Anonymous(config_.GetName()).c_str(), config_.IsCustomEncryptParam());
    auto errCode = pool->Rekey(cryptoParam);
#if !defined(CROSS_PLATFORM)
    if (service != nullptr) {
        service->Enable(syncerParam_);
        if (errCode == E_OK && !config_.IsCustomEncryptParam()) {
            auto syncerParam = syncerParam_;
            syncerParam.password_ = config_.GetEncryptKey();
            service->AfterOpen(syncerParam);
        }
    }
#endif
    return errCode;
}

int32_t RdbStoreImpl::RekeyEx(const RdbStoreConfig::CryptoParam &cryptoParam)
{
    if (config_.GetDBType() == DB_VECTOR || isReadOnly_ || isMemoryRdb_ || config_.GetHaMode() != HAMode::SINGLE) {
        return E_NOT_SUPPORT;
    }
    if (!cryptoParam.IsValid()) {
        LOG_ERROR("Invalid crypto param, name:%{public}s", SqliteUtils::Anonymous(config_.GetName()).c_str());
        return E_INVALID_ARGS_NEW;
    }

    auto pool = GetPool();
    if (pool == nullptr) {
        LOG_ERROR("Database already closed.");
        return E_ALREADY_CLOSED;
    }

#if !defined(CROSS_PLATFORM)
    auto [err, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (service != nullptr) {
        service->Disable(syncerParam_);
    }
#endif
    pool->CloseAllConnections();
    auto rekeyCryptoParam = cryptoParam;
    if (rekeyCryptoParam.encryptAlgo != EncryptAlgo::PLAIN_TEXT && rekeyCryptoParam.iterNum == 0) {
        rekeyCryptoParam.encryptAlgo = EncryptAlgo::AES_256_GCM;
    }
    bool isHasAcl = SqliteUtils::HasAccessAcl(config_.GetPath(), SERVICE_GID);
    auto errCode = Connection::RekeyEx(config_, rekeyCryptoParam);
    if (errCode != E_OK) {
        LOG_ERROR("ReKey failed, err = %{public}d", errCode);
        pool->ReopenConns();
        return errCode;
    }
    config_.SetCryptoParam(rekeyCryptoParam);
    pool->ReopenConns();
    if(isHasAcl) {
        SetFileGid(config_, SERVICE_GID);
    }
#if !defined(CROSS_PLATFORM)
    if (service == nullptr) {
        return errCode;
    }
    service->Enable(syncerParam_);
    if (errCode == E_OK) {
        auto syncerParam = syncerParam_;
        syncerParam.isEncrypt_ = cryptoParam.encryptAlgo != EncryptAlgo::PLAIN_TEXT;
        syncerParam.password_ = (config_.IsEncrypt() && !config_.IsCustomEncryptParam()) ? config_.GetEncryptKey()
                                                                                         : std::vector<uint8_t>{};
        service->AfterOpen(syncerParam);
    }
#endif
    return errCode;
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
    auto [err, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (err != E_OK || service == nullptr) {
        errCode = err;
        return "";
    }
    auto tableName = service->ObtainDistributedTableName(syncerParam_, device, table);
    errCode = tableName.empty() ? E_ERROR : E_OK;
    return tableName;
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

std::string RdbStoreImpl::GetUri(const std::string &event)
{
    std::string rdbUri;
    if (config_.GetDataGroupId().empty()) {
        rdbUri = SCHEME_RDB + config_.GetBundleName() + "/" + path_ + "/" + event;
    } else {
        rdbUri = SCHEME_RDB + config_.GetDataGroupId() + "/" + path_ + "/" + event;
        Reportor::ReportFault(RdbFaultEvent(FT_CURD, E_DFX_GROUPID_INFO, config_.GetBundleName(),
            "GetUri GroupId db:[" + SqliteUtils::Anonymous(name_) + "]"));
    }
    return rdbUri;
}

int RdbStoreImpl::SubscribeLocal(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer)
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

int RdbStoreImpl::SubscribeLocalShared(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer)
{
    return obsManger_.Register(GetUri(option.event), observer);
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

int RdbStoreImpl::SubscribeRemote(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer)
{
    auto [errCode, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (errCode != E_OK) {
        return errCode;
    }
    return service->Subscribe(syncerParam_, option, observer);
}

int RdbStoreImpl::Subscribe(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer)
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

int RdbStoreImpl::UnSubscribeLocal(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer)
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

int RdbStoreImpl::UnSubscribeLocalShared(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer)
{
    return obsManger_.Unregister(GetUri(option.event), observer);
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

int RdbStoreImpl::UnSubscribeRemote(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer)
{
    auto [errCode, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (errCode != E_OK) {
        return errCode;
    }
    return service->UnSubscribe(syncerParam_, option, observer);
}

int RdbStoreImpl::UnSubscribe(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer)
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
    int32_t err = obsManger_.Notify(GetUri(event));
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
    std::weak_ptr<NativeRdb::KnowledgeSchemaHelper> helper = GetKnowledgeSchemaHelper();
    delayNotifier_->SetExecutorPool(TaskExecutor::GetInstance().GetExecutor());
    delayNotifier_->SetTask([param = syncerParam_, helper = helper](
        const DistributedRdb::RdbChangedData &rdbChangedData, const RdbNotifyConfig &rdbNotifyConfig) -> int {
        if (IsKnowledgeDataChange(rdbChangedData)) {
            auto realHelper = helper.lock();
            if (realHelper == nullptr) {
                LOG_WARN("knowledge helper is nullptr");
            } else {
                realHelper->DonateKnowledgeData();
            }
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
        if (pool != nullptr && retry < MAX_RETRY_TIMES) {
            retry++;
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
        return E_ALREADY_CLOSED;
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
    Suspender suspender(Suspender::SQL_LOG);
    auto [err, statement] = GetStatement(GlobalExpr::PRAGMA_VERSION);
    if (statement == nullptr || err != E_OK) {
        return err;
    }
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

int32_t RdbStoreImpl::ProcessOpenCallback(int version, RdbOpenCallback &openCallback)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t errCode = E_OK;
    if (version == -1) {
        return errCode;
    }

    int32_t currentVersion;
    errCode = GetVersion(currentVersion);
    if (errCode != E_OK) {
        return errCode;
    }

    if (version == currentVersion) {
        return openCallback.OnOpen(*this);
    }

    if (currentVersion == 0) {
        errCode = openCallback.OnCreate(*this);
    } else if (version > currentVersion) {
        errCode = openCallback.OnUpgrade(*this, currentVersion, version);
    } else {
        errCode = openCallback.OnDowngrade(*this, currentVersion, version);
    }

    if (errCode == E_OK) {
        errCode = SetVersion(version);
    }

    if (errCode != E_OK) {
        LOG_ERROR("openCallback failed. version: %{public}d -> %{public}d, errCode:%{public}d",
            currentVersion, version, errCode);
        return errCode;
    }

    return openCallback.OnOpen(*this);
}

bool RdbStoreImpl::TryAsyncRepair()
{
    std::string slavePath = SqliteUtils::GetSlavePath(path_);
    if (!SqliteUtils::IsUseAsyncRestore(config_, path_, slavePath)) {
        return false;
    }

    int errCode = Connection::CheckReplicaIntegrity(config_);
    if (errCode != E_OK) {
        return false;
    }

    SqliteUtils::DeleteDirtyFiles(path_);
    auto pool = ConnectionPool::Create(config_, errCode);
    if (errCode != E_OK) {
        LOG_WARN("create new connection failed");
        return false;
    }
    connectionPool_ = pool;
    errCode = StartAsyncRestore(pool);
    if (errCode != E_OK) {
        return false;
    }
    rebuild_ = RebuiltType::REPAIRED;
    
    Reportor::ReportRestore(Reportor::Create(config_, E_OK, "RestoreType:Rebuild", false), false);
    return true;
}
int32_t RdbStoreImpl::CreatePool(bool &created)
{
    int32_t errCode = E_OK;
    connectionPool_ = ConnectionPool::Create(config_, errCode);
    if (connectionPool_ == nullptr && (errCode == E_SQLITE_CORRUPT || errCode == E_INVALID_SECRET_KEY) &&
        !isReadOnly_) {
        LOG_ERROR("database corrupt, errCode:0x%{public}x, %{public}s, %{public}s", errCode,
            SqliteUtils::Anonymous(name_).c_str(),
            SqliteUtils::FormatDebugInfoBrief(Connection::Collect(config_), "master").c_str());
#if !defined(CROSS_PLATFORM)
        InitSyncerParam(config_, false);
        auto [err, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
        if (service != nullptr) {
            service->Disable(syncerParam_);
        }
#endif
        config_.SetIter(0);
        if (config_.IsEncrypt() && config_.GetAllowRebuild()) {
            auto key = config_.GetEncryptKey();
            RdbSecurityManager::GetInstance().RestoreKeyFile(path_, key);
            key.assign(key.size(), 0);
        }
        
        if (TryAsyncRepair()) {
            errCode = E_OK;
        } else {
            std::tie(rebuild_, connectionPool_) = ConnectionPool::HandleDataCorruption(config_, errCode);
        }
        created = true;
#if !defined(CROSS_PLATFORM)
        if (service != nullptr) {
            service->Enable(syncerParam_);
        }
#endif
    }
    return errCode;
}

int32_t RdbStoreImpl::SetSecurityLabel(const RdbStoreConfig &config)
{
    if (config.IsMemoryRdb()) {
        return E_OK;
    }
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    return SecurityPolicy::SetSecurityLabel(config);
#endif
    return E_OK;
}

int32_t RdbStoreImpl::Init(int version, RdbOpenCallback &openCallback, bool isNeedSetAcl)
{
    if (initStatus_ != -1) {
        return initStatus_;
    }
    isNeedSetAcl = isNeedSetAcl || SqliteUtils::HasAccessAcl(config_.GetPath(), SERVICE_GID) ||
                   SqliteUtils::HasAccessAcl(SqliteUtils::GetSlavePath(config_.GetPath()), SERVICE_GID);
    std::lock_guard<std::mutex> lock(initMutex_);
    if (initStatus_ != -1) {
        return initStatus_;
    }
    int32_t errCode = E_OK;
    bool created = access(path_.c_str(), F_OK) != 0;
    errCode = CreatePool(created);
    if (connectionPool_ == nullptr || errCode != E_OK) {
        connectionPool_ = nullptr;
        LOG_ERROR("Create connPool failed, err is %{public}d, path:%{public}s", errCode,
            SqliteUtils::Anonymous(path_).c_str());
        return errCode;
    }
    if (isNeedSetAcl) {
        isNeedSetAcl_ = true;
        SetFileGid(config_, SERVICE_GID);
    }
    InitSyncerParam(config_, created);
    InitReportFunc(syncerParam_);
    InnerOpen();

    if (config_.GetRoleType() == OWNER && !config_.IsReadOnly()) {
        errCode = SetSecurityLabel(config_);
        if (errCode != E_OK) {
            return errCode;
        }
        (void) ExchangeSlaverToMaster();
        SwitchOver(true);
        errCode = ProcessOpenCallback(version, openCallback);
        SwitchOver(false);
        if (errCode != E_OK) {
            LOG_ERROR("Callback fail, path:%{public}s code:%{public}d", SqliteUtils::Anonymous(path_).c_str(), errCode);
            return errCode;
        }
    }
    initStatus_ = errCode;
    return initStatus_;
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
    if (knowledgeSchemaHelper_ != nullptr) {
        knowledgeSchemaHelper_->Close();
    }
    *slaveStatus_ = SlaveStatus::DB_CLOSING;
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
    RdbStatReporter reportStat(RDB_PERF, INSERT, config_, reportFunc_);
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL);
    PerfStat perfStat(config_.GetPath(), "", PerfStat::Step::STEP_TOTAL);
    auto [status, sqlInfo] = RdbSqlUtils::GetInsertSqlInfo(table, row, resolution);
    if (status != E_OK) {
        return { status, -1 };
    }

    int64_t rowid = -1;
    auto errCode = ExecuteForLastInsertedRowId(rowid, sqlInfo.sql, sqlInfo.args);
    if (errCode == E_OK) {
        DoCloudSync(table);
    }

    return { errCode, rowid };
}

std::pair<int, int64_t> RdbStoreImpl::BatchInsert(const std::string &table, const ValuesBuckets &rows)
{
    if (isReadOnly_) {
        return { E_NOT_SUPPORT, -1 };
    }

    if (rows.RowSize() == 0) {
        return { E_OK, 0 };
    }

    RdbStatReporter reportStat(RDB_PERF, BATCHINSERT, config_, reportFunc_);
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL);
    PerfStat perfStat(config_.GetPath(), "", PerfStat::Step::STEP_TOTAL, 0, rows.RowSize());
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
        LOG_ERROR("empty, table=%{public}s, values:%{public}zu, max number:%{public}d.",
            SqliteUtils::Anonymous(table).c_str(), rows.RowSize(), conn->GetMaxVariable());
        return { E_INVALID_ARGS, -1 };
    }
    PauseDelayNotify pauseDelayNotify(delayNotifier_);
    for (const auto &[sql, bindArgs] : executeSqlArgs) {
        auto [errCode, statement] = GetStatement(sql, conn);
        if (statement == nullptr) {
            LOG_ERROR("statement is nullptr, errCode:0x%{public}x, args:%{public}zu, table:%{public}s, "
                "app self can check the SQL", errCode, bindArgs.size(), SqliteUtils::Anonymous(table).c_str());
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
                    errCode, bindArgs.size(), SqliteUtils::Anonymous(table).c_str());
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

std::pair<int32_t, Results> RdbStoreImpl::BatchInsert(const std::string &table, const RefRows &rows,
    const std::vector<std::string> &returningFields, Resolution resolution)
{
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR)) {
        return { E_NOT_SUPPORT, -1 };
    }

    if (rows.RowSize() == 0) {
        return { E_OK, 0 };
    }

    RdbStatReporter reportStat(RDB_PERF, BATCHINSERT, config_, reportFunc_);
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL);
    PerfStat perfStat(config_.GetPath(), "", PerfStat::Step::STEP_TOTAL, 0, rows.RowSize());
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
        LOG_ERROR("invalid! rows:%{public}zu, table:%{public}s, fields:%{public}zu, max:%{public}d.", rows.RowSize(),
            SqliteUtils::Anonymous(table).c_str(), fields != nullptr ? fields->size() : 0, conn->GetMaxVariable());
        return { E_INVALID_ARGS, -1 };
    }
    auto &[sql, bindArgs] = sqlArgs.front();
    SqliteSqlBuilder::AppendReturning(sql, returningFields);
    auto [errCode, statement] = GetStatement(sql, conn);
    if (statement == nullptr) {
        LOG_ERROR("statement is nullptr, errCode:0x%{public}x, args:%{public}zu, table:%{public}s, "
                  "app self can check the SQL", errCode, bindArgs.size(), SqliteUtils::Anonymous(table).c_str());
        return { errCode, -1 };
    }
    PauseDelayNotify pauseDelayNotify(delayNotifier_);
    errCode = statement->Execute(std::ref(bindArgs.front()));
    if (errCode == E_SQLITE_LOCKED || errCode == E_SQLITE_BUSY) {
        pool->Dump(true, "BATCH");
        return { errCode, -1 };
    }
    if (errCode != E_OK) {
        LOG_ERROR("failed,errCode:%{public}d,table:%{public}s,args:%{public}zu,resolution:%{public}d.", errCode,
            SqliteUtils::Anonymous(table).c_str(), bindArgs.front().size(), static_cast<int32_t>(resolution));
    }
    auto result = GenerateResult(errCode, statement);
    if (result.changed > 0) {
        DoCloudSync(table);
    }
    return { errCode, result };
}

std::pair<int32_t, Results> RdbStoreImpl::Update(const Row &row, const AbsRdbPredicates &predicates,
    const std::vector<std::string> &returningFields, Resolution resolution)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR)) {
        return { E_NOT_SUPPORT, -1 };
    }
    RdbStatReporter reportStat(RDB_PERF, UPDATE, config_, reportFunc_);
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL);
    PerfStat perfStat(config_.GetPath(), "", PerfStat::Step::STEP_TOTAL);
    auto [status, sqlInfo] = RdbSqlUtils::GetUpdateSqlInfo(predicates, row, resolution, returningFields);
    if (status != E_OK) {
        return { status, -1 };
    }
    auto [code, result] = ExecuteForRow(sqlInfo.sql, sqlInfo.args);
    if (result.changed > 0) {
        DoCloudSync(predicates.GetTableName());
    }
    return { code, result };
}

std::pair<int32_t, Results> RdbStoreImpl::Delete(
    const AbsRdbPredicates &predicates, const std::vector<std::string> &returningFields)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR)) {
        return { E_NOT_SUPPORT, -1 };
    }
    RdbStatReporter reportStat(RDB_PERF, DELETE, config_, reportFunc_);
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL);
    PerfStat perfStat(config_.GetPath(), "", PerfStat::Step::STEP_TOTAL);
    auto [status, sqlInfo] = RdbSqlUtils::GetDeleteSqlInfo(predicates, returningFields);
    if (status != E_OK) {
        return { status, -1 };
    }

    auto [code, result] = ExecuteForRow(sqlInfo.sql, predicates.GetBindArgs());
    if (result.changed > 0) {
        DoCloudSync(predicates.GetTableName());
    }
    return { code, result };
}

std::shared_ptr<AbsSharedResultSet> RdbStoreImpl::QuerySql(const std::string &sql, const Values &bindArgs)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (config_.GetDBType() == DB_VECTOR) {
        return nullptr;
    }
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL);
    PerfStat perfStat(config_.GetPath(), "", PerfStat::Step::STEP_TOTAL);
#if !defined(CROSS_PLATFORM)
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
    PerfStat perfStat(config_.GetPath(), "", PerfStat::Step::STEP_TOTAL);
    auto start = std::chrono::steady_clock::now();
    auto pool = GetPool();
    if (pool == nullptr) {
        LOG_ERROR("Database already closed.");
        return nullptr;
    }
#if !defined(CROSS_PLATFORM)
    return std::make_shared<StepResultSet>(start, pool->AcquireRef(true), sql, args, preCount);
#else
    return std::make_shared<StepResultSet>(start, pool->AcquireRef(true), sql, args, false);
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

int32_t RdbStoreImpl::HandleSchemaDDL(std::shared_ptr<Statement> &&statement, const std::string &sql)
{
    statement->Reset();
    Suspender suspender(Suspender::SQL_STATISTIC);
    statement->Prepare("PRAGMA schema_version");
    auto [err, version] = statement->ExecuteForValue();
    statement = nullptr;
    if (vSchema_ < static_cast<int64_t>(version)) {
        LOG_INFO("db:%{public}s exe DDL schema<%{public}" PRIi64 "->%{public}" PRIi64 ">",
            SqliteUtils::Anonymous(name_).c_str(), vSchema_, static_cast<int64_t>(version));
        vSchema_ = version;
        if (!isMemoryRdb_) {
            std::string dbPath = config_.GetPath();
            std::string bundleName = config_.GetBundleName();
            WriteToCompareFile(dbPath, bundleName, sql);
        }
        statement = nullptr;
        if (config_.GetEnableSemanticIndex() && !isKnowledgeSchemaReady_) {
            SetKnowledgeSchema();
        }
        auto pool = GetPool();
        if (pool == nullptr) {
            return E_ALREADY_CLOSED;
        }
        return pool->RestartConns();
    }
    return E_OK;
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
    PerfStat perfStat(config_.GetPath(), "", PerfStat::Step::STEP_TOTAL);
    auto [errCode, statement] = BeginExecuteSql(sql);
    if (statement == nullptr) {
        return errCode;
    }
    errCode = statement->Execute(args);
    if (errCode != E_OK) {
        LOG_ERROR("failed,error:0x%{public}x app self can check the SQL.", errCode);
        TryDump(errCode, "EXECUTE");
        return errCode;
    }
    int sqlType = SqliteUtils::GetSqlStatementType(sql);
    if (sqlType == SqliteUtils::STATEMENT_DDL) {
        HandleSchemaDDL(std::move(statement), sql);
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
    PerfStat perfStat(config_.GetPath(), "", PerfStat::Step::STEP_TOTAL);
    int sqlType = SqliteUtils::GetSqlStatementType(sql);
    if (!SqliteUtils::IsSupportSqlForExecute(sqlType)) {
        LOG_ERROR("Not support the sqlType: %{public}d, app self can check the SQL", sqlType);
        return { E_NOT_SUPPORT_THE_SQL, object };
    }

    if (config_.IsVector() && trxId > 0) {
        return { ExecuteByTrxId(sql, trxId, false, args), ValueObject() };
    }

    auto [errCode, statement] = GetStatement(sql, false);
    if (errCode != E_OK || statement == nullptr) {
        return { errCode != E_OK ? errCode : E_ERROR, object };
    }

    errCode = statement->Execute(args);
    TryDump(errCode, "EXECUTE");
    if (config_.IsVector()) {
        return { errCode, object };
    }

    return HandleDifferentSqlTypes(std::move(statement), sql, errCode, sqlType);
}

std::pair<int32_t, ValueObject> RdbStoreImpl::HandleDifferentSqlTypes(
    std::shared_ptr<Statement> &&statement, const std::string &sql, int32_t code, int sqlType)
{
    if (code != E_OK) {
        return { code, ValueObject() };
    }
    if (sqlType == SqliteUtils::STATEMENT_INSERT) {
        int64_t outValue = statement->Changes() > 0 ? statement->LastInsertRowId() : -1;
        return { code, ValueObject(outValue) };
    }

    if (sqlType == SqliteUtils::STATEMENT_UPDATE) {
        int outValue = statement->Changes();
        return { code, ValueObject(outValue) };
    }

    if (sqlType == SqliteUtils::STATEMENT_PRAGMA) {
        if (statement->GetColumnCount() == 1) {
            return statement->GetColumn(0);
        }

        if (statement->GetColumnCount() > 1) {
            LOG_ERROR("Not support the sql:app self can check the SQL, column count more than 1");
            return { E_NOT_SUPPORT_THE_SQL, ValueObject() };
        }
    }

    if (sqlType == SqliteUtils::STATEMENT_DDL) {
        HandleSchemaDDL(std::move(statement), sql);
    }
    return { code, ValueObject() };
}

std::pair<int32_t, Results> RdbStoreImpl::ExecuteExt(const std::string &sql, const Values &args)
{
    if (isReadOnly_ || config_.IsVector()) {
        return { E_NOT_SUPPORT, -1 };
    }

    RdbStatReporter reportStat(RDB_PERF, EXECUTE, config_, reportFunc_);
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL);
    int sqlType = SqliteUtils::GetSqlStatementType(sql);
    if (!SqliteUtils::IsSupportSqlForExecute(sqlType)) {
        LOG_ERROR("Not support the sqlType: %{public}d, app self can check the SQL", sqlType);
        return { E_NOT_SUPPORT_THE_SQL, -1 };
    }
    auto [errCode, statement] = GetStatement(sql, false);
    if (errCode != E_OK) {
        return { errCode, -1 };
    }
    errCode = statement->Execute(args);
    TryDump(errCode, "ExecuteExt");
    return HandleResults(std::move(statement), sql, errCode, sqlType);
}

std::pair<int32_t, Results> RdbStoreImpl::HandleResults(
    std::shared_ptr<Statement> &&statement, const std::string &sql, int32_t code, int sqlType)
{
    Results result = GenerateResult(
        code, statement, sqlType == SqliteUtils::STATEMENT_INSERT || sqlType == SqliteUtils::STATEMENT_UPDATE);
    if (sqlType == SqliteUtils::STATEMENT_DDL) {
        HandleSchemaDDL(std::move(statement), sql);
    }
    return { code, result };
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
            totalCostTime, prepareCost, execCost, resultCost, SqliteUtils::SqlAnonymous(sql).c_str());
    }
    return E_OK;
}

std::pair<int32_t, Results> RdbStoreImpl::ExecuteForRow(const std::string &sql, const Values &args)
{
    if (isReadOnly_ || (config_.GetDBType() == DB_VECTOR)) {
        return { E_NOT_SUPPORT, -1 };
    }
    auto [errCode, statement] = GetStatement(sql, false);
    if (statement == nullptr) {
        return { errCode, -1 };
    }
    errCode = statement->Execute(args);
    if (errCode == E_SQLITE_LOCKED || errCode == E_SQLITE_BUSY) {
        auto pool = GetPool();
        if (pool != nullptr) {
            pool->Dump(true, "UPG DEL");
        }
    }
    return { errCode, GenerateResult(errCode, statement) };
}

int RdbStoreImpl::ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql, const Values &args)
{
    auto [code, result] = ExecuteForRow(sql, args);
    outValue = result.changed;
    return code;
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
 * Support skipping verification.
 */
int RdbStoreImpl::Backup(const std::string &databasePath, const std::vector<uint8_t> &encryptKey, bool verifyDb)
{
    LOG_INFO("Backup db: %{public}s, verify: %{public}d.", SqliteUtils::Anonymous(config_.GetName()).c_str(), verifyDb);
    if (isReadOnly_ || isMemoryRdb_) {
        return E_NOT_SUPPORT;
    }
    std::string backupFilePath;
    if (TryGetMasterSlaveBackupPath(databasePath, backupFilePath)) {
        return InnerBackup(backupFilePath, encryptKey, verifyDb);
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
int RdbStoreImpl::InnerBackup(
    const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey, bool verifyDb)
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
        if (errCode != E_OK) {
            return errCode;
        }
        errCode = conn->Backup(databasePath, {}, false, slaveStatus_, verifyDb);
        if (SqliteUtils::HasAccessAcl(config_.GetPath(), SERVICE_GID)) {
            SetFileGid(config_, SERVICE_GID);
        }
        return errCode;
    }
    Suspender suspender(Suspender::SQL_LOG);
    auto config = config_;
    config.SetHaMode(HAMode::SINGLE);
    config.SetCreateNecessary(false);
    auto [result, conn] = CreateWritableConn(config);
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
    auto [errCode, statement] = GetStatement(GlobalExpr::ATTACH_BACKUP_SQL, conn);
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

    auto [errCode, statement] = GetStatement(sql, conn);
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
    Suspender suspender(Suspender::SQL_LOG);
    auto [errCode, statement] = GetStatement(sql, conn);
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
    return SetDefaultEncryptSql(statement, sql, config);
}

int RdbStoreImpl::AttachInner(const RdbStoreConfig &config, const std::string &attachName, const std::string &dbPath,
    const std::vector<uint8_t> &key, int32_t waitTime)
{
    auto pool = GetPool();
    if (pool == nullptr) {
        return E_ALREADY_CLOSED;
    }
    Suspender suspender(Suspender::SQL_LOG);
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
    if (!key.empty()) {
        auto ret = SetDefaultEncryptAlgo(conn, config);
        if (ret != E_OK) {
            return ret;
        }
        bindArgs.emplace_back(ValueObject(key));
        auto [errCode, statement] = GetStatement(GlobalExpr::ATTACH_WITH_KEY_SQL, conn);
        if (statement == nullptr || errCode != E_OK) {
            LOG_ERROR("Attach get statement failed, code is %{public}d", errCode);
            return E_ERROR;
        }
        return statement->Execute(bindArgs);
    }

    auto [errCode, statement] = GetStatement(GlobalExpr::ATTACH_SQL, conn);
    if (statement == nullptr || errCode != E_OK) {
        LOG_ERROR("Attach get statement failed, code is %{public}d", errCode);
        return errCode;
    }
    return statement->Execute(bindArgs);
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
            err, SqliteUtils::Anonymous(config_.GetName()).c_str(), SqliteUtils::Anonymous(attachName).c_str(),
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
    Suspender suspender(Suspender::SQL_LOG);
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
    auto [errCode, statement] = GetStatement(GlobalExpr::DETACH_SQL, connection);
    if (statement == nullptr || errCode != E_OK) {
        LOG_ERROR("Detach get statement failed, errCode %{public}d", errCode);
        return { errCode, 0 };
    }
    errCode = statement->Execute(bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("failed, errCode[%{public}d] fileName[%{public}s] attachName[%{public}s] attach", errCode,
            SqliteUtils::Anonymous(config_.GetName()).c_str(), SqliteUtils::Anonymous(attachName).c_str());
        return { errCode, 0 };
    }
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
    Suspender suspender(Suspender::SQL_LOG);
    auto [errCode, statement] = GetStatement(GlobalExpr::PRAGMA_VERSION, isReadOnly_);
    if (statement == nullptr) {
        return errCode;
    }
    ValueObject value;
    std::tie(errCode, value) = statement->ExecuteForValue();
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
    Suspender suspender(Suspender::SQL_LOG);
    std::string sql = std::string(GlobalExpr::PRAGMA_VERSION) + " = " + std::to_string(version);
    auto [errCode, statement] = GetStatement(sql);
    if (statement == nullptr) {
        return errCode;
    }
    return statement->Execute();
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
            SqliteUtils::Anonymous(name_).c_str(),
            SqliteUtils::SqlAnonymous(sqlStr).c_str());
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
    Suspender suspender(Suspender::SQL_LOG);
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
#if !defined(CROSS_PLATFORM)
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
    config_.SetCollatorLocales(localeStr);
    return pool->ConfigLocale(localeStr);
}

int32_t RdbStoreImpl::SetTokenizer(Tokenizer tokenizer)
{
    if (tokenizer < NONE_TOKENIZER || tokenizer >= TOKENIZER_END) {
        return E_INVALID_ARGS_NEW;
    }
    if (tokenizer == ICU_TOKENIZER) {
        return E_NOT_SUPPORT;
    }
    auto pool = GetPool();
    if (pool == nullptr) {
        return E_ALREADY_CLOSED;
    }
    if (config_.GetTokenizer() == tokenizer) {
        return E_OK;
    }
    config_.SetTokenizer(tokenizer);
    return pool->SetTokenizer(tokenizer);
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

void RdbStoreImpl::SwitchOver(bool isUseReplicaDb)
{
    isUseReplicaDb_ = isUseReplicaDb;
}

int32_t RdbStoreImpl::RestoreWithPool(std::shared_ptr<ConnectionPool> pool, const std::string &path)
{
    if (pool == nullptr) {
        return E_OK;
    }
    auto connection = pool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_DATABASE_BUSY;
    }
    pool->ReopenConns();
    auto curStatus = std::make_shared<SlaveStatus>(SlaveStatus::UNDEFINED);
    return connection->Restore(path, {}, curStatus);
}

int RdbStoreImpl::StartAsyncRestore(std::shared_ptr<ConnectionPool> pool) const
{
    auto keyFilesPtr = std::make_shared<RdbSecurityManager::KeyFiles>(path_ + ASYNC_RESTORE);
    SqliteUtils::SetSlaveRestoring(path_);
    auto err = keyFilesPtr->Lock(false);
    if (err == E_OK) {
        auto taskPool = TaskExecutor::GetInstance().GetExecutor();
        if (taskPool == nullptr) {
            LOG_ERROR("Get thread pool failed");
            keyFilesPtr->Unlock();
            return E_ERROR;
        }
        bool isNeedSetAcl = isNeedSetAcl_ || SqliteUtils::HasAccessAcl(config_.GetPath(), SERVICE_GID);
        taskPool->Execute([keyFilesPtr, config = config_, pool, isNeedSetAcl] {
            auto dbPath = config.GetPath();
            LOG_INFO("async restore started for %{public}s", SqliteUtils::Anonymous(dbPath).c_str());
            auto result = RdbStoreImpl::RestoreWithPool(pool, dbPath);
            if (result != E_OK) {
                LOG_WARN("async restore failed, retry once, %{public}d", result);
                result = RdbStoreImpl::RestoreWithPool(pool, dbPath);
            }
            if (result != E_OK) {
                LOG_WARN("async restore failed, %{public}d", result);
                SqliteUtils::SetSlaveInvalid(dbPath);
            }
            SqliteUtils::SetSlaveRestoring(dbPath, false);
            if (pool != nullptr) {
                pool->ReopenConns();
            }
            if (isNeedSetAcl) {
                SetFileGid(config, SERVICE_GID);
            }
            keyFilesPtr->Unlock();
        });

        return E_OK;
    }
    LOG_WARN("Get process lock failed. Async restore is started in another process, %{public}s",
        SqliteUtils::Anonymous(path_).c_str());
    return E_OK;
}

int RdbStoreImpl::StartAsyncBackupIfNeed(std::shared_ptr<SlaveStatus> slaveStatus)
{
    auto taskPool = TaskExecutor::GetInstance().GetExecutor();
    if (taskPool == nullptr) {
        LOG_ERROR("Get thread pool failed");
        return E_ERROR;
    }
    auto config = config_;
    config.SetCreateNecessary(false);
    taskPool->Execute([config, slaveStatus] {
        if (*slaveStatus == SlaveStatus::DB_CLOSING) {
            return;
        }
        auto [result, conn] = CreateWritableConn(config);
        if (result != E_OK || conn == nullptr) {
            return;
        }
        auto strategy = conn->GenerateExchangeStrategy(slaveStatus);
        if (*slaveStatus == SlaveStatus::DB_CLOSING) {
            return;
        }
        LOG_INFO("async exchange st:%{public}d,", strategy);
        if (strategy == ExchangeStrategy::BACKUP) {
            (void)conn->Backup({}, {}, false, slaveStatus);
        }
    });
    return E_OK;
}

int RdbStoreImpl::RestoreInner(const std::string &destPath, const std::vector<uint8_t> &newKey,
    std::shared_ptr<ConnectionPool> pool)
{
    bool isUseAsync = SqliteUtils::IsUseAsyncRestore(config_, path_, destPath);
    LOG_INFO("restore start, using async=%{public}d", isUseAsync);
    if (!isUseAsync) {
        bool isNeedSetAcl = isNeedSetAcl_ || SqliteUtils::HasAccessAcl(config_.GetPath(), SERVICE_GID);
        auto err = pool->ChangeDbFileForRestore(path_, destPath, newKey, slaveStatus_);
        LOG_INFO("restore finished, sync mode rc=%{public}d", err);
        if (isNeedSetAcl) {
            SetFileGid(config_, SERVICE_GID);
        }
        return err;
    }

    auto connection = pool->AcquireConnection(false);
    if (connection == nullptr) {
        LOG_WARN("Failed to obtain writer for async restore");
        return E_DATABASE_BUSY;
    }

    int errCode = connection->CheckReplicaForRestore();
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = StartAsyncRestore(pool);
    LOG_INFO("restore finished, async mode rc=%{public}d", errCode);
    return errCode;
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
#if !defined(CROSS_PLATFORM)
    auto [err, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (service != nullptr) {
        service->Disable(syncerParam_);
    }
#endif
    bool corrupt = Reportor::IsReportCorruptedFault(path_);
    int errCode = RestoreInner(destPath, newKey, pool);
    keyFiles.Unlock();
#if !defined(CROSS_PLATFORM)
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

std::pair<int32_t, std::shared_ptr<Connection>> RdbStoreImpl::CreateWritableConn(const RdbStoreConfig &config)
{
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

    if (config_.GetHaMode() != HAMode::SINGLE && SqliteUtils::IsSlaveRestoring(config_.GetPath())) {
        auto keyFiles = RdbSecurityManager::KeyFiles(config_.GetPath() + ASYNC_RESTORE);
        int32_t ret = keyFiles.Lock(false);
        if (ret != E_OK) {
            if (isUseReplicaDb_) {
                LOG_INFO("Use replica statement, %{public}s", SqliteUtils::Anonymous(config_.GetPath()).c_str());
                return conn->CreateReplicaStatement(sql, conn);
            }
            return { E_DATABASE_BUSY, nullptr };
        }
        SqliteUtils::SetSlaveRestoring(config_.GetPath(), false);
        (void)keyFiles.Unlock();
        auto strategy = conn->GenerateExchangeStrategy(slaveStatus_);
        LOG_WARN("Got lock file but process is not in restore, mark removed, st:%{public}d, %{public}s",
            strategy, SqliteUtils::Anonymous(config_.GetPath()).c_str());
        if (strategy != ExchangeStrategy::RESTORE) {
            return conn->CreateStatement(sql, conn);
        }
        auto result = conn->CheckReplicaForRestore();
        if (result == E_OK) {
            result = StartAsyncRestore(GetPool());
            return conn->CreateReplicaStatement(sql, conn);
        }
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
    return GetStatement(sql, conn);
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
    if (*slaveStatus_ == SlaveStatus::BACKING_UP) {
        *slaveStatus_ = SlaveStatus::BACKUP_INTERRUPT;
        return E_OK;
    }
    return E_CANCEL;
}

int32_t RdbStoreImpl::GetBackupStatus() const
{
    if (config_.GetHaMode() != HAMode::MANUAL_TRIGGER && config_.GetHaMode() != HAMode::MAIN_REPLICA) {
        return SlaveStatus::UNDEFINED;
    }
    return *slaveStatus_;
}

int32_t RdbStoreImpl::GetInitStatus() const
{
    return initStatus_;
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

bool RdbStoreImpl::IsInAsyncRestore(const std::string &dbPath)
{
    if (!SqliteUtils::IsSlaveRestoring(dbPath)) {
        return false;
    }
    auto keyFilesPtr = std::make_shared<RdbSecurityManager::KeyFiles>(dbPath + ASYNC_RESTORE);
    auto err = keyFilesPtr->Lock(false);
    if (err == E_OK) {
        SqliteUtils::SetSlaveRestoring(dbPath, false);
        keyFilesPtr->Unlock();
        return false;
    }
    return errno == EWOULDBLOCK;
}

int32_t RdbStoreImpl::ExchangeSlaverToMaster()
{
    if (isReadOnly_ || isMemoryRdb_ || rebuild_ != RebuiltType::NONE) {
        return E_OK;
    }
    auto [errCode, conn] = GetConn(false);
    if (errCode != E_OK) {
        return errCode;
    }
    auto strategy = conn->GenerateExchangeStrategy(slaveStatus_, false);
    if (strategy != ExchangeStrategy::NOT_HANDLE) {
        LOG_WARN("exchange st:%{public}d, %{public}s,", strategy, SqliteUtils::Anonymous(config_.GetName()).c_str());
    }
    int ret = E_OK;
    if (strategy == ExchangeStrategy::RESTORE && !IsInAsyncRestore(config_.GetPath())) {
        conn = nullptr;
        // disable is required before restore
        ret = Restore({}, {});
    } else if (strategy == ExchangeStrategy::BACKUP) {
        // async backup
        ret = conn->Backup({}, {}, true, slaveStatus_);
    } else if (strategy == ExchangeStrategy::PENDING_BACKUP) {
        ret = StartAsyncBackupIfNeed(slaveStatus_);
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
    PerfStat perfStat(config_.GetPath(), "", PerfStat::Step::STEP_TOTAL);
    auto [errCode, conn] = pool->CreateTransConn();
    if (conn == nullptr) {
        return { errCode, nullptr };
    }
    std::shared_ptr<Transaction> trans;
    std::tie(errCode, trans) = Transaction::Create(type, conn, config_.GetPath());
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

std::shared_ptr<ResultSet> RdbStoreImpl::GetValues(std::shared_ptr<Statement> statement)
{
    if (statement == nullptr) {
        return nullptr;
    }
    auto [code, rows] = statement->GetRows(MAX_RETURNING_ROWS);
    auto size = rows.size();
    std::shared_ptr<ResultSet> result = std::make_shared<CacheResultSet>(std::move(rows));
    // The correct number of changed rows can only be obtained after completing the step
    while (code == E_OK && size == MAX_RETURNING_ROWS) {
        std::tie(code, rows) = statement->GetRows(MAX_RETURNING_ROWS);
        size = rows.size();
    }
    return result;
}

Results RdbStoreImpl::GenerateResult(int32_t code, std::shared_ptr<Statement> statement, bool isDML)
{
    Results result{ -1 };
    if (statement == nullptr) {
        return result;
    }
    // There are no data changes in other scenarios
    if (code == E_OK) {
        result.results = GetValues(statement);
        result.changed = isDML ? statement->Changes() : 0;
    }
    if (code == E_SQLITE_CONSTRAINT) {
        result.changed = statement->Changes();
    }
    if (isDML && result.changed <= 0) {
        result.results = std::make_shared<CacheResultSet>();
    }
    return result;
}

void RdbStoreImpl::TryDump(int32_t code, const char *dumpHeader)
{
    if (code != E_SQLITE_LOCKED && code != E_SQLITE_BUSY) {
        return;
    }
    auto pool = GetPool();
    if (pool != nullptr) {
        pool->Dump(true, dumpHeader);
    }
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
        // from empty, then need schedule the cloud sync, others only wait the schedule execute.
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
    if (isKnowledgeSchemaReady_) {
        return;
    }
    ret = conn->SetKnowledgeSchema(schema);
    if (ret != E_OK) {
        LOG_ERROR("Set knowledge schema failed %{public}d.", ret);
        return;
    }
    isKnowledgeSchemaReady_ = true;
    auto helper = GetKnowledgeSchemaHelper();
    helper->Init(config_, schema);
    helper->DonateKnowledgeData();
}

int RdbStoreImpl::InitKnowledgeSchema(const DistributedRdb::RdbKnowledgeSchema &schema)
{
    auto [ret, conn] = GetConn(false);
    if (ret != E_OK) {
        LOG_ERROR("The database is busy or closed when set knowledge schema ret %{public}d.", ret);
        return ret;
    }
    ret = conn->SetKnowledgeSchema(schema);
    if (ret != E_OK) {
        LOG_ERROR("Set knowledge schema failed %{public}d.", ret);
        return ret;
    }
    return E_OK;
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

int RdbStoreImpl::RegisterAlgo(const std::string &clstAlgoName, ClusterAlgoFunc func)
{
    if (!config_.IsVector() || isMemoryRdb_ || isReadOnly_) {
        return E_NOT_SUPPORT;
    }

    auto [ret, conn] = GetConn(false);
    if (ret != E_OK) {
        LOG_ERROR("The database is busy or closed when RegisterAlgo ret %{public}d.", ret);
        return ret;
    }
    return conn->RegisterAlgo(clstAlgoName, func);
}
} // namespace OHOS::NativeRdb
