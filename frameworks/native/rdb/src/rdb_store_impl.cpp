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
#include <memory>
#include <mutex>
#include <sstream>
#include <string>

#include "cache_result_set.h"
#include "directory_ex.h"
#include "logger.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_store.h"
#include "rdb_trace.h"
#include "relational_store_client.h"
#include "sqlite_global_config.h"
#include "sqlite_sql_builder.h"
#include "sqlite_statement.h"
#include "sqlite_utils.h"
#include "step_result_set.h"
#include "task_executor.h"
#include "traits.h"
#include "rdb_radar_reporter.h"

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include "delay_notify.h"
#include "raw_data_parser.h"
#include "rdb_device_manager_adapter.h"
#include "rdb_manager_impl.h"
#include "rdb_security_manager.h"
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

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
using namespace std::chrono;
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
using RdbMgr = DistributedRdb::RdbManagerImpl;
#endif
int RdbStoreImpl::InnerOpen()
{
    LOG_DEBUG("open %{public}s.", SqliteUtils::Anonymous(path_).c_str());
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    pool_ = TaskExecutor::GetInstance().GetExecutor();
    syncerParam_.bundleName_ = config_.GetBundleName();
    syncerParam_.hapName_ = config_.GetModuleName();
    syncerParam_.storeName_ = config_.GetName();
    syncerParam_.customDir_ = config_.GetCustomDir();
    syncerParam_.area_ = config_.GetArea();
    syncerParam_.level_ = static_cast<int32_t>(config_.GetSecurityLevel());
    syncerParam_.type_ = config_.GetDistributedType();
    syncerParam_.isEncrypt_ = config_.IsEncrypt();
    syncerParam_.isAutoClean_ = config_.GetAutoClean();
    syncerParam_.isSearchable_ = config_.IsSearchable();
    syncerParam_.password_ = {};

    syncerParam_.roleType_ = config_.GetRoleType();
    if (config_.GetRoleType() == OWNER) {
        AfterOpen(config_);
    }

    int errCode = RegisterDataChangeCallback();
    if (errCode != E_OK) {
        LOG_ERROR("RegisterCallBackObserver is failed, err is %{public}d.", errCode);
    }
#endif
    isOpen_ = true;
    return E_OK;
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
std::string RdbStoreImpl::GetSecManagerName(const RdbStoreConfig &config)
{
    auto name = config.GetBundleName();
    if (name.empty()) {
        return std::string(config.GetPath()).substr(0, config.GetPath().rfind("/") + 1);
    }
    return name;
}

void RdbStoreImpl::AfterOpen(const RdbStoreConfig &config)
{
    std::vector<uint8_t> key = config.GetEncryptKey();
    RdbPassword rdbPwd;
    if (config.IsEncrypt()) {
        auto ret = RdbSecurityManager::GetInstance().Init(GetSecManagerName(config));
        if (ret != E_OK) {
            return;
        }
        rdbPwd = RdbSecurityManager::GetInstance().GetRdbPassword(config.GetPath(),
            RdbSecurityManager::KeyFileType::PUB_KEY_FILE);
        key.assign(key.size(), 0);
        key = std::vector<uint8_t>(rdbPwd.GetData(), rdbPwd.GetData() + rdbPwd.GetSize());
    }
    syncerParam_.password_ = std::vector<uint8_t>(key.data(), key.data() + key.size());
    key.assign(key.size(), 0);
    if (pool_ != nullptr) {
        auto param = syncerParam_;
        auto retry = 0;
        UploadSchema(param, retry);
    }
}

void RdbStoreImpl::UploadSchema(const DistributedRdb::RdbSyncerParam &param, uint32_t retry)
{
    auto [err, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(param);
    if (err != E_OK || service == nullptr) {
        LOG_ERROR("GetRdbService failed, err: %{public}d, storeName: %{public}s.", err, param.storeName_.c_str());
        auto pool = TaskExecutor::GetInstance().GetExecutor();
        if (err == E_SERVICE_NOT_FOUND && pool != nullptr && retry++ < MAX_RETRY_TIMES) {
            pool->Schedule(std::chrono::seconds(RETRY_INTERVAL), [param, retry]() { UploadSchema(param, retry); });
        }
        return;
    }
    err = service->AfterOpen(param);
    if (err != E_OK) {
        LOG_ERROR("AfterOpen failed, err: %{public}d, storeName: %{public}s.", err, param.storeName_.c_str());
    }
}

RdbStore::ModifyTime::ModifyTime(std::shared_ptr<ResultSet> result, std::map<std::vector<uint8_t>, PRIKey> hashKeys,
    bool isFromRowId)
    : result_(std::move(result)), hash_(std::move(hashKeys)), isFromRowId_(isFromRowId)
{
    for (auto &[_, priKey] : hash_) {
        if (priKey.index() != Traits::variant_index_of_v<std::string, PRIKey>) {
            break;
        }
        auto *val = Traits::get_if<std::string>(&priKey);
        if (val != nullptr && maxOriginKeySize_ <= val->length()) {
            maxOriginKeySize_ = val->length() + 1;
        }
    }
}

RdbStore::ModifyTime::operator std::map<PRIKey, Date>()
{
    if (result_ == nullptr) {
        return {};
    }
    int count = 0;
    if (result_->GetRowCount(count) != E_OK || count <= 0) {
        LOG_ERROR("get resultSet err.");
        return {};
    }
    std::map<PRIKey, Date> result;
    for (int i = 0; i < count; i++) {
        result_->GoToRow(i);
        int64_t timeStamp = 0;
        result_->GetLong(1, timeStamp);
        PRIKey index = 0;
        if (isFromRowId_) {
            int64_t rowid = 0;
            result_->GetLong(0, rowid);
            index = rowid;
        } else {
            std::vector<uint8_t> hashKey;
            result_->GetBlob(0, hashKey);
            index = hash_[hashKey];
        }
        result[index] = Date(timeStamp);
    }
    return result;
}

RdbStore::ModifyTime::operator std::shared_ptr<ResultSet>()
{
    return result_;
}

RdbStore::PRIKey RdbStore::ModifyTime::GetOriginKey(const std::vector<uint8_t> &hash)
{
    auto it = hash_.find(hash);
    return it != hash_.end() ? it->second : std::monostate();
}

size_t RdbStore::ModifyTime::GetMaxOriginKeySize()
{
    return maxOriginKeySize_;
}

bool RdbStore::ModifyTime::NeedConvert() const
{
    return !hash_.empty();
}

RdbStore::ModifyTime RdbStoreImpl::GetModifyTime(const std::string &table, const std::string &columnName,
    std::vector<PRIKey> &keys)
{
    if (table.empty() || columnName.empty() || keys.empty()) {
        LOG_ERROR("invalid para.");
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
            LOG_DEBUG("hash key fail");
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
    auto resultSet = QueryByStep(sql, hashKeys);
    int count = 0;
    if (resultSet == nullptr || resultSet->GetRowCount(count) != E_OK || count <= 0) {
        LOG_ERROR("get resultSet err.");
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
    auto resultSet = QueryByStep(sql, args);
    int count = 0;
    if (resultSet == nullptr || resultSet->GetRowCount(count) != E_OK || count <= 0) {
        LOG_ERROR("get resultSet err.");
        return {};
    }
    return { resultSet, {}, true };
}

int RdbStoreImpl::CleanDirtyData(const std::string &table, uint64_t cursor)
{
    if (config_.GetRoleType() == VISITOR) {
        return E_NOT_SUPPORT;
    }
    if (table.empty()) {
        return E_INVALID_ARGS;
    }
    auto connection = connectionPool_->AcquireConnection(false);
    if (connection == nullptr) {
        return E_DATABASE_BUSY;
    }
    int errCode = connection->CleanDirtyData(table, cursor);
    return errCode;
}
#endif

RdbStoreImpl::RdbStoreImpl(const RdbStoreConfig &config)
    : config_(config), isOpen_(false), isReadOnly_(config.IsReadOnly()),
      isMemoryRdb_(config.IsMemoryRdb()), isEncrypt_(config.IsEncrypt()), path_(config.GetPath()),
      orgPath_(config.GetPath()), name_(config.GetName()), fileType_(config.GetDatabaseFileType()),
      connectionPool_(nullptr), rebuild_(RebuiltType::NONE)
{
}

RdbStoreImpl::RdbStoreImpl(const RdbStoreConfig &config, int &errCode)
    : config_(config), isReadOnly_(config.IsReadOnly()), isMemoryRdb_(config.IsMemoryRdb()),
      isEncrypt_(config.IsEncrypt()), name_(config.GetName()), fileType_(config.GetDatabaseFileType()),
      rebuild_(RebuiltType::NONE)
{
    path_ = (config.GetRoleType() == VISITOR) ? config.GetVisitorDir() : config.GetPath();
    connectionPool_ = SqliteConnectionPool::Create(config_, errCode);
    if (connectionPool_ == nullptr && errCode == E_SQLITE_CORRUPT && config.GetAllowRebuild()) {
        auto realPath = config.GetPath();
        RemoveDbFiles(realPath);
        connectionPool_ = SqliteConnectionPool::Create(config_, errCode);
        if (errCode == E_OK) {
            rebuild_ = RebuiltType::REBUILT;
        }
        LOG_WARN("db %{public}s corrupt, rebuild ret %{public}d, encrypt %{public}d",
            name_.c_str(), errCode, isEncrypt_);
    }
    if (connectionPool_ == nullptr || errCode != E_OK) {
        connectionPool_ = nullptr;
        LOG_ERROR("Create connPool failed, err is %{public}d, path:%{public}s",
            errCode, path_.c_str());
        return;
    }

    InnerOpen();
}

RdbStoreImpl::~RdbStoreImpl()
{
    connectionPool_ = nullptr;
}

void RdbStoreImpl::RemoveDbFiles(std::string &path)
{
    SqliteUtils::DeleteFile(path);
    SqliteUtils::DeleteFile(path + "-shm");
    SqliteUtils::DeleteFile(path + "-wal");
    SqliteUtils::DeleteFile(path + "-journal");
}

const RdbStoreConfig &RdbStoreImpl::GetConfig()
{
    return config_;
}

int RdbStoreImpl::Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &values)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    RdbRadar ret(Scene::SCENE_INSERT, __FUNCTION__);
    ret = InsertWithConflictResolutionEntry(outRowId, table, values, ConflictResolution::ON_CONFLICT_NONE);
    return ret;
}

int RdbStoreImpl::BatchInsert(int64_t &outInsertNum, const std::string &table, const std::vector<ValuesBucket> &values)
{
    RdbRadar ret(Scene::SCENE_BATCH_INSERT, __FUNCTION__);
    ret = BatchInsertEntry(outInsertNum, table, values);
    return ret;
}

int RdbStoreImpl::BatchInsertEntry(int64_t &outInsertNum, const std::string &table,
    const std::vector<ValuesBucket> &values)
{
    if (config_.GetRoleType() == VISITOR) {
        return E_NOT_SUPPORT;
    }
    if (values.empty()) {
        outInsertNum = 0;
        return E_OK;
    }
    auto connection = connectionPool_->AcquireConnection(false);
    if (connection == nullptr) {
        return E_DATABASE_BUSY;
    }
    auto executeSqlArgs = GenerateSql(table, values, connection->GetMaxVariable());
    if (executeSqlArgs.empty()) {
        LOG_ERROR("empty, table=%{public}s, values:%{public}zu, max number:%{public}d.", table.c_str(),
            values.size(), connection->GetMaxVariable());
        return E_INVALID_ARGS;
    }
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    PauseDelayNotify pauseDelayNotify(delayNotifier_);
#endif
    for (const auto &[sql, bindArgs] : executeSqlArgs) {
        auto [errCode, statement] = GetStatement(sql, connection);
        if (statement == nullptr) {
            continue;
        }
        for (const auto &args : bindArgs) {
            auto errCode = statement->Execute(args);
            if (errCode != E_OK) {
                outInsertNum = -1;
                LOG_ERROR("BatchInsert failed, errCode : %{public}d, bindArgs : %{public}zu,"
                    "table : %{public}s, sql : %{public}s", errCode, bindArgs.size(), table.c_str(), sql.c_str());
                return E_OK;
            }
        }
    }
    connection = nullptr;
    outInsertNum = static_cast<int64_t>(values.size());
    DoCloudSync(table);
    return E_OK;
}

RdbStoreImpl::ExecuteSqls RdbStoreImpl::GenerateSql(const std::string& table, const std::vector<ValuesBucket>& buckets,
    int limit)
{
    std::vector<std::vector<ValueObject>> values;
    std::map<std::string, uint32_t> fields;
    int32_t valuePosition = 0;
    for (size_t row = 0; row < buckets.size(); row++) {
        auto &vBucket = buckets[row];
        if (values.max_size() == 0) {
            values.reserve(vBucket.values_.size() * EXPANSION);
        }
        for (auto &[key, value] : vBucket.values_) {
            if (value.GetType() == ValueObject::TYPE_ASSET || value.GetType() == ValueObject::TYPE_ASSETS) {
                SetAssetStatus(value, AssetValue::STATUS_INSERT);
            }
            int32_t col = 0;
            auto it = fields.find(key);
            if (it == fields.end()) {
                values.emplace_back(std::vector<ValueObject>(buckets.size()));
                col = valuePosition;
                fields.insert(std::make_pair(key, col));
                valuePosition++;
            } else {
                col = static_cast<int32_t>(it->second);
            }
            values[col][row] = value;
        }
    }

    std::string sql = "INSERT OR REPLACE INTO " + table + " (";
    std::vector<ValueObject> args(buckets.size() * values.size());
    int32_t col = 0;
    for (auto &[key, pos] : fields) {
        for (size_t row = 0; row < buckets.size(); ++row) {
            args[col + static_cast<int32_t>(row * fields.size())] = std::move(values[pos][row]);
        }
        col++;
        sql.append(key).append(",");
    }
    sql.pop_back();
    sql.append(") VALUES ");
    return SqliteSqlBuilder::MakeExecuteSqls(sql, std::move(args), fields.size(), limit);
}

int RdbStoreImpl::Replace(int64_t &outRowId, const std::string &table, const ValuesBucket &values)
{
    RdbRadar ret(Scene::SCENE_REPLACE, __FUNCTION__);
    ret = InsertWithConflictResolutionEntry(outRowId, table, values, ConflictResolution::ON_CONFLICT_REPLACE);
    return ret;
}

int RdbStoreImpl::InsertWithConflictResolution(int64_t &outRowId, const std::string &table,
    const ValuesBucket &values, ConflictResolution conflictResolution)
{
    RdbRadar ret(Scene::SCENE_INSERT, __FUNCTION__);
    ret = InsertWithConflictResolutionEntry(outRowId, table, values, conflictResolution);
    return ret;
}

int RdbStoreImpl::InsertWithConflictResolutionEntry(int64_t &outRowId, const std::string &table,
    const ValuesBucket &values, ConflictResolution conflictResolution)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (config_.GetRoleType() == VISITOR) {
        return E_NOT_SUPPORT;
    }
    if (table.empty()) {
        return E_EMPTY_TABLE_NAME;
    }

    if (values.IsEmpty()) {
        return E_EMPTY_VALUES_BUCKET;
    }

    auto conflictClause = SqliteUtils::GetConflictClause(static_cast<int>(conflictResolution));
    if (conflictClause == nullptr) {
        return E_INVALID_CONFLICT_FLAG;
    }

    std::string sql;
    sql.append("INSERT").append(conflictClause).append(" INTO ").append(table).append("(");
    size_t bindArgsSize = values.values_.size();
    std::vector<ValueObject> bindArgs;
    bindArgs.reserve(bindArgsSize);
    const char *split = "";
    for (const auto &[key, val] : values.values_) {
        sql.append(split).append(key);
        if (val.GetType() == ValueObject::TYPE_ASSETS &&
            conflictResolution == ConflictResolution::ON_CONFLICT_REPLACE) {
            return E_INVALID_ARGS;
        }
        if (val.GetType() == ValueObject::TYPE_ASSET || val.GetType() == ValueObject::TYPE_ASSETS) {
            SetAssetStatus(val, AssetValue::STATUS_INSERT);
        }
        bindArgs.push_back(val);  // columnValue
        split = ",";
    }

    sql.append(") VALUES (");
    if (bindArgsSize > 0) {
        sql.append(SqliteSqlBuilder::GetSqlArgs(bindArgsSize));
    }

    sql.append(")");
    auto errCode = ExecuteForLastInsertedRowId(outRowId, sql, bindArgs);
    if (errCode != E_OK) {
        return errCode;
    }
    DoCloudSync(table);
    return E_OK;
}

void RdbStoreImpl::SetAssetStatus(const ValueObject &val, int32_t status)
{
    if (val.GetType() == ValueObject::TYPE_ASSET) {
        auto *asset = Traits::get_if<ValueObject::Asset>(&val.value);
        if (asset != nullptr) {
            asset->status = static_cast<AssetValue::Status>(status);
        }
    }
    if (val.GetType() == ValueObject::TYPE_ASSETS) {
        auto *assets = Traits::get_if<ValueObject::Assets>(&val.value);
        if (assets != nullptr) {
            for (auto &asset : *assets) {
                asset.status = static_cast<AssetValue::Status>(status);
            }
        }
    }
}

int RdbStoreImpl::Update(int &changedRows, const std::string &table, const ValuesBucket &values,
    const std::string &whereClause, const std::vector<std::string> &whereArgs)
{
    std::vector<ValueObject> bindArgs;
    std::for_each(
        whereArgs.begin(), whereArgs.end(), [&bindArgs](const auto &it) { bindArgs.push_back(ValueObject(it)); });
    return UpdateWithConflictResolution(
        changedRows, table, values, whereClause, bindArgs, ConflictResolution::ON_CONFLICT_NONE);
}

int RdbStoreImpl::Update(int &changedRows, const std::string &table, const ValuesBucket &values,
    const std::string &whereClause, const std::vector<ValueObject> &bindArgs)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    return UpdateWithConflictResolution(
        changedRows, table, values, whereClause, bindArgs, ConflictResolution::ON_CONFLICT_NONE);
}

int RdbStoreImpl::Update(int &changedRows, const ValuesBucket &values, const AbsRdbPredicates &predicates)
{
    return Update(
        changedRows, predicates.GetTableName(), values, predicates.GetWhereClause(), predicates.GetBindArgs());
}

int RdbStoreImpl::UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
    const std::string &whereClause, const std::vector<std::string> &whereArgs, ConflictResolution conflictResolution)
{
    std::vector<ValueObject> bindArgs;
    std::for_each(
        whereArgs.begin(), whereArgs.end(), [&bindArgs](const auto &it) { bindArgs.push_back(ValueObject(it)); });
    return UpdateWithConflictResolutionEntry(
        changedRows, table, values, whereClause, bindArgs, conflictResolution);
}

int RdbStoreImpl::UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
    const std::string &whereClause, const std::vector<ValueObject> &bindArgs, ConflictResolution conflictResolution)
{
    RdbRadar ret(Scene::SCENE_UPDATE, __FUNCTION__);
    ret = UpdateWithConflictResolutionEntry(changedRows, table, values, whereClause, bindArgs, conflictResolution);
    return ret;
}

int RdbStoreImpl::UpdateWithConflictResolutionEntry(int &changedRows, const std::string &table,
    const ValuesBucket &values, const std::string &whereClause, const std::vector<ValueObject> &bindArgs,
    ConflictResolution conflictResolution)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (config_.GetRoleType() == VISITOR) {
        return E_NOT_SUPPORT;
    }
    if (table.empty()) {
        return E_EMPTY_TABLE_NAME;
    }

    if (values.IsEmpty()) {
        return E_EMPTY_VALUES_BUCKET;
    }

    auto clause = SqliteUtils::GetConflictClause(static_cast<int>(conflictResolution));
    if (clause == nullptr) {
        return E_INVALID_CONFLICT_FLAG;
    }

    std::string sql;
    sql.append("UPDATE").append(clause).append(" ").append(table).append(" SET ");
    std::vector<ValueObject> tmpBindArgs;
    size_t tmpBindSize = values.values_.size() + bindArgs.size();
    tmpBindArgs.reserve(tmpBindSize);
    const char *split = "";
    for (auto &[key, val] : values.values_) {
        sql.append(split);
        if (val.GetType() != ValueObject::TYPE_ASSETS) {
            sql.append(key).append("=?"); // columnName
        } else {
            sql.append(key).append("=merge_assets(").append(key).append(", ?)"); // columnName
        }
        tmpBindArgs.push_back(val); // columnValue
        split = ",";
    }

    if (!whereClause.empty()) {
        sql.append(" WHERE ").append(whereClause);
    }

    tmpBindArgs.insert(tmpBindArgs.end(), bindArgs.begin(), bindArgs.end());

    int64_t changes = -1;
    auto errCode = ExecuteForChangedRowCount(changes, sql, tmpBindArgs);
    if (errCode != E_OK) {
        return errCode;
    }
    changedRows = changes;
    DoCloudSync(table);
    return errCode;
}

int RdbStoreImpl::Delete(int &deletedRows, const AbsRdbPredicates &predicates)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    RdbRadar ret(Scene::SCENE_DELETE, __FUNCTION__);
    ret = Delete(deletedRows, predicates.GetTableName(), predicates.GetWhereClause(), predicates.GetBindArgs());
    return ret;
}

int RdbStoreImpl::Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
    const std::vector<std::string> &whereArgs)
{
    std::vector<ValueObject> bindArgs;
    std::for_each(
        whereArgs.begin(), whereArgs.end(), [&bindArgs](const auto &it) { bindArgs.push_back(ValueObject(it)); });
    RdbRadar ret(Scene::SCENE_DELETE, __FUNCTION__);
    ret = Delete(deletedRows, table, whereClause, bindArgs);
    return ret;
}

int RdbStoreImpl::Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
    const std::vector<ValueObject> &bindArgs)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (config_.GetRoleType() == VISITOR) {
        return E_NOT_SUPPORT;
    }
    if (table.empty()) {
        return E_EMPTY_TABLE_NAME;
    }

    std::string sql;
    sql.append("DELETE FROM ").append(table);
    if (!whereClause.empty()) {
        sql.append(" WHERE ").append(whereClause);
    }
    int64_t changes = -1;
    auto errCode = ExecuteForChangedRowCount(changes, sql, bindArgs);
    if (errCode != E_OK) {
        return errCode;
    }
    deletedRows = changes;
    DoCloudSync(table);
    return E_OK;
}

std::shared_ptr<ResultSet> RdbStoreImpl::QueryByStep(
    const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::string sql;
    if (predicates.HasSpecificField()) {
        std::string table = predicates.GetTableName();
        std::string logTable = DistributedDB::RelationalStoreManager::GetDistributedLogTableName(table);
        sql = SqliteSqlBuilder::BuildLockRowQueryString(predicates, columns, logTable);
    } else {
        sql = SqliteSqlBuilder::BuildQueryString(predicates, columns);
    }
    return QueryByStep(sql, predicates.GetBindArgs());
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
std::shared_ptr<AbsSharedResultSet> RdbStoreImpl::Query(
    const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::string sql;
    std::pair<bool, bool> queryStatus = { ColHasSpecificField(columns), predicates.HasSpecificField() };
    if (queryStatus.first || queryStatus.second) {
        std::string table = predicates.GetTableName();
        std::string logTable = DistributedDB::RelationalStoreManager::GetDistributedLogTableName(table);
        sql = SqliteSqlBuilder::BuildCursorQueryString(predicates, columns, logTable, queryStatus);
    } else {
        sql = SqliteSqlBuilder::BuildQueryString(predicates, columns);
    }
    return QuerySql(sql, predicates.GetBindArgs());
}

std::pair<int32_t, std::shared_ptr<ResultSet>> RdbStoreImpl::QuerySharingResource(
    const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    auto [errCode, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(syncerParam_);
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

std::shared_ptr<ResultSet> RdbStoreImpl::RemoteQuery(const std::string &device,
    const AbsRdbPredicates &predicates, const std::vector<std::string> &columns, int &errCode)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::vector<std::string> selectionArgs = predicates.GetWhereArgs();
    std::string sql = SqliteSqlBuilder::BuildQueryString(predicates, columns);
    auto [err, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(syncerParam_);
    if (err != E_OK) {
        LOG_ERROR("RdbStoreImpl::RemoteQuery get service failed");
        errCode = err;
        return nullptr;
    }
    auto [status, resultSet] = service->RemoteQuery(syncerParam_, device, sql, selectionArgs);
    errCode = status;
    return resultSet;
}

std::shared_ptr<AbsSharedResultSet> RdbStoreImpl::Query(int &errCode, bool distinct,
    const std::string &table, const std::vector<std::string> &columns,
    const std::string &whereClause, const std::vector<ValueObject> &bindArgs, const std::string &groupBy,
    const std::string &indexName, const std::string &orderBy, const int &limit, const int &offset)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::string sql;
    errCode = SqliteSqlBuilder::BuildQueryString(
        distinct, table, "", columns, whereClause, groupBy, indexName, orderBy, limit, offset, sql);
    if (errCode != E_OK) {
        return nullptr;
    }

    auto resultSet = QuerySql(sql, bindArgs);
    return resultSet;
}

std::shared_ptr<AbsSharedResultSet> RdbStoreImpl::QuerySql(const std::string &sql,
    const std::vector<std::string> &sqlArgs)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::vector<ValueObject> bindArgs;
    std::for_each(sqlArgs.begin(), sqlArgs.end(), [&bindArgs](const auto &it) { bindArgs.push_back(ValueObject(it)); });
    return std::make_shared<SqliteSharedResultSet>(connectionPool_, path_, sql, bindArgs);
}

std::shared_ptr<AbsSharedResultSet> RdbStoreImpl::QuerySql(const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    return std::make_shared<SqliteSharedResultSet>(connectionPool_, path_, sql, bindArgs);
}
#endif

#if defined(WINDOWS_PLATFORM) || defined(MAC_PLATFORM) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
std::shared_ptr<ResultSet> RdbStoreImpl::Query(
    const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RdbStoreImpl::Query on called.");
    std::string sql = SqliteSqlBuilder::BuildQueryString(predicates, columns);
    return QueryByStep(sql, predicates.GetBindArgs());
}
#endif

int RdbStoreImpl::Count(int64_t &outValue, const AbsRdbPredicates &predicates)
{
    std::string sql = SqliteSqlBuilder::BuildCountString(predicates);

    return ExecuteAndGetLong(outValue, sql, predicates.GetBindArgs());
}

int RdbStoreImpl::ExecuteSql(const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    RdbRadar ret(Scene::SCENE_EXECUTE_SQL, __FUNCTION__);
    ret = ExecuteSqlEntry(sql, bindArgs);
    return ret;
}

int RdbStoreImpl::ExecuteSqlEntry(const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int ret = CheckAttach(sql);
    if (ret != E_OK) {
        return ret;
    }

    auto [errCode, statement] = BeginExecuteSql(sql);
    if (statement == nullptr) {
        return errCode;
    }
    errCode = statement->Execute(bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("RDB_STORE Execute SQL ERROR.");
        return errCode;
    }
    int sqlType = SqliteUtils::GetSqlStatementType(sql);
    if (sqlType == SqliteUtils::STATEMENT_DDL) {
        statement->Reset();
        statement->Prepare("PRAGMA schema_version");
        auto [err, version] = statement->ExecuteForValue();
        statement = nullptr;
        if (vSchema_ < static_cast<int64_t>(version)) {
            LOG_INFO("db:%{public}s exe DDL schema<%{public}" PRIi64 "->%{public}" PRIi64 "> sql:%{public}s.",
                     name_.c_str(), vSchema_, static_cast<int64_t>(version), sql.c_str());
            vSchema_ = version;
            errCode = connectionPool_->RestartReaders();
        }
    }
    statement = nullptr;
    if (errCode == E_OK && (sqlType == SqliteUtils::STATEMENT_UPDATE || sqlType == SqliteUtils::STATEMENT_INSERT)) {
        DoCloudSync("");
    }
    return errCode;
}

std::pair<int32_t, ValueObject> RdbStoreImpl::Execute(const std::string &sql, const std::vector<ValueObject> &bindArgs,
    int64_t trxId)
{
    RdbRadar radarObj(Scene::SCENE_EXECUTE_SQL, __FUNCTION__);
    auto [ret, object] =  ExecuteEntry(sql, bindArgs, trxId);
    radarObj = ret;
    return {ret, object};
}

std::pair<int32_t, ValueObject> RdbStoreImpl::ExecuteEntry(const std::string &sql,
    const std::vector<ValueObject> &bindArgs, int64_t trxId)
{
    ValueObject object;
    int sqlType = SqliteUtils::GetSqlStatementType(sql);
    if (!SqliteUtils::IsSupportSqlForExecute(sqlType)) {
        LOG_ERROR("Not support the sqlType: %{public}d, sql: %{public}s", sqlType, sql.c_str());
        return { E_NOT_SUPPORT_THE_SQL, object };
    }

    auto connect = connectionPool_->AcquireConnection(false);
    if (connect == nullptr) {
        return { E_CON_OVER_LIMIT, object };
    }

    auto [errCode, statement] = GetStatement(sql, connect);
    if (errCode != E_OK) {
        return { errCode, object };
    }

    errCode = statement->Execute(bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("execute sql failed, sql: %{public}s, error: %{public}d.", sql.c_str(), errCode);
        return { errCode, object };
    }

    if (sqlType == SqliteUtils::STATEMENT_INSERT) {
        int outValue = statement->Changes() > 0 ? statement->LastInsertRowId() : -1;
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
            LOG_ERROR("Not support the sql:%{public}s, column count more than 1", sql.c_str());
            return { E_NOT_SUPPORT_THE_SQL, object };
        }
    }

    if (sqlType == SqliteUtils::STATEMENT_DDL) {
        statement->Reset();
        statement->Prepare("PRAGMA schema_version");
        auto [err, version] = statement->ExecuteForValue();
        if (vSchema_ < static_cast<int64_t>(version)) {
            LOG_INFO("db:%{public}s exe DDL schema<%{public}" PRIi64 "->%{public}" PRIi64 "> sql:%{public}s.",
                     name_.c_str(), vSchema_, static_cast<int64_t>(version), sql.c_str());
            vSchema_ = version;
            errCode = connectionPool_->RestartReaders();
        }
    }
    return { errCode, object };
}

int RdbStoreImpl::ExecuteAndGetLong(int64_t &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    auto [errCode, statement] = BeginExecuteSql(sql);
    if (statement == nullptr) {
        return errCode;
    }
    auto [err, object] = statement->ExecuteForValue(bindArgs);
    if (err != E_OK) {
        LOG_ERROR("failed, sql %{public}s,  ERROR is %{public}d.", sql.c_str(), errCode);
    }
    outValue = object;
    return errCode;
}

int RdbStoreImpl::ExecuteAndGetString(
    std::string &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    auto [errCode, statement] = BeginExecuteSql(sql);
    if (statement == nullptr) {
        return errCode;
    }
    ValueObject object;
    std::tie(errCode, object) = statement->ExecuteForValue(bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("failed, sql %{public}s,  ERROR is %{public}d.", sql.c_str(), errCode);
    }
    outValue = static_cast<std::string>(object);
    return errCode;
}

int RdbStoreImpl::ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    if (config_.GetRoleType() == VISITOR) {
        return E_NOT_SUPPORT;
    }
    auto [errCode, statement] = GetStatement(sql, false);
    if (statement == nullptr) {
        return errCode;
    }
    errCode = statement->Execute(bindArgs);
    if (errCode != E_OK) {
        return errCode;
    }
    outValue = statement->Changes() > 0 ? statement->LastInsertRowId() : -1;
    return E_OK;
}

int RdbStoreImpl::ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    if (config_.GetRoleType() == VISITOR) {
        return E_NOT_SUPPORT;
    }
    auto [errCode, statement] = GetStatement(sql, false);
    if (statement == nullptr) {
        return errCode;
    }
    errCode = statement->Execute(bindArgs);
    if (errCode != E_OK) {
        return errCode;
    }
    outValue = statement->Changes();
    return E_OK;
}

int RdbStoreImpl::GetDataBasePath(const std::string &databasePath, std::string &backupFilePath)
{
    if (databasePath.empty()) {
        LOG_ERROR("Empty databasePath.");
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

int RdbStoreImpl::ExecuteSqlInner(const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    auto [errCode, statement] = BeginExecuteSql(sql);
    if (statement == nullptr) {
        return errCode;
    }

    errCode = statement->Execute(bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("ExecuteSql ATTACH_BACKUP_SQL error %{public}d", errCode);
    }
    return errCode;
}

/**
 * Backup a database from a specified encrypted or unencrypted database file.
 */
int RdbStoreImpl::Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey)
{
    if (config_.GetRoleType() == VISITOR) {
        return E_NOT_SUPPORT;
    }
    std::string backupFilePath;
    int ret = GetDataBasePath(databasePath, backupFilePath);
    if (ret != E_OK) {
        return ret;
    }
    std::string tempPath = backupFilePath + "temp";
    while (access(tempPath.c_str(), F_OK) == E_OK) {
        tempPath += "temp";
    }
    if (access(backupFilePath.c_str(), F_OK) == E_OK) {
        SqliteUtils::RenameFile(backupFilePath, tempPath);
        ret = InnerBackup(backupFilePath, destEncryptKey);
        if (ret == E_OK) {
            SqliteUtils::DeleteFile(tempPath);
        } else {
            SqliteUtils::RenameFile(tempPath, backupFilePath);
        }
        return ret;
    }
    ret = InnerBackup(backupFilePath, destEncryptKey);
    return ret;
}

/**
 * Backup a database from a specified encrypted or unencrypted database file.
 */
int RdbStoreImpl::InnerBackup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey)
{
    if (config_.GetRoleType() == VISITOR) {
        return E_NOT_SUPPORT;
    }

    auto [errCode, statement] = GetStatement(GlobalExpr::CIPHER_DEFAULT_ATTACH_HMAC_ALGO, true);
    if (statement == nullptr) {
        return E_BASE;
    }
    std::vector<ValueObject> bindArgs;
    bindArgs.emplace_back(databasePath);
    if (!destEncryptKey.empty() && !isEncrypt_) {
        bindArgs.emplace_back(destEncryptKey);
        statement->Execute();
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    } else if (isEncrypt_) {
        RdbPassword rdbPwd = RdbSecurityManager::GetInstance().GetRdbPassword(
            config_.GetPath(), RdbSecurityManager::KeyFileType::PUB_KEY_FILE);
        std::vector<uint8_t> key = std::vector<uint8_t>(rdbPwd.GetData(), rdbPwd.GetData() + rdbPwd.GetSize());
        bindArgs.emplace_back(key);
        statement->Execute();
#endif
    } else {
        std::string str = "";
        bindArgs.emplace_back(str);
    }

    errCode = statement->Prepare(GlobalExpr::ATTACH_BACKUP_SQL);
    errCode = statement->Execute(bindArgs);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = statement->Prepare(GlobalExpr::EXPORT_SQL);
    int ret = statement->Execute();
    errCode = statement->Prepare(GlobalExpr::DETACH_BACKUP_SQL);
    int res = statement->Execute();
    return (res == E_OK) ? ret : res;
}

std::pair<int32_t, RdbStoreImpl::Stmt> RdbStoreImpl::BeginExecuteSql(const std::string& sql)
{
    int type = SqliteUtils::GetSqlStatementType(sql);
    if (SqliteUtils::IsSpecial(type)) {
        return { E_NOT_SUPPORTED, nullptr };
    }

    bool assumeReadOnly = SqliteUtils::IsSqlReadOnly(type);
    auto conn = connectionPool_->AcquireConnection(assumeReadOnly);
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
    return connectionPool_ != nullptr;
}

int RdbStoreImpl::AttachInner(
    const std::string &attachName, const std::string &dbPath, const std::vector<uint8_t> &key, int32_t waitTime)
{
    auto [conn, readers] = connectionPool_->AcquireAll(waitTime);
    if (conn == nullptr) {
        return E_DATABASE_BUSY;
    }

    if (config_.GetStorageMode() != StorageMode::MODE_MEMORY &&
        conn->GetJournalMode() == static_cast<int32_t>(JournalMode::MODE_WAL)) {
        // close first to prevent the connection from being put back.
        connectionPool_->CloseAllConnections();
        conn = nullptr;
        readers.clear();
        auto [err, newConn] = connectionPool_->DisableWal();
        if (err != E_OK) {
            return err;
        }
        conn = newConn;
    }
    std::vector<ValueObject> bindArgs;
    bindArgs.emplace_back(ValueObject(dbPath));
    bindArgs.emplace_back(ValueObject(attachName));
    if (!key.empty()) {
        auto [errCode, statement] = conn->CreateStatement(GlobalExpr::CIPHER_DEFAULT_ATTACH_HMAC_ALGO, conn);
        if (statement == nullptr) {
            LOG_ERROR("Attach get statement failed, code is %{public}d", errCode);
            return errCode;
        }
        errCode = statement->Execute();
        bindArgs.emplace_back(ValueObject(key));
        std::tie(errCode, statement) = conn->CreateStatement(GlobalExpr::ATTACH_WITH_KEY_SQL, conn);
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
    return statement->Execute(bindArgs);
}

/**
 * Attaches a database.
 */
std::pair<int32_t, int32_t> RdbStoreImpl::Attach(
    const RdbStoreConfig &config, const std::string &attachName, int32_t waitTime)
{
    if (config_.GetRoleType() == VISITOR) {
        return { E_NOT_SUPPORT, 0 };
    }
    std::string dbPath;
    int err = SqliteGlobalConfig::GetDbPath(config, dbPath);
    if (err != E_OK || access(dbPath.c_str(), F_OK) != E_OK) {
        return { E_INVALID_FILE_PATH, 0 };
    }

    // encrypted databases are not supported to attach a non encrypted database.
    if (!config.IsEncrypt() && isEncrypt_) {
        return { E_NOT_SUPPORTED, 0 };
    }

    if (attachedInfo_.Contains(attachName)) {
        return { E_ATTACHED_DATABASE_EXIST, 0 };
    }

    std::vector<uint8_t> key;
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    if (config.IsEncrypt()) {
        RdbPassword rdbPwd =
            RdbSecurityManager::GetInstance().GetRdbPassword(dbPath, RdbSecurityManager::KeyFileType::PUB_KEY_FILE);
        key = std::vector<uint8_t>(rdbPwd.GetData(), rdbPwd.GetData() + rdbPwd.GetSize());
    }
#endif
    err = AttachInner(attachName, dbPath, key, waitTime);
    if (err == SQLITE_ERROR) {
        // only when attachName is already in use, SQLITE-ERROR will be reported here.
        return { E_ATTACHED_DATABASE_EXIST, 0 };
    } else if (err != E_OK) {
        LOG_ERROR("failed, errCode[%{public}d] fileName[%{public}s] attachName[%{public}s] attach fileName"
                  "[%{public}s]",
            err, config_.GetName().c_str(), attachName.c_str(), config.GetName().c_str());
        return { err, 0 };
    }
    if (!attachedInfo_.Insert(attachName, dbPath)) {
        return { E_ATTACHED_DATABASE_EXIST, 0 };
    }
    return { E_OK, attachedInfo_.Size() };
}

std::pair<int32_t, int32_t> RdbStoreImpl::Detach(const std::string &attachName, int32_t waitTime)
{
    if (config_.GetRoleType() == VISITOR) {
        return { E_NOT_SUPPORT, 0 };
    }
    if (!attachedInfo_.Contains(attachName)) {
        return { E_OK, attachedInfo_.Size() };
    }

    auto [connection, readers] = connectionPool_->AcquireAll(waitTime);
    if (connection == nullptr) {
        return { E_DATABASE_BUSY, 0 };
    }
    std::vector<ValueObject> bindArgs;
    bindArgs.push_back(ValueObject(attachName));

    auto [errCode, statement] = connection->CreateStatement(GlobalExpr::DETACH_SQL, connection);
    if (statement == nullptr || errCode != E_OK) {
        LOG_ERROR("Detach get statement failed, errCode %{public}d", errCode);
        return { errCode, 0 };
    }
    errCode = statement->Execute(bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("failed, errCode[%{public}d] fileName[%{public}s] attachName[%{public}s] attach", errCode,
            config_.GetName().c_str(), attachName.c_str());
        return { errCode, 0 };
    }

    attachedInfo_.Erase(attachName);
    if (!attachedInfo_.Empty()) {
        return { E_OK, attachedInfo_.Size() };
    }
    statement = nullptr;
    // close first to prevent the connection from being put back.
    connectionPool_->CloseAllConnections();
    connection = nullptr;
    readers.clear();
    errCode = connectionPool_->EnableWal();
    return { errCode, 0 };
}

/**
 * Obtains the database version.
 */
int RdbStoreImpl::GetVersion(int &version)
{
    auto [errCode, statement] = GetStatement(GlobalExpr::PRAGMA_VERSION, config_.GetRoleType() == VISITOR);
    if (statement == nullptr) {
        return E_CON_OVER_LIMIT;
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
    if (config_.GetRoleType() == VISITOR) {
        return E_NOT_SUPPORT;
    }

    std::string sql = std::string(GlobalExpr::PRAGMA_VERSION) + " = " + std::to_string(version);
    auto [errCode, statement] = GetStatement(sql);
    if (statement == nullptr) {
        return E_CON_OVER_LIMIT;
    }
    return statement->Execute();
}
/**
 * Begins a transaction in EXCLUSIVE mode.
 */
int RdbStoreImpl::BeginTransaction()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::lock_guard<std::mutex> lockGuard(connectionPool_->GetTransactionStackMutex());
    if (config_.GetRoleType() == VISITOR) {
        return E_NOT_SUPPORT;
    }
    // size + 1 means the number of transactions in process
    size_t transactionId = connectionPool_->GetTransactionStack().size() + 1;
    BaseTransaction transaction(connectionPool_->GetTransactionStack().size());
    auto [errCode, statement] = GetStatement(transaction.GetTransactionStr());
    if (statement == nullptr) {
        return E_CON_OVER_LIMIT;
    }
    errCode = statement->Execute();
    if (errCode != E_OK) {
        LOG_ERROR("transaction id: %{public}zu, storeName: %{public}s, errCode: %{public}d",
            transactionId, name_.c_str(), errCode);

        return errCode;
    }
    connectionPool_->SetInTransaction(true);
    connectionPool_->GetTransactionStack().push(transaction);
    // 1 means the number of transactions in process
    if (transactionId > 1) {
        LOG_WARN("transaction id: %{public}zu, storeName: %{public}s, errCode: %{public}d",
            transactionId, name_.c_str(), errCode);
    }

    return E_OK;
}

std::pair<int, int64_t> RdbStoreImpl::BeginTrans()
{
    return { E_NOT_SUPPORT, 0 };
}

/**
* Begins a transaction in EXCLUSIVE mode.
*/
int RdbStoreImpl::RollBack()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::lock_guard<std::mutex> lockGuard(connectionPool_->GetTransactionStackMutex());
    if (config_.GetRoleType() == VISITOR) {
        return E_NOT_SUPPORT;
    }
    size_t transactionId = connectionPool_->GetTransactionStack().size();

    if (connectionPool_->GetTransactionStack().empty()) {
        LOG_ERROR("transaction id: %{public}zu, storeName: %{public}s", transactionId, name_.c_str());
        return E_NO_TRANSACTION_IN_SESSION;
    }
    BaseTransaction transaction = connectionPool_->GetTransactionStack().top();
    connectionPool_->GetTransactionStack().pop();
    if (transaction.GetType() != TransType::ROLLBACK_SELF && !connectionPool_->GetTransactionStack().empty()) {
        connectionPool_->GetTransactionStack().top().SetChildFailure(true);
    }
    auto [errCode, statement] = GetStatement(transaction.GetRollbackStr());
    if (statement == nullptr) {
        // size + 1 means the number of transactions in process
        LOG_ERROR("transaction id: %{public}zu, storeName: %{public}s", transactionId + 1, name_.c_str());
        return E_DATABASE_BUSY;
    }
    errCode = statement->Execute();
    if (connectionPool_->GetTransactionStack().empty()) {
        connectionPool_->SetInTransaction(false);
    }
    // 1 means the number of transactions in process
    if (transactionId > 1) {
        LOG_WARN("transaction id: %{public}zu, storeName: %{public}s, errCode: %{public}d",
            transactionId, name_.c_str(), errCode);
    }
    return E_OK;
}

int RdbStoreImpl::RollBack(int64_t trxId)
{
    (void)trxId;
    return E_NOT_SUPPORT;
}

/**
* Begins a transaction in EXCLUSIVE mode.
*/
int RdbStoreImpl::Commit()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::lock_guard<std::mutex> lockGuard(connectionPool_->GetTransactionStackMutex());
    if (config_.GetRoleType() == VISITOR) {
        return E_NOT_SUPPORT;
    }
    size_t transactionId = connectionPool_->GetTransactionStack().size();

    if (connectionPool_->GetTransactionStack().empty()) {
        LOG_ERROR("transaction id: %{public}zu, storeName: %{public}s", transactionId, name_.c_str());
        return E_OK;
    }
    BaseTransaction transaction = connectionPool_->GetTransactionStack().top();
    std::string sqlStr = transaction.GetCommitStr();
    if (sqlStr.size() <= 1) {
        LOG_INFO("transaction id: %{public}zu, storeName: %{public}s", transactionId, name_.c_str());
        connectionPool_->GetTransactionStack().pop();
        return E_OK;
    }
    auto [errCode, statement] = GetStatement(sqlStr);
    if (statement == nullptr) {
        LOG_ERROR("transaction id: %{public}zu, storeName: %{public}s", transactionId, name_.c_str());
        return E_DATABASE_BUSY;
    }
    errCode = statement->Execute();
    connectionPool_->SetInTransaction(false);
    // 1 means the number of transactions in process
    if (transactionId > 1) {
        LOG_WARN("transaction id: %{public}zu, storeName: %{public}s, errCode: %{public}d",
            transactionId, name_.c_str(), errCode);
    }
    connectionPool_->GetTransactionStack().pop();
    return E_OK;
}

int RdbStoreImpl::Commit(int64_t trxId)
{
    (void)trxId;
    return E_NOT_SUPPORT;
}

bool RdbStoreImpl::IsInTransaction()
{
    if (config_.GetRoleType() == VISITOR) {
        return false;
    }
    return connectionPool_->IsInTransaction();
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

    auto [errCode, statement] = GetStatement(GlobalExpr::PRAGMA_JOUR_MODE_EXP);
    if (statement == nullptr) {
        return E_CON_OVER_LIMIT;
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
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    {
        std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
        if (cloudTables_.empty() || (!table.empty() && cloudTables_.find(table) == cloudTables_.end())) {
            return;
        }
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (syncTables_ == nullptr) {
            syncTables_ = std::make_shared<std::set<std::string>>();
        }
        auto empty = syncTables_->empty();
        if (table.empty()) {
            syncTables_->insert(cloudTables_.begin(), cloudTables_.end());
        } else {
            syncTables_->insert(table);
        }
        if (!empty) {
            return;
        }
    }
    if (pool_ == nullptr) {
        return;
    }
    auto interval =
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::milliseconds(INTERVAL));
    pool_->Schedule(interval, [this]() {
        std::shared_ptr<std::set<std::string>> ptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ptr = syncTables_;
            syncTables_ = nullptr;
        }
        if (ptr == nullptr) {
            return;
        }
        DistributedRdb::RdbService::Option option = { DistributedRdb::TIME_FIRST, 0, true, true };
        InnerSync(option,
            AbsRdbPredicates(std::vector<std::string>(ptr->begin(), ptr->end())).GetDistributedPredicates(), nullptr);
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
        return E_ERROR;
    }

    if (connectionPool_ == nullptr) {
        LOG_ERROR("connectionPool_ is null");
        return E_ERROR;
    }
    return connectionPool_->ConfigLocale(localeStr);
}

int RdbStoreImpl::Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey)
{
    if (!isOpen_) {
        LOG_ERROR("The connection pool has been closed.");
        return E_ERROR;
    }

    if (connectionPool_ == nullptr) {
        LOG_ERROR("The connectionPool_ is null.");
        return E_ERROR;
    }

    std::string backupFilePath;
    int ret = GetDataBasePath(backupPath, backupFilePath);
    if (ret != E_OK) {
        return ret;
    }

    if (access(backupFilePath.c_str(), F_OK) != E_OK) {
        LOG_ERROR("The backupFilePath does not exists.");
        return E_INVALID_FILE_PATH;
    }

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    auto [err, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
    if (service != nullptr) {
        service->Disable(syncerParam_);
    }
#endif
    int errCode = connectionPool_->ChangeDbFileForRestore(path_, backupFilePath, newKey);
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    SecurityPolicy::SetSecurityLabel(config_);
    if (service != nullptr) {
        service->Enable(syncerParam_);
        return errCode;
    }
#endif
    return errCode;
}

/**
 * Queries data in the database based on specified conditions.
 */
std::shared_ptr<ResultSet> RdbStoreImpl::QueryByStep(const std::string &sql,
    const std::vector<std::string> &sqlArgs)
{
    std::vector<ValueObject> bindArgs;
    std::for_each(sqlArgs.begin(), sqlArgs.end(), [&bindArgs](const auto &it) { bindArgs.push_back(ValueObject(it)); });
    return std::make_shared<StepResultSet>(connectionPool_, sql, bindArgs);
}

std::shared_ptr<ResultSet> RdbStoreImpl::QueryByStep(const std::string &sql, const std::vector<ValueObject> &args)
{
    return std::make_shared<StepResultSet>(connectionPool_, sql, args);
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
int RdbStoreImpl::SetDistributedTables(const std::vector<std::string> &tables, int32_t type,
    const DistributedRdb::DistributedConfig &distributedConfig)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (tables.empty()) {
        LOG_WARN("The distributed tables to be set is empty.");
        return E_OK;
    }
    auto [errCode, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(syncerParam_);
    if (errCode != E_OK) {
        return errCode;
    }
    int32_t errorCode = service->SetDistributedTables(syncerParam_, tables, distributedConfig.references, type);
    if (errorCode != E_OK) {
        LOG_ERROR("Fail to set distributed tables, error=%{public}d", errorCode);
        return errorCode;
    }
    if (type != DistributedRdb::DISTRIBUTED_CLOUD || !distributedConfig.autoSync) {
        return E_OK;
    }
    {
        std::unique_lock<decltype(rwMutex_)> lock(rwMutex_);
        cloudTables_.insert(tables.begin(), tables.end());
    }
    return E_OK;
}

std::string RdbStoreImpl::ObtainDistributedTableName(const std::string &device, const std::string &table, int &errCode)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));

    std::string uuid;
    DeviceManagerAdaptor::RdbDeviceManagerAdaptor &deviceManager =
        DeviceManagerAdaptor::RdbDeviceManagerAdaptor::GetInstance(syncerParam_.bundleName_);
    errCode = deviceManager.GetEncryptedUuidByNetworkId(device, uuid);
    if (errCode != E_OK) {
        LOG_ERROR("GetUuid is failed");
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
    DistributedRdb::RdbService::Option rdbOption;
    rdbOption.mode = option.mode;
    rdbOption.isAsync = !option.isBlock;
    return InnerSync(rdbOption, predicate.GetDistributedPredicates(), async);
}

int RdbStoreImpl::InnerSync(const DistributedRdb::RdbService::Option &option,
    const DistributedRdb::PredicatesMemo &predicates, const RdbStore::AsyncDetail &async)
{
    auto [errCode, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(syncerParam_);
    if (errCode != E_OK) {
        LOG_ERROR("GetRdbService is failed, err is %{public}d.", errCode);
        return errCode;
    }
    errCode = service->Sync(syncerParam_, option, predicates, async);
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

int RdbStoreImpl::SubscribeLocal(const SubscribeOption& option, RdbStoreObserver *observer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    localObservers_.try_emplace(option.event);
    auto &list = localObservers_.find(option.event)->second;
    for (auto it = list.begin(); it != list.end(); it++) {
        if ((*it)->getObserver() == observer) {
            LOG_ERROR("duplicate subscribe");
            return E_OK;
        }
    }

    localObservers_[option.event].push_back(std::make_shared<RdbStoreLocalObserver>(observer));
    return E_OK;
}

int RdbStoreImpl::SubscribeLocalShared(const SubscribeOption& option, RdbStoreObserver *observer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    localSharedObservers_.try_emplace(option.event);
    auto &list = localSharedObservers_.find(option.event)->second;
    for (auto it = list.begin(); it != list.end(); it++) {
        if ((*it)->getObserver() == observer) {
            LOG_ERROR("duplicate subscribe");
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

int32_t RdbStoreImpl::SubscribeLocalDetail(const SubscribeOption &option,
    const std::shared_ptr<RdbStoreObserver> &observer)
{
    auto connection = connectionPool_->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }
    int32_t errCode = connection->Subscribe(option.event, observer);
    if (errCode != E_OK) {
        LOG_ERROR("subscribe local detail observer failed. db name:%{public}s errCode:%{public}" PRId32,
            config_.GetName().c_str(), errCode);
    }
    return errCode;
}

int RdbStoreImpl::SubscribeRemote(const SubscribeOption& option, RdbStoreObserver *observer)
{
    auto [errCode, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(syncerParam_);
    if (errCode != E_OK) {
        return errCode;
    }
    return service->Subscribe(syncerParam_, option, observer);
}

int RdbStoreImpl::Subscribe(const SubscribeOption &option, RdbStoreObserver *observer)
{
    if (option.mode == SubscribeMode::LOCAL) {
        return SubscribeLocal(option, observer);
    }
    if (option.mode == SubscribeMode::LOCAL_SHARED) {
        return SubscribeLocalShared(option, observer);
    }
    return SubscribeRemote(option, observer);
}

int RdbStoreImpl::UnSubscribeLocal(const SubscribeOption& option, RdbStoreObserver *observer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto obs = localObservers_.find(option.event);
    if (obs == localObservers_.end()) {
        return E_OK;
    }

    auto &list = obs->second;
    for (auto it = list.begin(); it != list.end(); it++) {
        if ((*it)->getObserver() == observer) {
            it = list.erase(it);
            break;
        }
    }

    if (list.empty()) {
        localObservers_.erase(option.event);
    }
    return E_OK;
}

int RdbStoreImpl::UnSubscribeLocalAll(const SubscribeOption& option)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto obs = localObservers_.find(option.event);
    if (obs == localObservers_.end()) {
        return E_OK;
    }

    localObservers_.erase(option.event);
    return E_OK;
}

int RdbStoreImpl::UnSubscribeLocalShared(const SubscribeOption& option, RdbStoreObserver *observer)
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
    for (auto it = list.begin(); it != list.end(); it++) {
        if ((*it)->getObserver() == observer) {
            int32_t err = client->UnregisterObserver(GetUri(option.event), *it);
            if (err != 0) {
                LOG_ERROR("UnSubscribeLocalShared failed.");
                return err;
            }
            list.erase(it);
            break;
        }
    }
    if (list.empty()) {
        localSharedObservers_.erase(option.event);
    }
    return E_OK;
}

int RdbStoreImpl::UnSubscribeLocalSharedAll(const SubscribeOption& option)
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
    auto it = list.begin();
    while (it != list.end()) {
        int32_t err = client->UnregisterObserver(GetUri(option.event), *it);
        if (err != 0) {
            LOG_ERROR("UnSubscribe failed.");
            return err;
        }
        it = list.erase(it);
    }

    localSharedObservers_.erase(option.event);
    return E_OK;
}

int32_t RdbStoreImpl::UnsubscribeLocalDetail(const SubscribeOption& option,
    const std::shared_ptr<RdbStoreObserver> &observer)
{
    auto connection = connectionPool_->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }
    int32_t errCode = connection->Unsubscribe(option.event, observer);
    if (errCode != E_OK) {
        LOG_ERROR("unsubscribe local detail observer failed. db name:%{public}s errCode:%{public}" PRId32,
            config_.GetName().c_str(), errCode);
    }
    return errCode;
}

int RdbStoreImpl::UnSubscribeRemote(const SubscribeOption& option, RdbStoreObserver *observer)
{
    auto [errCode, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(syncerParam_);
    if (errCode != E_OK) {
        return errCode;
    }
    return service->UnSubscribe(syncerParam_, option, observer);
}

int RdbStoreImpl::UnSubscribe(const SubscribeOption &option, RdbStoreObserver *observer)
{
    if (option.mode == SubscribeMode::LOCAL && observer) {
        return UnSubscribeLocal(option, observer);
    } else if (option.mode == SubscribeMode::LOCAL && !observer) {
        return UnSubscribeLocalAll(option);
    } else if (option.mode == SubscribeMode::LOCAL_SHARED && observer) {
        return UnSubscribeLocalShared(option, observer);
    } else if (option.mode == SubscribeMode::LOCAL_SHARED && !observer) {
        return UnSubscribeLocalSharedAll(option);
    }
    return UnSubscribeRemote(option, observer);
}

int RdbStoreImpl::SubscribeObserver(const SubscribeOption& option, const std::shared_ptr<RdbStoreObserver> &observer)
{
    return SubscribeLocalDetail(option, observer);
}

int RdbStoreImpl::UnsubscribeObserver(const SubscribeOption& option, const std::shared_ptr<RdbStoreObserver> &observer)
{
    return UnsubscribeLocalDetail(option, observer);
}

int RdbStoreImpl::Notify(const std::string &event)
{
    auto client = OHOS::AAFwk::DataObsMgrClient::GetInstance();
    if (client == nullptr) {
        LOG_ERROR("Failed to get DataObsMgrClient.");
        return E_GET_DATAOBSMGRCLIENT_FAIL;
    }
    int32_t err = client->NotifyChange(GetUri(event));
    if (err != 0) {
        LOG_ERROR("Notify failed.");
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto obs = localObservers_.find(event);
    if (obs != localObservers_.end()) {
        auto &list = obs->second;
        for (auto &it : list) {
            it->OnChange();
        }
    }
    return E_OK;
}

int RdbStoreImpl::RegisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer)
{
    auto [errCode, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(syncerParam_);
    if (errCode != E_OK) {
        return errCode;
    }
    return service->RegisterAutoSyncCallback(syncerParam_, observer);
}

int RdbStoreImpl::UnregisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer)
{
    auto [errCode, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(syncerParam_);
    if (errCode != E_OK) {
        return errCode;
    }
    return service->UnregisterAutoSyncCallback(syncerParam_, observer);
}

void RdbStoreImpl::InitDelayNotifier()
{
    if (delayNotifier_ == nullptr) {
        delayNotifier_ = std::make_shared<DelayNotify>();
    }
    if (delayNotifier_ == nullptr) {
        LOG_ERROR("Init delay notifier failed");
        return;
    }
    delayNotifier_->SetExecutorPool(pool_);
    delayNotifier_->SetTask([param = syncerParam_](const DistributedRdb::RdbChangedData& rdbChangedData) -> int {
        auto [errCode, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(param);
        if (errCode != E_OK || service == nullptr) {
            LOG_ERROR("GetRdbService is failed, err is %{public}d.", errCode);
            return errCode;
        }
        return service->NotifyDataChange(param, rdbChangedData);
    });
}

int RdbStoreImpl::RegisterDataChangeCallback()
{
    if (!config_.IsSearchable()) {
        return E_OK;
    }
    if (config_.GetRoleType() == VISITOR) {
        return E_NOT_SUPPORT;
    }
    InitDelayNotifier();
    auto callBack = [delayNotifier = delayNotifier_](const std::set<std::string> &tables) {
        DistributedRdb::RdbChangedData rdbChangedData;
        for (const auto& table : tables) {
            rdbChangedData.tableData[table].isTrackedDataChange = true;
        }
        if (delayNotifier != nullptr) {
            delayNotifier->UpdateNotify(rdbChangedData);
        }
    };
    auto connection = connectionPool_->AcquireConnection(false);
    if (connection == nullptr) {
        return E_DATABASE_BUSY;
    }
    return connection->SubscribeTableChanges(callBack);
}

bool RdbStoreImpl::ColHasSpecificField(const std::vector<std::string> &columns)
{
    for (const std::string &column : columns) {
        if (column.find(SqliteUtils::REP) != std::string::npos) {
            return true;
        }
    }
    return false;
}

int RdbStoreImpl::GetHashKeyForLockRow(const AbsRdbPredicates &predicates, std::vector<std::vector<uint8_t>> &hashKeys)
{
    std::string table = predicates.GetTableName();
    if (table.empty()) {
        return E_EMPTY_TABLE_NAME;
    }
    auto logTable = DistributedDB::RelationalStoreManager::GetDistributedLogTableName(table);
    std::string sql;
    sql.append("SELECT ").append(logTable).append(".hash_key ").append("FROM ").append(logTable);
    sql.append(" INNER JOIN ").append(table).append(" ON ");
    sql.append(table).append(".ROWID = ").append(logTable).append(".data_key");
    auto whereClause = predicates.GetWhereClause();
    if (!whereClause.empty()) {
        SqliteUtils::Replace(whereClause, SqliteUtils::REP, logTable + ".");
        sql.append(" WHERE ").append(whereClause);
    }

    auto result = QuerySql(sql, predicates.GetBindArgs());
    if (result == nullptr) {
        return E_ERROR;
    }
    int count = 0;
    if (result->GetRowCount(count) != E_OK) {
        return E_ERROR;
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
    std::vector<std::vector<uint8_t>> hashKeys;
    int ret = GetHashKeyForLockRow(predicates, hashKeys);
    if (ret != E_OK) {
        LOG_ERROR("GetHashKeyForLockRow failed, err is %{public}d.", ret);
        return ret;
    }
    auto [err, statement] = GetStatement(GlobalExpr::PRAGMA_VERSION);
    if (statement == nullptr || err != E_OK) {
        return err;
    }
    int errCode = statement->ModifyLockStatus(predicates.GetTableName(), hashKeys, isLock);
    if (errCode == E_WAIT_COMPENSATED_SYNC) {
        LOG_DEBUG("Start compensation sync.");
        DistributedRdb::RdbService::Option option = { DistributedRdb::TIME_FIRST, 0, true, true, true };
        InnerSync(option, AbsRdbPredicates(predicates.GetTableName()).GetDistributedPredicates(), nullptr);
        return E_OK;
    }
    if (errCode != E_OK) {
        LOG_ERROR("ModifyLockStatus failed, err is %{public}d.", errCode);
    }
    return errCode;
}
#endif

std::pair<int32_t, std::shared_ptr<Statement>> RdbStoreImpl::GetStatement(
    const std::string &sql, std::shared_ptr<Connection> conn) const
{
    if (conn == nullptr) {
        return { E_CON_OVER_LIMIT, nullptr };
    }
    return conn->CreateStatement(sql, conn);
}

std::pair<int32_t, std::shared_ptr<Statement>> RdbStoreImpl::GetStatement(const std::string& sql, bool read) const
{
    auto conn = connectionPool_->AcquireConnection(read);
    if (conn == nullptr) {
        return { E_CON_OVER_LIMIT, nullptr };
    }
    return conn->CreateStatement(sql, conn);
}

int RdbStoreImpl::GetRebuilt(RebuiltType &rebuilt)
{
    rebuilt = static_cast<RebuiltType>(rebuild_);
    return E_OK;
}
} // namespace OHOS::NativeRdb