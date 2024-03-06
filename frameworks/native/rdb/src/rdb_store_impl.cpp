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

#include "rdb_store_impl.h"

#include <unistd.h>

#include <algorithm>
#include <sstream>
#include <chrono>
#include <cinttypes>
#include "logger.h"
#include "cache_result_set.h"
#include "rdb_errno.h"
#include "rdb_sql_utils.h"
#include "rdb_store.h"
#include "rdb_trace.h"
#include "sqlite_global_config.h"
#include "sqlite_sql_builder.h"
#include "sqlite_utils.h"
#include "step_result_set.h"
#include "task_executor.h"
#include "traits.h"

#ifndef WINDOWS_PLATFORM
#include "directory_ex.h"
#endif

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include <sys/syscall.h>
#include "delay_notify.h"
#include "iresult_set.h"
#include "raw_data_parser.h"
#include "rdb_device_manager_adapter.h"
#include "rdb_manager_impl.h"
#include "relational_store_manager.h"
#include "rdb_security_manager.h"
#include "result_set_proxy.h"
#include "runtime_config.h"
#include "sqlite_shared_result_set.h"
#include "sqlite_connection.h"
#include "relational_store_client.h"
#endif

#ifdef WINDOWS_PLATFORM
#define ISFILE(filePath) ((filePath.find("\\") == std::string::npos))
#else
#define ISFILE(filePath) ((filePath.find("/") == std::string::npos))
#endif

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
using namespace std::chrono;
int RdbStoreImpl::InnerOpen()
{
    LOG_DEBUG("open %{public}s.", SqliteUtils::Anonymous(rdbStoreConfig.GetPath()).c_str());
    int errCode = E_OK;
    connectionPool = SqliteConnectionPool::Create(rdbStoreConfig, errCode);
    if (connectionPool == nullptr) {
        return errCode;
    }
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    syncerParam_.bundleName_ = rdbStoreConfig.GetBundleName();
    syncerParam_.hapName_ = rdbStoreConfig.GetModuleName();
    syncerParam_.storeName_ = rdbStoreConfig.GetName();
    syncerParam_.customDir_ = rdbStoreConfig.GetCustomDir();
    syncerParam_.area_ = rdbStoreConfig.GetArea();
    syncerParam_.level_ = static_cast<int32_t>(rdbStoreConfig.GetSecurityLevel());
    syncerParam_.type_ = rdbStoreConfig.GetDistributedType();
    syncerParam_.isEncrypt_ = rdbStoreConfig.IsEncrypt();
    syncerParam_.isAutoClean_ = rdbStoreConfig.GetAutoClean();
    syncerParam_.isSearchable_ = rdbStoreConfig.IsSearchable();
    syncerParam_.password_ = {};
    GetSchema(rdbStoreConfig);

    errCode = RegisterDataChangeCallback();
    if (errCode != E_OK) {
        LOG_ERROR("RegisterCallBackObserver is failed, err is %{public}d.", errCode);
    }
#endif
    return E_OK;
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
void RdbStoreImpl::GetSchema(const RdbStoreConfig &config)
{
    std::vector<uint8_t> key = config.GetEncryptKey();
    RdbPassword rdbPwd;
    if (config.IsEncrypt()) {
        auto ret = RdbSecurityManager::GetInstance().Init(config.GetBundleName());
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
    if (pool_ == nullptr) {
        pool_ = TaskExecutor::GetInstance().GetExecutor();
    }
    if (pool_ != nullptr) {
        auto param = syncerParam_;
        pool_->Execute([param]() {
            auto [err, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(param);
            if (err != E_OK || service == nullptr) {
                LOG_DEBUG("GetRdbService failed, err is %{public}d.", err);
                return;
            }
            err = service->GetSchema(param);
            if (err != E_OK) {
                LOG_ERROR("GetSchema failed, err is %{public}d.", err);
            }
        });
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
    sql.append(GetSqlArgs(hashKeys.size()));
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
    sql.append(GetSqlArgs(keys.size()));
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
    if (table.empty()) {
        return E_INVALID_ARGS;
    }
    auto connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }
    int errCode = connection->CleanDirtyData(table, cursor);
    connectionPool->ReleaseConnection(connection);
    return errCode;
}

#endif

std::string RdbStoreImpl::GetSqlArgs(size_t size)
{
    std::string args((size << 1) - 1, '?');
    for (size_t i = 1; i < size; ++i) {
        args[(i << 1) - 1] = ',';
    }
    return args;
}

RdbStoreImpl::RdbStoreImpl(const RdbStoreConfig &config, int &errCode)
    : rdbStoreConfig(config), connectionPool(nullptr), isOpen(true), path(config.GetPath()), orgPath(config.GetPath()),
      isReadOnly(config.IsReadOnly()), isMemoryRdb(config.IsMemoryRdb()), name(config.GetName()),
      fileType(config.GetDatabaseFileType()), isEncrypt_(config.IsEncrypt())
{
    errCode = InnerOpen();
    if (errCode != E_OK) {
        LOG_ERROR("RdbStoreManager GetRdbStore fail to open RdbStore, err is %{public}d", errCode);
        if (connectionPool) {
            delete connectionPool;
            connectionPool = nullptr;
        }
        isOpen = false;
    }
}

RdbStoreImpl::~RdbStoreImpl()
{
    LOG_DEBUG("destroy.");
    if (connectionPool) {
        delete connectionPool;
        connectionPool = nullptr;
    }
}

#ifdef WINDOWS_PLATFORM
void RdbStoreImpl::Clear()
{
    delete connectionPool;
    connectionPool = nullptr;
}
#endif

const RdbStoreConfig &RdbStoreImpl::GetConfig()
{
    return rdbStoreConfig;
}
int RdbStoreImpl::Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    return InsertWithConflictResolution(outRowId, table, initialValues, ConflictResolution::ON_CONFLICT_NONE);
}

int RdbStoreImpl::BatchInsert(int64_t &outInsertNum, const std::string &table,
    const std::vector<ValuesBucket> &initialBatchValues)
{
    if (initialBatchValues.empty()) {
        outInsertNum = 0;
        return E_OK;
    }
    auto connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }
    auto executeSqlArgs = GenerateSql(table, initialBatchValues, connection->GetMaxVariableNumber());
    if (executeSqlArgs.empty()) {
        connectionPool->ReleaseConnection(connection);
        LOG_ERROR("empty, table=%{public}s, values:%{public}zu, max number:%{public}d.", table.c_str(),
            initialBatchValues.size(), connection->GetMaxVariableNumber());
        return E_INVALID_ARGS;
    }
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    if (delayNotifier_ != nullptr) {
        delayNotifier_->SetAutoSyncInterval(AUTO_SYNC_MAX_INTERVAL);
    }
#endif
    for (const auto &[sql, bindArgs] : executeSqlArgs) {
        for (const auto &args : bindArgs) {
            auto errCode = connection->ExecuteSql(sql, args);
            if (errCode != E_OK) {
                outInsertNum = -1;
                connectionPool->ReleaseConnection(connection);
                LOG_ERROR("BatchInsert failed, errCode : %{public}d, bindArgs : %{public}zu,"
                    "table : %{public}s, sql : %{public}s", errCode, bindArgs.size(), table.c_str(), sql.c_str());
                return E_OK;
            }
        }
    }
    outInsertNum = initialBatchValues.size();
    connectionPool->ReleaseConnection(connection);
    DoCloudSync(table);
    return E_OK;
}

RdbStoreImpl::ExecuteSqls RdbStoreImpl::GenerateSql(
    const std::string &table, const std::vector<ValuesBucket> &initialBatchValues, int limitVariableNumber)
{
    std::vector<std::vector<ValueObject>> values;
    std::map<std::string, uint32_t> fields;
    int32_t valuePosition = 0;
    for (size_t row = 0; row < initialBatchValues.size(); row++) {
        auto &vBucket = initialBatchValues[row];
        if (values.max_size() == 0) {
            values.reserve(vBucket.values_.size() * EXPANSION);
        }
        for (auto &[key, value] : vBucket.values_) {
            if (value.GetType() == ValueObject::TYPE_ASSET ||
                value.GetType() == ValueObject::TYPE_ASSETS) {
                SetAssetStatus(value, AssetValue::STATUS_INSERT);
            }
            int32_t col = 0;
            auto it = fields.find(key);
            if (it == fields.end()) {
                values.emplace_back(std::vector<ValueObject>(initialBatchValues.size()));
                col = valuePosition;
                fields.insert(std::pair{key, col});
                valuePosition++;
            } else {
                col = it->second;
            }
            values[col][row] = value;
        }
    }

    std::string sql = "INSERT OR REPLACE INTO " + table + " (";
    std::vector<ValueObject> args(initialBatchValues.size() * values.size());
    int32_t col = 0;
    for (auto &[key, pos] : fields) {
        for (size_t row = 0; row < initialBatchValues.size(); ++row) {
            args[col + row * fields.size()] = std::move(values[pos][row]);
        }
        col++;
        sql.append(key).append(",");
    }
    sql.pop_back();
    sql.append(") VALUES ");
    return MakeExecuteSqls(sql, args, fields.size(), limitVariableNumber);
}

RdbStoreImpl::ExecuteSqls RdbStoreImpl::MakeExecuteSqls(
    const std::string &sql, const std::vector<ValueObject> &args, int fieldSize, int limitVariableNumber)
{
    if (fieldSize == 0) {
        return ExecuteSqls();
    }
    size_t rowNumbers = args.size() / fieldSize;
    size_t maxRowNumbersOneTimes = limitVariableNumber / fieldSize;
    size_t executeTimes = rowNumbers / maxRowNumbersOneTimes;
    size_t remainingRows = rowNumbers % maxRowNumbersOneTimes;
    LOG_DEBUG("rowNumbers %{public}zu, maxRowNumbersOneTimes %{public}zu, executeTimes %{public}zu,"
        "remainingRows %{public}zu, fieldSize %{public}d, limitVariableNumber %{public}d",
        rowNumbers, maxRowNumbersOneTimes, executeTimes, remainingRows, fieldSize, limitVariableNumber);
    std::string singleRowSqlArgs = "(" + GetSqlArgs(fieldSize) + ")";
    auto appendAgsSql = [&singleRowSqlArgs, &sql] (size_t rowNumber) {
        std::string sqlStr = sql;
        for (size_t i = 0; i < rowNumber; ++i) {
            sqlStr.append(singleRowSqlArgs).append(",");
        }
        sqlStr.pop_back();
        return sqlStr;
    };
    std::string executeSql;
    ExecuteSqls executeSqls;
    auto start = args.begin();
    if (executeTimes != 0) {
        executeSql = appendAgsSql(maxRowNumbersOneTimes);
        std::vector<std::vector<ValueObject>> sqlArgs;
        size_t maxVariableNumbers = maxRowNumbersOneTimes * fieldSize;
        for (size_t i = 0; i < executeTimes; ++i) {
            std::vector<ValueObject> bindValueArgs(start, start + maxVariableNumbers);
            sqlArgs.emplace_back(std::move(bindValueArgs));
            start += maxVariableNumbers;
        }
        executeSqls.emplace_back(std::make_pair(executeSql, std::move(sqlArgs)));
    }

    if (remainingRows != 0) {
        executeSql = appendAgsSql(remainingRows);
        std::vector<std::vector<ValueObject>> sqlArgs(1, std::vector<ValueObject>(start, args.end()));
        executeSqls.emplace_back(std::make_pair(executeSql, std::move(sqlArgs)));
    }
    return executeSqls;
}

int RdbStoreImpl::Replace(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues)
{
    return InsertWithConflictResolution(outRowId, table, initialValues, ConflictResolution::ON_CONFLICT_REPLACE);
}

int RdbStoreImpl::InsertWithConflictResolution(int64_t &outRowId, const std::string &table,
    const ValuesBucket &initialValues, ConflictResolution conflictResolution)
{
    if (table.empty()) {
        return E_EMPTY_TABLE_NAME;
    }

    if (initialValues.IsEmpty()) {
        return E_EMPTY_VALUES_BUCKET;
    }

    std::string conflictClause;
    int errCode = SqliteUtils::GetConflictClause(static_cast<int>(conflictResolution), conflictClause);
    if (errCode != E_OK) {
        return errCode;
    }

    std::string sql;
    sql.append("INSERT").append(conflictClause).append(" INTO ").append(table).append("(");
    size_t bindArgsSize = initialValues.values_.size();
    std::vector<ValueObject> bindArgs;
    bindArgs.reserve(bindArgsSize);
    const char *split = "";
    for (const auto &[key, val] : initialValues.values_) {
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
        sql.append(GetSqlArgs(bindArgsSize));
    }

    sql.append(")");
    auto connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    errCode = connection->ExecuteForLastInsertedRowId(outRowId, sql, bindArgs);
    connectionPool->ReleaseConnection(connection);
    if (errCode == E_OK) {
        DoCloudSync(table);
    }
    return errCode;
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
    return UpdateWithConflictResolution(
        changedRows, table, values, whereClause, bindArgs, conflictResolution);
}

int RdbStoreImpl::UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
    const std::string &whereClause, const std::vector<ValueObject> &bindArgs, ConflictResolution conflictResolution)
{
    if (table.empty()) {
        return E_EMPTY_TABLE_NAME;
    }

    if (values.IsEmpty()) {
        return E_EMPTY_VALUES_BUCKET;
    }

    std::string conflictClause;
    int errCode = SqliteUtils::GetConflictClause(static_cast<int>(conflictResolution), conflictClause);
    if (errCode != E_OK) {
        return errCode;
    }

    std::string sql;
    sql.append("UPDATE").append(conflictClause).append(" ").append(table).append(" SET ");
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
        tmpBindArgs.push_back(val);  // columnValue
        split = ",";
    }

    if (!whereClause.empty()) {
        sql.append(" WHERE ").append(whereClause);
    }

    tmpBindArgs.insert(tmpBindArgs.end(), bindArgs.begin(), bindArgs.end());

    auto connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    errCode = connection->ExecuteForChangedRowCount(changedRows, sql, tmpBindArgs);
    connectionPool->ReleaseConnection(connection);
    if (errCode == E_OK) {
        DoCloudSync(table);
    }
    return errCode;
}

int RdbStoreImpl::Delete(int &deletedRows, const AbsRdbPredicates &predicates)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    return Delete(deletedRows, predicates.GetTableName(), predicates.GetWhereClause(), predicates.GetBindArgs());
}

int RdbStoreImpl::Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
    const std::vector<std::string> &whereArgs)
{
    std::vector<ValueObject> bindArgs;
    std::for_each(
        whereArgs.begin(), whereArgs.end(), [&bindArgs](const auto &it) { bindArgs.push_back(ValueObject(it)); });
    return Delete(deletedRows, table, whereClause, bindArgs);
}

int RdbStoreImpl::Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
    const std::vector<ValueObject> &bindArgs)
{
    if (table.empty()) {
        return E_EMPTY_TABLE_NAME;
    }

    std::string sql;
    sql.append("DELETE FROM ").append(table);
    if (!whereClause.empty()) {
        sql.append(" WHERE ").append(whereClause);
    }

    auto connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    int errCode = connection->ExecuteForChangedRowCount(deletedRows, sql, bindArgs);
    connectionPool->ReleaseConnection(connection);
    if (errCode == E_OK) {
        DoCloudSync(table);
    }
    return errCode;
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
std::shared_ptr<AbsSharedResultSet> RdbStoreImpl::Query(
    const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::string sql;
    std::pair<bool, bool> queryStatus = {ColHasSpecificField(columns), predicates.HasSpecificField()};
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

std::shared_ptr<ResultSet> RdbStoreImpl::QueryByStep(
    const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::string sql = SqliteSqlBuilder::BuildQueryString(predicates, columns);
    return QueryByStep(sql, predicates.GetBindArgs());
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
    std::vector<ValueObject> bindArgs;
    std::for_each(sqlArgs.begin(), sqlArgs.end(), [&bindArgs](const auto &it) { bindArgs.push_back(ValueObject(it)); });
    return std::make_shared<SqliteSharedResultSet>(shared_from_this(), connectionPool, path, sql, bindArgs);
}

std::shared_ptr<AbsSharedResultSet> RdbStoreImpl::QuerySql(const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    return std::make_shared<SqliteSharedResultSet>(shared_from_this(), connectionPool, path, sql, bindArgs);
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
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int errCode = CheckAttach(sql);
    if (errCode != E_OK) {
        return errCode;
    }

    std::shared_ptr<SqliteConnection> connection;
    errCode = BeginExecuteSql(sql, connection);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = connection->ExecuteSql(sql, bindArgs);
    connectionPool->ReleaseConnection(connection);
    if (errCode != E_OK) {
        LOG_ERROR("RDB_STORE Execute SQL ERROR.");
        return errCode;
    }
    int sqlType = SqliteUtils::GetSqlStatementType(sql);
    if (sqlType == SqliteUtils::STATEMENT_DDL) {
        LOG_DEBUG("sql ddl execute.");
        errCode = connectionPool->ReOpenAvailableReadConnections();
    }

    if (errCode == E_OK && (sqlType == SqliteUtils::STATEMENT_UPDATE || sqlType == SqliteUtils::STATEMENT_INSERT)) {
        DoCloudSync("");
    }
    return errCode;
}

std::pair<int32_t, ValueObject> RdbStoreImpl::Execute(const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    int errCode = E_OK;
    ValueObject outValue;
    int sqlType = SqliteUtils::GetSqlStatementType(sql);
    if (sqlType == SqliteUtils::STATEMENT_SELECT) {
        LOG_ERROR("Not support the sql: %{public}s", SqliteUtils::Anonymous(sql).c_str());
        return { E_NOT_SUPPORT_THE_SQL, outValue };
    }

    if (sqlType == SqliteUtils::STATEMENT_INSERT) {
        int64_t intOutValue = -1;
        errCode = ExecuteForLastInsertedRowId(intOutValue, sql, bindArgs);
        return { errCode, ValueObject(intOutValue) };
    }

    if (sqlType == SqliteUtils::STATEMENT_UPDATE) {
        int64_t intOutValue = -1;
        errCode = ExecuteForChangedRowCount(intOutValue, sql, bindArgs);
        return { errCode, ValueObject(intOutValue) };
    }

    if (sqlType == SqliteUtils::STATEMENT_PRAGMA) {
        std::string strOutValue;
        errCode = ExecuteAndGetString(strOutValue, sql, bindArgs);
        return { errCode, ValueObject(strOutValue) };
    }

    if (sqlType == SqliteUtils::STATEMENT_DDL) {
        errCode = ExecuteSql(sql, bindArgs);
        return { errCode, outValue };
    } else {
        LOG_ERROR("Not support the sql: %{public}s", SqliteUtils::Anonymous(sql).c_str());
        return { E_NOT_SUPPORT_THE_SQL, outValue } ;
    }
}

int RdbStoreImpl::ExecuteAndGetLong(int64_t &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    std::shared_ptr<SqliteConnection> connection;
    int errCode = BeginExecuteSql(sql, connection);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = connection->ExecuteGetLong(outValue, sql, bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("RDB_STORE ExecuteAndGetLong ERROR is %{public}d.", errCode);
    }
    connectionPool->ReleaseConnection(connection);
    return errCode;
}

int RdbStoreImpl::ExecuteAndGetString(
    std::string &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    std::shared_ptr<SqliteConnection> connection;
    int errCode = BeginExecuteSql(sql, connection);
    if (errCode != E_OK) {
        return errCode;
    }
    connection->ExecuteGetString(outValue, sql, bindArgs);
    connectionPool->ReleaseConnection(connection);
    return errCode;
}

int RdbStoreImpl::ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    auto connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    int errCode = connection->ExecuteForLastInsertedRowId(outValue, sql, bindArgs);
    connectionPool->ReleaseConnection(connection);
    return errCode;
}

int RdbStoreImpl::ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    int changeRow = 0;
    auto connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    int errCode = connection->ExecuteForChangedRowCount(changeRow, sql, bindArgs);
    connectionPool->ReleaseConnection(connection);
    outValue = changeRow;
    return errCode;
}

int RdbStoreImpl::GetDataBasePath(const std::string &databasePath, std::string &backupFilePath)
{
    if (databasePath.empty()) {
        LOG_ERROR("Empty databasePath.");
        return E_INVALID_FILE_PATH;
    }

    if (ISFILE(databasePath)) {
        backupFilePath = ExtractFilePath(path) + databasePath;
    } else {
        // 2 represents two characters starting from the len - 2 position
        if (!PathToRealPath(ExtractFilePath(databasePath), backupFilePath) || databasePath.back() == '/' ||
            databasePath.substr(databasePath.length() - 2, 2) == "\\") {
            LOG_ERROR("Invalid databasePath.");
            return E_INVALID_FILE_PATH;
        }
        backupFilePath = databasePath;
    }

    if (backupFilePath == path) {
        LOG_ERROR("The backupPath and path should not be same.");
        return E_INVALID_FILE_PATH;
    }

    LOG_INFO("databasePath is %{public}s.", SqliteUtils::Anonymous(backupFilePath).c_str());
    return E_OK;
}

int RdbStoreImpl::ExecuteSqlInner(const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    std::shared_ptr<SqliteConnection> connection;
    int errCode = BeginExecuteSql(sql, connection);
    if (errCode != 0) {
        return errCode;
    }

    errCode = connection->ExecuteSql(sql, bindArgs);
    connectionPool->ReleaseConnection(connection);
    if (errCode != E_OK) {
        LOG_ERROR("ExecuteSql ATTACH_BACKUP_SQL error %{public}d", errCode);
        return errCode;
    }
    return errCode;
}

int RdbStoreImpl::ExecuteGetLongInner(const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    int64_t count;
    std::shared_ptr<SqliteConnection> connection;
    int errCode = BeginExecuteSql(sql, connection);
    if (errCode != 0) {
        return errCode;
    }
    errCode = connection->ExecuteGetLong(count, sql, bindArgs);
    connectionPool->ReleaseConnection(connection);
    if (errCode != E_OK) {
        LOG_ERROR("ExecuteSql EXPORT_SQL error %{public}d", errCode);
        return errCode;
    }
    return errCode;
}

/**
 * Backup a database from a specified encrypted or unencrypted database file.
 */
int RdbStoreImpl::Backup(const std::string databasePath, const std::vector<uint8_t> destEncryptKey)
{
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
int RdbStoreImpl::InnerBackup(const std::string databasePath, const std::vector<uint8_t> destEncryptKey)
{
    std::vector<ValueObject> bindArgs;
    bindArgs.push_back(ValueObject(databasePath));
    if (destEncryptKey.size() != 0 && !isEncrypt_) {
        bindArgs.push_back(ValueObject(destEncryptKey));
        ExecuteSql(GlobalExpr::CIPHER_DEFAULT_ATTACH_HMAC_ALGO);
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    } else if (isEncrypt_) {
        RdbPassword rdbPwd = RdbSecurityManager::GetInstance().GetRdbPassword(
            rdbStoreConfig.GetPath(), RdbSecurityManager::KeyFileType::PUB_KEY_FILE);
        std::vector<uint8_t> key = std::vector<uint8_t>(rdbPwd.GetData(), rdbPwd.GetData() + rdbPwd.GetSize());
        bindArgs.push_back(ValueObject(key));
        ExecuteSql(GlobalExpr::CIPHER_DEFAULT_ATTACH_HMAC_ALGO);
#endif
    } else {
        std::string str = "";
        bindArgs.push_back(ValueObject(str));
    }

    int ret = ExecuteSqlInner(GlobalExpr::ATTACH_BACKUP_SQL, bindArgs);
    if (ret != E_OK) {
        return ret;
    }

    ret = ExecuteGetLongInner(GlobalExpr::EXPORT_SQL, std::vector<ValueObject>());

    int res = ExecuteSqlInner(GlobalExpr::DETACH_BACKUP_SQL, std::vector<ValueObject>());

    return res == E_OK ? ret : res;
}

int RdbStoreImpl::BeginExecuteSql(const std::string &sql, std::shared_ptr<SqliteConnection> &connection)
{
    int type = SqliteUtils::GetSqlStatementType(sql);
    if (SqliteUtils::IsSpecial(type)) {
        return E_TRANSACTION_IN_EXECUTE;
    }

    bool assumeReadOnly = SqliteUtils::IsSqlReadOnly(type);
    bool isReadOnly = false;
    connection = connectionPool->AcquireConnection(assumeReadOnly);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    int errCode = connection->Prepare(sql, isReadOnly);
    if (errCode != 0) {
        connectionPool->ReleaseConnection(connection);
        return errCode;
    }

    if (isReadOnly == connection->IsWriteConnection()) {
        connectionPool->ReleaseConnection(connection);
        connection = connectionPool->AcquireConnection(isReadOnly);
        if (connection == nullptr) {
            return E_CON_OVER_LIMIT;
        }

        if (!isReadOnly && !connection->IsWriteConnection()) {
            LOG_ERROR("StoreSession BeginExecutea : read connection can not execute write operation");
            connectionPool->ReleaseConnection(connection);
            return E_EXECUTE_WRITE_IN_READ_CONNECTION;
        }
    }

    return E_OK;
}
bool RdbStoreImpl::IsHoldingConnection()
{
    return connectionPool != nullptr;
}


/**
 * Attaches a database.
 */
int RdbStoreImpl::Attach(const std::string &alias, const std::string &pathName,
    const std::vector<uint8_t> destEncryptKey)
{
    std::shared_ptr<SqliteConnection> connection;
    std::string sql = GlobalExpr::PRAGMA_JOUR_MODE_EXP;
    int errCode = BeginExecuteSql(sql, connection);
    if (errCode != 0) {
        return errCode;
    }
    std::string journalMode;
    errCode = connection->ExecuteGetString(journalMode, sql, std::vector<ValueObject>());
    if (errCode != E_OK) {
        connectionPool->ReleaseConnection(connection);
        LOG_ERROR("RdbStoreImpl CheckAttach fail to get journal mode : %d", errCode);
        return errCode;
    }
    journalMode = SqliteUtils::StrToUpper(journalMode);
    if (journalMode == GlobalExpr::DEFAULT_JOURNAL_MODE) {
        connectionPool->ReleaseConnection(connection);
        LOG_ERROR("RdbStoreImpl attach is not supported in WAL mode");
        return E_NOT_SUPPORTED_ATTACH_IN_WAL_MODE;
    }

    std::vector<ValueObject> bindArgs;
    bindArgs.push_back(ValueObject(pathName));
    bindArgs.push_back(ValueObject(alias));
    if (destEncryptKey.size() != 0 && !isEncrypt_) {
        bindArgs.push_back(ValueObject(destEncryptKey));
        ExecuteSql(GlobalExpr::CIPHER_DEFAULT_ATTACH_HMAC_ALGO);
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    } else if (isEncrypt_) {
        RdbPassword rdbPwd =
            RdbSecurityManager::GetInstance().GetRdbPassword(rdbStoreConfig.GetPath(),
                RdbSecurityManager::KeyFileType::PUB_KEY_FILE);
        std::vector<uint8_t> key = std::vector<uint8_t>(rdbPwd.GetData(), rdbPwd.GetData() + rdbPwd.GetSize());
        bindArgs.push_back(ValueObject(key));
        ExecuteSql(GlobalExpr::CIPHER_DEFAULT_ATTACH_HMAC_ALGO);
#endif
    } else {
        std::string str = "";
        bindArgs.push_back(ValueObject(str));
    }
    sql = GlobalExpr::ATTACH_SQL;
    errCode = connection->ExecuteSql(sql, bindArgs);
    connectionPool->ReleaseConnection(connection);
    if (errCode != E_OK) {
        LOG_ERROR("ExecuteSql ATTACH_SQL error %d", errCode);
    }

    return errCode;
}

/**
 * Obtains the database version.
 */
int RdbStoreImpl::GetVersion(int &version)
{
    int64_t value = 0;
    int errCode = ExecuteAndGetLong(value, GlobalExpr::PRAGMA_VERSION, std::vector<ValueObject>());
    version = static_cast<int>(value);
    return errCode;
}

/**
 * Sets the version of a new database.
 */
int RdbStoreImpl::SetVersion(int version)
{
    std::string sql = std::string(GlobalExpr::PRAGMA_VERSION) + " = " + std::to_string(version);
    return ExecuteSql(sql, std::vector<ValueObject>());
}
/**
 * Begins a transaction in EXCLUSIVE mode.
 */
int RdbStoreImpl::BeginTransaction()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::lock_guard<std::mutex> lockGuard(connectionPool->GetTransactionStackMutex());
    // size + 1 means the number of transactions in process
    size_t transactionId = connectionPool->GetTransactionStack().size() + 1;

    auto time = static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
    BaseTransaction transaction(connectionPool->GetTransactionStack().size());
    auto connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        LOG_ERROR("transaction id: %{public}zu, storeName: %{public}s times:%{public}" PRIu64 ".",
            transactionId, name.c_str(), time);
        return E_CON_OVER_LIMIT;
    }

    int errCode = connection->ExecuteSql(transaction.GetTransactionStr());
    connectionPool->ReleaseConnection(connection);
    if (errCode != E_OK) {
        LOG_ERROR("transaction id: %{public}zu, storeName: %{public}s, errCode: %{public}d times:%{public}" PRIu64 ".",
            transactionId, name.c_str(), errCode, time);
        return errCode;
    }

    connection->SetInTransaction(true);
    connectionPool->GetTransactionStack().push(transaction);

    std::string logMsg = std::to_string(transactionId) + name + std::to_string(errCode);
    if (IsPrintLog(logMsg)) {
        LOG_INFO("transaction id: %{public}zu, storeName: %{public}s times:%{public}" PRIu64 ".",
            transactionId, name.c_str(), time);
    }
    return E_OK;
}

/**
* Begins a transaction in EXCLUSIVE mode.
*/
int RdbStoreImpl::RollBack()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::lock_guard<std::mutex> lockGuard(connectionPool->GetTransactionStackMutex());
    size_t transactionId = connectionPool->GetTransactionStack().size();

    auto time = static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
    if (connectionPool->GetTransactionStack().empty()) {
        LOG_ERROR("transaction id: %{public}zu, storeName: %{public}s time:%{public}" PRIu64 ".",
            transactionId, name.c_str(), time);
        return E_NO_TRANSACTION_IN_SESSION;
    }
    BaseTransaction transaction = connectionPool->GetTransactionStack().top();
    connectionPool->GetTransactionStack().pop();
    if (transaction.GetType() != TransType::ROLLBACK_SELF && !connectionPool->GetTransactionStack().empty()) {
        connectionPool->GetTransactionStack().top().SetChildFailure(true);
    }
    auto connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        // size + 1 means the number of transactions in process
        LOG_ERROR("transaction id: %{public}zu, storeName: %{public}s time:%{public}" PRIu64 ".",
            transactionId + 1, name.c_str(), time);
        return E_CON_OVER_LIMIT;
    }

    int errCode = connection->ExecuteSql(transaction.GetRollbackStr());
    connectionPool->ReleaseConnection(connection);
    if (connectionPool->GetTransactionStack().empty()) {
        connection->SetInTransaction(false);
    }
	
    std::string logMsg = std::to_string(transactionId + 1) + name + std::to_string(errCode);
    if (IsPrintLog(logMsg)) {
        // size + 1 means the number of transactions in process
        LOG_INFO("transaction id: %{public}zu, storeName: %{public}s, errCode:%{public}d time:%{public}" PRIu64 ".",
            transactionId + 1, name.c_str(), errCode, time);
    }
    return E_OK;
}

/**
* Begins a transaction in EXCLUSIVE mode.
*/
int RdbStoreImpl::Commit()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::lock_guard<std::mutex> lockGuard(connectionPool->GetTransactionStackMutex());
    size_t transactionId = connectionPool->GetTransactionStack().size();

    auto time = static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
    if (connectionPool->GetTransactionStack().empty()) {
        LOG_ERROR("transaction id: %{public}zu, storeName: %{public}s time:%{public}" PRIu64 ".",
            transactionId, name.c_str(), time);
        return E_OK;
    }
    BaseTransaction transaction = connectionPool->GetTransactionStack().top();
    std::string sqlStr = transaction.GetCommitStr();
    if (sqlStr.size() <= 1) {
        LOG_INFO("transaction id: %{public}zu, storeName: %{public}s time:%{public}" PRIu64 ".",
            transactionId, name.c_str(), time);
        connectionPool->GetTransactionStack().pop();
        return E_OK;
    }

    auto connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        LOG_ERROR("transaction id: %{public}zu, storeName: %{public}s time:%{public}" PRIu64 ".",
           transactionId, name.c_str(), time);
        return E_CON_OVER_LIMIT;
    }

    int errCode = connection->ExecuteSql(sqlStr);
    connectionPool->ReleaseConnection(connection);
    connection->SetInTransaction(false);
    
    std::string logMsg = std::to_string(transactionId) + name + std::to_string(errCode);
    if (IsPrintLog(logMsg)) {
        LOG_INFO("transaction id: %{public}zu, storeName: %{public}s errCode:%{public}d time:%{public}" PRIu64 ".",
            transactionId, name.c_str(), errCode, time);
    }
    connectionPool->GetTransactionStack().pop();
    return E_OK;
}

bool RdbStoreImpl::IsPrintLog(std::string logMsg)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    bool isPrint = false;
    if (logRecord_.size() > MAX_SIZE) {
        std::map<std::string, uint32_t>().swap(logRecord_);
    }
    std::string msgTemp = std::string(__FUNCTION__) + "_" + std::to_string(getpid()) + "_"
    + std::to_string(syscall(SYS_gettid)) + "_" + logMsg;
    if (logRecord_.count(msgTemp) != 0) {
        if ((++logRecord_[msgTemp] % PRINT_CNT) == 0) {
            logRecord_[msgTemp] = 0;
            isPrint = true;
        }
    } else {
        logRecord_[msgTemp] = 0;
        isPrint = true;
    }
    return isPrint;
#else
    return true;
#endif
}

int RdbStoreImpl::FreeTransaction(std::shared_ptr<SqliteConnection> connection, const std::string &sql)
{
    int errCode = connection->ExecuteSql(sql);
    if (errCode == E_OK) {
        connection->SetInTransaction(false);
        connectionPool->ReleaseTransaction();
    } else {
        LOG_ERROR("%{public}s with error code %{public}d.", sql.c_str(), errCode);
    }
    connectionPool->ReleaseConnection(connection);
    return errCode;
}

bool RdbStoreImpl::IsInTransaction()
{
    bool res = true;
    auto connection = connectionPool->AcquireConnection(false);
    if (connection != nullptr) {
        res = connection->IsInTransaction();
        connectionPool->ReleaseConnection(connection);
    }
    return res;
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

    auto connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    std::string journalMode;
    int errCode =
        connection->ExecuteGetString(journalMode, GlobalExpr::PRAGMA_JOUR_MODE_EXP, std::vector<ValueObject>());
    connectionPool->ReleaseConnection(connection);
    if (errCode != E_OK) {
        LOG_ERROR("RdbStoreImpl CheckAttach fail to get journal mode : %{public}d", errCode);
        return errCode;
    }

    journalMode = SqliteUtils::StrToUpper(journalMode);
    if (journalMode == GlobalExpr::DEFAULT_JOURNAL_MODE) {
        LOG_ERROR("RdbStoreImpl attach is not supported in WAL mode");
        return E_NOT_SUPPORTED_ATTACH_IN_WAL_MODE;
    }

    return E_OK;
}

#if defined(WINDOWS_PLATFORM) || defined(MAC_PLATFORM) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)

std::string RdbStoreImpl::ExtractFilePath(const std::string &fileFullName)
{
#ifdef WINDOWS_PLATFORM
    return std::string(fileFullName).substr(0, fileFullName.rfind("\\") + 1);
#else
    return std::string(fileFullName).substr(0, fileFullName.rfind("/") + 1);
#endif
}

bool RdbStoreImpl::PathToRealPath(const std::string &path, std::string &realPath)
{
    if (path.empty()) {
        LOG_ERROR("path is empty!");
        return false;
    }

    if ((path.length() >= PATH_MAX)) {
        LOG_ERROR("path len is error, the len is: [%{public}zu]", path.length());
        return false;
    }

    char tmpPath[PATH_MAX] = { 0 };
#ifdef WINDOWS_PLATFORM
    if (_fullpath(tmpPath, path.c_str(), PATH_MAX) == NULL) {
        LOG_ERROR("path to realpath error");
        return false;
    }
#else
    if (realpath(path.c_str(), tmpPath) == NULL) {
        LOG_ERROR("path (%{public}s) to realpath error", SqliteUtils::Anonymous(path).c_str());
        return false;
    }
#endif
    realPath = tmpPath;
    if (access(realPath.c_str(), F_OK) != 0) {
        LOG_ERROR("check realpath (%{public}s) error", SqliteUtils::Anonymous(realPath).c_str());
        return false;
    }
    return true;
}
#endif

bool RdbStoreImpl::IsOpen() const
{
    return isOpen;
}

std::string RdbStoreImpl::GetPath()
{
    return path;
}

std::string RdbStoreImpl::GetOrgPath()
{
    return orgPath;
}

bool RdbStoreImpl::IsReadOnly() const
{
    return isReadOnly;
}

bool RdbStoreImpl::IsMemoryRdb() const
{
    return isMemoryRdb;
}

std::string RdbStoreImpl::GetName()
{
    return name;
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
    return fileType;
}

#ifdef RDB_SUPPORT_ICU
/**
 * Sets the database locale.
 */
int RdbStoreImpl::ConfigLocale(const std::string localeStr)
{
    if (isOpen == false) {
        LOG_ERROR("The connection pool has been closed.");
        return E_ERROR;
    }

    if (connectionPool == nullptr) {
        LOG_ERROR("connectionPool is null");
        return E_ERROR;
    }
    return connectionPool->ConfigLocale(localeStr);
}
#endif

int RdbStoreImpl::Restore(const std::string backupPath, const std::vector<uint8_t> &newKey)
{
    if (isOpen == false) {
        LOG_ERROR("The connection pool has been closed.");
        return E_ERROR;
    }

    if (connectionPool == nullptr) {
        LOG_ERROR("The connectionPool is null.");
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

    return connectionPool->ChangeDbFileForRestore(path, backupFilePath, newKey);
}

/**
 * Queries data in the database based on specified conditions.
 */
std::shared_ptr<ResultSet> RdbStoreImpl::QueryByStep(const std::string &sql,
    const std::vector<std::string> &sqlArgs)
{
    std::vector<ValueObject> bindArgs;
    std::for_each(sqlArgs.begin(), sqlArgs.end(), [&bindArgs](const auto &it) { bindArgs.push_back(ValueObject(it)); });
    return std::make_shared<StepResultSet>(shared_from_this(), connectionPool, sql, bindArgs);
}

std::shared_ptr<ResultSet> RdbStoreImpl::QueryByStep(const std::string &sql, const std::vector<ValueObject> &args)
{
    return std::make_shared<StepResultSet>(shared_from_this(), connectionPool, sql, args);
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
    if (rdbStoreConfig.GetDataGroupId().empty()) {
        rdbUri = SCHEME_RDB + rdbStoreConfig.GetBundleName() + "/" + path + "/" + event;
    } else {
        rdbUri = SCHEME_RDB + rdbStoreConfig.GetDataGroupId() + "/" + path + "/" + event;
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
    if (pool_ == nullptr) {
        pool_ = TaskExecutor::GetInstance().GetExecutor();
    }
    if (pool_ != nullptr) {
        delayNotifier_->SetExecutorPool(pool_);
    }
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
    if (!rdbStoreConfig.IsSearchable()) {
        return E_OK;
    }
    InitDelayNotifier();
    auto callBack = [this](ClientChangedData &clientChangedData) {
        DistributedRdb::RdbChangedData rdbChangedData;
        for (const auto& entry : clientChangedData.tableData) {
            DistributedRdb::RdbChangeProperties rdbProperties;
            rdbProperties.isTrackedDataChange = entry.second.isTrackedDataChange;
            rdbChangedData.tableData[entry.first] = rdbProperties;
        }
        if (delayNotifier_ != nullptr) {
            delayNotifier_->UpdateNotify(rdbChangedData);
        }
    };
    auto connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }
    int code = connection->RegisterCallBackObserver(callBack);
    connectionPool->ReleaseConnection(connection);
    return code;
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
#endif
} // namespace OHOS::NativeRdb