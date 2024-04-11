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
#define LOG_TAG "VdbStoreImpl"
#include "vdb_store_impl.h"

#include <algorithm>
#include <sstream>
#include <chrono>
#include <cinttypes>
#include "logger.h"
#include "cache_result_set.h"
#include "rdb_errno.h"
#include "rdb_sql_utils.h"
#include "rdb_store.h"
#include "rdb_store_impl.h"
#include "rdb_trace.h"
#include "rd_result_set.h"
#include "rd_utils.h"
#include "sqlite_global_config.h"
#include "sqlite_sql_builder.h"
#include "sqlite_utils.h"
#include "step_result_set.h"
#include "task_executor.h"
#include "traits.h"

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
using namespace std::chrono;

VdbStoreImpl::VdbStoreImpl(const RdbStoreConfig &config, int &errCode) : RdbStoreImpl(config),
    rdConnectionPool_(nullptr)
{
    rdConnectionPool_ = RdbConnectionPool::Create(config_, errCode);
    if (rdConnectionPool_ == nullptr || errCode != E_OK) {
        rdConnectionPool_ = nullptr;
        LOG_ERROR("InnerOpen failed, err is %{public}d", errCode);
        return;
    }
}

VdbStoreImpl::~VdbStoreImpl()
{
    rdConnectionPool_ = nullptr;
}

std::pair<int, int64_t> VdbStoreImpl::BeginTrans()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto time = static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
    int64_t tmpTrxId = 0;
    auto connection = rdConnectionPool_->AcquireNewConnection(false, tmpTrxId);
    if (connection == nullptr) {
        LOG_ERROR("Get null connection, storeName: %{public}s time:%{public}" PRIu64 ".", name_.c_str(), time);
        return {E_DATABASE_BUSY, 0};
    }
    int ret = connection->ExecuteSql(RdUtils::BEGIN_TRANSACTION_SQL);
    if (ret != E_OK) {
        LOG_ERROR("transaction id: %{public}" PRIu64 ", storeName: %{public}s, errCode:\
            %{public}d times:%{public}" PRIu64 ".", tmpTrxId, name_.c_str(), ret, time);
        return {ret, 0};
    }
    connection->SetInTransaction(true);
    return {E_OK, tmpTrxId};
}

int VdbStoreImpl::Commit(int64_t trxId)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto time = static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
    auto connection = rdConnectionPool_->AcquireConnection(false, trxId);
    if (connection == nullptr) {
        LOG_ERROR("Get null connection, storeName: %{public}s time:%{public}" PRIu64 ".", name_.c_str(), time);
        return E_INVALID_ARGS;
    }
    int ret = connection->ExecuteSql(RdUtils::COMMIT_TRANSACTION_SQL);
    if (ret != E_OK) {
        LOG_ERROR("transaction id: %{public}" PRIu64 ", storeName: %{public}s, errCode:\
            %{public}d times:%{public}" PRIu64 ".", trxId, name_.c_str(), ret, time);
        return ret;
    }
    connection->SetInTransaction(false);
    rdConnectionPool_->ReleaseConnection(connection);
    return E_OK;
}

int VdbStoreImpl::RollBack(int64_t trxId)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto time = static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
    auto connection = rdConnectionPool_->AcquireConnection(false, trxId);
    if (connection == nullptr) {
        LOG_ERROR("Get null connection, storeName: %{public}s time:%{public}" PRIu64 ".", name_.c_str(), time);
        return E_INVALID_ARGS;
    }
    int ret = connection->ExecuteSql(RdUtils::ROLLBACK_TRANSACTION_SQL);
    if (ret != E_OK) {
        LOG_ERROR(
            "transaction id: %{public}" PRIu64 ", storeName: %{public}s, errCode: %{public}d times:%{public}" PRIu64,
            trxId, name_.c_str(), ret, time);
        return ret;
    }
    connection->SetInTransaction(false);
    rdConnectionPool_->ReleaseConnection(connection);
    return E_OK;
}

std::pair<int32_t, ValueObject> VdbStoreImpl::Execute(const std::string &sql,
    const std::vector<ValueObject> &bindArgs, int64_t txId)
{
    ValueObject outValue;
    int sqlType = SqliteUtils::GetSqlStatementType(sql);
    if (sqlType == SqliteUtils::STATEMENT_SELECT) {
        LOG_ERROR("Not support the sql: %{public}s", SqliteUtils::Anonymous(sql).c_str());
        return { E_NOT_SUPPORT_THE_SQL, outValue };
    }
    if (sqlType == SqliteUtils::STATEMENT_PRAGMA) {
        LOG_ERROR("Not support the sql: %{public}s", SqliteUtils::Anonymous(sql).c_str());
        return { E_NOT_SUPPORT_THE_SQL, outValue };
    }
    int32_t ret = E_OK;
    txId < 0 ? ret = E_INVALID_ARGS : ret = ExecuteSqlByTrxId(sql, bindArgs, (uint64_t)txId);
    return { ret, ValueObject() };
}

int VdbStoreImpl::ExecuteSqlByTrxId(const std::string &sql, const std::vector<ValueObject> &bindArgs, int64_t trxId)
{
    bool isRead = trxId == 0 ? true : false;
    auto connection = rdConnectionPool_->AcquireConnection(isRead, trxId);
    if (connection == nullptr) {
        LOG_ERROR("Get null connection");
        return E_INVALID_ARGS;
    }
    int ret = connection->ExecuteSql(sql, bindArgs);
    if (ret != E_OK) {
        LOG_ERROR("RdbStore unable to execute sql");
        return ret;
    }
    if (trxId == 0) {
        rdConnectionPool_->ReleaseConnection(connection);
    }
    return E_OK;
}

std::shared_ptr<AbsSharedResultSet> VdbStoreImpl::QuerySql(const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    return std::make_shared<RdSharedResultSet>(rdConnectionPool_, sql, bindArgs);
}

int VdbStoreImpl::Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &values)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::BatchInsert(int64_t& outInsertNum, const std::string& table, const std::vector<ValuesBucket>& values)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::Replace(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::InsertWithConflictResolution(int64_t &outRowId, const std::string &table, const ValuesBucket &values,
    ConflictResolution conflictResolution)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::Update(int &changedRows, const std::string &table, const ValuesBucket &values,
    const std::string &whereClause, const std::vector<std::string> &whereArgs)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::Update(int &changedRows, const std::string &table, const ValuesBucket &values,
    const std::string &whereClause, const std::vector<ValueObject> &bindArgs)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
    const std::string &whereClause, const std::vector<std::string> &whereArgs,
    ConflictResolution conflictResolution)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
    const std::string &whereClause, const std::vector<ValueObject> &bindArgs,
    ConflictResolution conflictResolution)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
    const std::vector<std::string> &whereArgs)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
    const std::vector<ValueObject> &bindArgs)
{
    return E_NOT_SUPPORT;
}

std::shared_ptr<AbsSharedResultSet> VdbStoreImpl::Query(int &errCode, bool distinct,
    const std::string &table, const std::vector<std::string> &columns,
    const std::string &whereClause, const std::vector<ValueObject> &bindArgs, const std::string &groupBy,
    const std::string &indexName, const std::string &orderBy, const int &limit, const int &offset)
{
    return nullptr;
}

std::shared_ptr<AbsSharedResultSet> VdbStoreImpl::QuerySql(const std::string &sql,
    const std::vector<std::string> &sqlArgs)
{
    return nullptr;
}

int VdbStoreImpl::ExecuteSql(const std::string& sql, const std::vector<ValueObject>& bindArgs)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::ExecuteAndGetLong(
    int64_t &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::ExecuteAndGetString(std::string &outValue, const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::GetVersion(int &version)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::SetVersion(int version)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::BeginTransaction()
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::RollBack()
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::Commit()
{
    return E_NOT_SUPPORT;
}

bool VdbStoreImpl::IsInTransaction()
{
    return false;
}

int VdbStoreImpl::Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey)
{
    return E_NOT_SUPPORT;
}

std::shared_ptr<ResultSet> VdbStoreImpl::QueryByStep(const std::string &sql, const std::vector<std::string> &sqlArgs)
{
    return nullptr;
}

std::shared_ptr<ResultSet> VdbStoreImpl::QueryByStep(const std::string &sql, const std::vector<ValueObject> &args)
{
    return nullptr;
}

std::shared_ptr<ResultSet> VdbStoreImpl::QueryByStep(
    const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    return nullptr;
}

std::shared_ptr<AbsSharedResultSet> VdbStoreImpl::Query(
    const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    return nullptr;
}

std::pair<int32_t, std::shared_ptr<ResultSet>> VdbStoreImpl::QuerySharingResource(
    const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    return { E_NOT_SUPPORT, nullptr };
}

int VdbStoreImpl::Count(int64_t &outValue, const AbsRdbPredicates &predicates)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::Update(int &changedRows, const ValuesBucket &values, const AbsRdbPredicates &predicates)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::Delete(int &deletedRows, const AbsRdbPredicates &predicates)
{
    return E_NOT_SUPPORT;
}

std::shared_ptr<ResultSet> VdbStoreImpl::RemoteQuery(const std::string &device, const AbsRdbPredicates &predicates,
    const std::vector<std::string> &columns, int &errCode)
{
    return nullptr;
}

int VdbStoreImpl::SetDistributedTables(const std::vector<std::string> &tables, int32_t type,
    const DistributedRdb::DistributedConfig &distributedConfig)
{
    return E_NOT_SUPPORT;
}

std::string VdbStoreImpl::ObtainDistributedTableName(const std::string& device, const std::string& table, int &errCode)
{
    return "";
}

int VdbStoreImpl::Sync(const SyncOption &option, const AbsRdbPredicates &predicate, const AsyncBrief &async)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::Sync(const SyncOption &option, const std::vector<std::string> &tables, const AsyncDetail &async)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::Sync(const SyncOption &option, const AbsRdbPredicates &predicate, const AsyncDetail &async)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::Subscribe(const SubscribeOption& option, RdbStoreObserver *observer)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::UnSubscribe(const SubscribeOption& option, RdbStoreObserver *observer)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::RegisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::UnregisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer)
{
    return E_NOT_SUPPORT;
}

int VdbStoreImpl::Notify(const std::string &event)
{
    return E_NOT_SUPPORT;
}

RdbStore::ModifyTime VdbStoreImpl::GetModifyTime(const std::string& table, const std::string& columnName,
    std::vector<PRIKey>& keys)
{
    return {};
}

int VdbStoreImpl::CleanDirtyData(const std::string &table, uint64_t cursor)
{
    return E_NOT_SUPPORT;
}

std::pair<int32_t, int32_t> VdbStoreImpl::Attach(
    const RdbStoreConfig &config, const std::string &attachName, int32_t waitTime)
    {
        return { E_NOT_SUPPORT, 0 };
    }

std::pair<int32_t, int32_t> VdbStoreImpl::Detach(const std::string &attachName, int32_t waitTime)
{
    return { E_NOT_SUPPORT, 0 };
}

} // namespace OHOS::NativeRdb