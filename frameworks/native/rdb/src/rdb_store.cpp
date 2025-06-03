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
#include "rdb_store.h"

#include "logger.h"
#include "sqlite_sql_builder.h"
#include "sqlite_utils.h"
#include "traits.h"
namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
RdbStore::ModifyTime::ModifyTime(
    std::shared_ptr<ResultSet> result, std::map<std::vector<uint8_t>, PRIKey> hashKeys, bool isFromRowId)
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

static std::vector<ValueObject> ToValues(const std::vector<std::string> &args)
{
    std::vector<ValueObject> newArgs;
    std::for_each(args.begin(), args.end(), [&newArgs](const auto &it) {
        newArgs.push_back(ValueObject(it));
    });
    return newArgs;
}

static bool ColHasSpecificField(const std::vector<std::string> &columns)
{
    for (const std::string &column : columns) {
        if (column.find(SqliteUtils::REP) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::pair<int, int64_t> RdbStore::Insert(const std::string &table, const Row &row, Resolution resolution)
{
    (void)table;
    (void)row;
    (void)resolution;
    return { E_NOT_SUPPORT, -1 };
}

int RdbStore::Insert(int64_t &outRowId, const std::string &table, const Row &row)
{
    auto [errCode, rowid] = Insert(table, row, NO_ACTION);
    if (errCode == E_OK) {
        outRowId = rowid;
    }
    return errCode;
}

int RdbStore::InsertWithConflictResolution(
    int64_t &outRowId, const std::string &table, const Row &row, Resolution resolution)
{
    auto [errCode, rowid] = Insert(table, row, resolution);
    if (errCode == E_OK) {
        outRowId = rowid;
    }
    return errCode;
}

int RdbStore::Replace(int64_t &outRowId, const std::string &table, const Row &row)
{
    auto [errCode, rowid] = Insert(table, row, Resolution::ON_CONFLICT_REPLACE);
    if (errCode == E_OK) {
        outRowId = rowid;
    }
    return errCode;
}

// Old version implementation, cannot be modified
std::pair<int, int64_t> RdbStore::BatchInsert(const std::string &table, const RefRows &rows)
{
    return { E_NOT_SUPPORT, -1 };
}

int RdbStore::BatchInsert(int64_t &outInsertNum, const std::string &table, const Rows &rows)
{
    ValuesBuckets refRows;
    for (auto &row : rows) {
        refRows.Put(row);
    }
    auto [errCode, count] = BatchInsert(table, refRows);
    if (errCode == E_OK) {
        outInsertNum = count;
    }
    return errCode;
}

std::pair<int, int64_t> RdbStore::BatchInsert(const std::string &table, const RefRows &rows, Resolution resolution)
{
    auto [code, result] = BatchInsert(table, rows, {}, resolution);
    return { code, result.changed };
}

std::pair<int, Results> RdbStore::BatchInsert(const std::string &table, const RefRows &rows,
    const std::vector<std::string> &returningFields, Resolution resolution)
{
    return { E_NOT_SUPPORT, -1 };
}

std::pair<int, int> RdbStore::Update(
    const std::string &table, const Row &row, const std::string &where, const Values &args, Resolution resolution)
{
    AbsRdbPredicates predicates(table);
    predicates.SetWhereClause(where);
    predicates.SetBindArgs(args);
    auto [code, result] = Update(row, predicates, {}, resolution);
    return { code, result.changed };
}

int RdbStore::Update(
    int &changedRows, const std::string &table, const Row &row, const std::string &whereClause, const Values &args)
{
    auto [errCode, changes] = Update(table, row, whereClause, args, NO_ACTION);
    if (errCode == E_OK) {
        changedRows = changes;
    }
    return errCode;
}

int RdbStore::Update(int &changedRows, const Row &row, const AbsRdbPredicates &predicates)
{
    return Update(changedRows, predicates.GetTableName(), row, predicates.GetWhereClause(), predicates.GetBindArgs());
}

int RdbStore::Update(
    int &changedRows, const std::string &table, const Row &row, const std::string &whereClause, const Olds &args)
{
    return Update(changedRows, table, row, whereClause, ToValues(args));
};

std::pair<int32_t, Results> RdbStore::Update(const Row &row, const AbsRdbPredicates &predicates,
    const std::vector<std::string> &returningFields, Resolution resolution)
{
    return { E_NOT_SUPPORT, -1 };
}

int RdbStore::UpdateWithConflictResolution(int &changedRows, const std::string &table, const Row &row,
    const std::string &whereClause, const Olds &args, Resolution resolution)
{
    auto [errCode, changes] = Update(table, row, whereClause, ToValues(args), resolution);
    if (errCode == E_OK) {
        changedRows = changes;
    }
    return errCode;
}

int RdbStore::UpdateWithConflictResolution(int &changedRows, const std::string &table, const Row &row,
    const std::string &whereClause, const Values &args, Resolution resolution)
{
    auto [errCode, changes] = Update(table, row, whereClause, args, resolution);
    if (errCode == E_OK) {
        changedRows = changes;
    }
    return errCode;
}

int RdbStore::Delete(int &deletedRows, const std::string &table, const std::string &whereClause, const Olds &args)
{
    return Delete(deletedRows, table, whereClause, ToValues(args));
}

int RdbStore::Delete(int &deletedRows, const AbsRdbPredicates &predicates)
{
    return Delete(deletedRows, predicates.GetTableName(), predicates.GetWhereClause(), predicates.GetBindArgs());
}

int RdbStore::Delete(
    int &deletedRows, const std::string &table, const std::string &whereClause, const RdbStore::Values &args)
{
    AbsRdbPredicates predicates(table);
    predicates.SetWhereClause(whereClause);
    predicates.SetBindArgs(args);
    auto [code, result] = Delete(predicates);
    deletedRows = result.changed;
    return code;
}

std::pair<int32_t, Results> RdbStore::Delete(
    const AbsRdbPredicates &predicates, const std::vector<std::string> &returningFields)
{
    return { E_NOT_SUPPORT, -1 };
}

std::shared_ptr<AbsSharedResultSet> RdbStore::Query(int &errCode, bool distinct, const std::string &table,
    const Fields &columns, const std::string &whereClause, const Values &args, const std::string &groupBy,
    const std::string &indexName, const std::string &orderBy, const int &limit, const int &offset)
{
    std::string sql;
    errCode = SqliteSqlBuilder::BuildQueryString(
        distinct, table, "", columns, whereClause, groupBy, indexName, orderBy, limit, offset, sql);
    if (errCode != E_OK) {
        return nullptr;
    }
    return QuerySql(sql, args);
}

std::shared_ptr<AbsSharedResultSet> RdbStore::Query(const AbsRdbPredicates &predicates, const Fields &columns)
{
    std::string sql;
    std::pair<bool, bool> queryStatus = { ColHasSpecificField(columns), predicates.HasSpecificField() };
    if (queryStatus.first || queryStatus.second) {
        std::string logTable = GetLogTableName(predicates.GetTableName());
        sql = SqliteSqlBuilder::BuildCursorQueryString(predicates, columns, logTable, queryStatus);
    } else {
        sql = SqliteSqlBuilder::BuildQueryString(predicates, columns);
    }
    return QuerySql(sql, predicates.GetBindArgs());
}

std::shared_ptr<AbsSharedResultSet> RdbStore::QuerySql(const std::string &sql, const Olds &args)
{
    return QuerySql(sql, ToValues(args));
}

std::shared_ptr<ResultSet> RdbStore::QueryByStep(const std::string &sql, const Olds &args)
{
    return QueryByStep(sql, ToValues(args));
}

std::shared_ptr<ResultSet> RdbStore::QueryByStep(const AbsRdbPredicates &predicates, const RdbStore::Fields &columns,
    bool preCount)
{
    std::string sql;
    std::pair<bool, bool> queryStatus = { ColHasSpecificField(columns), predicates.HasSpecificField() };
    if (queryStatus.first || queryStatus.second) {
        std::string table = predicates.GetTableName();
        std::string logTable = GetLogTableName(table);
        sql = SqliteSqlBuilder::BuildLockRowQueryString(predicates, columns, logTable);
    } else {
        sql = SqliteSqlBuilder::BuildQueryString(predicates, columns);
    }
    return QueryByStep(sql, predicates.GetBindArgs(), preCount);
}

std::shared_ptr<ResultSet> RdbStore::RemoteQuery(
    const std::string &device, const AbsRdbPredicates &predicates, const Fields &columns, int &errCode)
{
    (void)device;
    (void)predicates;
    (void)columns;
    errCode = E_NOT_SUPPORT;
    return nullptr;
}

std::pair<int32_t, std::shared_ptr<ResultSet>> RdbStore::QuerySharingResource(
    const AbsRdbPredicates &predicates, const Fields &columns)
{
    (void)predicates;
    (void)columns;
    return { E_NOT_SUPPORT, nullptr };
}

int RdbStore::ExecuteSql(const std::string &sql, const Values &args)
{
    auto [errCode, value] = Execute(sql, args, 0);
    return errCode;
}

std::pair<int32_t, ValueObject> RdbStore::Execute(const std::string &sql, const Values &args, int64_t trxId)
{
    return { E_NOT_SUPPORT, ValueObject() };
}

std::pair<int32_t, Results> RdbStore::ExecuteExt(const std::string &sql, const Values &args)
{
    return { E_NOT_SUPPORT, -1 };
}

int RdbStore::ExecuteAndGetLong(int64_t &outValue, const std::string &sql, const Values &args)
{
    auto [errCode, value] = Execute(sql, args);
    if (errCode == E_OK) {
        outValue = static_cast<int64_t>(value);
    }
    return errCode;
}

int RdbStore::ExecuteAndGetString(std::string &outValue, const std::string &sql, const Values &args)
{
    auto [errCode, value] = Execute(sql, args);
    if (errCode == E_OK) {
        outValue = static_cast<std::string>(value);
    }
    return errCode;
}

int RdbStore::ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql, const Values &args)
{
    auto [errCode, value] = Execute(sql, args);
    if (errCode == E_OK) {
        (void)value.GetLong(outValue);
    }
    return errCode;
}

int RdbStore::ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql, const Values &args)
{
    auto [errCode, value] = Execute(sql, args);
    if (errCode == E_OK) {
        (void)value.GetLong(outValue);
    }
    return errCode;
}

int RdbStore::Backup(const std::string &databasePath, const std::vector<uint8_t> &encryptKey)
{
    (void)databasePath;
    (void)encryptKey;
    return E_NOT_SUPPORT;
}

int RdbStore::Attach(const std::string &alias, const std::string &pathName, const std::vector<uint8_t> encryptKey)
{
    (void)alias;
    (void)pathName;
    (void)encryptKey;
    return E_OK;
}

int RdbStore::Count(int64_t &outValue, const AbsRdbPredicates &predicates)
{
    (void)outValue;
    (void)predicates;
    return E_NOT_SUPPORT;
}

std::pair<int32_t, std::shared_ptr<Transaction>> RdbStore::CreateTransaction(int32_t type)
{
    (void)type;
    return { E_NOT_SUPPORT, nullptr };
}

int RdbStore::BeginTransaction()
{
    return E_NOT_SUPPORT;
}

std::pair<int, int64_t> RdbStore::BeginTrans()
{
    return { E_NOT_SUPPORT, 0 };
}

int RdbStore::RollBack()
{
    return E_NOT_SUPPORT;
}

int RdbStore::RollBack(int64_t trxId)
{
    (void)trxId;
    return E_NOT_SUPPORT;
}

int RdbStore::Commit()
{
    return E_NOT_SUPPORT;
}

int RdbStore::Commit(int64_t trxId)
{
    (void)trxId;
    return E_NOT_SUPPORT;
}

bool RdbStore::IsInTransaction()
{
    return true;
}

std::string RdbStore::GetPath()
{
    return "";
}

bool RdbStore::IsHoldingConnection()
{
    return true;
}

int RdbStore::Rekey(const RdbStoreConfig::CryptoParam &cryptoParam)
{
    (void)cryptoParam;
    return E_NOT_SUPPORT;
}

bool RdbStore::IsOpen() const
{
    return true;
}

bool RdbStore::IsReadOnly() const
{
    return false;
}

bool RdbStore::IsMemoryRdb() const
{
    return false;
}

int RdbStore::Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey)
{
    (void)backupPath;
    (void)newKey;
    return E_NOT_SUPPORT;
}

int RdbStore::SetDistributedTables(
    const std::vector<std::string> &tables, int32_t type, const DistributedRdb::DistributedConfig &distributedConfig)
{
    (void)tables;
    (void)type;
    (void)distributedConfig;
    return E_NOT_SUPPORT;
}

std::string RdbStore::ObtainDistributedTableName(const std::string &device, const std::string &table, int &errCode)
{
    errCode = E_NOT_SUPPORT;
    return table + "_" + device;
}

int RdbStore::Sync(const SyncOption &option, const AbsRdbPredicates &predicate, const AsyncBrief &async)
{
    (void)option;
    (void)predicate;
    (void)async;
    return E_NOT_SUPPORT;
}

int RdbStore::Sync(const SyncOption &option, const std::vector<std::string> &tables, const AsyncDetail &async)
{
    (void)option;
    (void)tables;
    (void)async;
    return E_NOT_SUPPORT;
}

int RdbStore::Sync(const SyncOption &option, const AbsRdbPredicates &predicate, const AsyncDetail &async)
{
    (void)option;
    (void)predicate;
    (void)async;
    return E_NOT_SUPPORT;
}

int RdbStore::Subscribe(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer)
{
    (void)option;
    (void)observer;
    return E_NOT_SUPPORT;
}

int RdbStore::UnSubscribe(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer)
{
    (void)option;
    (void)observer;
    return E_NOT_SUPPORT;
}

int RdbStore::SubscribeObserver(const SubscribeOption &option, const std::shared_ptr<RdbStoreObserver> &observer)
{
    (void)option;
    (void)observer;
    return E_NOT_SUPPORT;
}

int RdbStore::UnsubscribeObserver(const SubscribeOption &option, const std::shared_ptr<RdbStoreObserver> &observer)
{
    (void)option;
    (void)observer;
    return E_NOT_SUPPORT;
}

int RdbStore::RegisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer)
{
    (void)observer;
    return E_NOT_SUPPORT;
}

int RdbStore::UnregisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer)
{
    (void)observer;
    return E_NOT_SUPPORT;
}

int RdbStore::Notify(const std::string &event)
{
    (void)event;
    return E_NOT_SUPPORT;
}

bool RdbStore::IsSlaveDiffFromMaster() const
{
    return false;
}

int32_t RdbStore::GetDbType() const
{
    return DB_SQLITE;
}

std::pair<int32_t, uint32_t> RdbStore::LockCloudContainer()
{
    return { E_OK, 0 };
}

int32_t RdbStore::UnlockCloudContainer()
{
    return E_OK;
}

int RdbStore::InterruptBackup()
{
    return E_OK;
}

int32_t RdbStore::GetBackupStatus() const
{
    return SlaveStatus::UNDEFINED;
}

RdbStore::ModifyTime RdbStore::GetModifyTime(
    const std::string &table, const std::string &column, std::vector<PRIKey> &keys)
{
    (void)table;
    (void)column;
    (void)keys;
    return {};
}

int RdbStore::CleanDirtyData(const std::string &table, uint64_t cursor)
{
    (void)table;
    (void)cursor;
    return E_NOT_SUPPORT;
}

int RdbStore::GetRebuilt(RebuiltType &rebuilt)
{
    (void)rebuilt;
    return E_NOT_SUPPORT;
}

std::pair<int32_t, int32_t> RdbStore::Attach(
    const RdbStoreConfig &config, const std::string &attachName, int32_t waitTime)
{
    (void)config;
    (void)attachName;
    (void)waitTime;
    return { E_NOT_SUPPORT, 0 };
}

std::pair<int32_t, int32_t> RdbStore::Detach(const std::string &attachName, int32_t waitTime)
{
    (void)attachName;
    (void)waitTime;
    return { E_NOT_SUPPORT, 0 };
}

int RdbStore::ModifyLockStatus(const AbsRdbPredicates &predicates, bool isLock)
{
    (void)predicates;
    (void)isLock;
    return E_NOT_SUPPORT;
}

int RdbStore::SetSearchable(bool isSearchable)
{
    (void)isSearchable;
    return E_NOT_SUPPORT;
}

std::string RdbStore::GetLogTableName(const std::string &tableName)
{
    return "naturalbase_rdb_aux_" + tableName + "_log";
}

int RdbStore::CleanDirtyLog([[gnu::unused]] const std::string &table, [[gnu::unused]] uint64_t cursor)
{
    return E_NOT_SUPPORT;
}

int RdbStore::ConfigLocale(const std::string &localeStr)
{
    (void)localeStr;
    return E_NOT_SUPPORT;
}

int RdbStore::InitKnowledgeSchema(const DistributedRdb::RdbKnowledgeSchema &schema)
{
    return E_NOT_SUPPORT;
}
} // namespace OHOS::NativeRdb