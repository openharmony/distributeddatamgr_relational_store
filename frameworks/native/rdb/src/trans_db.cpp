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
#define LOG_TAG "TransDB"
#include "trans_db.h"

#include "logger.h"
#include "rdb_sql_statistic.h"
#include "rdb_trace.h"
#include "sqlite_sql_builder.h"
#include "sqlite_utils.h"
#include "step_result_set.h"
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include "sqlite_shared_result_set.h"
#endif
namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
using namespace DistributedRdb;
TransDB::TransDB(std::shared_ptr<Connection> conn, const std::string &path) : conn_(conn), path_(path)
{
    maxArgs_ = conn->GetMaxVariable();
}

std::pair<int, int64_t> TransDB::Insert(const std::string &table, const Row &row, Resolution resolution)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto conflictClause = SqliteUtils::GetConflictClause(static_cast<int>(resolution));
    if (table.empty() || row.IsEmpty() || conflictClause == nullptr) {
        return { E_INVALID_ARGS, -1 };
    }

    std::string sql("INSERT");
    sql.append(conflictClause).append(" INTO ").append(table).append("(");
    std::vector<ValueObject> args;
    args.reserve(row.values_.size());
    const char *split = "";
    for (const auto &[key, val] : row.values_) {
        sql.append(split).append(key);
        if (val.GetType() == ValueObject::TYPE_ASSETS && resolution == ConflictResolution::ON_CONFLICT_REPLACE) {
            return { E_INVALID_ARGS, -1 };
        }
        SqliteSqlBuilder::UpdateAssetStatus(val, AssetValue::STATUS_INSERT);
        args.push_back(val); // columnValue
        split = ",";
    }

    sql.append(") VALUES (");
    if (!args.empty()) {
        sql.append(SqliteSqlBuilder::GetSqlArgs(args.size()));
    }

    sql.append(")");
    int64_t rowid = -1;
    auto [errCode, statement] = GetStatement(sql);
    if (statement == nullptr) {
        return { errCode, rowid };
    }
    errCode = statement->Execute(args);
    if (errCode != E_OK) {
        return { errCode, rowid };
    }
    rowid = statement->Changes() > 0 ? statement->LastInsertRowId() : -1;
    return { errCode, rowid };
}

std::pair<int, int64_t> TransDB::BatchInsert(const std::string &table, const RefRows &rows)
{
    if (rows.RowSize() == 0) {
        return { E_OK, 0 };
    }

    auto batchInfo = SqliteSqlBuilder::GenerateSqls(table, rows, maxArgs_);
    if (table.empty() || batchInfo.empty()) {
        LOG_ERROR("empty,table=%{public}s,rows:%{public}zu,max:%{public}d.", table.c_str(), rows.RowSize(), maxArgs_);
        return { E_INVALID_ARGS, -1 };
    }

    for (const auto &[sql, batchArgs] : batchInfo) {
        auto [errCode, statement] = GetStatement(sql);
        if (statement == nullptr) {
            return { errCode, -1 };
        }
        for (const auto &args : batchArgs) {
            errCode = statement->Execute(args);
            if (errCode == E_OK) {
                continue;
            }
            LOG_ERROR("failed(0x%{public}x) db:%{public}s table:%{public}s args:%{public}zu", errCode,
                SqliteUtils::Anonymous(path_).c_str(), table.c_str(), args.size());
            return { errCode, -1 };
        }
    }
    return { E_OK, int64_t(rows.RowSize()) };
}

std::pair<int, int64_t> TransDB::BatchInsertWithConflictResolution(
    const std::string &table, const ValuesBuckets &rows, Resolution resolution)
{
    if (rows.RowSize() == 0) {
        return { E_OK, 0 };
    }

    auto sqlArgs = SqliteSqlBuilder::GenerateSqls(table, rows, maxArgs_, resolution);
    if (sqlArgs.size() != 1 || sqlArgs.front().second.size() != 1) {
        auto [fields, values] = rows.GetFieldsAndValues();
        LOG_ERROR("invalid args, table=%{public}s, rows:%{public}zu, fields:%{public}zu, max:%{public}d.",
            table.c_str(), rows.RowSize(), fields != nullptr ? fields->size() : 0, maxArgs_);
        return { E_INVALID_ARGS, -1 };
    }
    auto &[sql, bindArgs] = sqlArgs.front();
    auto [errCode, statement] = GetStatement(sql);
    if (statement == nullptr) {
        LOG_ERROR("statement is nullptr, errCode:0x%{public}x, args:%{public}zu, table:%{public}s.", errCode,
            bindArgs.size(), table.c_str());
        return { errCode, -1 };
    }
    auto args = std::ref(bindArgs.front());
    errCode = statement->Execute(args);
    if (errCode != E_OK) {
        LOG_ERROR("failed,errCode:%{public}d,table:%{public}s,args:%{public}zu,resolution:%{public}d.", errCode,
            table.c_str(), args.get().size(), static_cast<int32_t>(resolution));
        return { errCode, errCode == E_SQLITE_CONSTRAINT ? int64_t(statement->Changes()) : -1 };
    }
    return { E_OK, int64_t(statement->Changes()) };
}

std::pair<int, int> TransDB::Update(
    const std::string &table, const Row &row, const std::string &where, const Values &args, Resolution resolution)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto clause = SqliteUtils::GetConflictClause(static_cast<int>(resolution));
    if (table.empty() || row.IsEmpty() || clause == nullptr) {
        return { E_INVALID_ARGS, 0 };
    }

    std::string sql("UPDATE");
    sql.append(clause).append(" ").append(table).append(" SET ");
    std::vector<ValueObject> totalArgs;
    totalArgs.reserve(row.values_.size() + args.size());
    const char *split = "";
    for (auto &[key, val] : row.values_) {
        sql.append(split);
        if (val.GetType() == ValueObject::TYPE_ASSETS) {
            sql.append(key).append("=merge_assets(").append(key).append(", ?)");
        } else if (val.GetType() == ValueObject::TYPE_ASSET) {
            sql.append(key).append("=merge_asset(").append(key).append(", ?)");
        } else {
            sql.append(key).append("=?");
        }
        totalArgs.push_back(val);
        split = ",";
    }

    if (!where.empty()) {
        sql.append(" WHERE ").append(where);
    }

    totalArgs.insert(totalArgs.end(), args.begin(), args.end());
    auto [errCode, statement] = GetStatement(sql);
    if (statement == nullptr) {
        return { errCode, 0 };
    }

    errCode = statement->Execute(totalArgs);
    if (errCode != E_OK) {
        return { errCode, 0 };
    }
    return { errCode, int32_t(statement->Changes()) };
}

int TransDB::Delete(int &deletedRows, const std::string &table, const std::string &whereClause, const Values &args)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (table.empty()) {
        return E_INVALID_ARGS;
    }

    std::string sql;
    sql.append("DELETE FROM ").append(table);
    if (!whereClause.empty()) {
        sql.append(" WHERE ").append(whereClause);
    }
    auto [errCode, statement] = GetStatement(sql);
    if (statement == nullptr) {
        return errCode;
    }
    errCode = statement->Execute(args);
    if (errCode != E_OK) {
        return errCode;
    }
    deletedRows = statement->Changes();
    return E_OK;
}

std::shared_ptr<AbsSharedResultSet> TransDB::QuerySql(const std::string &sql, const Values &args)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    auto start = std::chrono::steady_clock::now();
    return std::make_shared<SqliteSharedResultSet>(start, conn_.lock(), sql, args, path_);
#else
    (void)sql;
    (void)args;
    return nullptr;
#endif
}

std::shared_ptr<ResultSet> TransDB::QueryByStep(const std::string &sql, const Values &args, bool preCount)
{
    auto start = std::chrono::steady_clock::now();
    return std::make_shared<StepResultSet>(start, conn_.lock(), sql, args, true, true);
}

std::pair<int32_t, ValueObject> TransDB::Execute(const std::string &sql, const Values &args, int64_t trxId)
{
    (void)trxId;
    ValueObject object;
    int sqlType = SqliteUtils::GetSqlStatementType(sql);
    if (!SqliteUtils::IsSupportSqlForExecute(sqlType) && !SqliteUtils::IsSpecial(sqlType)) {
        LOG_ERROR("Not support the sql:app self can check the SQL");
        return { E_INVALID_ARGS, object };
    }

    auto [errCode, statement] = GetStatement(sql);
    if (errCode != E_OK) {
        return { errCode, object };
    }

    errCode = statement->Execute(args);
    if (errCode != E_OK) {
        LOG_ERROR("failed,app self can check the SQL, error:0x%{public}x.", errCode);
        return { errCode, object };
    }

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
    }

    if (sqlType == SqliteUtils::STATEMENT_DDL) {
        statement->Reset();
        statement->Prepare("PRAGMA schema_version");
        auto [err, version] = statement->ExecuteForValue();
        if (vSchema_ < static_cast<int64_t>(version)) {
            LOG_INFO("db:%{public}s exe DDL schema<%{public}" PRIi64 "->%{public}" PRIi64
                     "> app self can check the SQL.",
                SqliteUtils::Anonymous(path_).c_str(), vSchema_, static_cast<int64_t>(version));
            vSchema_ = version;
        }
    }
    return { errCode, object };
}

int TransDB::GetVersion(int &version)
{
    return E_NOT_SUPPORT;
}

int TransDB::SetVersion(int version)
{
    return E_NOT_SUPPORT;
}

int TransDB::Sync(const SyncOption &option, const std::vector<std::string> &tables, const AsyncDetail &async)
{
    if (option.mode != TIME_FIRST || tables.empty()) {
        return E_INVALID_ARGS;
    }
    return RdbStore::Sync(option, tables, async);
}

std::pair<int32_t, std::shared_ptr<Statement>> TransDB::GetStatement(const std::string &sql) const
{
    auto connection = conn_.lock();
    if (connection == nullptr) {
        return { E_ALREADY_CLOSED, nullptr };
    }
    return connection->CreateStatement(sql, connection);
}
} // namespace OHOS::NativeRdb