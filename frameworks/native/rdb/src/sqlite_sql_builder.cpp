/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#define LOG_TAG "SqliteSqlBuilder"
#include "sqlite_sql_builder.h"

#include <list>
#include <regex>

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_trace.h"
#include "sqlite_utils.h"
#include "string_utils.h"
#include "traits.h"
namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
std::vector<std::string> g_onConflictClause = {
    "", " OR ROLLBACK", " OR ABORT", " OR FAIL", " OR IGNORE", " OR REPLACE"
};
ValueObject SqliteSqlBuilder::nullObject_;
std::reference_wrapper<ValueObject> SqliteSqlBuilder::nullRef_ = SqliteSqlBuilder::nullObject_;

SqliteSqlBuilder::SqliteSqlBuilder() {}
SqliteSqlBuilder::~SqliteSqlBuilder() {}

/**
 * Build a query SQL string using the given condition for SQLite.
 */
int SqliteSqlBuilder::BuildQueryString(bool distinct, const std::string &table, const std::string &joinClause,
    const std::vector<std::string> &columns, const std::string &whereClause, const std::string &groupBy,
    const std::string &indexName, const std::string &orderBy, const int &limit, const int &offset, std::string &outSql)
{
    if (table.empty()) {
        return E_EMPTY_TABLE_NAME;
    }
    outSql = GetSelectClause(columns, distinct, "*");
    AppendClause(outSql, " FROM ", HandleTable(table));
    AppendClause(outSql, " INDEXED BY ", indexName);
    AppendClause(outSql, " ", joinClause);
    AppendClause(outSql, " WHERE ", whereClause);
    AppendClause(outSql, " GROUP BY ", groupBy);
    AppendClause(outSql, " ORDER BY ", orderBy);
    AppendLimitAndOffset(outSql, limit, offset);
    return E_OK;
}

std::string SqliteSqlBuilder::BuildClauseFromPredicates(const AbsRdbPredicates &predicates)
{
    std::string sqlString;
    AppendClause(sqlString, " INDEXED BY ", predicates.GetIndex());
    AppendClause(sqlString, " ", predicates.GetJoinClause());
    AppendClause(sqlString, " WHERE ", predicates.GetWhereClause());
    AppendClause(sqlString, " GROUP BY ", predicates.GetGroup());
    AppendClause(sqlString, " HAVING ", predicates.GetHaving());
    AppendClause(sqlString, " ORDER BY ", predicates.GetOrder());
    AppendLimitAndOffset(sqlString, predicates.GetLimit(), predicates.GetOffset());

    return sqlString;
}

void SqliteSqlBuilder::AppendClause(
    std::string &builder, const std::string &name, const std::string &clause, const std::string &table)
{
    if (clause.empty()) {
        return;
    }
    builder.append(name);
    if (!table.empty()) {
        builder.append(table).append(".");
    }
    builder.append(clause);
}

/**
 * Add the names that are non-null in columns to s, separating them with commas.
 */
void SqliteSqlBuilder::AppendColumns(
    std::string &builder, const std::vector<std::string> &columns, const std::string &table)
{
    for (size_t i = 0; i < columns.size(); i++) {
        const auto &col = columns[i];
        if (col.empty()) {
            continue;
        }
        if (i > 0 && !(columns[i - 1].empty())) {
            builder.append(", ");
        }
        if (!table.empty()) {
            builder.append(table).append(".");
        }
        builder.append(col);
    }
    if (table.empty()) {
        builder += ' ';
    }
}

void SqliteSqlBuilder::AppendLimitAndOffset(std::string &builder, int limit, int offset)
{
    std::string limitStr = (limit == AbsPredicates::INIT_LIMIT_VALUE) ? "" : std::to_string(limit);
    std::string offsetStr = (offset == AbsPredicates::INIT_OFFSET_VALUE) ? "" : std::to_string(offset);
    AppendClause(builder, " LIMIT ", limitStr);
    AppendClause(builder, " OFFSET ", offsetStr);
}

std::string SqliteSqlBuilder::GetSelectClause(
    const std::vector<std::string> &columns, bool IsDistinct, const std::string &ast, const std::string &table)
{
    std::string sql;
    sql.append("SELECT ");
    if (IsDistinct) {
        sql.append("DISTINCT ");
    }
    if (!columns.empty()) {
        AppendColumns(sql, columns, table);
    } else {
        sql.append(table + ast);
    }
    return sql;
}

std::string SqliteSqlBuilder::BuildQueryString(
    const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    if (predicates.GetTableName().empty()) {
        return "";
    }

    std::string sqlStr = GetSelectClause(columns, predicates.IsDistinct(), "*");
    AppendClause(sqlStr, " FROM ", HandleTable(predicates.GetTableName()));
    sqlStr.append(BuildClauseFromPredicates(predicates));
    return sqlStr;
}

std::string SqliteSqlBuilder::BuildCountString(const AbsRdbPredicates &predicates)
{
    std::string tableName = predicates.GetTableName();
    return "SELECT COUNT(*) FROM " + HandleTable(tableName) + BuildClauseFromPredicates(predicates);
}

std::string SqliteSqlBuilder::BuildCursorQueryString(const AbsRdbPredicates &predicates,
    const std::vector<std::string> &columns, const std::string &logTable, const std::pair<bool, bool> &queryStatus)
{
    std::string table = HandleTable(predicates.GetTableName());
    auto logName = HandleTable(logTable);
    if (table.empty() || logName.empty()) {
        return "";
    }
    std::string sql = GetSelectClause(columns, predicates.IsDistinct(), ".*", table);
    logName += ".";
    if (queryStatus.first) {
        std::string field = SqliteUtils::Replace(DistributedRdb::Field::SHARING_RESOURCE_FIELD, SqliteUtils::REP, "");
        sql = SqliteUtils::Replace(sql, table + "." + DistributedRdb::Field::SHARING_RESOURCE_FIELD,
            logName + SHARING_RESOURCE + " AS " + field);
    }
    if (queryStatus.second) {
        sql.append(", " + logTable + ".cursor");
        sql.append(", CASE WHEN ").append(logTable).append(".")
            .append("flag & 0x8 = 0x8 THEN true ELSE false END AS deleted_flag");
        sql.append(", CASE WHEN ").append(logTable).append(".");
        sql.append("flag & 0x808 = 0x808 THEN 3 WHEN ").append(logTable).append(".flag & 0x800 = 0x800 THEN 1 WHEN ")
            .append(logTable).append(".flag & 0x8 = 0x8 THEN 2 ELSE 0 END AS data_status");
    }
    sql.append(" FROM ").append(table);
    AppendClause(sql, " INDEXED BY ", predicates.GetIndex());
    sql.append(" INNER JOIN ").append(logTable).append(" ON ").append(table)
        .append(".ROWID = ").append(logTable).append(".data_key");
    
    AppendClause(sql, " WHERE ", SqliteUtils::Replace(predicates.GetWhereClause(), SqliteUtils::REP, logName));
    AppendClause(sql, " GROUP BY ", predicates.GetGroup(), table);
    AppendClause(sql, " HAVING ", SqliteUtils::Replace(predicates.GetHaving(), SqliteUtils::REP, logName));
    AppendClause(sql, " ORDER BY ", SqliteUtils::Replace(predicates.GetOrder(), SqliteUtils::REP, logName));
    AppendLimitAndOffset(sql, predicates.GetLimit(), predicates.GetOffset());
    return sql;
}

std::string SqliteSqlBuilder::BuildLockRowQueryString(
    const AbsRdbPredicates &predicates, const std::vector<std::string> &columns, const std::string &logTable)
{
    std::string table = HandleTable(predicates.GetTableName());
    auto logName = HandleTable(logTable);
    if (table.empty() || logName.empty()) {
        return "";
    }
    std::string sql = GetSelectClause(columns, predicates.IsDistinct(), ".*", table);
    sql.append(" FROM ").append(table);
    AppendClause(sql, " INDEXED BY ", predicates.GetIndex());
    sql.append(" INNER JOIN ").append(logName).append(" ON ");
    logName += ".";
    sql.append(table).append(".ROWID = ").append(logName).append("data_key");
    auto whereClause = predicates.GetWhereClause();
    if (whereClause.empty()) {
        sql.append(" WHERE ").append(logName).append("status = 2 OR ").append(logName).append("status = 3 ");
    } else {
        AppendClause(sql, " WHERE ", SqliteUtils::Replace(whereClause, SqliteUtils::REP, logName));
    }
    AppendClause(sql, " GROUP BY ", predicates.GetGroup(), table);
    AppendClause(sql, " HAVING ", SqliteUtils::Replace(predicates.GetHaving(), SqliteUtils::REP, logName));
    AppendClause(sql, " ORDER BY ", SqliteUtils::Replace(predicates.GetOrder(), SqliteUtils::REP, logName));
    AppendLimitAndOffset(sql, predicates.GetLimit(), predicates.GetOffset());
    return sql;
}

std::string SqliteSqlBuilder::GetSqlArgs(size_t size)
{
    std::string args((size << 1) - 1, '?');
    for (size_t i = 1; i < size; ++i) {
        args[(i << 1) - 1] = ',';
    }
    return args;
}

SqliteSqlBuilder::BatchRefSqls SqliteSqlBuilder::GenerateSqls(
    const std::string &table, const ValuesBuckets &buckets, int limit, ConflictResolution resolution)
{
    auto [fields, values] = buckets.GetFieldsAndValues();
    auto columnSize = fields->size();
    auto rowSize = buckets.RowSize();
    std::vector<std::reference_wrapper<ValueObject>> args(columnSize * rowSize, nullRef_);
    std::string sql = "INSERT" + g_onConflictClause[static_cast<int32_t>(resolution)] + " INTO " + table + " (";
    size_t columnIndex = 0;
    for (auto &field : *fields) {
        for (size_t row = 0; row < rowSize; ++row) {
            auto [errorCode, value] = buckets.Get(row, std::ref(field));
            if (errorCode != E_OK) {
                continue;
            }
            SqliteSqlBuilder::UpdateAssetStatus(value.get(), AssetValue::STATUS_INSERT);
            args[columnIndex + row * columnSize] = value;
        }
        columnIndex++;
        sql.append(field).append(",");
    }
    sql.pop_back();
    sql.append(") VALUES ");
    return SqliteSqlBuilder::MakeExecuteSqls(sql, args, columnSize, limit);
}

SqliteSqlBuilder::BatchRefSqls SqliteSqlBuilder::MakeExecuteSqls(
    const std::string &sql, const std::vector<RefValue> &args, int fieldSize, int limit)
{
    if (fieldSize == 0) {
        return BatchRefSqls();
    }
    size_t rowNumbers = args.size() / static_cast<size_t>(fieldSize);
    size_t maxRowNumbersOneTimes = static_cast<size_t>(limit / fieldSize);
    if (maxRowNumbersOneTimes == 0) {
        return BatchRefSqls();
    }
    size_t executeTimes = rowNumbers / maxRowNumbersOneTimes;
    size_t remainingRows = rowNumbers % maxRowNumbersOneTimes;
    std::string singleRowSqlArgs = "(" + SqliteSqlBuilder::GetSqlArgs(fieldSize) + ")";
    auto appendAgsSql = [&singleRowSqlArgs, &sql](size_t rowNumber) {
        std::string sqlStr = sql;
        for (size_t i = 0; i < rowNumber; ++i) {
            sqlStr.append(singleRowSqlArgs).append(",");
        }
        sqlStr.pop_back();
        return sqlStr;
    };
    std::string executeSql;
    BatchRefSqls executeSqls;
    auto start = args.begin();
    if (executeTimes != 0) {
        executeSql = appendAgsSql(maxRowNumbersOneTimes);
        std::vector<std::vector<RefValue>> sqlArgs;
        size_t maxVariableNumbers = maxRowNumbersOneTimes * static_cast<size_t>(fieldSize);
        for (size_t i = 0; i < executeTimes; ++i) {
            std::vector<RefValue> bindValueArgs(start, start + maxVariableNumbers);
            sqlArgs.emplace_back(std::move(bindValueArgs));
            start += maxVariableNumbers;
        }
        executeSqls.emplace_back(std::make_pair(executeSql, std::move(sqlArgs)));
    }

    if (remainingRows != 0) {
        executeSql = appendAgsSql(remainingRows);
        std::vector<std::vector<RefValue>> sqlArgs(1, std::vector<RefValue>(start, args.end()));
        executeSqls.emplace_back(std::make_pair(executeSql, std::move(sqlArgs)));
    }
    return executeSqls;
}

std::string SqliteSqlBuilder::HandleTable(const std::string &tableName)
{
    if (tableName.empty()) {
        return tableName;
    }
    std::regex validName("^([a-zA-Z_][a-zA-Z0-9_\\.\\ ]*)$");
    if (std::regex_match(tableName, validName)) {
        return tableName;
    }
    return "'" + tableName + "'";
}

void SqliteSqlBuilder::UpdateAssetStatus(const ValueObject &val, int32_t status)
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
} // namespace NativeRdb
} // namespace OHOS
