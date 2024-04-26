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
#include "string_utils.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
std::vector<std::string> g_onConflictClause = {
    "", " OR ROLLBACK", " OR ABORT", " OR FAIL", " OR IGNORE", " OR REPLACE"
};
SqliteSqlBuilder::SqliteSqlBuilder() {}
SqliteSqlBuilder::~SqliteSqlBuilder() {}

/**
 * Build a delete SQL string using the given condition for SQLite.
 */
std::string SqliteSqlBuilder::BuildDeleteString(const std::string &tableName, const std::string &index,
    const std::string &whereClause, const std::string &group, const std::string &order, int limit, int offset)
{
    std::string sql;
    sql.append("Delete ").append("FROM ").append(tableName).append(
        BuildSqlStringFromPredicates(index, "", whereClause, group, order, limit, offset));
    return sql;
}

/**
 * Build a count SQL string using the given condition for SQLite.
 */
std::string SqliteSqlBuilder::BuildUpdateString(const ValuesBucket &values, const std::string &tableName,
    const std::vector<std::string> &whereArgs, const std::string &index, const std::string &whereClause,
    const std::string &group, const std::string &order, int limit, int offset, std::vector<ValueObject> &bindArgs,
    ConflictResolution conflictResolution)
{
    std::string sql;

    sql.append("UPDATE")
        .append(g_onConflictClause[static_cast<int>(conflictResolution)])
        .append(" ")
        .append(tableName)
        .append(" SET ");
    const char *split = "";
    for (auto &[key, val] : values.values_) {
        sql.append(split);
        sql.append(key).append("=?");
        bindArgs.push_back(val);
        split = ",";
    }

    if (!whereArgs.empty()) {
        for (size_t i = 0; i < whereArgs.size(); i++) {
            bindArgs.push_back(ValueObject(whereArgs[i]));
        }
    }
    sql.append(BuildSqlStringFromPredicates(index, "", whereClause, group, order, limit, offset));
    return sql;
}

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

    std::string sql;
    sql.append("SELECT ");
    if (distinct) {
        sql.append("DISTINCT ");
    }
    if (columns.size() != 0) {
        AppendColumns(sql, columns);
    } else {
        sql.append("* ");
    }
    sql.append("FROM ").append(table).append(
        BuildSqlStringFromPredicates(indexName, joinClause, whereClause, groupBy, orderBy, limit, offset));
    outSql = sql;

    return E_OK;
}

/**
 * Build a count SQL string using the given condition for SQLite.
 */
std::string SqliteSqlBuilder::BuildCountString(const std::string &tableName, const std::string &index,
    const std::string &whereClause, const std::string &group, const std::string &order, int limit, int offset)
{
    std::string sql;
    sql.append("SELECT COUNT(*) FROM ")
        .append(tableName)
        .append(BuildSqlStringFromPredicates(index, "", whereClause, group, order, limit, offset));
    return sql;
}

std::string SqliteSqlBuilder::BuildSqlStringFromPredicates(const std::string &index, const std::string &joinClause,
    const std::string &whereClause, const std::string &group, const std::string &order, int limit, int offset)
{
    std::string sqlString;

    std::string limitStr = (limit == AbsPredicates::INIT_LIMIT_VALUE) ? "" : std::to_string(limit);
    std::string offsetStr = (offset == AbsPredicates::INIT_OFFSET_VALUE) ? "" : std::to_string(offset);

    AppendClause(sqlString, " INDEXED BY ", index);
    AppendClause(sqlString, " ", joinClause);
    AppendClause(sqlString, " WHERE ", whereClause);
    AppendClause(sqlString, " GROUP BY ", group);
    AppendClause(sqlString, " ORDER BY ", order);
    AppendClause(sqlString, " LIMIT ", limitStr);
    AppendClause(sqlString, " OFFSET ", offsetStr);

    return sqlString;
}

std::string SqliteSqlBuilder::BuildSqlStringFromPredicates(const AbsPredicates &predicates)
{
    std::string limitStr =
        (predicates.GetLimit() == AbsPredicates::INIT_LIMIT_VALUE) ? "" : std::to_string(predicates.GetLimit());
    std::string offsetStr =
        (predicates.GetOffset() == AbsPredicates::INIT_OFFSET_VALUE) ? "" : std::to_string(predicates.GetOffset());

    std::string sqlString;
    AppendClause(sqlString, " INDEXED BY ", predicates.GetIndex());
    AppendClause(sqlString, " WHERE ", predicates.GetWhereClause());
    AppendClause(sqlString, " GROUP BY ", predicates.GetGroup());
    AppendClause(sqlString, " ORDER BY ", predicates.GetOrder());
    AppendClause(sqlString, " LIMIT ", limitStr);
    AppendClause(sqlString, " OFFSET ", offsetStr);

    return sqlString;
}

std::string SqliteSqlBuilder::BuildSqlStringFromPredicatesNoWhere(const std::string &index,
    const std::string &whereClause, const std::string &group, const std::string &order, int limit, int offset)
{
    std::string limitStr = (limit == AbsPredicates::INIT_LIMIT_VALUE) ? "" : std::to_string(limit);
    std::string offsetStr = (offset == AbsPredicates::INIT_OFFSET_VALUE) ? "" : std::to_string(offset);

    std::string sqlString;
    AppendClause(sqlString, " INDEXED BY ", index);
    AppendClause(sqlString, " ", whereClause);
    AppendClause(sqlString, " GROUP BY ", group);
    AppendClause(sqlString, " ORDER BY ", order);
    AppendClause(sqlString, " LIMIT ", limitStr);
    AppendClause(sqlString, " OFFSET ", offsetStr);

    return sqlString;
}

void SqliteSqlBuilder::AppendClause(std::string &builder, const std::string &name,
    const std::string &clause, const std::string &table)
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

std::string SqliteSqlBuilder::BuildQueryString(
    const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    bool distinct = predicates.IsDistinct();
    std::string tableName = predicates.GetTableName();
    std::string joinClauseStr = predicates.GetJoinClause();
    std::string whereClauseStr = predicates.GetWhereClause();
    std::string groupStr = predicates.GetGroup();
    std::string indexStr = predicates.GetIndex();
    std::string orderStr = predicates.GetOrder();
    int limit = predicates.GetLimit();
    int offset = predicates.GetOffset();
    std::string sqlStr;
    BuildQueryString(distinct, tableName, joinClauseStr, columns, whereClauseStr,
        groupStr, indexStr, orderStr, limit, offset, sqlStr);
    return sqlStr;
}

std::string SqliteSqlBuilder::BuildCountString(const AbsRdbPredicates &predicates)
{
    std::string tableName = predicates.GetTableName();
    return "SELECT COUNT(*) FROM " + tableName + BuildSqlStringFromPredicates(predicates);
}

std::string SqliteSqlBuilder::BuildCursorQueryString(const AbsRdbPredicates &predicates,
    const std::vector<std::string> &columns, const std::string &logTable,  const std::pair<bool, bool> &queryStatus)
{
    std::string sql;
    std::string table = predicates.GetTableName();
    if (table.empty() || logTable.empty()) {
        return sql;
    }
    sql.append("SELECT ");
    if (predicates.IsDistinct()) {
        sql.append("DISTINCT ");
    }
    if (!columns.empty()) {
        AppendColumns(sql, columns, table);
    } else {
        sql.append(table + ".*");
    }
    if (queryStatus.first) {
        std::string field = DistributedRdb::Field::SHARING_RESOURCE_FIELD;
        SqliteUtils::Replace(field, SqliteUtils::REP, "");
        SqliteUtils::Replace(sql, table + "." + DistributedRdb::Field::SHARING_RESOURCE_FIELD,
            logTable + "." + SHARING_RESOURCE + " AS " + field);
    }
    if (queryStatus.second) {
        sql.append(", " + logTable + ".cursor");
        sql.append(", CASE WHEN ").append(logTable).append(".")
            .append("flag & 0x8 = 0x8 THEN true ELSE false END AS deleted_flag");
    }
    sql.append(" FROM ").append(table);
    AppendClause(sql, " INDEXED BY ", predicates.GetIndex());
    sql.append(" INNER JOIN ").append(logTable).append(" ON ").append(table)
        .append(".ROWID = ").append(logTable).append(".data_key");
    auto whereClause = predicates.GetWhereClause();
    SqliteUtils::Replace(whereClause, SqliteUtils::REP, logTable + ".");
    AppendClause(sql, " WHERE ", whereClause);
    AppendClause(sql, " GROUP BY ", predicates.GetGroup(), table);
    auto order = predicates.GetOrder();
    SqliteUtils::Replace(order, SqliteUtils::REP, logTable + ".");
    AppendClause(sql, " ORDER BY ", order);
    int limit = predicates.GetLimit();
    auto limitClause = (limit == AbsPredicates::INIT_LIMIT_VALUE) ? "" : std::to_string(limit);
    int offset = predicates.GetOffset();
    auto offsetClause = (offset == AbsPredicates::INIT_OFFSET_VALUE) ? "" : std::to_string(offset);
    AppendClause(sql, " LIMIT ", limitClause);
    AppendClause(sql, " OFFSET ", offsetClause);
    return sql;
}

std::string SqliteSqlBuilder::BuildLockRowQueryString(
    const AbsRdbPredicates &predicates, const std::vector<std::string> &columns, const std::string &logTable)
{
    std::string sql;
    std::string table = predicates.GetTableName();
    if (table.empty() || logTable.empty()) {
        return sql;
    }
    sql.append("SELECT ");
    if (predicates.IsDistinct()) {
        sql.append("DISTINCT ");
    }
    if (!columns.empty()) {
        AppendColumns(sql, columns, table);
    } else {
        sql.append(table + ".*");
    }
    sql.append(" FROM ").append(table);
    AppendClause(sql, " INDEXED BY ", predicates.GetIndex());
    sql.append(" INNER JOIN ").append(logTable).append(" ON ");
    sql.append(table).append(".ROWID = ").append(logTable).append(".data_key");
    auto whereClause = predicates.GetWhereClause();
    if (whereClause.empty()) {
        sql.append(" WHERE ").append(logTable).append(".status = 2 OR ").append(logTable).append(".status = 3 ");
    } else {
        SqliteUtils::Replace(whereClause, SqliteUtils::REP, logTable + ".");
        AppendClause(sql, " WHERE ", whereClause);
    }
    AppendClause(sql, " GROUP BY ", predicates.GetGroup(), table);
    auto order = predicates.GetOrder();
    SqliteUtils::Replace(order, SqliteUtils::REP, logTable + ".");
    AppendClause(sql, " ORDER BY ", order);
    int limit = predicates.GetLimit();
    auto limitClause = (limit == AbsPredicates::INIT_LIMIT_VALUE) ? "" : std::to_string(limit);
    int offset = predicates.GetOffset();
    auto offsetClause = (offset == AbsPredicates::INIT_OFFSET_VALUE) ? "" : std::to_string(offset);
    AppendClause(sql, " LIMIT ", limitClause);
    AppendClause(sql, " OFFSET ", offsetClause);
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

SqliteSqlBuilder::ExecuteSqls SqliteSqlBuilder::MakeExecuteSqls(
    const std::string &sql, std::vector<ValueObject> &&args, int fieldSize, int limit)
{
    if (fieldSize == 0) {
        return ExecuteSqls();
    }
    size_t rowNumbers = args.size() / static_cast<size_t>(fieldSize);
    size_t maxRowNumbersOneTimes = static_cast<size_t>(limit / fieldSize);
    if (maxRowNumbersOneTimes == 0) {
        return ExecuteSqls();
    }
    size_t executeTimes = rowNumbers / maxRowNumbersOneTimes;
    size_t remainingRows = rowNumbers % maxRowNumbersOneTimes;
    LOG_DEBUG("rowNumbers %{public}zu, maxRowNumbersOneTimes %{public}zu, executeTimes %{public}zu,"
        "remainingRows %{public}zu, fieldSize %{public}d, limit %{public}d",
        rowNumbers, maxRowNumbersOneTimes, executeTimes, remainingRows, fieldSize, limit);
    std::string singleRowSqlArgs = "(" + SqliteSqlBuilder::GetSqlArgs(fieldSize) + ")";
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
        size_t maxVariableNumbers = maxRowNumbersOneTimes * static_cast<size_t>(fieldSize);
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
} // namespace NativeRdb
} // namespace OHOS
