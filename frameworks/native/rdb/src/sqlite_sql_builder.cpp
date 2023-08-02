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

#include "sqlite_sql_builder.h"

#include <list>
#include <regex>

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_trace.h"
#include "string_utils.h"

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
        BuildSqlStringFromPredicates(index, whereClause, group, order, limit, offset));
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
    sql.append(BuildSqlStringFromPredicates(index, whereClause, group, order, limit, offset));
    return sql;
}

std::string SqliteSqlBuilder::BuildUpdateStringOnlyWhere(const ValuesBucket &values, const std::string &tableName,
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

    if (!whereArgs.empty()) {
        for (size_t i = 0; i < whereArgs.size(); i++) {
            bindArgs.push_back(ValueObject(whereArgs[i]));
        }
    }

    sql.append(BuildSqlStringFromPredicates(index, whereClause, group, order, limit, offset));
    return sql;
}

/**
 * Build a query SQL string using the given condition for SQLite.
 */
int SqliteSqlBuilder::BuildQueryString(bool distinct, const std::string &table, const std::vector<std::string> &columns,
    const std::string &where, const std::string &groupBy, const std::string &having, const std::string &orderBy,
    const std::string &limit, const std::string &offset, std::string &outSql)
{
    if (table.empty()) {
        return E_EMPTY_TABLE_NAME;
    }

    std::string sql;
    sql.append("SELECT ");
    if (distinct) {
        sql.append("DISTINCT ");
    }
    int errorCode = 0;
    if (columns.size() != 0) {
        AppendColumns(sql, columns, errorCode);
    } else {
        sql.append("* ");
    }
    int climit = std::stoi(limit);
    int coffset = std::stoi(offset);
    sql.append("FROM ").append(table).append(
        BuildSqlStringFromPredicates(having, where, groupBy, orderBy, climit, coffset));
    outSql = sql;

    return errorCode;
}

/**
 * Build a query SQL string using the given condition for SQLite.
 */
std::string SqliteSqlBuilder::BuildQueryStringWithExpr(const std::string &tableName, bool distinct,
    const std::string &index, const std::string &whereClause, const std::string &group, const std::string &order,
    int limit, int offset, std::vector<std::string> &expr)
{
    std::string sql;

    sql.append("SELECT ");
    if (distinct) {
        sql.append("DISTINCT ");
    }
    if (expr.size() != 0) {
        AppendExpr(sql, expr);
    } else {
        sql.append("* ");
    }
    sql.append("FROM ").append(tableName).append(
        BuildSqlStringFromPredicates(index, whereClause, group, order, limit, offset));

    return sql;
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
        .append(BuildSqlStringFromPredicates(index, whereClause, group, order, limit, offset));
    return sql;
}

std::string SqliteSqlBuilder::BuildSqlStringFromPredicates(const std::string &index, const std::string &whereClause,
    const std::string &group, const std::string &order, int limit, int offset)
{
    std::string sqlString;

    std::string limitStr = (limit == AbsPredicates::INIT_LIMIT_VALUE) ? "" : std::to_string(limit);
    std::string offsetStr = (offset == AbsPredicates::INIT_OFFSET_VALUE) ? "" : std::to_string(offset);

    AppendClause(sqlString, " INDEXED BY ", index);
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

void SqliteSqlBuilder::AppendClause(std::string &builder, const std::string &name, const std::string &clause)
{
    if (clause.empty()) {
        return;
    }
    builder.append(name);
    builder.append(clause);
}

/**
 * Add the names that are non-null in columns to s, separating them with commas.
 */
void SqliteSqlBuilder::AppendColumns(std::string &builder, const std::vector<std::string> &columns, int &errorCode)
{
    size_t length = columns.size();
    for (size_t i = 0; i < length; i++) {
        std::string column = columns[i];

        if (column.size() != 0) {
            if (i > 0) {
                builder.append(", ");
            }
            builder.append(column);
        }
    }

    builder += ' ';
}

void SqliteSqlBuilder::AppendExpr(std::string &builder, std::vector<std::string> &exprs)
{
    size_t length = exprs.size();

    for (size_t i = 0; i < length; i++) {
        std::string expr = exprs[i];

        if (expr.size() != 0) {
            if (i > 0) {
                builder.append(", ");
            }
            builder.append(expr);
        }
    }

    builder += ' ';
}

std::string SqliteSqlBuilder::BuildQueryString(
    const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    bool distinct = predicates.IsDistinct();
    std::string tableNameStr = predicates.GetJoinClause();
    std::string whereClauseStr = predicates.GetWhereClause();
    std::string groupStr = predicates.GetGroup();
    std::string indexStr = predicates.GetIndex();
    std::string orderStr = predicates.GetOrder();
    std::string limitStr = std::to_string(predicates.GetLimit());
    std::string offsetStr = std::to_string(predicates.GetOffset());
    std::string sqlStr;
    BuildQueryString(
        distinct, tableNameStr, columns, whereClauseStr, groupStr, indexStr, orderStr, limitStr, offsetStr, sqlStr);
    return sqlStr;
}

std::string SqliteSqlBuilder::BuildCountString(const AbsRdbPredicates &predicates)
{
    std::string tableName = predicates.GetTableName();
    return "SELECT COUNT(*) FROM " + tableName + BuildSqlStringFromPredicates(predicates);
}
} // namespace NativeRdb
} // namespace OHOS
