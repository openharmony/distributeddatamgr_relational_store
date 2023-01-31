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

const std::string SqliteSqlBuilder::patternWords_ = "['\"`]?(\\w+)['\"`]?|['\"`]([^`\"']+)['\"`]";
const std::string SqliteSqlBuilder::patternTableColumn_ = "(" + patternWords_ + ")[.](" + patternWords_ + "|\\*)";

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
    std::map<std::string, ValueObject> valuesMap;
    values.GetAll(valuesMap);
    for (auto iter = valuesMap.begin(); iter != valuesMap.end(); iter++) {
        sql.append((iter == valuesMap.begin()) ? "" : ",");
        sql.append(iter->first).append("=?");
        bindArgs.push_back(iter->second);
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

    std::string limitStr = (limit == -1) ? "" : std::to_string(limit);
    std::string offsetStr = (offset == -1) ? "" : std::to_string(offset);

    AppendClause(sqlString, " INDEXED BY ", index);
    AppendClause(sqlString, " WHERE ", whereClause);
    AppendClause(sqlString, " GROUP BY ", group);
    AppendClause(sqlString, " ORDER BY ", order);
    AppendClause(sqlString, " LIMIT ", limitStr);
    AppendClause(sqlString, " OFFSET ", offsetStr);

    return sqlString;
}

std::string SqliteSqlBuilder::BuildSqlStringFromPredicates(const AbsRdbPredicates &predicates)
{
    std::string sqlString;

    std::string limitStr = (predicates.GetLimit() == -1) ? "" : std::to_string(predicates.GetLimit());
    std::string offsetStr = (predicates.GetOffset() == -1) ? "" : std::to_string(predicates.GetOffset());

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
    std::string sqlString;
    std::string limitStr = (limit == -1) ? "" : std::to_string(limit);
    std::string offsetStr = (offset == -1) ? "" : std::to_string(offset);

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
            builder.append(NormalizeAlias(column, errorCode));
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

bool SqliteSqlBuilder::IsNotEmptyString(const std::string &str)
{
    return (!str.empty());
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

std::string SqliteSqlBuilder::PredicatesNormalize(const std::string &source, int &errorCode)
{
    errorCode = 0;
    if (StringUtils::IsEmpty(source)) {
        LOG_ERROR("Input param is empty.");
        return "";
    }

    auto index = source.rfind("(*");
    if (index != -1) {
        return source;
    }

    index = source.rfind(".");
    if (index == -1) {
        return StringUtils::SurroundWithQuote(source, "`");
    }

    auto fIndex = source.find(".");
    if (index != fIndex) {
        LOG_ERROR("More than one '.' exists in source");
        errorCode = -1;
        return "";
    }

    std::string retStr1 =  StringUtils::SurroundWithQuote(source.substr(0, index), "`");
    std::string source2 =  StringUtils::Trim(source.substr(index + 1));
    std::string retStr2 = source2 == "*" ? source2 : StringUtils::SurroundWithQuote(source2, "`");

    return retStr1 + "." + retStr2;
}

std::string SqliteSqlBuilder::NormalizeWords(const std::string &source, int &errorCode)
{
    DISTRIBUTED_DATA_HITRACE("SqliteSqlBuilder::NormalizeWords");
    errorCode = 0;
    if (StringUtils::IsEmpty(source)) {
        return "";
    }
    std::string strTrimed = StringUtils::Trim(source);
    std::string obj = "*";
    if (obj == strTrimed) {
        return "*";
    }
    std::regex pattern("^(" + patternWords_ + ")$");
    std::smatch result;
    auto wordMatcher = std::regex_match(strTrimed, result, pattern);
    if (!wordMatcher) {
        return "";
    }
    std::string words = StringUtils::IsEmpty(result[2]) ? result[3] : result[2];
    return StringUtils::SurroundWithQuote(words, "`");
}

std::string SqliteSqlBuilder::NormalizeTableColumn(const std::string &source, int &errorCode)
{
    DISTRIBUTED_DATA_HITRACE("SqliteSqlBuilder::NormalizeTableColumn");
    errorCode = 0;
    if (StringUtils::IsEmpty(source)) {
        return "";
    }
    std::string strTrimed = StringUtils::Trim(source);
    std::regex pattern_table("^(" + patternWords_ + ")[.](" + patternWords_ + "|\\*)$");
    std::smatch result;
    bool columnMatcher = std::regex_match(strTrimed, result, pattern_table);
    if (!columnMatcher) {
        return "";
    }
    std::string firstName = StringUtils::IsEmpty(result[2]) ? StringUtils::Trim(result[3])
                                                            : StringUtils::Trim(result[2]);
    std::string lastName = StringUtils::IsEmpty(result[5]) ? StringUtils::Trim(result[6])
                                                           : StringUtils::Trim(result[5]);
    lastName = StringUtils::IsEmpty(lastName) ? StringUtils::Trim(result[4]) : lastName;
    std::string aresult(StringUtils::SurroundWithQuote(firstName, "`"));
    std::string obj = "*";
    if (obj == lastName) {
        aresult.append(".").append(lastName);
    } else {
        aresult.append(".").append(StringUtils::SurroundWithQuote(lastName, "`"));
    }
    return aresult;
}

std::string SqliteSqlBuilder::NormalizeMethodPattern(const std::string &source, int &errorCode)
{
    DISTRIBUTED_DATA_HITRACE("SqliteSqlBuilder::NormalizeMethodPattern");
    errorCode = 0;
    if (StringUtils::IsEmpty(source)) {
        return "";
    }
    std::string strTrimed = StringUtils::Trim(source);
    std::regex pattern("^(\\w+)(\\()(.*)(\\))$");
    std::smatch result;
    bool columnMatcher = std::regex_match(strTrimed, result, pattern);
    if (!columnMatcher) {
        return StringUtils::SurroundWithQuote(strTrimed, "`");
    }
    std::string methodName = StringUtils::Trim(result[1]);
    std::string methodParams = StringUtils::Trim(result[3]);
    if (StringUtils::IsEmpty(methodParams)) {
        return methodName.append("()");
    }
    return methodName.append("(").append(methodParams).append(")");
}

std::string SqliteSqlBuilder::Normalize(const std::string &words, int &errorCode)
{
    DISTRIBUTED_DATA_HITRACE("SqliteSqlBuilder::Normalize");
    errorCode = 0;
    std::string aresult = NormalizeWords(words, errorCode);
    if (!StringUtils::IsEmpty(aresult)) {
        return aresult;
    }
    aresult = NormalizeTableColumn(words, errorCode);
    if (!StringUtils::IsEmpty(aresult)) {
        return aresult;
    }
    aresult = NormalizeMethodPattern(words, errorCode);
    if (!StringUtils::IsEmpty(aresult)) {
        return aresult;
    }
    return "";
}

std::string SqliteSqlBuilder::NormalizeAlias(const std::string &source, int &errorCode)
{
    errorCode = 0;
    if (StringUtils::IsEmpty(source)) {
        return "";
    }
    std::string strTrimed = StringUtils::Trim(source);
    std::regex pattern("^(.+)\\s+(AS|as)\\s+(" + patternWords_ + ")$");
    std::smatch result;
    bool columnMatcher = std::regex_match(strTrimed, result, pattern);
    if (!columnMatcher) {
        return Normalize(strTrimed, errorCode);
    }
    std::string words = StringUtils::Trim(result[1]);
    if (StringUtils::IsEmpty(words)) {
        errorCode = E_SQLITE_SQL_BUILDER_NORMALIZE_FAIL;
        return "";
    }
    std::string aresult = Normalize(words, errorCode);
    if (StringUtils::IsEmpty(aresult)) {
        LOG_DEBUG("NormalizeAlias words no match Normalize %{public}s", words.c_str());
        return "";
    }

    std::string alias = result[3];
    if (StringUtils::IsEmpty(alias)) {
        LOG_DEBUG("NormalizeAlias alias is empty");
        return aresult;
    }
    std::string obj = aresult.substr(aresult.length() - 1, 1);
    if ("*" == obj) {
        errorCode = E_SQLITE_SQL_BUILDER_NORMALIZE_FAIL;
        return "";
    }
    std::string presult = NormalizeWords(alias, errorCode);
    if (!StringUtils::IsEmpty(presult)) {
        LOG_DEBUG("NormalizeAlias alias no match NormalizeWords %{public}s", alias.c_str());
        aresult.append(" as ").append(presult);
    }
    return aresult;
}
} // namespace NativeRdb
} // namespace OHOS
