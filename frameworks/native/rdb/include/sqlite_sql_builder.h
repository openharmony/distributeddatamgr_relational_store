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

#ifndef NATIVE_RDB_SQLITE_SQL_BUILDER_H
#define NATIVE_RDB_SQLITE_SQL_BUILDER_H

#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "rdb_store.h"
namespace OHOS {
namespace NativeRdb {
class SqliteSqlBuilder {
public:
    using ExecuteSqls = std::vector<std::pair<std::string, std::vector<std::vector<ValueObject>>>>;
    SqliteSqlBuilder();
    ~SqliteSqlBuilder();
    static std::string BuildDeleteString(const std::string &tableName, const std::string &index,
        const std::string &whereClause, const std::string &group, const std::string &order, int limit, int offset);
    static std::string BuildUpdateString(const ValuesBucket &values, const std::string &tableName,
        const std::vector<std::string> &whereArgs, const std::string &index, const std::string &whereClause,
        const std::string &group, const std::string &order, int limit, int offset, std::vector<ValueObject> &bindArgs,
        ConflictResolution conflictResolution);
    static int BuildQueryString(bool distinct, const std::string &table, const std::string &joinClause,
        const std::vector<std::string> &columns, const std::string &whereClause, const std::string &groupBy,
        const std::string &indexName, const std::string &orderBy, const int &limit,
        const int &offset, std::string &outSql);
    static std::string BuildCountString(const std::string &tableName, const std::string &index,
        const std::string &whereClause, const std::string &group, const std::string &order, int limit, int offset);
    static std::string BuildSqlStringFromPredicates(const std::string &index, const std::string &joinClause,
        const std::string &whereClause, const std::string &group, const std::string &order, int limit, int offset);
    static std::string BuildSqlStringFromPredicatesNoWhere(const std::string &index, const std::string &whereClause,
        const std::string &group, const std::string &order, int limit, int offset);
    static std::string BuildQueryString(const AbsRdbPredicates &predicates, const std::vector<std::string> &columns);
    static std::string BuildCountString(const AbsRdbPredicates &predicates);
    static std::string BuildSqlStringFromPredicates(const AbsPredicates &predicates);
    static std::string BuildCursorQueryString(const AbsRdbPredicates &predicates,
        const std::vector<std::string> &columns, const std::string &logTable, const std::pair<bool, bool> &queryStatus);
    static std::string BuildLockRowQueryString(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns, const std::string &logTable);
    static std::string GetSqlArgs(size_t size);

    static ExecuteSqls MakeExecuteSqls(
        const std::string &sql, std::vector<ValueObject> &&args, int fieldSize, int limit);
private:
    static void AppendClause(std::string &builder, const std::string &name,
        const std::string &clause, const std::string &table = "");
    static void AppendColumns(
        std::string &builder, const std::vector<std::string> &columns, const std::string &table = "");

    static constexpr const char *SHARING_RESOURCE = "sharing_resource";
};
} // namespace NativeRdb
} // namespace OHOS
#endif
