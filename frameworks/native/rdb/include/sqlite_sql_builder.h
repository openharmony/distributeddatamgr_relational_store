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
    using RefValue = std::reference_wrapper<ValueObject>;
    using BatchRefSqls = std::vector<std::pair<std::string, std::vector<std::vector<RefValue>>>>;
    SqliteSqlBuilder();
    ~SqliteSqlBuilder();
    static int BuildQueryString(bool distinct, const std::string &table, const std::string &joinClause,
        const std::vector<std::string> &columns, const std::string &whereClause, const std::string &groupBy,
        const std::string &indexName, const std::string &orderBy, int limit, int offset, std::string &outSql);
    static std::string BuildQueryString(const AbsRdbPredicates &predicates, const std::vector<std::string> &columns);
    static std::string BuildCountString(const AbsRdbPredicates &predicates);
    static std::string BuildClauseFromPredicates(const AbsRdbPredicates &predicates);
    static std::string BuildCursorQueryString(const AbsRdbPredicates &predicates,
        const std::vector<std::string> &columns, const std::string &logTable, const std::pair<bool, bool> &queryStatus);
    static std::string BuildLockRowQueryString(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns, const std::string &logTable);
    static std::string GetSqlArgs(size_t size);

    static void AppendReturning(std::string &sql, const std::vector<std::string> &fields);

    static BatchRefSqls GenerateSqls(const std::string &table, const ValuesBuckets &buckets, int limit,
        ConflictResolution resolution = ConflictResolution::ON_CONFLICT_REPLACE);
    static void UpdateAssetStatus(const ValueObject &value, int32_t status);

private:
    static BatchRefSqls MakeExecuteSqls(
        const std::string &sql, const std::vector<RefValue> &args, int fieldSize, int limit);
    static void AppendClause(
        std::string &builder, const std::string &name, const std::string &clause, const std::string &table = "");
    static void AppendColumns(
        std::string &builder, const std::vector<std::string> &columns, const std::string &table = "");
    static void AppendLimitAndOffset(std::string &builder, int limit, int offset);
    static std::string GetSelectClause(const std::vector<std::string> &columns, bool IsDistinct,
        const std::string &ast, const std::string &table = "");
    static constexpr const char *SHARING_RESOURCE = "sharing_resource";
    static constexpr uint32_t EXPANSION = 2;
    static ValueObject nullObject_;
    static std::reference_wrapper<ValueObject> nullRef_;
};
} // namespace NativeRdb
} // namespace OHOS
#endif
