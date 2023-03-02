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

#ifndef NATIVE_RDB_ABSPREDICATES_H
#define NATIVE_RDB_ABSPREDICATES_H

#include <string>
#include <vector>
#include "rdb_visibility.h"

namespace OHOS {
namespace NativeRdb {
class RDB_API_EXPORT AbsPredicates {
public:
    RDB_API_EXPORT AbsPredicates();
    RDB_API_EXPORT virtual ~AbsPredicates();

    enum JoinType {
        INNER,
        LEFT,
        CROSS
    };

    RDB_API_EXPORT std::string GetWhereClause() const;
    RDB_API_EXPORT void SetWhereClause(std::string whereClause);
    RDB_API_EXPORT std::vector<std::string> GetWhereArgs() const;
    RDB_API_EXPORT void SetWhereArgs(std::vector<std::string> whereArgs);
    RDB_API_EXPORT std::string GetOrder() const;
    RDB_API_EXPORT void SetOrder(std::string order);
    RDB_API_EXPORT int GetLimit() const;
    RDB_API_EXPORT int GetOffset() const;
    RDB_API_EXPORT bool IsDistinct() const;
    RDB_API_EXPORT std::string GetGroup() const;
    RDB_API_EXPORT std::string GetIndex() const;
    RDB_API_EXPORT bool IsNeedAnd() const;
    RDB_API_EXPORT bool IsSorted() const;

public:
    RDB_API_EXPORT virtual void Clear();
    RDB_API_EXPORT virtual AbsPredicates *EqualTo(std::string field, std::string value);
    RDB_API_EXPORT virtual AbsPredicates *NotEqualTo(std::string field, std::string value);
    RDB_API_EXPORT virtual AbsPredicates *BeginWrap();
    RDB_API_EXPORT virtual AbsPredicates *EndWrap();
    RDB_API_EXPORT virtual AbsPredicates *Or();
    RDB_API_EXPORT virtual AbsPredicates *And();
    RDB_API_EXPORT virtual AbsPredicates *Contains(std::string field, std::string value);
    RDB_API_EXPORT virtual AbsPredicates *BeginsWith(std::string field, std::string value);
    RDB_API_EXPORT virtual AbsPredicates *EndsWith(std::string field, std::string value);
    RDB_API_EXPORT virtual AbsPredicates *IsNull(std::string field);
    RDB_API_EXPORT virtual AbsPredicates *IsNotNull(std::string field);
    RDB_API_EXPORT virtual AbsPredicates *Like(std::string field, std::string value);
    RDB_API_EXPORT virtual AbsPredicates *Glob(std::string field, std::string value);
    RDB_API_EXPORT virtual AbsPredicates *Between(std::string field, std::string low, std::string high);
    RDB_API_EXPORT virtual AbsPredicates *NotBetween(std::string field, std::string low, std::string high);
    RDB_API_EXPORT virtual AbsPredicates *GreaterThan(std::string field, std::string value);
    RDB_API_EXPORT virtual AbsPredicates *LessThan(std::string field, std::string value);
    RDB_API_EXPORT virtual AbsPredicates *GreaterThanOrEqualTo(std::string field, std::string value);
    RDB_API_EXPORT virtual AbsPredicates *LessThanOrEqualTo(std::string field, std::string value);
    RDB_API_EXPORT virtual AbsPredicates *OrderByAsc(std::string field);
    RDB_API_EXPORT virtual AbsPredicates *OrderByDesc(std::string field);
    RDB_API_EXPORT virtual AbsPredicates *Distinct();
    RDB_API_EXPORT virtual AbsPredicates *Limit(int value);
    RDB_API_EXPORT virtual AbsPredicates *Offset(int rowOffset);
    RDB_API_EXPORT virtual AbsPredicates *GroupBy(std::vector<std::string> fields);
    RDB_API_EXPORT virtual AbsPredicates *IndexedBy(std::string indexName);
    RDB_API_EXPORT virtual AbsPredicates *In(std::string field, std::vector<std::string> values);
    RDB_API_EXPORT virtual AbsPredicates *NotIn(std::string field, std::vector<std::string> values);

private:
    std::string whereClause;
    std::vector<std::string> whereArgs;
    std::string order;
    std::string group;
    std::string index;
    int limit;
    int offset;
    bool distinct;
    bool isNeedAnd;
    bool isSorted;

    void Initial();
    bool CheckParameter(std::string methodName, std::string field, std::initializer_list<std::string> args) const;
    std::string RemoveQuotes(std::string source) const;
    std::string Normalized(std::string source);
    void CheckIsNeedAnd();
    void AppendWhereClauseWithInOrNotIn(std::string methodName, std::string field,
        std::vector<std::string> replaceValues);
};
} // namespace NativeRdb
} // namespace OHOS

#endif