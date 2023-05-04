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
class API_EXPORT AbsPredicates {
public:
    API_EXPORT AbsPredicates();
    API_EXPORT virtual ~AbsPredicates();

    enum JoinType {
        INNER,
        LEFT,
        CROSS
    };

    API_EXPORT std::string GetWhereClause() const;
    API_EXPORT void SetWhereClause(std::string whereClause);
    API_EXPORT std::vector<std::string> GetWhereArgs() const;
    API_EXPORT void SetWhereArgs(std::vector<std::string> whereArgs);
    API_EXPORT std::string GetOrder() const;
    API_EXPORT void SetOrder(std::string order);
    API_EXPORT int GetLimit() const;
    API_EXPORT int GetOffset() const;
    API_EXPORT bool IsDistinct() const;
    API_EXPORT std::string GetGroup() const;
    API_EXPORT std::string GetIndex() const;
    API_EXPORT bool IsNeedAnd() const;
    API_EXPORT bool IsSorted() const;

public:
    API_EXPORT virtual void Clear();
    API_EXPORT virtual AbsPredicates *EqualTo(std::string field, std::string value);
    API_EXPORT virtual AbsPredicates *NotEqualTo(std::string field, std::string value);
    API_EXPORT virtual AbsPredicates *BeginWrap();
    API_EXPORT virtual AbsPredicates *EndWrap();
    API_EXPORT virtual AbsPredicates *Or();
    API_EXPORT virtual AbsPredicates *And();
    API_EXPORT virtual AbsPredicates *Contains(std::string field, std::string value);
    API_EXPORT virtual AbsPredicates *BeginsWith(std::string field, std::string value);
    API_EXPORT virtual AbsPredicates *EndsWith(std::string field, std::string value);
    API_EXPORT virtual AbsPredicates *IsNull(std::string field);
    API_EXPORT virtual AbsPredicates *IsNotNull(std::string field);
    API_EXPORT virtual AbsPredicates *Like(std::string field, std::string value);
    API_EXPORT virtual AbsPredicates *Glob(std::string field, std::string value);
    API_EXPORT virtual AbsPredicates *Between(std::string field, std::string low, std::string high);
    API_EXPORT virtual AbsPredicates *NotBetween(std::string field, std::string low, std::string high);
    API_EXPORT virtual AbsPredicates *GreaterThan(std::string field, std::string value);
    API_EXPORT virtual AbsPredicates *LessThan(std::string field, std::string value);
    API_EXPORT virtual AbsPredicates *GreaterThanOrEqualTo(std::string field, std::string value);
    API_EXPORT virtual AbsPredicates *LessThanOrEqualTo(std::string field, std::string value);
    API_EXPORT virtual AbsPredicates *OrderByAsc(std::string field);
    API_EXPORT virtual AbsPredicates *OrderByDesc(std::string field);
    API_EXPORT virtual AbsPredicates *Distinct();
    API_EXPORT virtual AbsPredicates *Limit(int value);
    API_EXPORT virtual AbsPredicates *Offset(int rowOffset);
    API_EXPORT virtual AbsPredicates *GroupBy(std::vector<std::string> fields);
    API_EXPORT virtual AbsPredicates *IndexedBy(std::string indexName);
    API_EXPORT virtual AbsPredicates *In(std::string field, std::vector<std::string> values);
    API_EXPORT virtual AbsPredicates *NotIn(std::string field, std::vector<std::string> values);

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