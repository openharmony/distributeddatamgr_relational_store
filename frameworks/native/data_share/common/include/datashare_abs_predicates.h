/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DATASHARE_ABSPREDICATES_H
#define DATASHARE_ABSPREDICATES_H

#include <string>
#include <vector>

namespace OHOS {
namespace DataShare {
class DataShareAbsPredicates {
public:
    DataShareAbsPredicates();
    virtual ~DataShareAbsPredicates();

    enum JoinType {
        INNER,
        LEFT,
        CROSS
    };

    std::string GetWhereClause() const;
    void SetWhereClause(std::string whereClause);
    std::vector<std::string> GetWhereArgs() const;
    void SetWhereArgs(std::vector<std::string> whereArgs);
    std::string GetOrder() const;
    void SetOrder(std::string order);
    int GetLimit() const;
    int GetOffset() const;
    bool IsDistinct() const;
    std::string GetGroup() const;
    std::string GetIndex() const;
    bool IsNeedAnd() const;
    bool IsSorted() const;

public:
    virtual void Clear();
    virtual DataShareAbsPredicates *EqualTo(std::string field, std::string value);
    virtual DataShareAbsPredicates *NotEqualTo(std::string field, std::string value);
    virtual DataShareAbsPredicates *BeginWrap();
    virtual DataShareAbsPredicates *EndWrap();
    virtual DataShareAbsPredicates *Or();
    virtual DataShareAbsPredicates *And();
    virtual DataShareAbsPredicates *Contains(std::string field, std::string value);
    virtual DataShareAbsPredicates *BeginsWith(std::string field, std::string value);
    virtual DataShareAbsPredicates *EndsWith(std::string field, std::string value);
    virtual DataShareAbsPredicates *IsNull(std::string field);
    virtual DataShareAbsPredicates *IsNotNull(std::string field);
    virtual DataShareAbsPredicates *Like(std::string field, std::string value);
    virtual DataShareAbsPredicates *Glob(std::string field, std::string value);
    virtual DataShareAbsPredicates *Between(std::string field, std::string low, std::string high);
    virtual DataShareAbsPredicates *NotBetween(std::string field, std::string low, std::string high);
    virtual DataShareAbsPredicates *GreaterThan(std::string field, std::string value);
    virtual DataShareAbsPredicates *LessThan(std::string field, std::string value);
    virtual DataShareAbsPredicates *GreaterThanOrEqualTo(std::string field, std::string value);
    virtual DataShareAbsPredicates *LessThanOrEqualTo(std::string field, std::string value);
    virtual DataShareAbsPredicates *OrderByAsc(std::string field);
    virtual DataShareAbsPredicates *OrderByDesc(std::string field);
    virtual DataShareAbsPredicates *Distinct();
    virtual DataShareAbsPredicates *Limit(int value);
    virtual DataShareAbsPredicates *Offset(int rowOffset);
    virtual DataShareAbsPredicates *GroupBy(std::vector<std::string> fields);
    virtual DataShareAbsPredicates *IndexedBy(std::string indexName);
    virtual DataShareAbsPredicates *In(std::string field, std::vector<std::string> values);
    virtual DataShareAbsPredicates *NotIn(std::string field, std::vector<std::string> values);

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
} // namespace DataShare
} // namespace OHOS

#endif