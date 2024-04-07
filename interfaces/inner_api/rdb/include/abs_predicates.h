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

#include <climits>
#include <string>
#include <vector>

#include "rdb_visibility.h"
#include "value_object.h"

namespace OHOS {
namespace NativeRdb {
class API_EXPORT AbsPredicates {
public:
    static constexpr int INIT_LIMIT_VALUE = INT_MIN;
    static constexpr int INIT_OFFSET_VALUE = INT_MIN;
    API_EXPORT AbsPredicates();
    API_EXPORT virtual ~AbsPredicates();

    enum JoinType {
        INNER,
        LEFT,
        CROSS
    };

    enum Origin {
        LOCAL = 0,
        CLOUD,
        REMOTE,
        BUTT
    };

    API_EXPORT std::string GetStatement() const;
    API_EXPORT std::string GetWhereClause() const;
    API_EXPORT void SetWhereClause(const std::string &whereClause);
    [[deprecated("Use GetBindArgs() instead.")]]
    API_EXPORT std::vector<std::string> GetWhereArgs() const;
    API_EXPORT std::vector<ValueObject> GetBindArgs() const;
    [[deprecated("Use SetBindArgs() instead.")]]
    API_EXPORT void SetWhereArgs(const std::vector<std::string> &whereArgs);
    API_EXPORT void SetBindArgs(const std::vector<ValueObject> &bindArgs);
    API_EXPORT std::string GetOrder() const;
    API_EXPORT void SetOrder(const std::string &order);
    API_EXPORT int GetLimit() const;
    API_EXPORT int GetOffset() const;
    API_EXPORT bool IsDistinct() const;
    API_EXPORT std::string GetGroup() const;
    API_EXPORT std::string GetIndex() const;
    API_EXPORT bool IsNeedAnd() const;
    API_EXPORT bool IsSorted() const;
    API_EXPORT bool HasSpecificField() const;

public:
    API_EXPORT virtual void Clear();
    API_EXPORT virtual AbsPredicates *EqualTo(const std::string &field, const ValueObject &value);
    API_EXPORT virtual AbsPredicates *NotEqualTo(const std::string &field, const ValueObject &value);
    API_EXPORT virtual AbsPredicates *BeginWrap();
    API_EXPORT virtual AbsPredicates *EndWrap();
    API_EXPORT virtual AbsPredicates *Or();
    API_EXPORT virtual AbsPredicates *And();
    API_EXPORT virtual AbsPredicates *Contains(const std::string &field, const std::string &value);
    API_EXPORT virtual AbsPredicates *NotContains(const std::string &field, const std::string &value);
    API_EXPORT virtual AbsPredicates *BeginsWith(const std::string &field, const std::string &value);
    API_EXPORT virtual AbsPredicates *EndsWith(const std::string &field, const std::string &value);
    API_EXPORT virtual AbsPredicates *IsNull(const std::string &field);
    API_EXPORT virtual AbsPredicates *IsNotNull(const std::string &field);
    API_EXPORT virtual AbsPredicates *Like(const std::string &field, const std::string &value);
    API_EXPORT virtual AbsPredicates *NotLike(const std::string &field, const std::string &value);
    API_EXPORT virtual AbsPredicates *Glob(const std::string &field, const std::string &value);
    API_EXPORT virtual AbsPredicates *Between(
        const std::string &field, const ValueObject &low, const ValueObject &high);
    API_EXPORT virtual AbsPredicates *NotBetween(
        const std::string &field, const ValueObject &low, const ValueObject &high);
    API_EXPORT virtual AbsPredicates *GreaterThan(const std::string &field, const ValueObject &value);
    API_EXPORT virtual AbsPredicates *LessThan(const std::string &field, const ValueObject &value);
    API_EXPORT virtual AbsPredicates *GreaterThanOrEqualTo(const std::string &field, const ValueObject &value);
    API_EXPORT virtual AbsPredicates *LessThanOrEqualTo(const std::string &field, const ValueObject &value);
    API_EXPORT virtual AbsPredicates *OrderByAsc(const std::string &field);
    API_EXPORT virtual AbsPredicates *OrderByDesc(const std::string &field);
    API_EXPORT virtual AbsPredicates *Distinct();
    API_EXPORT virtual AbsPredicates *Limit(const int limit);
    API_EXPORT virtual AbsPredicates *Limit(const int offset, const int limit);
    API_EXPORT virtual AbsPredicates *Offset(const int offset);
    API_EXPORT virtual AbsPredicates *GroupBy(const std::vector<std::string> &fields);
    API_EXPORT virtual AbsPredicates *IndexedBy(const std::string &indexName);
    [[deprecated("Use In(const std::string &, const std::vector<ValueObject> &) instead.")]]
    API_EXPORT virtual AbsPredicates *In(const std::string &field, const std::vector<std::string> &values);
    API_EXPORT virtual AbsPredicates *In(const std::string &field, const std::vector<ValueObject> &values);
    [[deprecated("Use NotIn(const std::string &, const std::vector<ValueObject> &) instead.")]]
    API_EXPORT virtual AbsPredicates *NotIn(const std::string &field, const std::vector<std::string> &values);
    API_EXPORT virtual AbsPredicates *NotIn(const std::string &field, const std::vector<ValueObject> &values);
private:
    static constexpr const char *LOG_ORIGIN_FIELD = "#_flag";

    std::string whereClause;
    std::vector<ValueObject> bindArgs;
    std::string order;
    std::string group;
    std::string index;
    int limit;
    int offset;
    bool distinct;
    bool isNeedAnd;
    bool isSorted;
    bool hasSpecificField = false;

    void Initial();
    bool CheckParameter(
        const std::string &methodName, const std::string &field, const std::initializer_list<ValueObject> &args) const;
    inline bool IsSpecificField(const std::string &field)
    {
        return field.find("#_") != std::string::npos;
    }
    std::string RemoveQuotes(const std::string &source) const;
    void CheckIsNeedAnd();
    void AppendWhereClauseWithInOrNotIn(const std::string &methodName, const std::string &field,
        const std::vector<std::string> &replaceValues);
};
} // namespace NativeRdb
} // namespace OHOS

#endif