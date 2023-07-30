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

#include "abs_predicates.h"

#include <algorithm>
#include <initializer_list>

#include "logger.h"
#include "rdb_trace.h"
#include "sqlite_sql_builder.h"
#include "string_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

AbsPredicates::AbsPredicates()
{
    Initial();
}

AbsPredicates::~AbsPredicates()
{
}

void AbsPredicates::Clear()
{
    Initial();
}

bool AbsPredicates::IsNeedAnd() const
{
    return isNeedAnd;
}

/**
 * Restricts the value of the field to be greater than the specified value.
 */
AbsPredicates *AbsPredicates::EqualTo(const std::string &field, const ValueObject &value)
{
    bool chekParaFlag = CheckParameter("equalTo", field, { value });
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: EqualTo() fails because Invalid parameter.");
        return this;
    }
    if (isNeedAnd) {
        whereClause += "AND ";
    } else {
        isNeedAnd = true;
    }
    whereClause += field + " = ? ";
    bindArgs.push_back(value);
    return this;
}

/**
 * Restricts the value of the field to be unequal to the specified value.
 */
AbsPredicates *AbsPredicates::NotEqualTo(const std::string &field, const ValueObject &value)
{
    bool chekParaFlag = CheckParameter("notEqualTo", field, { value });
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: NotEqualTo() fails because Invalid parameter.");
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " <> ? ";
    bindArgs.push_back(value);
    return this;
}

AbsPredicates *AbsPredicates::BeginWrap()
{
    if (isNeedAnd) {
        whereClause += "AND ";
        isNeedAnd = false;
    }
    whereClause += " ( ";
    return this;
}

AbsPredicates *AbsPredicates::EndWrap()
{
    if (!isNeedAnd) {
        LOG_WARN("fail to add EndWrap.");
        return this;
    }
    whereClause += " ) ";
    return this;
}

AbsPredicates *AbsPredicates::Or()
{
    if (!isNeedAnd) {
        LOG_WARN("fail to add Or.");
        return this;
    }
    whereClause += " OR ";
    isNeedAnd = false;
    return this;
}

AbsPredicates *AbsPredicates::And()
{
    if (!isNeedAnd) {
        LOG_WARN("fail to add And.");
        return this;
    }
    return this;
}

/**
 * Restricts the value of the field to contain the specified string.
 */
AbsPredicates *AbsPredicates::Contains(const std::string &field, const std::string &value)
{
    bool chekParaFlag = CheckParameter("contains", field, { value });
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: Contains() fails because Invalid parameter.");
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " LIKE ? ";
    bindArgs.push_back(ValueObject("%" + value + "%"));
    return this;
}

/**
 * Restricts the field to start with the specified string.
 */
AbsPredicates *AbsPredicates::BeginsWith(const std::string &field, const std::string &value)
{
    bool chekParaFlag = CheckParameter("beginsWith", field, { value });
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: BeginsWith() fails because Invalid parameter.");
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " LIKE ? ";
    bindArgs.push_back(ValueObject(value + "%"));
    return this;
}

/**
 * Restricts the field to end with the specified string.
 */
AbsPredicates *AbsPredicates::EndsWith(const std::string &field, const std::string &value)
{
    bool chekParaFlag = CheckParameter("endsWith", field, { value });
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: EndsWith() fails because Invalid parameter.");
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " LIKE ? ";
    bindArgs.push_back(ValueObject("%" + value));
    return this;
}

/**
 * Restricts the value of the field to be null.
 */
AbsPredicates *AbsPredicates::IsNull(const std::string &field)
{
    bool chekParaFlag = CheckParameter("isNull", field, {});
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: IsNull() fails because Invalid parameter.");
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " is null ";
    return this;
}

/**
 * estricts the value of the field not to be null.
 */
AbsPredicates *AbsPredicates::IsNotNull(const std::string &field)
{
    bool chekParaFlag = CheckParameter("isNotNull", field, {});
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: IsNotNull() fails because Invalid parameter.");
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " is not null ";
    return this;
}

/**
 * Restricts the value of the field to have a pattern like field.
 */
AbsPredicates *AbsPredicates::Like(const std::string &field, const std::string &value)
{
    bool chekParaFlag = CheckParameter("like", field, { value });
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: Like() fails because Invalid parameter.");
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " LIKE ? ";
    bindArgs.push_back(ValueObject(value));
    return this;
}

/**
 * Configures to match the specified field whose data type is String and the value contains a wildcard.
 */
AbsPredicates *AbsPredicates::Glob(const std::string &field, const std::string &value)
{
    bool chekParaFlag = CheckParameter("glob", field, { value });
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: Glob() fails because Invalid parameter.");
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " GLOB ? ";
    bindArgs.push_back(value);
    return this;
}

/**
 * Restricts the value of the field to be unequal to the specified value.
 */
AbsPredicates *AbsPredicates::Between(const std::string &field, const ValueObject &low, const ValueObject &high)
{
    bool chekParaFlag = CheckParameter("between", field, { low, high });
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: Between() fails because Invalid parameter.");
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " BETWEEN ? AND ? ";
    bindArgs.push_back(low);
    bindArgs.push_back(high);
    return this;
}

/**
 * Configures to match the specified field whose data type is String and value is out of a given range.
 */
AbsPredicates *AbsPredicates::NotBetween(const std::string &field, const ValueObject &low, const ValueObject &high)
{
    bool chekParaFlag = CheckParameter("notBetween", field, { low, high });
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: NotBetween() fails because Invalid parameter.");
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " NOT BETWEEN ? AND ? ";
    bindArgs.push_back(low);
    bindArgs.push_back(high);
    return this;
}

/**
 * Restricts the value of the field to be greater than the specified value.
 */
AbsPredicates *AbsPredicates::GreaterThan(const std::string &field, const ValueObject &value)
{
    bool chekParaFlag = CheckParameter("greaterThan", field, { value });
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: GreaterThan() fails because Invalid parameter.");
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " > ? ";
    bindArgs.push_back(value);
    return this;
}

/**
 * Restricts the value of the field to be smaller than the specified value.
 */
AbsPredicates *AbsPredicates::LessThan(const std::string &field, const ValueObject &value)
{
    bool chekParaFlag = CheckParameter("lessThan", field, { value });
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: LessThan() fails because Invalid parameter.");
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " < ? ";
    bindArgs.push_back(value);
    return this;
}

/**
 * Restricts the value of the field to be greater than or equal to the specified value.
 */
AbsPredicates *AbsPredicates::GreaterThanOrEqualTo(const std::string &field, const ValueObject &value)
{
    bool chekParaFlag = CheckParameter("greaterThanOrEqualTo", field, { value });
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: GreaterThanOrEqualTo() fails because Invalid parameter.");
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " >= ? ";
    bindArgs.push_back(value);
    return this;
}

/**
 * Restricts the value of the field to be smaller than or equal to the specified value.
 */
AbsPredicates *AbsPredicates::LessThanOrEqualTo(const std::string &field, const ValueObject &value)
{
    bool chekParaFlag = CheckParameter("greaterThanOrEqualTo", field, { value });
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: LessThanOrEqualTo() fails because Invalid parameter.");
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " <= ? ";
    bindArgs.push_back(value);
    return this;
}

/**
 * Restricts the ascending order of the return list. When there are several orders,
 * the one close to the head has the highest priority.
 */
AbsPredicates *AbsPredicates::OrderByAsc(const std::string &field)
{
    bool chekParaFlag = CheckParameter("orderByAsc", field, {});
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: OrderByAsc() fails because Invalid parameter.");
        return this;
    }
    if (isSorted) {
        order += ',';
    }
    order += field + " ASC ";
    isSorted = true;
    return this;
}

/**
 * Restricts the descending order of the return list. When there are several orders,
 * the one close to the head has the highest priority.
 */
AbsPredicates *AbsPredicates::OrderByDesc(const std::string &field)
{
    bool chekParaFlag = CheckParameter("orderByDesc", field, {});
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: OrderByDesc() fails because Invalid parameter.");
        return this;
    }
    if (isSorted) {
        order += ',';
    }
    order += field + " DESC ";
    isSorted = true;
    return this;
}

AbsPredicates *AbsPredicates::Distinct()
{
    distinct = true;
    return this;
}

/**
 * Restricts the max number of return records.
 */
AbsPredicates *AbsPredicates::Limit(const int limit)
{
    this->limit = (limit <= 0) ? -1 : limit;
    return this;
}

/**
 * Restricts the max number of return records.
 */
AbsPredicates *AbsPredicates::Limit(const int offset, const int limit)
{
    return this->Limit(limit)->Offset(offset);
}

/**
 * Configures to specify the start position of the returned result.
 */
AbsPredicates *AbsPredicates::Offset(const int offset)
{
    this->offset = (offset < 0) ? -1 : offset;
    return this;
}

/**
 * Configures {@code AbsPredicates} to group query results by specified columns.
 */
AbsPredicates *AbsPredicates::GroupBy(const std::vector<std::string> &fields)
{
    if (fields.empty()) {
        LOG_WARN("AbsPredicates: groupBy() fails because fields can't be null.");
        return this;
    }
    for (auto &field : fields) {
        bool chekParaFlag = CheckParameter("GroupBy", field, {});
        if (!chekParaFlag) {
            LOG_WARN("AbsPredicates: GroupBy() fails because Invalid parameter.");
            return this;
        }
        group += field + ",";
    }
    size_t pos = group.find_last_of(",");
    if (pos != group.npos) {
        group.erase(pos, 1);
    }
    return this;
}

/**
 * Configures {@code AbsPredicates} to specify the index column.
 */
AbsPredicates *AbsPredicates::IndexedBy(const std::string &indexName)
{
    bool chekParaFlag = CheckParameter("indexedBy", indexName, {});
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: IndexedBy() fails because Invalid parameter.");
        return this;
    }
    index = RemoveQuotes(indexName);
    return this;
}

AbsPredicates *AbsPredicates::In(const std::string &field, const std::vector<std::string> &values)
{
    std::vector<ValueObject> bindArgs;
    for (auto &arg : values) {
        bindArgs.push_back(ValueObject(arg));
    }
    return In(field, bindArgs);
}

/**
 * Configures to match the specified field whose data type is String array and values are within a given range.
 */
AbsPredicates *AbsPredicates::In(const std::string &field, const std::vector<ValueObject> &values)
{
    bool chekParaFlag = CheckParameter("in", field, {});
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: In() fails because Invalid parameter.");
        return this;
    }
    if (values.empty()) {
        LOG_WARN("AbsPredicates: in() fails because values can't be null.");
        return this;
    }

    CheckIsNeedAnd();

    std::vector<std::string> replaceValues;
    for (auto &value : values) {
        replaceValues.push_back("?");
        bindArgs.push_back(std::move(value));
    }
    AppendWhereClauseWithInOrNotIn(" IN ", field, replaceValues);
    return this;
}

AbsPredicates *AbsPredicates::NotIn(const std::string &field, const std::vector<std::string> &values)
{
    std::vector<ValueObject> bindArgs;
    for (auto &arg : values) {
        bindArgs.push_back(ValueObject(arg));
    }
    return NotIn(field, bindArgs);
}

/**
 * Configures to match the specified field whose data type is String array and values are out of a given range.
 */
AbsPredicates *AbsPredicates::NotIn(const std::string &field, const std::vector<ValueObject> &values)
{
    bool chekParaFlag = CheckParameter("notIn", field, {});
    if (!chekParaFlag) {
        LOG_WARN("AbsPredicates: NotIn() fails because Invalid parameter.");
        return this;
    }
    if (values.empty()) {
        LOG_WARN("AbsPredicates: notIn() fails because values is null.");
        return this;
    }
    CheckIsNeedAnd();
    std::vector<std::string> replaceValues;
    for (auto &value : values) {
        replaceValues.push_back("?");
        bindArgs.push_back(std::move(value));
    }
    AppendWhereClauseWithInOrNotIn(" NOT IN ", field, replaceValues);
    return this;
}

void AbsPredicates::Initial()
{
    distinct = false;
    isNeedAnd = false;
    isSorted = false;
    bindArgs.clear();
    whereClause.clear();
    order.clear();
    group.clear();
    index.clear();
    limit = INT_MIN;
    offset = INT_MIN;
}

/**
 * Check the parameter validity.
 */
bool AbsPredicates::CheckParameter(
    const std::string &methodName, const std::string &field, const std::initializer_list<ValueObject> &args) const
{
    if (field.empty()) {
        LOG_WARN("%{public}s: string 'field' is empty.", methodName.c_str());
        return false;
    }
    for (auto &arg : args) {
        if (auto pval = std::get_if<std::string>(&arg.value)) {
            if ((*pval).empty()) {
                LOG_WARN("%{public}s: value is empty.", methodName.c_str());
                return false;
            }
        }
    }
    return true;
}

std::string AbsPredicates::RemoveQuotes(const std::string &source) const
{
    std::string src = source;
    if (source.empty()) {
        return source;
    }
    src.erase(std::remove(src.begin(), src.end(), '\''), src.end());
    src.erase(std::remove(src.begin(), src.end(), '\"'), src.end());
    src.erase(std::remove(src.begin(), src.end(), '`'), src.end());
    return src;
}

void AbsPredicates::CheckIsNeedAnd()
{
    if (isNeedAnd) {
        whereClause += " AND ";
    } else {
        isNeedAnd = true;
    }
}

void AbsPredicates::AppendWhereClauseWithInOrNotIn(
    const std::string &methodName, const std::string &field, const std::vector<std::string> &replaceValues)
{
    whereClause += field + StringUtils::SurroundWithFunction(methodName, ",", replaceValues);
}

std::string AbsPredicates::GetWhereClause() const
{
    return whereClause;
}

void AbsPredicates::SetWhereClause(const std::string &whereClause)
{
    if (whereClause.empty()) {
        return;
    }
    this->whereClause = whereClause;
}

std::vector<std::string> AbsPredicates::GetWhereArgs() const
{
    std::vector<std::string> whereArgs;
    for (auto &arg : this->bindArgs) {
        if (auto pval = std::get_if<std::string>(&arg.value)){
            whereArgs.push_back(std::get<std::string>(arg.value));
        }
    }
    return whereArgs;
}

void AbsPredicates::SetWhereArgs(const std::vector<std::string> &whereArgs)
{
    this->bindArgs.clear();
    for (auto &arg : whereArgs) {
        this->bindArgs.push_back(ValueObject(arg));
    }
}

std::vector<ValueObject> AbsPredicates::GetBindArgs() const
{
    return bindArgs;
}

void AbsPredicates::SetBindArgs(const std::vector<ValueObject> &bindArgs)
{
    this->bindArgs = bindArgs;
}

std::string AbsPredicates::GetOrder() const
{
    return order;
}

void AbsPredicates::SetOrder(const std::string &order)
{
    if (order.empty()) {
        return;
    }
    this->order = order;
}

int AbsPredicates::GetLimit() const
{
    return limit;
}

int AbsPredicates::GetOffset() const
{
    return offset;
}

bool AbsPredicates::IsDistinct() const
{
    return distinct;
}

bool AbsPredicates::IsSorted() const
{
    return isSorted;
}

std::string AbsPredicates::GetGroup() const
{
    return group;
}

std::string AbsPredicates::GetIndex() const
{
    return index;
}
} // namespace NativeRdb
} // namespace OHOS