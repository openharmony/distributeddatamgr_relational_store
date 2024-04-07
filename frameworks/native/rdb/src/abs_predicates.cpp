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
#define LOG_TAG "AbsPredicates"
#include "abs_predicates.h"

#include <algorithm>
#include <initializer_list>
#include <variant>

#include "logger.h"
#include "rdb_trace.h"
#include "rdb_types.h"
#include "sqlite_sql_builder.h"
#include "string_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
static constexpr const char* FLAG[AbsPredicates::Origin::BUTT] = { "0x02", "0x0", "0x0" };
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
    if (!CheckParameter("equalTo", field, {})) {
        return this;
    }
    hasSpecificField = hasSpecificField || IsSpecificField(field);
    ValueObject valObj = value;
    std::string newField = field;
    std::string flagVal;
    if (newField == DistributedRdb::Field::ORIGIN_FIELD) {
        newField = LOG_ORIGIN_FIELD;
        double location = 0;
        valObj.GetDouble(location);
        if (location < 0 || location > Origin::REMOTE) {
            return this;
        }
        flagVal = FLAG[static_cast<int>(location)];
        valObj = ValueObject(flagVal);
    }
    if (isNeedAnd) {
        whereClause += "AND ";
    } else {
        isNeedAnd = true;
    }
    if (flagVal.empty()) {
        whereClause += newField + " = ? ";
        bindArgs.push_back(std::move(valObj));
    } else {
        whereClause += "(" + newField + " & 0x02 = " + flagVal + ")";
    }
    return this;
}

/**
 * Restricts the value of the field to be unequal to the specified value.
 */
AbsPredicates *AbsPredicates::NotEqualTo(const std::string &field, const ValueObject &value)
{
    if (!CheckParameter("notEqualTo", field, {})) {
        return this;
    }
    hasSpecificField = hasSpecificField || IsSpecificField(field);
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
    return this;
}

/**
 * Restricts the value of the field to contain the specified string.
 */
AbsPredicates *AbsPredicates::Contains(const std::string &field, const std::string &value)
{
    if (!CheckParameter("contains", field, { value })) {
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " LIKE ? ";
    bindArgs.push_back(ValueObject("%" + value + "%"));
    return this;
}

/**
 * Restricts the value of the field to not contain the specified string.
 */
AbsPredicates *AbsPredicates::NotContains(const std::string &field, const std::string &value)
{
    if (!CheckParameter("notContains", field, { value })) {
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " NOT LIKE ? ";
    bindArgs.push_back(ValueObject("%" + value + "%"));
    return this;
}

/**
 * Restricts the field to start with the specified string.
 */
AbsPredicates *AbsPredicates::BeginsWith(const std::string &field, const std::string &value)
{
    if (!CheckParameter("beginsWith", field, { value })) {
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
    if (!CheckParameter("endsWith", field, { value })) {
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
    if (!CheckParameter("isNull", field, {})) {
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " IS NULL ";
    return this;
}

/**
 * estricts the value of the field not to be null.
 */
AbsPredicates *AbsPredicates::IsNotNull(const std::string &field)
{
    if (!CheckParameter("isNotNull", field, {})) {
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " IS NOT NULL ";
    return this;
}

/**
 * Restricts the value of the field to have a pattern like field.
 */
AbsPredicates *AbsPredicates::Like(const std::string &field, const std::string &value)
{
    if (!CheckParameter("like", field, { value })) {
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " LIKE ? ";
    bindArgs.push_back(ValueObject(value));
    return this;
}

/**
 * Restricts the value of the field to have a pattern like field.
 */
AbsPredicates *AbsPredicates::NotLike(const std::string &field, const std::string &value)
{
    if (!CheckParameter("notLike", field, { value })) {
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " NOT LIKE ? ";
    bindArgs.push_back(ValueObject(value));
    return this;
}

/**
 * Configures to match the specified field whose data type is String and the value contains a wildcard.
 */
AbsPredicates *AbsPredicates::Glob(const std::string &field, const std::string &value)
{
    if (!CheckParameter("glob", field, { value })) {
        return this;
    }
    CheckIsNeedAnd();
    whereClause += field + " GLOB ? ";
    bindArgs.push_back(ValueObject(value));
    return this;
}

/**
 * Restricts the value of the field to be unequal to the specified value.
 */
AbsPredicates *AbsPredicates::Between(const std::string &field, const ValueObject &low, const ValueObject &high)
{
    if (!CheckParameter("between", field, { low, high })) {
        return this;
    }
    hasSpecificField = hasSpecificField || IsSpecificField(field);
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
    if (!CheckParameter("notBetween", field, { low, high })) {
        return this;
    }
    hasSpecificField = hasSpecificField || IsSpecificField(field);
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
    if (!CheckParameter("greaterThan", field, { value })) {
        return this;
    }
    hasSpecificField = hasSpecificField || IsSpecificField(field);
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
    if (!CheckParameter("lessThan", field, { value })) {
        return this;
    }
    hasSpecificField = hasSpecificField || IsSpecificField(field);
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
    if (!CheckParameter("greaterThanOrEqualTo", field, { value })) {
        return this;
    }
    hasSpecificField = hasSpecificField || IsSpecificField(field);
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
    if (!CheckParameter("greaterThanOrEqualTo", field, { value })) {
        return this;
    }
    hasSpecificField = hasSpecificField || IsSpecificField(field);
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
    if (!CheckParameter("orderByAsc", field, {})) {
        return this;
    }
    hasSpecificField = hasSpecificField || IsSpecificField(field);
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
    if (!CheckParameter("orderByDesc", field, {})) {
        return this;
    }
    hasSpecificField = hasSpecificField || IsSpecificField(field);
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
        LOG_WARN("groupBy() fails because fields can't be null.");
        return this;
    }
    for (auto &field : fields) {
        if (!CheckParameter("GroupBy", field, {})) {
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
    if (!CheckParameter("indexedBy", indexName, {})) {
        return this;
    }
    index = RemoveQuotes(indexName);
    return this;
}

AbsPredicates *AbsPredicates::In(const std::string &field, const std::vector<std::string> &values)
{
    std::vector<ValueObject> bindArgs;
    std::for_each(values.begin(), values.end(), [&bindArgs](const auto &it) { bindArgs.push_back(ValueObject(it)); });
    return In(field, bindArgs);
}

/**
 * Configures to match the specified field whose data type is String array and values are within a given range.
 */
AbsPredicates *AbsPredicates::In(const std::string &field, const std::vector<ValueObject> &values)
{
    bool chekParaFlag = CheckParameter("in", field, {});
    if (!chekParaFlag) {
        return this;
    }
    if (values.empty()) {
        LOG_WARN("in() fails because values can't be null.");
        return this;
    }

    CheckIsNeedAnd();

    std::vector<std::string> replaceValues(values.size(), "?");
    bindArgs.insert(bindArgs.end(), values.begin(), values.end());
    AppendWhereClauseWithInOrNotIn(" IN ", field, replaceValues);
    return this;
}

AbsPredicates *AbsPredicates::NotIn(const std::string &field, const std::vector<std::string> &values)
{
    std::vector<ValueObject> bindArgs;
    std::for_each(values.begin(), values.end(), [&bindArgs](const auto &it) { bindArgs.push_back(ValueObject(it)); });
    return NotIn(field, bindArgs);
}

/**
 * Configures to match the specified field whose data type is String array and values are out of a given range.
 */
AbsPredicates *AbsPredicates::NotIn(const std::string &field, const std::vector<ValueObject> &values)
{
    bool chekParaFlag = CheckParameter("notIn", field, {});
    if (!chekParaFlag) {
        return this;
    }
    if (values.empty()) {
        LOG_WARN("fails as values is null.");
        return this;
    }
    CheckIsNeedAnd();
    std::vector<std::string> replaceValues(values.size(), "?");
    bindArgs.insert(bindArgs.end(), values.begin(), values.end());
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
    limit = INIT_LIMIT_VALUE;
    offset = INIT_OFFSET_VALUE;
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

std::string AbsPredicates::GetStatement()  const
{
    return SqliteSqlBuilder::BuildSqlStringFromPredicates(*this);
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
        std::string temp;
        if (!arg.GetString(temp)) {
            LOG_DEBUG("No matching type, empty string instead.");
        }
        whereArgs.push_back(temp);
    }
    return whereArgs;
}

void AbsPredicates::SetWhereArgs(const std::vector<std::string> &whereArgs)
{
    this->bindArgs.clear();
    std::for_each(whereArgs.begin(), whereArgs.end(), [this](const auto &it) { bindArgs.push_back(ValueObject(it)); });
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

bool AbsPredicates::HasSpecificField() const
{
    return hasSpecificField;
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