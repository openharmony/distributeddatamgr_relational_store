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
#define LOG_TAG "AbsRdbPredicates"
#include "abs_rdb_predicates.h"

#include <variant>

#include "logger.h"
#include "rdb_trace.h"

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;

AbsRdbPredicates::AbsRdbPredicates(const std::string &tableName)
{
    if (tableName.empty()) {
        tableName_ = "";
        LOG_DEBUG("no tableName specified.");
        return;
    }
    tableName_ = std::move(tableName);
    predicates_.tables_.push_back(tableName_);
}

AbsRdbPredicates::AbsRdbPredicates(const std::vector<std::string> &tables)
{
    if (tables.empty()) {
        tableName_ = "";
        LOG_DEBUG("no tableName specified.");
        return;
    }
    tableName_ = *(tables.begin());
    predicates_.tables_ = std::move(tables);
}

void AbsRdbPredicates::Clear()
{
    AbsPredicates::Clear();
    InitialParam();
}

void AbsRdbPredicates::InitialParam()
{
    joinTypes.clear();
    joinTableNames.clear();
    joinConditions.clear();
    joinCount = 0;
}

std::vector<std::string> AbsRdbPredicates::GetJoinTypes()
{
    return joinTypes;
}

/**
 * Sets the join types in the predicates. The value can be {@code INNER JOIN}, {@code LEFT OUTER JOIN},
 * and {@code CROSS JOIN}.
 */
void AbsRdbPredicates::SetJoinTypes(const std::vector<std::string> &joinTypes)
{
    this->joinTypes = joinTypes;
}

/**
 * Obtains the database table names of the joins in the predicates.
 */
std::vector<std::string> AbsRdbPredicates::GetJoinTableNames()
{
    return joinTableNames;
}

/**
 * Sets the database table names of the joins in the predicates.
 */
void AbsRdbPredicates::SetJoinTableNames(const std::vector<std::string> &joinTableNames)
{
    this->joinTableNames = joinTableNames;
}

/**
 * Obtains the join conditions in the predicates.
 */
std::vector<std::string> AbsRdbPredicates::GetJoinConditions()
{
    return joinConditions;
}

/**
 * Sets the join conditions required in the predicates.
 */
void AbsRdbPredicates::SetJoinConditions(const std::vector<std::string> &joinConditions)
{
    this->joinConditions = joinConditions;
}

/**
 * Obtains the join clause in the predicates.
 */
std::string AbsRdbPredicates::GetJoinClause() const
{
    return "";
}

/**
 * Obtains the number of joins in the predicates.
 */
int AbsRdbPredicates::GetJoinCount() const
{
    return joinCount;
}

/**
 * Sets the number of joins in the predicates.
 */
void AbsRdbPredicates::SetJoinCount(int joinCount)
{
    this->joinCount = joinCount;
}

/**
 * Obtains the table name.
 */
std::string AbsRdbPredicates::GetTableName() const
{
    return tableName_;
}

std::string AbsRdbPredicates::ToString() const
{
    std::string args;
    for (const auto& item : GetWhereArgs()) {
        args += item + ", ";
    }
    return "TableName = " + GetTableName() + ", {WhereClause:" + GetWhereClause() + ", bindArgs:{" + args + "}"
           + ", order:" + GetOrder() + ", group:" + GetGroup() + ", index:" + GetIndex()
           + ", limit:" + std::to_string(GetLimit()) + ", offset:" + std::to_string(GetOffset())
           + ", distinct:" + std::to_string(IsDistinct()) + ", isNeedAnd:" + std::to_string(IsNeedAnd())
           + ", isSorted:" + std::to_string(IsSorted()) + "}";
}

AbsRdbPredicates* AbsRdbPredicates::InDevices(std::vector<std::string> &devices)
{
    predicates_.devices_ = devices;
    return this;
}

AbsRdbPredicates* AbsRdbPredicates::InAllDevices()
{
    predicates_.devices_.clear();
    return this;
}

const DistributedRdb::PredicatesMemo& AbsRdbPredicates::GetDistributedPredicates() const
{
    int limit = GetLimit();
    if (limit >= 0) {
        predicates_.AddOperation(DistributedRdb::RdbPredicateOperator::LIMIT,
                                 std::to_string(limit), std::to_string(GetOffset()));
    }
    return predicates_;
}

AbsRdbPredicates* AbsRdbPredicates::EqualTo(const std::string &field, const ValueObject &value)
{
    DISTRIBUTED_DATA_HITRACE("AbsRdbPredicates::EqualTo");
    if (auto pval = std::get_if<std::string>(&value.value)) {
        predicates_.AddOperation(DistributedRdb::EQUAL_TO, field, *pval);
    }
    return (AbsRdbPredicates *)AbsPredicates::EqualTo(field, value);
}

AbsRdbPredicates* AbsRdbPredicates::NotEqualTo(const std::string &field, const ValueObject &value)
{
    if (auto pval = std::get_if<std::string>(&value.value)) {
        predicates_.AddOperation(DistributedRdb::NOT_EQUAL_TO, field, *pval);
    }
    return (AbsRdbPredicates *)AbsPredicates::NotEqualTo(field, value);
}

AbsRdbPredicates* AbsRdbPredicates::And()
{
    predicates_.AddOperation(DistributedRdb::AND, "", "");
    return (AbsRdbPredicates *)AbsPredicates::And();
}

AbsRdbPredicates* AbsRdbPredicates::Or()
{
    predicates_.AddOperation(DistributedRdb::OR, "", "");
    return (AbsRdbPredicates *)AbsPredicates::Or();
}

AbsRdbPredicates* AbsRdbPredicates::OrderByAsc(const std::string &field)
{
    std::string isAsc = "true";
    predicates_.AddOperation(DistributedRdb::ORDER_BY, field, isAsc);
    return (AbsRdbPredicates *)AbsPredicates::OrderByAsc(field);
}

AbsRdbPredicates* AbsRdbPredicates::OrderByDesc(const std::string &field)
{
    std::string isAsc = "false";
    predicates_.AddOperation(DistributedRdb::ORDER_BY, field, isAsc);
    return (AbsRdbPredicates *)AbsPredicates::OrderByDesc(field);
}

AbsPredicates *AbsRdbPredicates::BeginWrap()
{
    predicates_.AddOperation(DistributedRdb::BEGIN_GROUP, {}, "");
    return (AbsRdbPredicates *)AbsPredicates::BeginWrap();
}

AbsPredicates *AbsRdbPredicates::EndWrap()
{
    predicates_.AddOperation(DistributedRdb::END_GROUP, {}, "");
    return (AbsRdbPredicates *)AbsPredicates::EndWrap();
}

AbsPredicates *AbsRdbPredicates::In(const std::string &field, const std::vector<ValueObject> &values)
{
    std::vector<std::string> vals;
    vals.reserve(values.size());
    for (const auto &value : values) {
        auto val = std::get_if<std::string>(&value.value);
        if (val == nullptr) {
            return (AbsRdbPredicates *)AbsPredicates::In(field, values);
        }
        vals.emplace_back(std::move(*val));
    }
    predicates_.AddOperation(DistributedRdb::IN, field, vals);
    return (AbsRdbPredicates *)AbsPredicates::In(field, values);
}

AbsPredicates *AbsRdbPredicates::In(const std::string &field, const std::vector<std::string> &values)
{
    predicates_.AddOperation(DistributedRdb::IN, field, values);
    return (AbsRdbPredicates *)AbsPredicates::In(field, values);
}

AbsRdbPredicates *AbsRdbPredicates::Contains(const std::string &field, const std::string &value)
{
    predicates_.AddOperation(DistributedRdb::CONTAIN, field, value);
    return (AbsRdbPredicates *)AbsPredicates::Contains(field, value);
}

AbsRdbPredicates *AbsRdbPredicates::NotContains(const std::string &field, const std::string &value)
{
    predicates_.AddOperation(DistributedRdb::NOT_CONTAINS, field, value);
    return (AbsRdbPredicates *)AbsPredicates::NotContains(field, value);
}

AbsRdbPredicates *AbsRdbPredicates::BeginsWith(const std::string &field, const std::string &value)
{
    predicates_.AddOperation(DistributedRdb::BEGIN_WITH, field, value);
    return (AbsRdbPredicates *)AbsPredicates::BeginsWith(field, value);
}
AbsRdbPredicates *AbsRdbPredicates::EndsWith(const std::string &field, const std::string &value)
{
    predicates_.AddOperation(DistributedRdb::END_WITH, field, value);
    return (AbsRdbPredicates *)AbsPredicates::EndsWith(field, value);
}
AbsRdbPredicates *AbsRdbPredicates::IsNull(const std::string &field)
{
    predicates_.AddOperation(DistributedRdb::IS_NULL, field, "");
    return (AbsRdbPredicates *)AbsPredicates::IsNull(field);
}
AbsRdbPredicates *AbsRdbPredicates::IsNotNull(const std::string &field)
{
    predicates_.AddOperation(DistributedRdb::IS_NOT_NULL, field, "");
    return (AbsRdbPredicates *)AbsPredicates::IsNotNull(field);
}
AbsRdbPredicates *AbsRdbPredicates::Like(const std::string &field, const std::string &value)
{
    predicates_.AddOperation(DistributedRdb::LIKE, field, value);
    return (AbsRdbPredicates *)AbsPredicates::Like(field, value);
}
AbsRdbPredicates *AbsRdbPredicates::NotLike(const std::string &field, const std::string &value)
{
    predicates_.AddOperation(DistributedRdb::NOT_LIKE, field, value);
    return (AbsRdbPredicates *)AbsPredicates::NotLike(field, value);
}
AbsRdbPredicates *AbsRdbPredicates::Glob(const std::string &field, const std::string &value)
{
    predicates_.AddOperation(DistributedRdb::GLOB, field, value);
    return (AbsRdbPredicates *)AbsPredicates::Glob(field, value);
}
AbsRdbPredicates *AbsRdbPredicates::Distinct()
{
    predicates_.AddOperation(DistributedRdb::DISTINCT, "", "");
    return (AbsRdbPredicates *)AbsPredicates::Distinct();
}
AbsRdbPredicates *AbsRdbPredicates::IndexedBy(const std::string &indexName)
{
    predicates_.AddOperation(DistributedRdb::INDEXED_BY, indexName, "");
    return (AbsRdbPredicates *)AbsPredicates::IndexedBy(indexName);
}
AbsRdbPredicates *AbsRdbPredicates::NotIn(const std::string &field, const std::vector<std::string> &values)
{
    predicates_.AddOperation(DistributedRdb::NOT_IN, field, values);
    return (AbsRdbPredicates *)AbsPredicates::NotIn(field, values);
}
AbsRdbPredicates *AbsRdbPredicates::NotIn(const std::string &field, const std::vector<ValueObject> &values)
{
    std::vector<std::string> vals;
    vals.reserve(values.size());
    for (const auto &value : values) {
        auto val = std::get_if<std::string>(&value.value);
        if (val == nullptr) {
            return (AbsRdbPredicates *)AbsPredicates::NotIn(field, values);
        }
        vals.emplace_back(std::move(*val));
    }
    predicates_.AddOperation(DistributedRdb::NOT_IN, field, vals);
    return (AbsRdbPredicates *)AbsPredicates::NotIn(field, values);
}
} // namespace OHOS::NativeRdb