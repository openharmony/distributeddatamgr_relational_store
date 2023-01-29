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
#include "logger.h"
#include "rdb_trace.h"
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#include "rdb_manager.h"
#include "rdb_service.h"
#endif

namespace OHOS::NativeRdb {
AbsRdbPredicates::AbsRdbPredicates(std::string tableName)
{
    if (tableName.empty()) {
        this->tableName = "";
        LOG_INFO("no tableName specified.");
        return;
    }
    this->tableName = tableName;
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    predicates_.table_ = tableName;
#endif
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
void AbsRdbPredicates::SetJoinTypes(const std::vector<std::string> joinTypes)
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
void AbsRdbPredicates::SetJoinTableNames(const std::vector<std::string> joinTableNames)
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
void AbsRdbPredicates::SetJoinConditions(const std::vector<std::string> joinConditions)
{
    this->joinConditions = joinConditions;
}

/**
 * Obtains the join clause in the predicates.
 */
std::string AbsRdbPredicates::GetJoinClause() const
{
    return tableName;
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
    return tableName;
}

std::string AbsRdbPredicates::ToString() const
{
    std::string args;
    for (const auto& item : GetWhereArgs()) {
        args += item + ", ";
    }
    return "TableName = " + GetTableName() + ", {WhereClause:" + GetWhereClause() + ", whereArgs:{" + args + "}"
           + ", order:" + GetOrder() + ", group:" + GetGroup() + ", index:" + GetIndex()
           + ", limit:" + std::to_string(GetLimit()) + ", offset:" + std::to_string(GetOffset())
           + ", distinct:" + std::to_string(IsDistinct()) + ", isNeedAnd:" + std::to_string(IsNeedAnd())
           + ", isSorted:" + std::to_string(IsSorted()) + "}";
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
AbsRdbPredicates* AbsRdbPredicates::InDevices(std::vector<std::string> &devices)
{
    for (const auto& device : devices) {
        LOG_INFO("%{public}.6s", device.c_str());
    }
    predicates_.devices_ = devices;
    return this;
}

AbsRdbPredicates* AbsRdbPredicates::InAllDevices()
{
    LOG_INFO("enter");
    predicates_.devices_.clear();
    return this;
}

const DistributedRdb::RdbPredicates& AbsRdbPredicates::GetDistributedPredicates() const
{
    int limit = GetLimit();
    if (limit >= 0) {
        predicates_.AddOperation(DistributedRdb::RdbPredicateOperator::LIMIT,
                                 std::to_string(limit), std::to_string(GetOffset()));
    }
    return predicates_;
}

AbsRdbPredicates* AbsRdbPredicates::EqualTo(std::string field, std::string value)
{
    predicates_.AddOperation(DistributedRdb::EQUAL_TO, field, value);
    return (AbsRdbPredicates *)AbsPredicates::EqualTo(field, value);
}

AbsRdbPredicates* AbsRdbPredicates::NotEqualTo(std::string field, std::string value)
{
    predicates_.AddOperation(DistributedRdb::NOT_EQUAL_TO, field, value);
    return (AbsRdbPredicates *)AbsPredicates::NotEqualTo(field, value);
}

AbsRdbPredicates* AbsRdbPredicates::And()
{
    std::string field;
    std::string value;
    predicates_.AddOperation(DistributedRdb::AND, field, value);
    return (AbsRdbPredicates *)AbsPredicates::And();
}

AbsRdbPredicates* AbsRdbPredicates::Or()
{
    std::string field;
    std::string value;
    predicates_.AddOperation(DistributedRdb::OR, field, value);
    return (AbsRdbPredicates *)AbsPredicates::Or();
}

AbsRdbPredicates* AbsRdbPredicates::OrderByAsc(std::string field)
{
    std::string isAsc = "true";
    predicates_.AddOperation(DistributedRdb::ORDER_BY, field, isAsc);
    return (AbsRdbPredicates *)AbsPredicates::OrderByAsc(field);
}

AbsRdbPredicates* AbsRdbPredicates::OrderByDesc(std::string field)
{
    std::string isAsc = "false";
    predicates_.AddOperation(DistributedRdb::ORDER_BY, field, isAsc);
    return (AbsRdbPredicates *)AbsPredicates::OrderByDesc(field);
}
#endif
} // namespace OHOS::NativeRdb