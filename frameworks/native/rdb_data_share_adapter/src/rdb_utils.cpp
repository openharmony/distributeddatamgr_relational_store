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

#include "rdb_utils.h"

#include "rdb_logger.h"

using namespace OHOS::RdbDataShareAdapter;
using namespace OHOS::DataShare;
using namespace OHOS::NativeRdb;

constexpr RdbUtils::OperateHandler RdbUtils::HANDLERS[LAST_TYPE];

ValuesBucket RdbUtils::ToValuesBucket(const DataShareValuesBucket &valuesBucket)
{
    std::map<std::string, ValueObject> valuesMap;
    auto values = valuesBucket.valuesMap;
    for (auto &[key, value] : values) {
        if (value.type == DataShareValueObjectType::TYPE_BOOL) {
            valuesMap.insert(std::pair<std::string, ValueObject>(key, ValueObject(value.operator bool())));
        } else if (value.type == DataShareValueObjectType::TYPE_INT) {
            valuesMap.insert(std::pair<std::string, ValueObject>(key, ValueObject(value.operator int())));
        } else if (value.type == DataShareValueObjectType::TYPE_INT64) {
            valuesMap.insert(std::pair<std::string, ValueObject>(key, ValueObject(value.operator int64_t())));
        } else if (value.type == DataShareValueObjectType::TYPE_DOUBLE) {
            valuesMap.insert(std::pair<std::string, ValueObject>(key, ValueObject(value.operator double())));
        } else if (value.type == DataShareValueObjectType::TYPE_STRING) {
            valuesMap.insert(std::pair<std::string, ValueObject>(key, ValueObject(value.operator std::string())));
        } else if (value.type == DataShareValueObjectType::TYPE_BLOB) {
            valuesMap.insert(
                std::pair<std::string, ValueObject>(key, ValueObject(value.operator std::vector<uint8_t>())));
        } else {
            LOG_INFO("Convert ValueBucket successful.");
        }
    }
    return ValuesBucket(valuesMap);
}

RdbPredicates RdbUtils::ToPredicates(const DataShareAbsPredicates &predicates, const std::string &table)
{
    RdbPredicates rdbPredicates(table);
    if (predicates.GetSettingMode() == QUERY_LANGUAGE) {
        rdbPredicates.SetWhereClause(predicates.GetWhereClause());
        rdbPredicates.SetWhereArgs(predicates.GetWhereArgs());
        rdbPredicates.SetOrder(predicates.GetOrder());
    }

    const auto &operations = predicates.GetOperationList();
    for (const auto &oper : operations) {
        if (oper.operation >= 0 && oper.operation < LAST_TYPE) {
            (*HANDLERS[oper.operation])(oper, rdbPredicates);
        }
    }
    return rdbPredicates;
}

std::string RdbUtils::ToString(const DataSharePredicatesObject &predicatesObject)
{
    std::string str = " ";
    switch (predicatesObject.type) {
        case DataSharePredicatesObjectType::TYPE_INT:
            str = std::to_string(predicatesObject.operator int());
            break;
        case DataSharePredicatesObjectType::TYPE_DOUBLE:
            str = std::to_string(predicatesObject.operator double());
            break;
        case DataSharePredicatesObjectType::TYPE_STRING:
            str = predicatesObject.operator std::string();
            break;
        case DataSharePredicatesObjectType::TYPE_BOOL:
            str = std::to_string(predicatesObject.operator bool());
            break;
        case DataSharePredicatesObjectType::TYPE_LONG:
            str = std::to_string(predicatesObject.operator int64_t());
            break;
        default:
            LOG_INFO("RdbUtils::ToString No matching type");
            return str;
    }
    return str;
}

std::shared_ptr<ResultSetBridge> RdbUtils::ToResultSetBridge(std::shared_ptr<ResultSet> resultSet)
{
    if (resultSet == nullptr) {
        LOG_ERROR("resultSet is null");
        return nullptr;
    }
    return std::make_shared<RdbResultSetBridge>(resultSet);
}

void RdbUtils::NoSupport(const OperationItem &item, RdbPredicates &query)
{
    LOG_ERROR("invalid operation:%{public}d", item.operation);
}

void RdbUtils::EqualTo(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.EqualTo(item.singleParams[0], ToString(item.singleParams[1]));
}

void RdbUtils::NotEqualTo(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.NotEqualTo(item.singleParams[0], ToString(item.singleParams[1]));
}

void RdbUtils::GreaterThan(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.GreaterThan(item.singleParams[0], ToString(item.singleParams[1]));
}

void RdbUtils::LessThan(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.LessThan(item.singleParams[0], ToString(item.singleParams[1]));
}

void RdbUtils::GreaterThanOrEqualTo(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.GreaterThanOrEqualTo(item.singleParams[0], ToString(item.singleParams[1]));
}

void RdbUtils::LessThanOrEqualTo(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.LessThanOrEqualTo(item.singleParams[0], ToString(item.singleParams[1]));
}

void RdbUtils::And(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.And();
}

void RdbUtils::Or(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.Or();
}

void RdbUtils::IsNull(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.IsNull(item.singleParams[0]);
}

void RdbUtils::IsNotNull(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.IsNotNull(item.singleParams[0]);
}

void RdbUtils::In(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.In(item.singleParams[0], item.multiParams[0]);
}

void RdbUtils::NotIn(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.NotIn(item.singleParams[0], item.multiParams[0]);
}

void RdbUtils::Like(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.Like(item.singleParams[0], ToString(item.singleParams[1]));
}

void RdbUtils::OrderByAsc(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.OrderByAsc(item.singleParams[0]);
}

void RdbUtils::OrderByDesc(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.OrderByDesc(item.singleParams[0]);
}

void RdbUtils::Limit(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.Limit(item.singleParams[0].operator int());
    predicates.Offset(item.singleParams[1].operator int());
}

void RdbUtils::Offset(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.Offset(item.singleParams[0].operator int());
}

void RdbUtils::BeginWrap(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.BeginWrap();
}

void RdbUtils::EndWrap(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.EndWrap();
}

void RdbUtils::BeginsWith(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.BeginsWith(item.singleParams[0], ToString(item.singleParams[1]));
}

void RdbUtils::EndsWith(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.EndsWith(item.singleParams[0], ToString(item.singleParams[1]));
}

void RdbUtils::Distinct(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.Distinct();
}

void RdbUtils::GroupBy(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.GroupBy(item.multiParams[0]);
}

void RdbUtils::IndexedBy(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.IndexedBy(item.singleParams[0]);
}

void RdbUtils::Contains(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.Contains(item.singleParams[0], ToString(item.singleParams[1]));
}

void RdbUtils::Glob(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.Glob(item.singleParams[0], ToString(item.singleParams[1]));
}

void RdbUtils::Between(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.Between(item.singleParams[0], ToString(item.singleParams[1]), ToString(item.singleParams[2]));
}

void RdbUtils::NotBetween(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.NotBetween(item.singleParams[0], ToString(item.singleParams[1]), ToString(item.singleParams[2]));
}

RdbUtils::RdbUtils()
{
}

RdbUtils::~RdbUtils()
{
}
