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
    return std::make_shared<RdbResultSetBridge>(resultSet);
}

void RdbUtils::NoSupport(const OperationItem &item, RdbPredicates &query)
{
    LOG_ERROR("invalid operation:%{public}d", item.operation);
}

void RdbUtils::EqualTo(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.EqualTo(item.para1, ToString(item.para2));
}

void RdbUtils::NotEqualTo(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.NotEqualTo(item.para1, ToString(item.para2));
}

void RdbUtils::GreaterThan(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.GreaterThan(item.para1, ToString(item.para2));
}

void RdbUtils::LessThan(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.LessThan(item.para1, ToString(item.para2));
}

void RdbUtils::GreaterThanOrEqualTo(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.GreaterThanOrEqualTo(item.para1, ToString(item.para2));
}

void RdbUtils::LessThanOrEqualTo(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.LessThanOrEqualTo(item.para1, ToString(item.para2));
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
    predicates.IsNull(item.para1);
}

void RdbUtils::IsNotNull(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.IsNotNull(item.para1);
}
void RdbUtils::In(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.In(item.para1, std::get<std::vector<std::string>>(item.para2.value));
}

void RdbUtils::NotIn(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.NotIn(item.para1, std::get<std::vector<std::string>>(item.para2.value));
}

void RdbUtils::Like(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.Like(item.para1, ToString(item.para2));
}

void RdbUtils::OrderByAsc(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.OrderByAsc(item.para1);
}

void RdbUtils::OrderByDesc(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.OrderByDesc(item.para1);
}
void RdbUtils::Limit(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.Limit(item.para1.operator int());
}

void RdbUtils::Offset(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.Offset(item.para1.operator int());
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
    predicates.BeginsWith(item.para1, ToString(item.para2));
}

void RdbUtils::EndsWith(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.EndsWith(item.para1, ToString(item.para2));
}

void RdbUtils::Distinct(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.Distinct();
}

void RdbUtils::GroupBy(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.GroupBy(std::get<std::vector<std::string>>(item.para1.value));
}

void RdbUtils::IndexedBy(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.IndexedBy(item.para1);
}

void RdbUtils::Contains(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.Contains(item.para1, ToString(item.para2));
}

void RdbUtils::Glob(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.Glob(item.para1, ToString(item.para2));
}

void RdbUtils::Between(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.Between(item.para1, ToString(item.para2), ToString(item.para3));
}

void RdbUtils::NotBetween(const DataShare::OperationItem &item, RdbPredicates &predicates)
{
    predicates.NotBetween(item.para1, ToString(item.para2), ToString(item.para3));
}

RdbUtils::RdbUtils()
{
}

RdbUtils::~RdbUtils()
{
}
