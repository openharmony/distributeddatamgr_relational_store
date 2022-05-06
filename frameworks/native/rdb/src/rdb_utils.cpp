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
#include "logger.h"

using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;

ValuesBucket RdbUtils::ConvertToValuesBucket(DataShareValuesBucket dataShareValuesBucket) {
    std::map<std::string, ValueObject> valuesMap;
    std::map<std::string, DataShareValueObject> dataShareValuesMap;
    dataShareValuesBucket.GetAll(dataShareValuesMap);
    for (auto &[key, value] : dataShareValuesMap) {
        if (value.GetType() == DataShareValueObjectType::TYPE_BOOL) {
            bool tmpVal;
            value.GetBool(tmpVal);
            valuesMap.insert(std::pair<std::string, ValueObject>(key, ValueObject(tmpVal)));
        } else if (value.GetType() == DataShareValueObjectType::TYPE_INT) {
            int32_t tmpVal;
            value.GetInt(tmpVal);
            valuesMap.insert(std::pair<std::string, ValueObject>(key, ValueObject(tmpVal)));
        } else if (value.GetType() == DataShareValueObjectType::TYPE_DOUBLE) {
            double tmpVal;
            value.GetDouble(tmpVal);
            valuesMap.insert(std::pair<std::string, ValueObject>(key, ValueObject(tmpVal)));
        } else if (value.GetType() == DataShareValueObjectType::TYPE_STRING) {
            std::string tmpVal;
            value.GetString(tmpVal);
            valuesMap.insert(std::pair<std::string, ValueObject>(key, ValueObject(tmpVal)));
        } else if (value.GetType() == DataShareValueObjectType::TYPE_BLOB) {
            std::vector<uint8_t> tmpVal;
            value.GetBlob(tmpVal);
            valuesMap.insert(std::pair<std::string, ValueObject>(key, ValueObject(tmpVal)));
        } else {
            LOG_INFO("Convert ValueBucket successful.");
        }
    }
    return ValuesBucket(valuesMap);
}

void RdbUtils::ToOperateFirst(std::list<OperationItem>::iterator operations,
        std::shared_ptr<AbsPredicates> predicates) {
    switch (operations->operation) {
        case OperationType::EQUAL_TO:
            predicates->EqualTo(
                    std::get<std::string>(operations->para1.value),
                    std::get<std::string>(operations->para2.value));
            break;
        case OperationType::NOT_EQUAL_TO:
            predicates->NotEqualTo(
                    std::get<std::string>(operations->para1.value),
                    std::get<std::string>(operations->para2.value));
            break;
        case OperationType::GREATER_THAN:
            predicates->GreaterThan(
                    std::get<std::string>(operations->para1.value),
                    std::get<std::string>(operations->para2.value));
            break;
        case OperationType::LESS_THAN:
            predicates->LessThan(
                    std::get<std::string>(operations->para1.value),
                    std::get<std::string>(operations->para2.value));
            break;
        case OperationType::GREATER_THAN_OR_EQUAL_TO:
            predicates->GreaterThanOrEqualTo(
                    std::get<std::string>(operations->para1.value),
                    std::get<std::string>(operations->para2.value));
            break;
        case OperationType::AND:
            predicates->And();
            break;
        case OperationType::OR:
            predicates->Or();
            break;
        case OperationType::BEGIN_WARP:
            predicates->BeginWrap();
            break;
        case OperationType::BETWEEN:
            predicates->Between(std::get<std::string>(operations->para1.value),
                                   std::get<std::string>(operations->para2.value),
                                   std::get<std::string>(operations->para3.value));
            break;
        default:
            LOG_INFO("RdbUtils::ToOperateFirst successful");
            return;
    }
}

void RdbUtils::ToOperateSecond(std::list<OperationItem>::iterator operations,
        std::shared_ptr<AbsPredicates> predicates) {
    switch (operations->operation) {
        case OperationType::BEGIN_WITH:
            predicates->BeginsWith(
                    std::get<std::string>(operations->para1.value),
                    std::get<std::string>(operations->para2.value));
            break;
        case OperationType::CONTAINS:
            predicates->Contains(
                    std::get<std::string>(operations->para1.value),
                    std::get<std::string>(operations->para2.value));
            break;
        case OperationType::DISTINCT:
            predicates->Distinct();
            break;
        case OperationType::IN:
            predicates->BeginsWith(
                    std::get<std::string>(operations->para1.value),
                    std::get<std::string>(operations->para2.value));
            break;
        case OperationType::GLOB:
            predicates->Glob(
                    std::get<std::string>(operations->para1.value),
                    std::get<std::string>(operations->para2.value));
            break;
        case OperationType::END_WARP:
            predicates->EndWrap();
            break;
        case OperationType::INDEXED_BY:
            predicates->IndexedBy(std::get<std::string>(operations->para1.value));
            break;
        case OperationType::NOTBETWEEN:
            predicates->NotBetween(std::get<std::string>(operations->para1.value),
                                      std::get<std::string>(operations->para2.value),
                                      std::get<std::string>(operations->para3.value));
            break;
        case OperationType::ORDER_BY_ASC:
            predicates->OrderByAsc(std::get<std::string>(operations->para1.value));
            break;
        default:
            LOG_INFO("RdbUtils::ToOperateFirst successful");
            return;
    }
}

void RdbUtils::ToOperateThird(std::list<OperationItem>::iterator operations,
        std::shared_ptr<AbsPredicates> predicates) {
    switch (operations->operation) {
        case OperationType::ORDER_BY_DESC:
            predicates->OrderByDesc(std::get<std::string>(operations->para1.value));
            break;
        case OperationType::END_WITH:
            predicates->EndsWith(
                    std::get<std::string>(operations->para1.value),
                    std::get<std::string>(operations->para2.value));
            break;
        case OperationType::IS_NULL:
            predicates->IsNull(std::get<std::string>(operations->para1.value));
            break;
        case OperationType::IS_NOT_NULL:
            predicates->IsNotNull(std::get<std::string>(operations->para1.value));
            break;
        case OperationType::OFFSET:
            predicates->Offset(std::get<int>(operations->para1.value));
            break;
        case OperationType::LESS_THAN_OR_EQUAL_TO:
            predicates->LessThanOrEqualTo(
                    std::get<std::string>(operations->para1.value),
                    std::get<std::string>(operations->para2.value));
            break;
        case OperationType::NOT_IN:
            predicates->NotIn(std::get<std::string>(operations->para1.value),
                                 std::get<std::vector<std::string>>(operations->para2.value));
            break;
        case OperationType::LIKE:
            predicates->Like(
                    std::get<std::string>(operations->para1.value),
                    std::get<std::string>(operations->para2.value));
            break;
        case OperationType::LIMIT:
            predicates->Limit(std::get<int>(operations->para1.value));
            break;
        case OperationType::GROUP_BY:
            predicates->GroupBy(std::get<std::vector<std::string>>(operations->para1.value));
            break;
        default:
            LOG_INFO("RdbUtils::ToOperateFirst successful");
            return;
    }
}

std::shared_ptr<AbsPredicates> RdbUtils::ToOperate(const DataSharePredicates &dataSharePredicates) {
    std::list<OperationItem> operationLists = dataSharePredicates.GetOperationList();
    std::list<OperationItem>::iterator operations;
    std::shared_ptr<AbsPredicates> predicates = std::make_shared<AbsPredicates>();
    for (operations = operationLists.begin(); operations != operationLists.end(); operations++) {
        ToOperateFirst(operations, predicates);
        ToOperateSecond(operations, predicates);
        ToOperateThird(operations, predicates);
    }
    return predicates;
}

std::string RdbUtils::ToString(DataShare::DataSharePredicatesObject &predicatesObject)
{
    std::string str = " ";
    switch (predicatesObject.GetType()) {
        case DataSharePredicatesObjectType::TYPE_INT:
            int intValue;
            predicatesObject.GetInt(intValue);
            str = std::to_string(intValue);
            break;
        case DataSharePredicatesObjectType::TYPE_DOUBLE:
            double doubleValue;
            predicatesObject.GetDouble(doubleValue);
            str = std::to_string(doubleValue);
            break;
        case DataSharePredicatesObjectType::TYPE_STRING:
            predicatesObject.GetString(str);
            break;
        case DataSharePredicatesObjectType::TYPE_BOOL:
            bool boolValue;
            predicatesObject.GetBool(boolValue);
            str = std::to_string(boolValue);
            break;
        case DataSharePredicatesObjectType::TYPE_LONG:
            int64_t longValue;
            predicatesObject.GetLong(longValue);
            str = std::to_string(longValue);
            break;
        default:
            LOG_INFO("RdbUtils::ToString No matching type");
            return str;
    }
    return str;
}

RdbUtils::RdbUtils() {
}

RdbUtils::~RdbUtils() {
}