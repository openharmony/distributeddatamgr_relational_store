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

#include "rdb_data_ability_utils.h"
#include "result_set_utils.h"

using namespace OHOS::RdbDataAbilityAdapter;
using namespace OHOS::DataShare;
using namespace OHOS::NativeRdb;

RdbDataAbilityUtils::RdbDataAbilityUtils()
{
}

RdbDataAbilityUtils::~RdbDataAbilityUtils()
{
}

DataShareValuesBucket RdbDataAbilityUtils::ToDataShareValuesBucket(const ValuesBucket &valuesBucket)
{
    std::map<std::string, DataShareValueObject> values;
    std::map<std::string, ValueObject> valuesMap;
    valuesBucket.GetAll(valuesMap);
    for (auto &[key, value] : valuesMap) {
        if (value.GetType() == ValueObjectType::TYPE_BOOL) {
            values.insert(std::make_pair(key, DataShareValueObject(value.operator bool())));
        } else if (value.GetType() == ValueObjectType::TYPE_INT) {
            values.insert(std::make_pair(key, DataShareValueObject(value.operator int())));
        } else if (value.GetType() == ValueObjectType::TYPE_DOUBLE) {
            values.insert(std::make_pair(key, DataShareValueObject(value.operator double())));
        } else if (value.GetType() == ValueObjectType::TYPE_STRING) {
            values.insert(std::make_pair(key, DataShareValueObject(value.operator std::string())));
        } else if (value.GetType() == ValueObjectType::TYPE_BLOB) {
            values.insert(std::make_pair(key, DataShareValueObject(value.operator std::vector<uint8_t>())));
        }
    }
    return DataShareValuesBucket(values);
}

DataSharePredicates RdbDataAbilityUtils::ToDataSharePredicates(const DataAbilityPredicates &predicates)
{
    DataSharePredicates dataSharePredicates;

    if (predicates.IsDistinct()) {
        dataSharePredicates.Distinct();
    }
    if (!predicates.GetGroup().empty()) {
        std::vector<std::string> groups;
        groups.push_back(predicates.GetGroup());
        dataSharePredicates.GroupBy(groups);
    }
    if (!predicates.GetIndex().empty()) {
        dataSharePredicates.IndexedBy(predicates.GetIndex());
    }
    if (predicates.GetLimit() != 0 || predicates.GetOffset()) {
        dataSharePredicates.Limit(predicates.GetLimit(), predicates.GetOffset());
    }

    dataSharePredicates.SetSettingMode(QUERY_LANGUAGE);
    dataSharePredicates.SetWhereClause(predicates.GetWhereClause());
    dataSharePredicates.SetWhereArgs(predicates.GetWhereArgs());
    dataSharePredicates.SetOrder(predicates.GetOrder());
    return dataSharePredicates;
}

std::shared_ptr<AbsSharedResultSet> RdbDataAbilityUtils::ToAbsSharedResultSet(std::shared_ptr<DSResultSet> resultSet)
{
    return std::make_shared<ResultSetUtils>(resultSet);
}
