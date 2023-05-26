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

#include "raw_data_parser.h"
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

DataShareValuesBucket RdbDataAbilityUtils::ToDataShareValuesBucket(ValuesBucket valuesBucket)
{
    std::map<std::string, DataShareValueObject::Type> values;
    for (auto &[key, value] : valuesBucket.values_) {
        DataShareValueObject::Type dsValue;
        RawDataParser::Convert(std::move(value.value), dsValue);
        values.insert(std::make_pair(key, std::move(dsValue)));
    }
    return DataShareValuesBucket(std::move(values));
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
