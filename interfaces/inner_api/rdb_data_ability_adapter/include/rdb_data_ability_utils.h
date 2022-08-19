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

#ifndef RDB_DATA_ABILITY_UTILS_H
#define RDB_DATA_ABILITY_UTILS_H

#include <list>
#include <memory>
#include <string>
#include <vector>

#include "result_set.h"
#include "data_ability_predicates.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "values_bucket.h"

namespace OHOS {
namespace DataShare {
class ResultSet;
}
namespace NativeRdb {
class AbsSharedResultSet;
}
namespace RdbDataAbilityAdapter {
class RdbDataAbilityUtils {
public:
    using ValuesBucket = NativeRdb::ValuesBucket;
    using DataShareValuesBucket = DataShare::DataShareValuesBucket;
    using DSResultSet = DataShare::ResultSet;
    using DataSharePredicates = DataShare::DataSharePredicates;
    using DataAbilityPredicates = NativeRdb::DataAbilityPredicates;
    using AbsSharedResultSet = NativeRdb::AbsSharedResultSet;

    static DataShareValuesBucket ToDataShareValuesBucket(const ValuesBucket &valuesBucket);

    static DataSharePredicates ToDataSharePredicates(const DataAbilityPredicates &predicates);

    static std::shared_ptr<AbsSharedResultSet> ToAbsSharedResultSet(std::shared_ptr<DSResultSet> resultSet);

private:
    RdbDataAbilityUtils();
    ~RdbDataAbilityUtils();
};
} // namespace RdbDataAbilityAdapter
} // namespace OHOS
#endif // RDB_DATA_ABILITY_UTILS_H

