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
/**
 * The RdbDataAbilityUtils class of RDB.
 */
class API_EXPORT RdbDataAbilityUtils {
public:
    /**
     * @brief Use ValuesBucket replace NativeRdb::ValuesBucket namespace.
     */
    using ValuesBucket = NativeRdb::ValuesBucket;

    /**
     * @brief Use DataShareValuesBucket replace DataShare::DataShareValuesBucket namespace.
     */
    using DataShareValuesBucket = DataShare::DataShareValuesBucket;

    /**
     * @brief Use DSResultSet replace DataShare::ResultSet namespace.
     */
    using DSResultSet = DataShare::ResultSet;

    /**
     * @brief Use DataSharePredicates replace DataShare::DataSharePredicates namespace.
     */
    using DataSharePredicates = DataShare::DataSharePredicates;

    /**
     * @brief Use DataAbilityPredicates replace NativeRdb::DataAbilityPredicates namespace.
     */
    using DataAbilityPredicates = NativeRdb::DataAbilityPredicates;

    /**
     * @brief Use AbsSharedResultSet replace NativeRdb::AbsSharedResultSet namespace.
     */
    using AbsSharedResultSet = NativeRdb::AbsSharedResultSet;

    /**
     * @brief Convert NativeRdb::ValuesBucket to DataShare::DataShareValuesBucket.
     */
    API_EXPORT static DataShareValuesBucket ToDataShareValuesBucket(ValuesBucket valuesBucket);

    /**
     * @brief Convert NativeRdb::DataAbilityPredicates to DataShare::DataSharePredicates.
     */
    API_EXPORT static DataSharePredicates ToDataSharePredicates(const DataAbilityPredicates &predicates);

    /**
     * @brief Convert NDataShare::ResultSet to NativeRdb::AbsSharedResultSet.
     */
    API_EXPORT static std::shared_ptr<AbsSharedResultSet> ToAbsSharedResultSet(
        std::shared_ptr<DSResultSet> resultSet);

private:
    RdbDataAbilityUtils();
    ~RdbDataAbilityUtils();
};
} // namespace RdbDataAbilityAdapter
} // namespace OHOS
#endif // RDB_DATA_ABILITY_UTILS_H

