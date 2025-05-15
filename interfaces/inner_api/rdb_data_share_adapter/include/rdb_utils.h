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

#ifndef RDB_UTILS_H
#define RDB_UTILS_H

#include <list>
#include <memory>
#include <string>
#include <vector>

#include "result_set.h"
#include "abs_predicates.h"
#include "rdb_predicates.h"
#include "rdb_result_set_bridge.h"
#include "result_set_bridge.h"
#include "value_object.h"
#include "values_bucket.h"
#include "cache_result_set.h"

namespace OHOS {
namespace DataShare {
    class DataShareValuesBucket;
    class DataShareAbsPredicates;
    struct OperationItem;
    class SingleValue;
}
namespace RdbDataShareAdapter {
/**
 * The RdbUtils class of RDB.
 */
class API_EXPORT RdbUtils {
public:
    /**
     * @brief Use RdbPredicates replace NativeRdb::RdbPredicates namespace.
     */
    using RdbPredicates = NativeRdb::RdbPredicates;

    /**
     * @brief Use ResultSet replace NativeRdb::ResultSet namespace.
     */
    using ResultSet = NativeRdb::ResultSet;

    /**
     * @brief Use ValuesBucket replace NativeRdb::ValuesBucket namespace.
     */
    using ValuesBucket = NativeRdb::ValuesBucket;

    /**
     * @brief Use DataShareValuesBucket replace DataShare::DataShareValuesBucket namespace.
     */
    using DataShareValuesBucket = DataShare::DataShareValuesBucket;

    /**
     * @brief Use DataShareAbsPredicates replace DataShare::DataShareAbsPredicates namespace.
     */
    using DataShareAbsPredicates = DataShare::DataShareAbsPredicates;

    /**
     * @brief Use ResultSetBridge replace DataShare::ResultSetBridge namespace.
     */
    using ResultSetBridge = DataShare::ResultSetBridge;

    /**
     * @brief Use OperationItem replace DataShare::OperationItem namespace.
     */
    using OperationItem = DataShare::OperationItem;

    /**
     * @brief Use DataSharePredicatesObject replace DataShare::SingleValue namespace.
     */
    using DataSharePredicatesObject = DataShare::SingleValue;

    /**
     * @brief Convert DataShare::DataShareValuesBucket to NativeRdb::ValuesBucket.
     */
    API_EXPORT static ValuesBucket ToValuesBucket(DataShareValuesBucket bucket);

    /**
     * @brief Convert DataShare::DataShareAbsPredicates to NativeRdb::RdbPredicates.
     *
     * @param table Indicates the table name.
     */
    API_EXPORT static RdbPredicates ToPredicates(
        const DataShareAbsPredicates &predicates, const std::string &table);

    /**
     * @brief Convert NativeRdb::ResultSet to DataShare::ResultSetBridge.
     */
    API_EXPORT static std::shared_ptr<ResultSetBridge> ToResultSetBridge(std::shared_ptr<ResultSet> resultSet);

private:
    RdbUtils();
    ~RdbUtils();
};
} // namespace RdbDataShareAdapter
} // namespace OHOS
#endif // RDB_UTILS_H
