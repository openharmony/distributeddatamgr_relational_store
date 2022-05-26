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

#include "../../rdb/include/result_set.h"
#include "abs_predicates.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "rdb_predicates.h"
#include "rdb_result_set_bridge.h"
#include "result_set_bridge.h"
#include "value_object.h"
#include "values_bucket.h"

namespace OHOS {
namespace RdbDataShareAdapter {
class RdbUtils {
public:
    using RdbPredicates = NativeRdb::RdbPredicates;
    using ResultSet = NativeRdb::ResultSet;
    using ValuesBucket = NativeRdb::ValuesBucket;
    using DataShareValuesBucket = DataShare::DataShareValuesBucket;
    using DataSharePredicates = DataShare::DataSharePredicates;
    using ResultSetBridge = DataShare::ResultSetBridge;
    using OperationItem = DataShare::OperationItem;
    using DataSharePredicatesObject = DataShare::DataSharePredicatesObject;

    static ValuesBucket ToValuesBucket(const DataShareValuesBucket &bucket);

    static RdbPredicates ToPredicates(const DataSharePredicates &predicates, const std::string &table);

    static std::shared_ptr<ResultSetBridge> ToResultSetBridge(std::shared_ptr<ResultSet> resultSet);

private:
    RdbUtils();
    ~RdbUtils();
    static void ToOperateThird(
        const std::list<OperationItem>::iterator operations, std::shared_ptr<RdbPredicates> &predicates);
    static void ToOperateSecond(
        const std::list<OperationItem>::iterator operations, std::shared_ptr<RdbPredicates> &predicates);
    static void ToOperateFirst(
        const std::list<OperationItem>::iterator operations, std::shared_ptr<RdbPredicates> &predicates);
    static std::string ToString(const DataSharePredicatesObject &predicatesObject);
};
} // namespace RdbDataShareAdapter
} // namespace OHOS
#endif // RDB_UTILS_H
