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

#ifndef NATIVE_RDB_RDBUTILS_H
#define NATIVE_RDB_RDBUTILS_H

#include <memory>
#include <string>
#include <vector>

#include "abs_rdb_predicates.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "values_bucket.h"

namespace OHOS {
namespace NativeRdb {
class RdbUtils {
public:
    static ValuesBucket ConvertToValuesBucket(DataShare::DataShareValuesBucket dataShareValuesBucket);
    static std::shared_ptr<AbsRdbPredicates> ToOperate(const DataShare::DataSharePredicates &dataSharePredicates);

private:
    RdbUtils();
    ~RdbUtils();
    static void ToOperateThird(
            std::list<DataShare::OperationItem>::iterator operations,
            std::shared_ptr<AbsRdbPredicates> predicates);
    static void ToOperateSecond(
            std::list<DataShare::OperationItem>::iterator operations,
            std::shared_ptr<AbsRdbPredicates> predicates);
    static void ToOperateFirst(
            std::list<DataShare::OperationItem>::iterator operations,
            std::shared_ptr<AbsRdbPredicates> predicates);
    static std::string ToString(
            const DataShare::DataSharePredicatesObject &predicatesObject);
};
} // namespace NativeRdb
} // namespace OHOS

#endif
