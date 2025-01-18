/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_DATA_INTERFACE_GDB_DB_STORE_H
#define OHOS_DISTRIBUTED_DATA_INTERFACE_GDB_DB_STORE_H
#include "rdb_visibility.h"
#include "result.h"
#include "transaction.h"

namespace OHOS::DistributedDataAip {
class API_EXPORT DBStore {
public:
    API_EXPORT virtual std::pair<int32_t, std::shared_ptr<Result>> QueryGql(const std::string &gql) = 0;
    API_EXPORT virtual std::pair<int32_t, std::shared_ptr<Result>> ExecuteGql(const std::string &gql) = 0;
    API_EXPORT virtual std::pair<int32_t, std::shared_ptr<Transaction>> CreateTransaction() = 0;
    API_EXPORT virtual int32_t Close() = 0;

    virtual ~DBStore() = default;
};
} // namespace OHOS::DistributedDataAip
#endif //OHOS_DISTRIBUTED_DATA_INTERFACE_GDB_DB_STORE_H
