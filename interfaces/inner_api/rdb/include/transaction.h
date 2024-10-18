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

#ifndef OHOS_RELATIONAL_STORE_TRANSACTION_H
#define OHOS_RELATIONAL_STORE_TRANSACTION_H
#include <memory>

#include "rdb_visibility.h"
namespace OHOS::NativeRdb {
class RdbStore;
class Connection;
class API_EXPORT Transaction {
public:
    enum TransType : int32_t {
        DEFERRED,
        IMMEDIATE,
        EXCLUSIVE,
        TRANS_BUTT
    };
    static std::pair<int32_t, std::shared_ptr<Transaction>> Create(int32_t type, std::shared_ptr<Connection> conn,
        const std::string &name);
    Transaction() = default;
    virtual ~Transaction() = default;
    virtual int32_t Commit() = 0;
    virtual int32_t Rollback() = 0;
    virtual std::pair<int32_t, std::shared_ptr<RdbStore>> GetTransDB() = 0;
    virtual int32_t Close() = 0;
};
}
#endif // OHOS_RELATIONAL_STORE_TRANSACTION_H
