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

#ifndef RDB_JSKIT_NAPI_TRANSACTION_H
#define RDB_JSKIT_NAPI_TRANSACTION_H

#include <memory>

#include "js_proxy.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "transaction.h"

namespace OHOS {
namespace RelationalStoreJsKit {
class TransactionProxy final : public JSProxy::JSProxy<NativeRdb::Transaction> {
public:
    TransactionProxy() = default;
    ~TransactionProxy();
    TransactionProxy(std::shared_ptr<NativeRdb::Transaction> transaction);
    static void Init(napi_env env, napi_value exports);
    static napi_value NewInstance(napi_env env, std::shared_ptr<NativeRdb::Transaction> transaction);

private:
    static napi_value Initialize(napi_env env, napi_callback_info info);
    static napi_value Commit(napi_env env, napi_callback_info info);
    static napi_value Rollback(napi_env env, napi_callback_info info);
    static napi_value Delete(napi_env env, napi_callback_info info);
    static napi_value Update(napi_env env, napi_callback_info info);
    static napi_value Insert(napi_env env, napi_callback_info info);
    static napi_value BatchInsert(napi_env env, napi_callback_info info);
    static napi_value BatchInsertWithConflictResolution(napi_env env, napi_callback_info info);
    static napi_value Query(napi_env env, napi_callback_info info);
    static napi_value QueryWithoutRowCount(napi_env env, napi_callback_info info);
    static napi_value QuerySqlWithoutRowCount(napi_env env, napi_callback_info info);
    static napi_value QuerySql(napi_env env, napi_callback_info info);
    static napi_value Execute(napi_env env, napi_callback_info info);
    static void AddSyncFunctions(std::vector<napi_property_descriptor> &properties);
};
} // namespace RelationalStoreJsKit
} // namespace OHOS
#endif // RDB_JSKIT_NAPI_TRANSACTION_H
