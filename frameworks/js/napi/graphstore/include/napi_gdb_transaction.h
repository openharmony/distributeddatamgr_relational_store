/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef OHOS_DISTRIBUTED_DATA_GDB_JS_NAPI_GDB_TRANSACTION_H
#define OHOS_DISTRIBUTED_DATA_GDB_JS_NAPI_GDB_TRANSACTION_H

#include <functional>
#include <list>
#include <memory>
#include <mutex>

#include "js_proxy.h"
#include "js_uv_queue.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "transaction.h"

namespace OHOS::GraphStoreJsKit {
using Transaction = DistributedDataAip::Transaction;
class GdbTransactionProxy final : public GraphStoreJsKit::JSProxy<Transaction> {
public:
    GdbTransactionProxy() = default;
    ~GdbTransactionProxy();
    explicit GdbTransactionProxy(std::shared_ptr<Transaction> gdbTransaction);
    static void Init(napi_env env, napi_value exports);
    static napi_value NewInstance(napi_env env, std::shared_ptr<Transaction> value);

private:
    static napi_value Initialize(napi_env env, napi_callback_info info);
    static napi_value Read(napi_env env, napi_callback_info info);
    static napi_value Write(napi_env env, napi_callback_info info);
    static napi_value Commit(napi_env env, napi_callback_info info);
    static napi_value Rollback(napi_env env, napi_callback_info info);
};
} // namespace OHOS::GraphStoreJsKit
#endif