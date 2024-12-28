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
#ifndef OHOS_DISTRIBUTED_DATA_GDB_JS_NAPI_GDB_STORE_H
#define OHOS_DISTRIBUTED_DATA_GDB_JS_NAPI_GDB_STORE_H

#include <functional>
#include <list>
#include <memory>
#include <mutex>

#include "gdb_store.h"
#include "js_proxy.h"
#include "js_uv_queue.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS::GraphStoreJsKit {
using namespace DistributedDataAip;
#define ASSERT_CALL(env, theCall, object)    \
    do {                                     \
        if ((theCall) != napi_ok) {          \
            delete (object);                 \
            GET_AND_THROW_LAST_ERROR((env)); \
            return nullptr;                  \
        }                                    \
    } while (0)

using Descriptor = std::function<std::vector<napi_property_descriptor>(void)>;
class GdbStoreProxy : public GraphStoreJsKit::JSProxy<DBStore> {
public:
    static void Init(napi_env env, napi_value exports);
    static napi_value NewInstance(napi_env env, std::shared_ptr<DBStore> value, bool isSystemAppCalled);
    GdbStoreProxy();
    ~GdbStoreProxy();
    GdbStoreProxy(std::shared_ptr<DBStore> gdbStore);
    GdbStoreProxy &operator=(std::shared_ptr<DBStore> GdbStore);
    bool IsSystemAppCalled();
    static constexpr int32_t MAX_GQL_LEN = 1024 * 1024;

private:
    static napi_value Initialize(napi_env env, napi_callback_info info);
    static napi_value Read(napi_env env, napi_callback_info info);
    static napi_value Write(napi_env env, napi_callback_info info);
    static napi_value Close(napi_env env, napi_callback_info info);

    static Descriptor GetDescriptors();

    static napi_value New(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void *nativeObject, void *finalize_hint);

    bool isSystemAppCalled_ = false;
    std::shared_ptr<AppDataMgrJsKit::UvQueue> queue_;
};
} // namespace OHOS::GraphStoreJsKit
#endif