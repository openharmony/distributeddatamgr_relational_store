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

#ifndef OHOS_DISTRIBUTED_DATA_GDB_JS_NAPI_GDB_JS_UTILS_H
#define OHOS_DISTRIBUTED_DATA_GDB_JS_NAPI_GDB_JS_UTILS_H
#include "full_result.h"
#include "gdb_store_config.h"
#include "js_utils.h"
#include "logger.h"
#include "napi_gdb_context.h"

namespace OHOS::AppDataMgrJsKit::JSUtils {
using namespace GraphStoreJsKit;
using StoreConfig = DistributedDataAip::StoreConfig;
using Vertex = OHOS::DistributedDataAip::Vertex;
using Edge = OHOS::DistributedDataAip::Edge;
using PathSegment = OHOS::DistributedDataAip::PathSegment;
using Path = OHOS::DistributedDataAip::Path;

#define GRAPH_ASSERT(condition, message, retVal)                 \
    do {                                                         \
        if (!(condition)) {                                      \
            LOG_ERROR("test (" #condition ") failed: " message); \
            return retVal;                                       \
        }                                                        \
    } while (0)

#define NAPI_CALL_RETURN_ERR(theCall, retVal) \
    do {                                      \
        if ((theCall) != napi_ok) {           \
            return retVal;                    \
        }                                     \
    } while (0)

#ifndef PATH_SPLIT
#define PATH_SPLIT '/'
#endif

static inline OHOS::HiviewDFX::HiLogLabel LogLabel()
{
    return { LOG_CORE, 0xD001660, "GdbJSUtils" };
}

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, ContextParam &context);

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, StoreConfig &config);

template<>
napi_value Convert2JSValue(napi_env env, const std::shared_ptr<Result> &result);

template<>
napi_value Convert2JSValue(napi_env env, const std::shared_ptr<Vertex> &value);

template<>
napi_value Convert2JSValue(napi_env env, const std::shared_ptr<Edge> &edge);

template<>
napi_value Convert2JSValue(napi_env env, const std::shared_ptr<PathSegment> &pathSegment);

template<>
napi_value Convert2JSValue(napi_env env, const std::shared_ptr<Path> &path);

std::tuple<int32_t, std::shared_ptr<Error>> GetRealPath(StoreConfig &config, ContextParam &param);
} // namespace OHOS::AppDataMgrJsKit::JSUtils

#endif