/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define LOG_TAG "NapiRdbSendableUtils"
#include "napi_rdb_sendable_utils.h"

#define NAPI_CALL_RETURN_ERR(theCall, retVal) \
    do {                                      \
        if ((theCall) != napi_ok) {           \
            return retVal;                    \
        }                                     \
    } while (0)

namespace OHOS::AppDataMgrJsKit {
namespace JSUtils {

template<>
napi_value Convert2Sendable(napi_env env, const Asset &value)
{
    auto outputStatus = value.status & ~0xF0000000;
    std::vector<napi_property_descriptor> descriptors = {
        DECLARE_SENDABLE_PROPERTY(env, "name", value.name),
        DECLARE_SENDABLE_PROPERTY(env, "uri", value.uri),
        DECLARE_SENDABLE_PROPERTY(env, "createTime", value.createTime),
        DECLARE_SENDABLE_PROPERTY(env, "modifyTime", value.modifyTime),
        DECLARE_SENDABLE_PROPERTY(env, "size", value.size),
        DECLARE_SENDABLE_PROPERTY(env, "path", value.path),
        DECLARE_SENDABLE_PROPERTY(env, "status", outputStatus),
    };

    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(
        napi_create_sendable_object_with_properties(env, descriptors.size(), descriptors.data(), &object), object);
    return object;
}

template<>
napi_value Convert2Sendable(napi_env env, const RowEntity &rowEntity)
{
    napi_value map = nullptr;
    NAPI_CALL_RETURN_ERR(napi_create_sendable_map(env, &map), nullptr);
    auto &values = rowEntity.Get();
    for (auto const &[key, value] : values) {
        NAPI_CALL_RETURN_ERR(napi_map_set_named_property(env, map, key.c_str(), Convert2Sendable(env, value)), nullptr);
    }
    return map;
}

template<>
napi_value Convert2Sendable(napi_env env, const ValueObject &value)
{
    return Convert2Sendable(env, value.value);
}

template<>
napi_value Convert2Sendable(napi_env env, const BigInt &value)
{
    return Convert2JSValue(env, value);
}
}; // namespace JSUtils
} // namespace OHOS::AppDataMgrJsKit