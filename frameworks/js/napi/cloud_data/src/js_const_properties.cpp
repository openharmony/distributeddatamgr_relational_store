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

#include "js_const_properties.h"

#include "cloud_service.h"
#include "napi_queue.h"

using namespace OHOS::Rdb;
using Action = OHOS::CloudData::CloudService::Action;

namespace OHOS::CloudData {
static napi_status SetNamedProperty(napi_env env, napi_value &obj, const std::string &name, int32_t value)
{
    napi_value property = nullptr;
    napi_status status = napi_create_int32(env, value, &property);
    ASSERT(status == napi_ok, "int32_t to napi_value failed!", status);
    status = napi_set_named_property(env, obj, name.c_str(), property);
    ASSERT(status == napi_ok, "napi_set_named_property failed!", status);
    return status;
}

static napi_value ExportAction(napi_env env)
{
    napi_value action = nullptr;
    napi_create_object(env, &action);
    SetNamedProperty(env, action, "CLEAR_CLOUD_INFO", (int32_t)Action::CLEAR_CLOUD_INFO);
    SetNamedProperty(env, action, "CLEAR_CLOUD_DATA_AND_INFO", (int32_t)Action::CLEAR_CLOUD_DATA_AND_INFO);
    napi_object_freeze(env, action);
    return action;
}

napi_status InitConstProperties(napi_env env, napi_value exports)
{
    const napi_property_descriptor properties[] = {
        DECLARE_NAPI_PROPERTY("Action", ExportAction(env)),
    };
    size_t count = sizeof(properties) / sizeof(properties[0]);

    return napi_define_properties(env, exports, count, properties);
}
} // namespace OHOS::CloudData
