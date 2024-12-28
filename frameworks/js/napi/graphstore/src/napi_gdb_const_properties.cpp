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

#include "napi_gdb_const_properties.h"

#include "gdb_common.h"
#include "gdb_store.h"
#include "js_utils.h"

namespace OHOS::GraphStoreJsKit {
using namespace AppDataMgrJsKit;
using namespace DistributedDataAip;
#define SET_NAPI_PROPERTY(object, prop, value) \
    napi_set_named_property((env), (object), (prop), JSUtils::Convert2JSValue((env), (value)))

static napi_value ExportSecurityLevel(napi_env env)
{
    napi_value securityLevel = nullptr;
    napi_create_object(env, &securityLevel);

    SET_NAPI_PROPERTY(securityLevel, "S1", 1);
    SET_NAPI_PROPERTY(securityLevel, "S2", 2);
    SET_NAPI_PROPERTY(securityLevel, "S3", 3);
    SET_NAPI_PROPERTY(securityLevel, "S4", 4);

    napi_object_freeze(env, securityLevel);
    return securityLevel;
}

napi_status InitConstProperties(napi_env env, napi_value exports)
{
    const napi_property_descriptor properties[] = {
        DECLARE_NAPI_PROPERTY("SecurityLevel", ExportSecurityLevel(env)),
    };

    size_t count = sizeof(properties) / sizeof(properties[0]);
    return napi_define_properties(env, exports, count, properties);
}
} // namespace OHOS::GraphStoreJsKit