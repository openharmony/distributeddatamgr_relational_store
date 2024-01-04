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

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "common_types.h"

namespace OHOS::CommonType {
static napi_status SetNamedProperty(napi_env env, napi_value &obj, const std::string &name,
    int32_t value)
{
    napi_value property = nullptr;
    napi_status status = napi_create_int32(env, value, &property);
    if (status != napi_ok) {
        return status;
    }
    status = napi_set_named_property(env, obj, name.c_str(), property);
    return status;
}

static napi_value ExportAssetStatus(napi_env env)
{
    napi_value assetStatus = nullptr;
    napi_create_object(env, &assetStatus);
    SetNamedProperty(env, assetStatus, "ASSET_NORMAL", AssetValue::STATUS_NORMAL);
    SetNamedProperty(env, assetStatus, "ASSET_INSERT", AssetValue::STATUS_INSERT);
    SetNamedProperty(env, assetStatus, "ASSET_UPDATE", AssetValue::STATUS_UPDATE);
    SetNamedProperty(env, assetStatus, "ASSET_DELETE", AssetValue::STATUS_DELETE);
    SetNamedProperty(env, assetStatus, "ASSET_ABNORMAL", AssetValue::STATUS_ABNORMAL);
    SetNamedProperty(env, assetStatus, "ASSET_DOWNLOADING", AssetValue::STATUS_DOWNLOADING);
    napi_object_freeze(env, assetStatus);
    return assetStatus;
}
}

static napi_value CommonTypeExport(napi_env env, napi_value exports)
{
    napi_status status;
    static napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("AssetStatus", OHOS::CommonType::ExportAssetStatus(env)),
    };

    status = napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    if (status != napi_ok) {
        return nullptr;
    }
    return exports;
}

static napi_module storageModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = CommonTypeExport,
    .nm_modname = "data.commonType",
    .nm_priv = ((void *)0),
    .reserved = { 0 },
};

static __attribute__((constructor)) void RegisterModule()
{
    napi_module_register(&storageModule);
}