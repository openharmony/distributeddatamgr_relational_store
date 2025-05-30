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
#define LOG_TAG "RegisterCloudDataModule"
#include "js_client.h"
#include "js_cloud_share.h"
#include "js_config.h"
#include "js_const_properties.h"
#include "logger.h"

using namespace OHOS::CloudData;
using namespace OHOS::Rdb;

static napi_value Init(napi_env env, napi_value exports)
{
    auto sharingExport = InitCloudSharing(env, exports);
    napi_status status = InitSharingConstProperties(env, sharingExport);
    LOG_INFO("Init Enumerate Constants of Sharing: %{public}d", status);
    exports = JsConfig::InitConfig(env, exports);
    status = InitConstProperties(env, exports);
    LOG_INFO("Init Enumerate Constants of Config: %{public}d", status);
    exports = InitClient(env, exports);
    status = InitClientProperties(env, exports);
    LOG_INFO("Init Enumerate Constants of Client: %{public}d", status);
    return exports;
}

static __attribute__((constructor)) void RegisterModule()
{
    static napi_module module = { .nm_version = 1,
        .nm_flags = 0,
        .nm_filename = nullptr,
        .nm_register_func = Init,
        .nm_modname = "data.cloudData",
        .nm_priv = ((void *)0),
        .reserved = { 0 } };
    napi_module_register(&module);
    LOG_INFO("Module register data.cloudData");
}
