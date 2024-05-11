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

#ifndef CLOUD_DATA_JS_CONFIG_H
#define CLOUD_DATA_JS_CONFIG_H

#include "cloud_manager.h"
#include "js_const_properties.h"

namespace OHOS::CloudData {
class JsConfig {
public:
    JsConfig();
    ~JsConfig();
    static napi_value InitConfig(napi_env env, napi_value exports);
    static napi_value New(napi_env env, napi_callback_info info);

    enum {
        /* exported js ClearAction  is (CloudData::ClearAction-1) */
        CLEAR_CLOUD_INFO = 0,
        CLEAR_CLOUD_DATA_AND_INFO = 1,
    };

    struct ExtraData {
        std::string eventId;
        std::string extraData;
    };

    static inline bool ValidSubscribeType(int32_t type)
    {
        return (CLEAR_CLOUD_INFO <= type) && (type <= CLEAR_CLOUD_DATA_AND_INFO);
    }

    static inline bool VerifyExtraData(const ExtraData &data)
    {
        return (!data.eventId.empty()) && (!data.extraData.empty());
    }

    static napi_value EnableCloud(napi_env env, napi_callback_info info);
    static napi_value DisableCloud(napi_env env, napi_callback_info info);
    static napi_value ChangeAppCloudSwitch(napi_env env, napi_callback_info info);
    static napi_value Clean(napi_env env, napi_callback_info info);
    static napi_value NotifyDataChange(napi_env env, napi_callback_info info);
    static napi_value QueryStatistics(napi_env env, napi_callback_info info);
    static napi_value SetGlobalCloudStrategy(napi_env env, napi_callback_info info);
    static napi_value QueryLastSyncInfo(napi_env env, napi_callback_info info);
};

} // namespace OHOS::CloudData
#endif //CLOUD_DATA_JS_CONFIG_H