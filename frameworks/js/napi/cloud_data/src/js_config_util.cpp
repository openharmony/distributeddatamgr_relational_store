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

#include "js_config_util.h"

namespace OHOS::AppDataMgrJsKit {
namespace JSUtils {
template<>
int32_t Convert2Value(napi_env env, napi_value input, OHOS::CloudData::JsConfig::ExtraData &output)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, input, &type);
    if (status != napi_ok || type != napi_object) {
        return napi_invalid_arg;
    }
    int32_t result = GET_PROPERTY(env, input, output, eventId);
    if (result != napi_ok) {
        return napi_invalid_arg;
    }
    return GET_PROPERTY(env, input, output, extraData);
}
} // namespace JSUtils
} // namespace OHOS::AppDataMgrJsKit