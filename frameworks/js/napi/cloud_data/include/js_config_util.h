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

#ifndef LDBPROJ_JS_CONFIG_UTIL_H
#define LDBPROJ_JS_CONFIG_UTIL_H

#include "js_config.h"
#include "js_utils.h"

namespace OHOS::AppDataMgrJsKit {
using ExtraData = OHOS::CloudData::JsConfig::ExtraData;
namespace JSUtils {
template<>
int32_t Convert2Value(napi_env env, napi_value input, ExtraData &output);
} // namespace JSUtils
} // namespace OHOS::AppDataMgrJsKit
#endif // LDBPROJ_JS_CONFIG_UTIL_H