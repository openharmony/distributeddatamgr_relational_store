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

#ifndef CLOUD_DATA_JS_ERROR_UTILS_H
#define CLOUD_DATA_JS_ERROR_UTILS_H

#include <optional>
#include <string>

#include "cloud_service.h"
#include "js_native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace CloudData {
using Status = OHOS::CloudData::CloudService::Status;

struct JsErrorCode {
    int32_t status = 0;
    int32_t jsCode = -1;
    const char *message = nullptr;
};

const std::optional<JsErrorCode> GetJsErrorCode(int32_t errorCode);
Status GenerateNapiError(int32_t status, int32_t &errCode, std::string &errMessage);
void ThrowNapiError(napi_env env, int32_t errCode, const std::string &errMessage);
napi_value GenerateErrorMsg(napi_env env, JsErrorCode jsInfo);

#define ASSERT_ERR(env, assertion, errorCode, message) \
    do {                                               \
        if (!(assertion)) {                            \
            ThrowNapiError(env, errorCode, message);   \
            return nullptr;                            \
        }                                              \
    } while (0)

#define ASSERT_BUSINESS_ERR(ctxt, assertion, errorCode, message) \
    do {                                                         \
        if (!(assertion)) {                                      \
            (ctxt)->isThrowError = true;                         \
            ThrowNapiError((ctxt)->env, errorCode, message);     \
            return;                                              \
        }                                                        \
    } while (0)

#define ASSERT_PERMISSION_ERR(ctxt, assertion, errorCode, message)  \
    do {                                                            \
        if (!(assertion)) {                                         \
            (ctxt)->isThrowError = true;                            \
            ThrowNapiError((ctxt)->env, errorCode, message);        \
            return;                                                 \
        }                                                           \
    } while (0)

} // namespace CloudData
} // namespace OHOS
#endif //CLOUD_DATA_JS_ERROR_UTILS_H
