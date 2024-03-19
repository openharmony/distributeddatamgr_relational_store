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
#define LOG_TAG "JSErrorUtils"
#include "js_error_utils.h"

#include <algorithm>

#include "logger.h"

namespace OHOS::CloudData {
using namespace OHOS::Rdb;
using JsErrorCode = OHOS::CloudData::JsErrorCode;

static constexpr JsErrorCode JS_ERROR_CODE_MSGS[] = {
    { Status::INVALID_ARGUMENT, 401, "Parameter error." },
    { Status::NOT_SUPPORT, 801, "Not support." },
    { Status::PERMISSION_DENIED, 202, "Permission denied, non-system app called system api." },
    { Status::CLOUD_CONFIG_PERMISSION_DENIED, 201, "Permission denied." }
};

const std::optional<JsErrorCode> GetJsErrorCode(int32_t errorCode)
{
    auto jsErrorCode = JsErrorCode{ errorCode, -1, "" };
    auto iter = std::lower_bound(JS_ERROR_CODE_MSGS,
        JS_ERROR_CODE_MSGS + sizeof(JS_ERROR_CODE_MSGS) / sizeof(JS_ERROR_CODE_MSGS[0]), jsErrorCode,
        [](const JsErrorCode &jsErrorCode1, const JsErrorCode &jsErrorCode2) {
            return jsErrorCode1.status < jsErrorCode2.status;
        });
    if (iter < JS_ERROR_CODE_MSGS + sizeof(JS_ERROR_CODE_MSGS) / sizeof(JS_ERROR_CODE_MSGS[0])
        && iter->status == errorCode) {
        return *iter;
    }
    return std::nullopt;
}

Status GenerateNapiError(int32_t status, int32_t &errCode, std::string &errMessage)
{
    auto errorMsg = GetJsErrorCode(status);
    if (errorMsg.has_value()) {
        auto napiError = errorMsg.value();
        errCode = napiError.jsCode;
        errMessage = napiError.message;
    } else {
        // unmatched status return unified error code
        errCode = -1;
        errMessage = "";
    }
    LOG_DEBUG("GenerateNapiError errCode is %{public}d", errCode);
    if (errCode == 0) {
        return Status::SUCCESS;
    }
    return static_cast<Status>(status);
}

void ThrowNapiError(napi_env env, int32_t status, const std::string &errMessage)
{
    LOG_DEBUG("ThrowNapiError message: %{public}s", errMessage.c_str());
    if (status == Status::SUCCESS) {
        return;
    }
    auto errorMsg = GetJsErrorCode(status);
    JsErrorCode napiError;
    if (errorMsg.has_value()) {
        napiError = errorMsg.value();
    } else {
        napiError.jsCode = -1;
        napiError.message = "";
    }

    std::string message(napiError.message);

    message += errMessage;

    std::string jsCode;
    if (napiError.jsCode == -1) {
        jsCode = "";
    } else {
        jsCode = std::to_string(napiError.jsCode);
    }
    napi_throw_error(env, jsCode.c_str(), message.c_str());
}
} // namespace OHOS::CloudData
