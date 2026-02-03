/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

 #define LOG_TAG "ErrorThrowUtils"
#include "error_throw_utils.h"

namespace OHOS {
namespace RdbTaihe {

std::string GetErrorString(int errcode)
{
    if (ERR_STRING_MAP.find(errcode) != ERR_STRING_MAP.end()) {
        return ERR_STRING_MAP.at(errcode);
    }
    return std::string();
}

void ThrowError(std::shared_ptr<Error> err)
{
    if (err != nullptr) {
        LOG_ERROR("code[%{public}d,%{public}d][%{public}s]", err->GetNativeCode(), err->GetCode(),
            err->GetMessage().c_str());
        taihe::set_business_error(err->GetCode(), err->GetMessage());
    }
}

void ThrowInnerError(int errCode)
{
    auto innErr = std::make_shared<InnerError>(errCode);
    ThrowError(innErr);
}

// Error codes that cannot be thrown in some old scenarios need to be converted in new scenarios.
void ThrowInnerErrorExt(int errCode)
{
    auto innErr = std::make_shared<InnerErrorExt>(errCode);
    if (innErr != nullptr) {
        taihe::set_business_error(innErr->GetCode(), innErr->GetMessage());
    }
}

void ThrowNonSystemError()
{
    auto innErr = std::make_shared<NonSystemError>();
    ThrowError(innErr);
}

void ThrowParamError(const char *message)
{
    if (message == nullptr) {
        return;
    }
    auto paraErr = std::make_shared<ParamError>(message);
    ThrowError(paraErr);
}
} // namespace RdbTaihe
} // namespace OHOS