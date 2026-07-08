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

#include <string>

#include "ani_ability_utils.h"
#include "ani_base_context.h"
#include "ani_utils.h"
#include "js_ability.h"
#include "js_utils.h"

namespace OHOS {
namespace RdbTaihe {
using namespace taihe;

std::string GetErrorString(int errcode)
{
    switch (errcode) {
        case NativeRdb::E_EMPTY_TABLE_NAME:
            return "The table must be not empty string.";
        case NativeRdb::E_EMPTY_VALUES_BUCKET:
            return "Bucket must not be empty.";
        case NativeRdb::E_INVALID_CONFLICT_FLAG:
            return "Conflict flag is not correct.";
        case NativeRdb::E_INVALID_ARGS:
            return "The ValueBucket contains Assets and conflictResolution is REPLACE.";
        default:
            return std::string();
    }
}

void ThrowError(std::shared_ptr<Error> err)
{
    if (err != nullptr) {
        LOG_ERROR("code[%{public}d,%{public}d][%{public}s]", err->GetNativeCode(), err->GetCode(),
            err->GetMessage().c_str());
        taihe::set_business_error(err->GetCode(), err->GetMessage());
    }
}

void ThrowInnerError(int errCode, const std::string &errMsg)
{
    auto innErr = std::make_shared<InnerError>(errCode, errMsg);
    ThrowError(innErr);
}

void ThrowInnerErrorExt(int errCode, const std::string &errMsg)
{
    auto innErr = std::make_shared<InnerErrorExt>(errCode, errMsg);
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
