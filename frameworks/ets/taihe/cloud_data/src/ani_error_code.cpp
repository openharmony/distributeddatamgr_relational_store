/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define LOG_TAG "AniErrorCode"
#include "ani_error_code.h"
#include "ohos.data.cloudData.proj.hpp"
#include "ohos.data.cloudData.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include "logger.h"
#include "cloud_service.h"

namespace AniCloudData {
using namespace OHOS::Rdb;
using Status = OHOS::CloudData::CloudService::Status;
constexpr size_t ANI_ERROR_CODE_COUNT = 5;
static constexpr AniErrorCode ANI_ERROR_CODE_MSGS[ANI_ERROR_CODE_COUNT] = {
    { Status::INVALID_ARGUMENT, 401, "Parameter error." },
    { Status::NOT_SUPPORT, 801, "Not support." },
    { Status::PERMISSION_DENIED, 202, "Permission denied, non-system app called system api." },
    { Status::CLOUD_CONFIG_PERMISSION_DENIED, 201, "Permission denied." },
    { Status::INVALID_ARGUMENT_V20, 14800001, "Invalid args." }
};

const std::optional<AniErrorCode> GetAniErrorCode(int32_t status)
{
    for (size_t i = 0; i < ANI_ERROR_CODE_COUNT; ++i) {
        if (ANI_ERROR_CODE_MSGS[i].status == status) {
            return ANI_ERROR_CODE_MSGS[i];
        }
    }
    return std::nullopt;
}

void ThrowAniError(int32_t status)
{
    if (status == Status::SUCCESS) {
        return;
    }
    LOG_ERROR("ThrowAniError status: %{public}d", status);
    auto errorMsg = GetAniErrorCode(status);
    AniErrorCode aniError;
    if (errorMsg.has_value()) {
        aniError = errorMsg.value();
    } else {
        aniError.errorCode = -1;
        aniError.message = "";
    }
    taihe::set_business_error(aniError.errorCode, aniError.message);
}
}  // namespace
