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
#define LOG_TAG "AniCloudDataUtils"
#include "ani_cloud_data_utils.h"
#include "logger.h"
#include "ani_error_code.h"

namespace AniCloudData {
using namespace OHOS::Rdb;
void RequestIPC(std::function<void(std::shared_ptr<CloudService>)> work)
{
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (proxy == nullptr) {
        if (state != CloudService::SERVER_UNAVAILABLE) {
            state = CloudService::NOT_SUPPORT;
        }
        LOG_ERROR("proxy is NULL");
        ThrowAniError(state);
        return;
    }
    work(proxy);
}
}  // namespace
