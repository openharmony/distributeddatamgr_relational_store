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

#define LOG_TAG "NapiCloudSyncInfoObserver"

#include "napi_cloud_sync_info_observer.h"

#include "js_utils.h"
#include "logger.h"

namespace OHOS::CloudData {
using namespace OHOS::Rdb;
NapiCloudSyncInfoObserver::NapiCloudSyncInfoObserver(napi_env env, napi_value callback,
    std::shared_ptr<UvQueue> uvQueue)
    : env_(env), uvQueue_(uvQueue)
{
    napi_create_reference(env, callback, 1, &callback_);
}

NapiCloudSyncInfoObserver::~NapiCloudSyncInfoObserver() noexcept
{
}

void NapiCloudSyncInfoObserver::OnSyncInfoChanged(const std::map<std::string, QueryLastResults> &data)
{
    auto uvQueue = uvQueue_;
    if (uvQueue == nullptr) {
        return;
    }
    uvQueue->AsyncCallInOrder({ callback_, true },
        [observer = shared_from_this(), data](napi_env env, int &argc, napi_value *argv) {
            argc = 1;
            argv[0] = JSUtils::Convert2JSValue(env, data);
        });
}

bool NapiCloudSyncInfoObserver::operator==(napi_value value)
{
    if (callback_ == nullptr) {
        return false;
    }
    napi_value callback = nullptr;
    napi_status status = napi_get_reference_value(env_, callback_, &callback);
    if (status != napi_ok) {
        LOG_ERROR("Call napi_get_reference_value failed status[%{public}d].", status);
        return false;
    }

    bool isEquals = false;
    status = napi_strict_equals(env_, value, callback, &isEquals);
    if (status != napi_ok) {
        LOG_ERROR("Call napi_strict_equals failed status[%{public}d].", status);
        return false;
    }
    return isEquals;
}

void NapiCloudSyncInfoObserver::Clear()
{
    if (callback_ == nullptr) {
        return;
    }
    napi_delete_reference(env_, callback_);
    callback_ = nullptr;
}
} // namespace OHOS::CloudData
