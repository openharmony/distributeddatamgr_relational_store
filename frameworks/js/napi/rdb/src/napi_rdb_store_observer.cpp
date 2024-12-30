/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#define LOG_TAG "NapiRdbStoreObserver"
#include "napi_rdb_store_observer.h"

#include "js_utils.h"
#include "logger.h"

using namespace OHOS::Rdb;
using namespace OHOS::AppDataMgrJsKit;

namespace OHOS::RdbJsKit {
NapiRdbStoreObserver::NapiRdbStoreObserver(napi_value callback, std::shared_ptr<UvQueue> uvQueue, int32_t mode)
    : uvQueue_(uvQueue)
{
    napi_create_reference(uvQueue_->GetEnv(), callback, 1, &callback_);
}

NapiRdbStoreObserver::~NapiRdbStoreObserver() noexcept
{
}

bool NapiRdbStoreObserver::operator==(napi_value value)
{
    return JSUtils::Equal(uvQueue_->GetEnv(), callback_, value);
}

void NapiRdbStoreObserver::OnChange(const std::vector<std::string> &devices)
{
    LOG_INFO("NapiRdbStoreObserver::OnChange begin");
    auto uvQueue = uvQueue_;
    if (uvQueue == nullptr) {
        return;
    }
    uvQueue->AsyncCall({ [observer = shared_from_this()](napi_env env) -> napi_value {
        if (observer->callback_ == nullptr) {
            return nullptr;
        }
        napi_value callback = nullptr;
        napi_get_reference_value(env, observer->callback_, &callback);
        return callback;
    } },
        [devices](napi_env env, int &argc, napi_value *argv) {
            argc = 1;
            argv[0] = JSUtils::Convert2JSValue(env, devices);
        });
}

void NapiRdbStoreObserver::Clear()
{
    if (callback_ == nullptr) {
        return;
    }
    napi_delete_reference(uvQueue_->GetEnv(), callback_);
    callback_ = nullptr;
}
} // namespace OHOS::RdbJsKit