/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "napi_sync_observer.h"
#include "napi_rdb_js_utils.h"

namespace OHOS {
namespace RelationalStoreJsKit {

using OHOS::DistributedRdb::Details;

SyncObserver::SyncObserver(
    napi_env env, napi_value callback, std::shared_ptr<AppDataMgrJsKit::UvQueue> queue)
    : env_(env), queue_(queue)
{
    napi_create_reference(env, callback, 1, &callback_);
}

SyncObserver::~SyncObserver()
{
}

void SyncObserver::Clear()
{
    if (callback_ == nullptr) {
        return;
    }
    napi_delete_reference(env_, callback_);
    callback_ = nullptr;
}

bool SyncObserver::operator==(napi_value value)
{
    return JSUtils::Equal(env_, callback_, value);
}

void SyncObserver::ProgressNotification(const Details &details)
{
    if (queue_ == nullptr) {
        return;
    }
    queue_->AsyncCall({ [observer = shared_from_this()](napi_env env) -> napi_value {
        if (observer->callback_ == nullptr) {
            return nullptr;
        }
        napi_value callback = nullptr;
        napi_get_reference_value(env, observer->callback_, &callback);
        return callback;
    } },
        [syncDetails = std::move(details)](napi_env env, int &argc, napi_value *argv) {
            argc = 1;
            argv[0] = syncDetails.empty() ? nullptr : JSUtils::Convert2JSValue(env, syncDetails.begin()->second);
        });
}
} // namespace RelationalStoreJsKit
} // namespace OHOS