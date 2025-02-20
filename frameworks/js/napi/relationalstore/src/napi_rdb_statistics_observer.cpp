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

#include "napi_rdb_statistics_observer.h"

#include "napi_rdb_js_utils.h"

namespace OHOS::RelationalStoreJsKit {
NapiStatisticsObserver::NapiStatisticsObserver(
    napi_env env, napi_value callback, std::shared_ptr<AppDataMgrJsKit::UvQueue> queue)
    : env_(env), queue_(queue)
{
    napi_create_reference(env, callback, 1, &callback_);
}

NapiStatisticsObserver::~NapiStatisticsObserver()
{
}

void NapiStatisticsObserver::Clear()
{
    if (callback_ == nullptr) {
        return;
    }
    napi_delete_reference(env_, callback_);
    callback_ = nullptr;
}

bool NapiStatisticsObserver::operator==(napi_value value)
{
    return JSUtils::Equal(env_, callback_, value);
}

void NapiStatisticsObserver::OnStatistic(const SqlExecutionInfo &sqlExeInfo)
{
    auto queue = queue_;
    if (queue == nullptr) {
        return;
    }
    queue->AsyncCall({ [observer = shared_from_this()](napi_env env) -> napi_value {
        if (observer->callback_ == nullptr) {
            return nullptr;
        }
        napi_value callback = nullptr;
        napi_get_reference_value(env, observer->callback_, &callback);
        return callback;
    } },
        [infos = std::move(sqlExeInfo)](napi_env env, int &argc, napi_value *argv) {
            argc = 1;
            argv[0] = JSUtils::Convert2JSValue(env, infos);
        });
}
} // namespace OHOS::RelationalStoreJsKit