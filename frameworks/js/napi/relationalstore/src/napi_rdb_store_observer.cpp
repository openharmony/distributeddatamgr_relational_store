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

#include "napi_rdb_store_observer.h"

#include "js_utils.h"
#include "logger.h"

using namespace OHOS::Rdb;
using namespace OHOS::AppDataMgrJsKit;

namespace OHOS::RelationalStoreJsKit {
NapiRdbStoreObserver::NapiRdbStoreObserver(napi_env env, napi_value callback, int32_t mode)
    : NapiUvQueue(env, callback), mode_(mode)
{
    LOG_INFO("NapiRdbStoreObserver construct");
}

NapiRdbStoreObserver::~NapiRdbStoreObserver() noexcept
{
    LOG_INFO("NapiRdbStoreObserver destroy");
}

void NapiRdbStoreObserver::OnChange(const std::vector<std::string> &devices)
{
    LOG_INFO("NapiRdbStoreObserver::OnChange begin");
    CallFunction([devices](napi_env env, int &argc, napi_value *argv) {
        argc = 1;
        argv[0] = JSUtils::Convert2JSValue(env, devices);
    });
    LOG_INFO("NapiRdbStoreObserver::OnChange end");
}

void NapiRdbStoreObserver::OnChange(const Origin &origin, const PrimaryFields &fields, ChangeInfo &&changeInfo)
{
    if (mode_ == DistributedRdb::CLOUD_DETAIL) {
        CallFunction([info = std::move(changeInfo)](napi_env env, int &argc, napi_value *argv) {
            argc = 1;
            // action
        });
    }
    RdbStoreObserver::OnChange(origin, fields, std::move(changeInfo));
}
} // namespace OHOS::RelationalStoreJsKit