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

namespace OHOS::RelationalStoreJsKit {
NapiRdbStoreObserver::NapiRdbStoreObserver(napi_value callback, std::shared_ptr<UvQueue> uvQueue, int32_t mode)
    : mode_(mode), uvQueue_(uvQueue)
{
    napi_create_reference(uvQueue_->GetEnv(), callback, 1, &callback_);
}

NapiRdbStoreObserver::~NapiRdbStoreObserver() noexcept
{
}

void NapiRdbStoreObserver::OnChange(const std::vector<std::string> &devices)
{
    LOG_INFO("NapiRdbStoreObserver::OnChange begin");
    uvQueue_->AsyncCall({[observer = shared_from_this()](napi_env env) -> napi_value {
                            if (observer->callback_ == nullptr) {
                                return nullptr;
                            }
                            napi_value callback = nullptr;
                            napi_get_reference_value(env, observer->callback_, &callback);
                            return callback;
                        }},
                        [devices](napi_env env, int &argc, napi_value *argv) {
                            argc = 1;
                            argv[0] = JSUtils::Convert2JSValue(env, devices);
                        });
}

void NapiRdbStoreObserver::OnChange(const Origin &origin, const PrimaryFields &fields, ChangeInfo &&changeInfo)
{
    if (mode_ == DistributedRdb::CLOUD_DETAIL || mode_ == DistributedRdb::LOCAL_DETAIL) {
        std::vector<JSChangeInfo> infos;
        for (auto it = changeInfo.begin(); it != changeInfo.end(); ++it) {
            infos.push_back(JSChangeInfo(origin, it));
        }

        uvQueue_->AsyncCall({[observer = shared_from_this()](napi_env env) -> napi_value {
                                if (observer->callback_ == nullptr) {
                                    return nullptr;
                                }
                                napi_value callback = nullptr;
                                napi_get_reference_value(env, observer->callback_, &callback);
                                return callback;
                            }},
                            [infos = std::move(infos)](napi_env env, int &argc, napi_value *argv) {
                                argc = 1;
                                argv[0] = JSUtils::Convert2JSValue(env, infos);
                            });
        return;
    }
    RdbStoreObserver::OnChange(origin, fields, std::move(changeInfo));
}

void NapiRdbStoreObserver::OnChange()
{
    uvQueue_->AsyncCall({[observer = shared_from_this()](napi_env env) -> napi_value {
                            if (observer->callback_ == nullptr) {
                                return nullptr;
                            }
                            napi_value callback = nullptr;
                            napi_get_reference_value(env, observer->callback_, &callback);
                            return callback;
                        }},
                        [](napi_env env, int &argc, napi_value *argv) {});
}

NapiRdbStoreObserver::JSChangeInfo::JSChangeInfo(const Origin &origin, ChangeInfo::iterator info)
{
    table = info->first;
    type = origin.dataType;
    inserted = std::move(info->second[CHG_TYPE_INSERT]);
    updated = std::move(info->second[CHG_TYPE_UPDATE]);
    deleted = std::move(info->second[CHG_TYPE_DELETE]);
}

bool NapiRdbStoreObserver::operator==(napi_value value)
{
    napi_value callback = nullptr;
    napi_get_reference_value(uvQueue_->GetEnv(), callback_, &callback);

    bool isEquals = false;
    napi_strict_equals(uvQueue_->GetEnv(), value, callback, &isEquals);
    return isEquals;
}

void NapiRdbStoreObserver::Clear()
{
    if (callback_ == nullptr) {
        return;
    }
    napi_delete_reference(uvQueue_->GetEnv(), callback_);
    callback_ = nullptr;
}
} // namespace OHOS::RelationalStoreJsKit