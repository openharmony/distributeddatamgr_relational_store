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

#ifndef NAPI_CLOUD_SYNC_INFO_OBSERVER_H
#define NAPI_CLOUD_SYNC_INFO_OBSERVER_H

#include "cloud_types.h"
#include "js_uv_queue.h"
#include "napi/native_api.h"

namespace OHOS::CloudData {
using namespace OHOS::AppDataMgrJsKit;

class NapiCloudSyncInfoObserver : public ISyncInfoObserver,
    public std::enable_shared_from_this<NapiCloudSyncInfoObserver> {
public:
    explicit NapiCloudSyncInfoObserver(napi_env env, napi_value callback, std::shared_ptr<UvQueue> uvQueue);
    virtual ~NapiCloudSyncInfoObserver() noexcept;

    void OnSyncInfoChanged(const std::map<std::string, QueryLastResults> &data) override;

    bool operator==(napi_value value);

    void Clear();

private:
    napi_env env_;
    std::shared_ptr<UvQueue> uvQueue_;
    napi_ref callback_;
};
} // namespace OHOS::CloudData
#endif // NAPI_CLOUD_SYNC_INFO_OBSERVER_H
