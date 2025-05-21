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
#include "dataobs_mgr_client_mock.h"

namespace OHOS {
namespace AAFwk {
std::shared_ptr<DataObsMgrClient> DataObsMgrClient::GetInstance()
{
    if (IDataObsMgrClient::dataObsMgrClient == nullptr) {
        return nullptr;
    }
    return IDataObsMgrClient::dataObsMgrClient->GetInstance();
}

ErrCode DataObsMgrClient::NotifyChange(const Uri &uri, int userId, DataObsOption opt)
{
    if (IDataObsMgrClient::dataObsMgrClient == nullptr) {
        return DATAOBS_SERVICE_NOT_CONNECTED;
    }
    return IDataObsMgrClient::dataObsMgrClient->NotifyChange(uri, userId, opt);
}
} // namespace AAFwk
} // namespace OHOS