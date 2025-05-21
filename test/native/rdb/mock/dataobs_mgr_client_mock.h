/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_DATAOBS_MGR_CLIENT_MOCK_H
#define OHOS_ABILITY_RUNTIME_DATAOBS_MGR_CLIENT_MOCK_H

#include <gmock/gmock.h>

#include "dataobs_mgr_client.h"

namespace OHOS {
namespace AAFwk {
class IDataObsMgrClient {
public:
    IDataObsMgrClient(){};
    virtual ~IDataObsMgrClient(){};
    virtual ErrCode NotifyChange(const Uri &uri, int32_t userId = -1, DataObsOption opt = DataObsOption()) = 0;
    virtual std::shared_ptr<DataObsMgrClient> GetInstance() = 0;

    static inline std::shared_ptr<IDataObsMgrClient> dataObsMgrClient = nullptr;
};
class MockDataObsMgrClient : public IDataObsMgrClient {
public:
    MOCK_METHOD((std::shared_ptr<DataObsMgrClient>), GetInstance, (), (override));
    MOCK_METHOD(ErrCode, NotifyChange, (const Uri &uri, int32_t userId, DataObsOption opt), (override));
};
} // namespace AAFwk
} // namespace OHOS
#endif