/*
* Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTED_RDB_RDB_MANAGER_H
#define DISTRIBUTED_RDB_RDB_MANAGER_H

#include <memory>
#include <mutex>

#include "rdb_types.h"
namespace OHOS::DistributedRdb {
class RdbService;
class RdbManager {
public:
    static RdbManager &GetInstance();
    static bool RegisterInstance(RdbManager *instance);

    virtual std::pair<int32_t, std::shared_ptr<RdbService>> GetRdbService(const RdbSyncerParam &param);

    virtual std::string GetSelfBundleName();

    virtual void OnRemoteDied();

protected:
    RdbManager();
    virtual ~RdbManager() = default;
    static std::once_flag onceFlag_;
    static RdbManager *instance_;
};
} // namespace OHOS::DistributedRdb
#endif
