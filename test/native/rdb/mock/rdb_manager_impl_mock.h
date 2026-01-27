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

#ifndef DISTRIBUTED_RDB_RDB_MANAGER_MOCK_H
#define DISTRIBUTED_RDB_RDB_MANAGER_MOCK_H

#include <gmock/gmock.h>

#include "rdb_manager_impl.h"
namespace OHOS::DistributedRdb {
class BRdbManagerImpl {
public:
    BRdbManagerImpl() = default;
    virtual ~BRdbManagerImpl() = default;
    virtual std::pair<int32_t, std::shared_ptr<RdbService>> GetRdbService(const RdbSyncerParam &param) = 0;
    virtual std::string GetSelfBundleName() = 0;

public:
    static inline std::shared_ptr<BRdbManagerImpl> rdbManagerImpl = nullptr;
};
class MockRdbManagerImpl : public BRdbManagerImpl {
public:
    MOCK_METHOD(
        (std::pair<int32_t, std::shared_ptr<RdbService>>), GetRdbService, (const RdbSyncerParam &param), (override));
    MOCK_METHOD((std::string), GetSelfBundleName, (), (override));
};
} // namespace OHOS::DistributedRdb
#endif