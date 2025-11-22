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

#include "rdb_service_proxy.h"

#include <gtest/gtest.h>

#include "rdb_manager_impl.h"
#include "rdb_service.h"
#include "rdb_types.h"

using namespace testing::ext;
using namespace OHOS::DistributedRdb;
namespace Test {
class RdbServiceProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp(void){};
    void TearDown(void){};
};

/**
 * @tc.name: OnRemoteDeadSyncComplete
 * @tc.desc: OnRemoteDeadSyncComplete callback is executed
 * @tc.type: FUNC
 */
HWTEST_F(RdbServiceProxyTest, OnRemoteDeadSyncComplete, TestSize.Level1)
{
    RdbSyncerParam param;
    param.bundleName_ = "com.example.test";
    param.storeName_ = "test.db";
    auto [status, service] = RdbManagerImpl::GetInstance().GetRdbService(param);
    ASSERT_NE(service, nullptr);

    auto callback = [](const Details &details) {
        ASSERT_NE(details.size(), 0);
        EXPECT_TRUE(details.begin()->first.empty());
        EXPECT_EQ(details.begin()->second.progress, Progress::SYNC_FINISH);
        EXPECT_EQ(details.begin()->second.code, ProgressCode::UNKNOWN_ERROR);
    };

    RdbService::Option option;
    option.seqNum = 1;
    auto proxy = std::static_pointer_cast<RdbServiceProxy>(service);
    ASSERT_NE(proxy, nullptr);
    proxy->syncCallbacks_.Insert(option.seqNum, callback);
    proxy->OnRemoteDeadSyncComplete();
}

/**
 * @tc.name: StopCloudSync
 * @tc.desc: StopCloudSync is executed, service check fail
 * @tc.type: FUNC
 */
HWTEST_F(RdbServiceProxyTest, StopCloudSync, TestSize.Level1)
{
    RdbSyncerParam param;
    param.bundleName_ = "com.example.test";
    param.storeName_ = "test.db";
    auto [status, service] = RdbManagerImpl::GetInstance().GetRdbService(param);
    ASSERT_NE(service, nullptr);
    auto proxy = std::static_pointer_cast<RdbServiceProxy>(service);
    ASSERT_NE(proxy, nullptr);
    auto errCode = proxy->StopCloudSync(param);
    EXPECT_EQ(errCode, RDB_ERROR);
}
} // namespace Test