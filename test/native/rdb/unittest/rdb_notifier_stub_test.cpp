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

#include "itypes_util.h"
#include "rdb_notifier_stub.h"
#include <gtest/gtest.h>
#include <iremote_broker.h>
#include <iremote_proxy.h>

using namespace testing::ext;
using namespace OHOS::DistributedRdb;
using namespace OHOS;
namespace OHOS::Test {
namespace OHOS::DistributedRdb{
using NotifierIFCode = RelationalStore::IRdbNotifierInterfaceCode;

class RdbNotifierStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RdbNotifierStubTest::SetUpTestCase(void)
{
}

void RdbNotifierStubTest::TearDownTestCase(void)
{
}

void RdbNotifierStubTest::SetUp(void)
{
}

void RdbNotifierStubTest::TearDown(void)
{
}

/**
 * @tc.name: OnAutoSyncTriggerInner_Normal_Success
 * @tc.desc: Test OnAutoSyncTriggerInner Sync callback notification
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbNotifierStubTest, OnAutoSyncTriggerInner_Normal_Success, TestSize.Level0)
{
    RdbNotifierStub rdbNotifierStub(nullptr, nullptr, nullptr, nullptr);
    MessageParcel reply;
    MessageParcel data;
    MessageOption option(MessageOption::TF_ASYNC);
    data.WriteInterfaceToken(RdbNotifierStub::GetDescriptor());
    auto code = static_cast<uint32_t>(NotifierIFCode::RDB_NOTIFIER_CMD_AUTO_SYNC_TRIGGER);
    auto ret = rdbNotifierStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, RDB_ERROR);
    std::string storeId = "testStoreId";
    int32_t triggerMode = 1;
    ITypesUtil::Marshal(data, storeId, triggerMode);
    ret = rdbNotifierStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: OnAutoSyncTriggerInner_InvalidTriggerMode001
 * @tc.desc: Test OnAutoSyncTriggerInner Sync callback invalid triggerMode < 0
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbNotifierStubTest, OnAutoSyncTriggerInner_InvalidTriggerMode001, TestSize.Level0)
{
    RdbNotifierStub rdbNotifierStub(nullptr, nullptr, nullptr, nullptr);
    MessageParcel reply;
    MessageParcel data;
    MessageOption option(MessageOption::TF_ASYNC);
    data.WriteInterfaceToken(RdbNotifierStub::GetDescriptor());
    auto code = static_cast<uint32_t>(NotifierIFCode::RDB_NOTIFIER_CMD_AUTO_SYNC_TRIGGER);
    std::string storeId = "testStoreId";
    int32_t triggerMode = 0;
    ITypesUtil::Marshal(data, storeId, triggerMode);
    auto ret = rdbNotifierStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, RDB_ERROR);
}

/**
 * @tc.name: OnAutoSyncTriggerInner_InvalidTriggerMode002
 * @tc.desc: Test OnAutoSyncTriggerInner Sync callback invalid triggerMode < 5
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbNotifierStubTest, OnAutoSyncTriggerInner_InvalidTriggerMode002, TestSize.Level0)
{
    RdbNotifierStub rdbNotifierStub(nullptr, nullptr, nullptr, nullptr);
    MessageParcel reply;
    MessageParcel data;
    MessageOption option(MessageOption::TF_ASYNC);
    data.WriteInterfaceToken(RdbNotifierStub::GetDescriptor());
    auto code = static_cast<uint32_t>(NotifierIFCode::RDB_NOTIFIER_CMD_AUTO_SYNC_TRIGGER);
    std::string storeId = "testStoreId";
    int32_t triggerMode = 5;
    ITypesUtil::Marshal(data, storeId, triggerMode);
    auto ret = rdbNotifierStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, RDB_ERROR);
}
} // namespace OHOS::DistributedRdb
} // namespace OHOS::Test