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

#include <functional>
#include <gtest/gtest.h>

#include "iremote_broker.h"
#include "iremote_object.h"
#include "message_parcel.h"
#include "rdb_manager_impl.h"
#include "rdb_service.h"
#include "rdb_types.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DistributedRdb;

namespace Test {
// Mock IRemoteObject for testing RdbServiceProxy
class MockIRemoteObject : public IRemoteObject {
public:
    MockIRemoteObject() : IRemoteObject(u"mock_rdb_service_remote_object"),
        sendRequestCallback(nullptr) {}
    ~MockIRemoteObject() override = default;

    // Callback type for SendRequest
    using SendRequestCallback = std::function<int(uint32_t, MessageParcel&, MessageParcel&, MessageOption&)>;

    void SetSendRequestCallback(SendRequestCallback callback)
    {
        sendRequestCallback = callback;
    }

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        if (sendRequestCallback) {
            return sendRequestCallback(code, data, reply, option);
        }
        return 0;
    }

    bool IsProxyObject() const override
    {
        return true;
    }

    bool CheckObjectLegality() const override
    {
        return true;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool Marshalling(Parcel &parcel) const override
    {
        return true;
    }

    sptr<IRemoteBroker> AsInterface() override
    {
        return nullptr;
    }

    int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        return 0;
    }

    std::u16string GetObjectDescriptor() const
    {
        return u"mock_rdb_service_remote_object";
    }

private:
    SendRequestCallback sendRequestCallback;
};

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
 * @tc.name: DoSync_UnmarshalSuccess
 * @tc.desc: Test DoSync when ITypesUtil::Unmarshal returns true
 * @tc.type: FUNC
 */
HWTEST_F(RdbServiceProxyTest, DoSync_UnmarshalSuccess, TestSize.Level2)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();

    mockRemote->SetSendRequestCallback([](uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option) {
        if (!reply.WriteInt32(0)) {
            return -1;
        }
        if (!reply.WriteInt32(RDB_OK)) {
            return -1;
        }
        if (!reply.WriteInt32(0)) {
            return -1;
        }
        return 0;
    });

    std::shared_ptr<RdbServiceProxy> proxy = std::make_shared<RdbServiceProxy>(mockRemote);

    RdbSyncerParam param;
    param.bundleName_ = "com.example.test";
    param.storeName_ = "test.db";

    RdbService::Option option;
    option.mode = PUSH;
    option.isAsync = false;

    PredicatesMemo predicates;

    AsyncDetail async = [](const Details &details) {
        EXPECT_TRUE(details.empty());
    };

    int32_t ret = proxy->Sync(param, option, predicates, async);

    EXPECT_EQ(ret, RDB_OK);
}

} // namespace Test
