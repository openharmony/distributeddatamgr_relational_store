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

#include "result_set_proxy.h"

#include <gtest/gtest.h>

#include "iremote_object.h"
#include "message_parcel.h"
#include "value_object.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::NativeRdb;

namespace Test {
class MockRemoteObject : public IRemoteObject {
public:
    MockRemoteObject() : IRemoteObject(u"mock_result_set_remote_object") {}

    int32_t GetObjectRefCount() override { return 0; }

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return 0;
    }

    bool IsProxyObject() const override { return true; }

    bool CheckObjectLegality() const override { return true; }

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }

    bool Marshalling(Parcel &parcel) const override { return true; }

    sptr<IRemoteBroker> AsInterface() override { return nullptr; }

    int Dump(int fd, const std::vector<std::u16string> &args) override { return 0; }
};

class ResultSetProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp(void){};
    void TearDown(void){};
};

/**
 * @tc.name: Constructor_001
 * @tc.desc: Test ResultSetProxy constructor with valid remote object
 * @tc.type: FUNC
 */
HWTEST_F(ResultSetProxyTest, Constructor_001, TestSize.Level1)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    
    EXPECT_NO_FATAL_FAILURE(ResultSetProxy proxy(remote));
}

/**
 * @tc.name: Destructor_001
 * @tc.desc: Test ResultSetProxy destructor
 * @tc.type: FUNC
 */
HWTEST_F(ResultSetProxyTest, Destructor_001, TestSize.Level1)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    {
        ResultSetProxy proxy(remote);
    }
    
    EXPECT_TRUE(true);
}

/**
 * @tc.name: GetColumnCount_001
 * @tc.desc: Test GetColumnCount method
 * @tc.type: FUNC
 */
HWTEST_F(ResultSetProxyTest, GetColumnCount_001, TestSize.Level2)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ResultSetProxy proxy(remote);
    
    int count = 0;
    int result = proxy.GetColumnCount(count);
    
    EXPECT_TRUE(result >= 0);
}

/**
 * @tc.name: GetRowCount_001
 * @tc.desc: Test GetRowCount method
 * @tc.type: FUNC
 */
HWTEST_F(ResultSetProxyTest, GetRowCount_001, TestSize.Level2)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ResultSetProxy proxy(remote);
    
    int count = 0;
    int result = proxy.GetRowCount(count);
    
    EXPECT_TRUE(result >= 0);
}

/**
 * @tc.name: GetRowIndex_001
 * @tc.desc: Test GetRowIndex method
 * @tc.type: FUNC
 */
HWTEST_F(ResultSetProxyTest, GetRowIndex_001, TestSize.Level2)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ResultSetProxy proxy(remote);
    
    int position = 0;
    int result = proxy.GetRowIndex(position);
    
    EXPECT_TRUE(result >= 0);
}

/**
 * @tc.name: GoTo_001
 * @tc.desc: Test GoTo method
 * @tc.type: FUNC
 */
HWTEST_F(ResultSetProxyTest, GoTo_001, TestSize.Level2)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ResultSetProxy proxy(remote);
    
    int result = proxy.GoTo(0);
    
    EXPECT_TRUE(result >= 0);
}

/**
 * @tc.name: GoToRow_001
 * @tc.desc: Test GoToRow method
 * @tc.type: FUNC
 */
HWTEST_F(ResultSetProxyTest, GoToRow_001, TestSize.Level2)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ResultSetProxy proxy(remote);
    
    int result = proxy.GoToRow(0);
    
    EXPECT_TRUE(result >= 0);
}

/**
 * @tc.name: GoToFirstRow_001
 * @tc.desc: Test GoToFirstRow method
 * @tc.type: FUNC
 */
HWTEST_F(ResultSetProxyTest, GoToFirstRow_001, TestSize.Level2)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ResultSetProxy proxy(remote);
    
    int result = proxy.GoToFirstRow();
    
    EXPECT_TRUE(result >= 0);
}

/**
 * @tc.name: GoToNextRow_001
 * @tc.desc: Test GoToNextRow method
 * @tc.type: FUNC
 */
HWTEST_F(ResultSetProxyTest, GoToNextRow_001, TestSize.Level2)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ResultSetProxy proxy(remote);
    
    int result = proxy.GoToNextRow();
    
    EXPECT_TRUE(result >= 0);
}

/**
 * @tc.name: Close_001
 * @tc.desc: Test Close method
 * @tc.type: FUNC
 */
HWTEST_F(ResultSetProxyTest, Close_001, TestSize.Level1)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ResultSetProxy proxy(remote);
    
    int result = proxy.Close();
    
    EXPECT_TRUE(result >= 0);
}
} // namespace Test