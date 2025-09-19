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
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <dlfcn.h>

#include "rdb_security_manager.h"
#include "relational_store_crypt.h"
#include "rdb_errno.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using ::testing::Return;
using ::testing::NiceMock;
class MockDlsym {
public:
    MOCK_METHOD(void *, dlopen, (const char *fileName, int flag));
    MOCK_METHOD(void *, dlsym, (void *handle, const char *symbol));
};

NiceMock<MockDlsym> *mockDlsym;

extern "C" {
// mock dlopen
void *dlopen(const char *fileName, int flag)
{
    if (mockDlsym == nullptr) {
        mockDlsym = new NiceMock<MockDlsym>();
    }
    return mockDlsym->dlopen(fileName, flag);
}

// mock dlsym
void *dlsym(void *handle, const char *symbol)
{
    if (mockDlsym == nullptr) {
        mockDlsym = new NiceMock<MockDlsym>();
    }
    return mockDlsym->dlsym(handle, symbol);
}
}

bool MockCleanUP()
{
    return false;
}

class MockRdbSecurityManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void MockRdbSecurityManagerTest::SetUpTestCase(void)
{
    mockDlsym = new NiceMock<MockDlsym>();
}

void MockRdbSecurityManagerTest::TearDownTestCase(void)
{
    delete mockDlsym;
    mockDlsym = nullptr;
}

void MockRdbSecurityManagerTest::SetUp()
{
}

void MockRdbSecurityManagerTest::TearDown()
{
}

/**
 * @tc.name: GenerateRandomNumTest
 * @tc.desc: Abnormal test for GenerateRandomNum
 * @tc.type: FUNC
 */
HWTEST_F(MockRdbSecurityManagerTest, GenerateRandomNumTest, TestSize.Level1)
{
    uint32_t len = 0;
    std::vector<uint8_t> ret = RdbSecurityManager::GetInstance().GenerateRandomNum(len);
    EXPECT_TRUE(ret.empty());
}

/**
 * @tc.name: CreateDelegateTest001
 * @tc.desc: Abnormal test for CreateDelegate
 * @tc.type: FUNC
 */
HWTEST_F(MockRdbSecurityManagerTest, CreateDelegateTest001, TestSize.Level1)
{
    auto handle = RdbSecurityManager::GetInstance().GetHandle();
    EXPECT_CALL(*mockDlsym, dlsym(handle, ::testing::StrEq("CreateRdbCryptoDelegate")))
        .WillRepeatedly(Return(nullptr));
    std::vector<uint8_t> key;
    auto delegate  = RdbSecurityManager::GetInstance().CreateDelegate(key);
    ASSERT_EQ(delegate, nullptr);
}

/**
 * @tc.name: CreateDelegateTest002
 * @tc.desc: Abnormal test for CreateDelegate
 * @tc.type: FUNC
 */
HWTEST_F(MockRdbSecurityManagerTest, CreateDelegateTest002, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlopen(::testing::_, RTLD_LAZY))
        .WillOnce(Return(nullptr));
    std::vector<uint8_t> key;
    auto delegate  = RdbSecurityManager::GetInstance().CreateDelegate(key);
    ASSERT_EQ(delegate, nullptr);
}

/**
 * @tc.name: InitTest
 * @tc.desc: Abnormal test for Init
 * @tc.type: FUNC
 */
HWTEST_F(MockRdbSecurityManagerTest, InitTest, TestSize.Level1)
{
    std::string bundleName = "";
    EXPECT_CALL(*mockDlsym, dlopen(::testing::_, RTLD_LAZY))
        .WillOnce(Return(nullptr));
    auto ret = RdbSecurityManager::GetInstance().Init(bundleName);
    EXPECT_EQ(ret, E_ERROR);
}

/**
 * @tc.name: SaveSecretKeyToFileKeyTest
 * @tc.desc: Abnormal test for SaveSecretKeyToFileKey
 * @tc.type: FUNC
 */  
HWTEST_F(MockRdbSecurityManagerTest, SaveSecretKeyToFileTest, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlopen(::testing::_, RTLD_LAZY))
        .WillOnce(Return(nullptr));
    std::vector<uint8_t> key;
    std::string keyPath = ""
    auto ret  = RdbSecurityManager::GetInstance().SaveSecretKeyToFile(key);
    EXPECT_FALSE(ret);
}