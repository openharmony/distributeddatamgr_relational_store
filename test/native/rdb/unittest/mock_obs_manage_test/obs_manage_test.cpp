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

#include "rdb_store_impl.h"
#include "sqlite_connection.h"

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

class RdbObsManageTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RdbObsManageTest::SetUpTestCase(void)
{
    mockDlsym = new NiceMock<MockDlsym>();
}

void RdbObsManageTest::TearDownTestCase(void)
{
    delete mockDlsym;
    mockDlsym = nullptr;
}

void RdbObsManageTest::SetUp()
{
}

void RdbObsManageTest::TearDown()
{
}

/**
* @tc.name: RdbObsManageTest_Dlopen01
* @tc.desc: No Mock All Symbols
* @tc.type: FUNC
*/
HWTEST_F(RdbObsManageTest, RdbObsManageTest_Dlopen01, TestSize.Level2)
{
    EXPECT_CALL(*mockDlsym, dlopen(::testing::_, RTLD_LAZY))
        .WillOnce(Return(nullptr));
    auto handle = ObsManger::GetHandle();
    EXPECT_EQ(handle, nullptr);
}

/**
* @tc.name: RdbObsManageTest_Dlopen02
* @tc.desc: No Mock All Symbols
* @tc.type: FUNC
*/
HWTEST_F(RdbObsManageTest, RdbObsManageTest_Dlopen02, TestSize.Level2)
{
    EXPECT_CALL(*mockDlsym, dlopen(::testing::_, RTLD_LAZY))
        .WillRepeatedly(Return(reinterpret_cast<void *>(0x1234)));
    auto handle = ObsManger::GetHandle();
    EXPECT_NE(handle, nullptr);
    EXPECT_CALL(*mockDlsym, dlsym(handle, ::testing::StrEq("CleanUp")))
        .WillRepeatedly(Return(reinterpret_cast<void *>(&MockCleanUP)));
    auto ret = ObsManger::CleanUp();
    EXPECT_EQ(ret, E_ERROR);
}
 
/**
* @tc.name: RdbObsManageTest_Dlopen03
* @tc.desc: No Mock All Symbols
* @tc.type: FUNC
*/
HWTEST_F(RdbObsManageTest, RdbObsManageTest_Dlopen03, TestSize.Level2)
{
    EXPECT_CALL(*mockDlsym, dlopen(::testing::_, RTLD_LAZY))
        .WillRepeatedly(Return(reinterpret_cast<void *>(0x1234)));
    auto handle = OHOS::NativeRdb::SqliteConnection::GetICUHandle();
    EXPECT_NE(handle, nullptr);
    EXPECT_CALL(*mockDlsym, dlsym(handle, ::testing::StrEq("CleanUp")))
        .WillRepeatedly(Return(nullptr));
    auto res = OHOS::NativeRdb::SqliteConnection::ICUCleanUp();
    EXPECT_EQ(res, E_ERROR);
}