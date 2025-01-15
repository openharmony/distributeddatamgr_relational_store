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

#include "gmock/gmock.h"
#include "grd_adapter_manager.h"
#include "grd_adapter.h"
#include "gdb_store.h"

using namespace testing::ext;
using namespace OHOS::DistributedDataAip;
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

class GdbAdaptTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void MockAllSymbols();
    static const std::string databaseName;
    static const std::string databasePath;
    const std::vector<std::pair<std::string, void *>> mockSymbols = {
        {"GRD_DBOpen", reinterpret_cast<void *>(0x1111)},
        {"GRD_DBClose", reinterpret_cast<void *>(0x2222)},
        {"GRD_DBRepair", reinterpret_cast<void *>(0x3333)},
        {"GRD_GqlPrepare", reinterpret_cast<void *>(0x4444)},
        {"GRD_GqlReset", reinterpret_cast<void *>(0x5555)},
        {"GRD_GqlFinalize", reinterpret_cast<void *>(0x6666)},
        {"GRD_GqlStep", reinterpret_cast<void *>(0x7777)},
        {"GRD_GqlColumnCount", reinterpret_cast<void *>(0x8888)},
        {"GRD_GqlColumnType", reinterpret_cast<void *>(0x9999)},
        {"GRD_GqlColumnBytes", reinterpret_cast<void *>(0xaaaa)},
        {"GRD_GqlColumnName", reinterpret_cast<void *>(0xbbbb)},
        {"GRD_GqlColumnValue", reinterpret_cast<void *>(0xcccc)},
        {"GRD_GqlColumnInt64", reinterpret_cast<void *>(0xdddd)},
        {"GRD_GqlColumnInt", reinterpret_cast<void *>(0xeeee)},
        {"GRD_GqlColumnDouble", reinterpret_cast<void *>(0xffff)},
        {"GRD_GqlColumnText", reinterpret_cast<void *>(0x1112)},
        {"GRD_DBBackup", reinterpret_cast<void *>(0x1222)},
        {"GRD_DBRestore", reinterpret_cast<void *>(0x1333)},
        {"GRD_DBRekey", reinterpret_cast<void *>(0x1444)},
    };
};

const std::string GdbAdaptTest::databaseName = "execute_test";
const std::string GdbAdaptTest::databasePath = "/data";

void GdbAdaptTest::SetUpTestCase(void)
{
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
        return;
    }
    mockDlsym = new NiceMock<MockDlsym>();
}

void GdbAdaptTest::TearDownTestCase(void)
{
    delete mockDlsym;
    mockDlsym = nullptr;
}

void GdbAdaptTest::SetUp()
{
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
        return;
    }
}

void GdbAdaptTest::TearDown()
{
}

void GdbAdaptTest::MockAllSymbols()
{
    EXPECT_CALL(*mockDlsym, dlopen(::testing::_, RTLD_LAZY))
        .WillRepeatedly(Return(reinterpret_cast<void *>(0x1234)));

    for (const auto &symbol : mockSymbols) {
        EXPECT_CALL(*mockDlsym, dlsym(::testing::_, ::testing::StrEq(symbol.first.c_str())))
            .WillRepeatedly(Return(symbol.second));
    }
}

/**
 * @tc.name: GdbAdaptTest_Dlopen01
 * @tc.desc: No Mock All Symbols
 * @tc.type: FUNC
 */
HWTEST_F(GdbAdaptTest, GdbAdaptTest_Dlopen01, TestSize.Level2)
{
    GetAdapterHolder();
    EXPECT_CALL(*mockDlsym, dlopen(::testing::_, RTLD_LAZY))
        .WillRepeatedly(Return(reinterpret_cast<void *>(0x1234)));
    GrdAdapterHolder holder = GetAdapterHolder();
    EXPECT_EQ(holder.Open, nullptr);
    EXPECT_EQ(holder.Close, nullptr);
    EXPECT_EQ(holder.Repair, nullptr);
    EXPECT_EQ(holder.Prepare, nullptr);
    EXPECT_EQ(holder.Reset, nullptr);
    EXPECT_EQ(holder.Finalize, nullptr);
    EXPECT_EQ(holder.Step, nullptr);
    EXPECT_EQ(holder.ColumnCount, nullptr);
    EXPECT_EQ(holder.GetColumnType, nullptr);
    EXPECT_EQ(holder.ColumnBytes, nullptr);
    EXPECT_EQ(holder.ColumnName, nullptr);
    EXPECT_EQ(holder.ColumnValue, nullptr);
    EXPECT_EQ(holder.ColumnInt64, nullptr);
    EXPECT_EQ(holder.ColumnInt, nullptr);
    EXPECT_EQ(holder.ColumnDouble, nullptr);
    EXPECT_EQ(holder.ColumnText, nullptr);
    EXPECT_EQ(holder.Backup, nullptr);
    EXPECT_EQ(holder.Restore, nullptr);
    EXPECT_EQ(holder.Rekey, nullptr);
    GrdAdapter::Open(databaseName.c_str(), databasePath.c_str(), 1, nullptr);
    GrdAdapter::Close(nullptr, 1);
    GrdAdapter::Repair(databasePath.c_str(), {});
    GrdAdapter::Prepare(nullptr, databaseName.c_str(), 1, nullptr, nullptr);
    GrdAdapter::Reset(nullptr);
    GrdAdapter::Finalize(nullptr);
    GrdAdapter::Step(nullptr);
    GrdAdapter::ColumnCount(nullptr);
    GrdAdapter::ColumnType(nullptr, 1);
    GrdAdapter::ColumnBytes(nullptr, 1);
    GrdAdapter::ColumnName(nullptr, 1);
    GrdAdapter::ColumnValue(nullptr, 1);
    GrdAdapter::ColumnInt64(nullptr, 1);
    GrdAdapter::ColumnInt(nullptr, 1);
    GrdAdapter::ColumnDouble(nullptr, 1);
    GrdAdapter::ColumnText(nullptr, 1);
    GrdAdapter::Backup(nullptr, databaseName.c_str(), {});
    GrdAdapter::Restore(nullptr, databaseName.c_str(), {});
    GrdAdapter::Rekey(nullptr, databaseName.c_str(), {});
}

/**
 * @tc.name: GdbAdaptTest_Dlopen02
 * @tc.desc: Mock All Symbols test.
 * @tc.type: FUNC
 */
HWTEST_F(GdbAdaptTest, GdbAdaptTest_Dlopen02, TestSize.Level2)
{
    EXPECT_CALL(*mockDlsym, dlopen(::testing::_, RTLD_LAZY))
        .WillRepeatedly(Return(reinterpret_cast<void *>(0x1234)));
    MockAllSymbols();
    GrdAdapterHolder holder = GetAdapterHolder();
    EXPECT_NE(holder.Open, nullptr);
    EXPECT_NE(holder.Close, nullptr);
    EXPECT_NE(holder.Repair, nullptr);
    EXPECT_NE(holder.Prepare, nullptr);
    EXPECT_NE(holder.Reset, nullptr);
    EXPECT_NE(holder.Finalize, nullptr);
    EXPECT_NE(holder.Step, nullptr);
    EXPECT_NE(holder.ColumnCount, nullptr);
    EXPECT_NE(holder.GetColumnType, nullptr);
    EXPECT_NE(holder.ColumnBytes, nullptr);
    EXPECT_NE(holder.ColumnName, nullptr);
    EXPECT_NE(holder.ColumnValue, nullptr);
    EXPECT_NE(holder.ColumnInt64, nullptr);
    EXPECT_NE(holder.ColumnInt, nullptr);
    EXPECT_NE(holder.ColumnDouble, nullptr);
    EXPECT_NE(holder.ColumnText, nullptr);
    EXPECT_NE(holder.Backup, nullptr);
    EXPECT_NE(holder.Restore, nullptr);
    EXPECT_NE(holder.Rekey, nullptr);
}