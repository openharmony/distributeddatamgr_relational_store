/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "rd_utils.h"

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <atomic>
#include <climits>
#include <mutex>
#include <string>
#include <unordered_set>

#include "grd_api_manager.h"
#include "grd_type_export.h"
#include "rdb_helper.h"
#include "task_executor.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

static std::mutex g_mutex;
static std::unordered_set<void *> allocatedAddresses;
static bool g_isRecord = false;

void *operator new[](size_t size, const std::nothrow_t &tag) noexcept
{
    void *ptr = std::malloc(size);
    if (g_isRecord && ptr != nullptr) {
        std::lock_guard<std::mutex> lock(g_mutex);
        allocatedAddresses.insert(ptr);
    }
    return ptr;
}

void operator delete[](void *ptr) noexcept
{
    if (g_isRecord && ptr != nullptr) {
        std::lock_guard<std::mutex> lock(g_mutex);
        allocatedAddresses.erase(ptr);
    }
    std::free(ptr);
}

namespace Test {
class RdUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) {};
    void TearDown(void) {};
};

void RdUtilsTest::SetUpTestCase(void)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_isRecord = true;
}

void RdUtilsTest::TearDownTestCase(void)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_isRecord = false;
}

static void ScheduleMock(void *param)
{
    (void)param;
    int sleepTime = 20;
    std::this_thread::sleep_for(std::chrono::seconds(sleepTime));
}

/**
 * @tc.name: RdUtils_Test_001
 * @tc.desc: Normal testCase of sqlite_utils for IsSpecial, if sqlType is special
 * @tc.type: FUNC
 */
HWTEST_F(RdUtilsTest, RdUtils_Test_001, TestSize.Level1)
{
    EXPECT_EQ(RdUtils::TransferGrdErrno(1), 1);
    EXPECT_EQ(RdUtils::TransferGrdErrno(0), E_OK);
    EXPECT_EQ(RdUtils::TransferGrdErrno(-9999), E_ERROR);
}

HWTEST_F(RdUtilsTest, RdUtils_Test_002, TestSize.Level1)
{
    EXPECT_EQ(RdUtils::TransferGrdTypeToColType(GRD_DB_DATATYPE_INTEGER), ColumnType::TYPE_INTEGER);
    EXPECT_EQ(RdUtils::TransferGrdTypeToColType(GRD_DB_DATATYPE_FLOAT), ColumnType::TYPE_FLOAT);
    EXPECT_EQ(RdUtils::TransferGrdTypeToColType(GRD_DB_DATATYPE_TEXT), ColumnType::TYPE_STRING);
    EXPECT_EQ(RdUtils::TransferGrdTypeToColType(GRD_DB_DATATYPE_BLOB), ColumnType::TYPE_BLOB);
    EXPECT_EQ(RdUtils::TransferGrdTypeToColType(GRD_DB_DATATYPE_FLOATVECTOR), ColumnType::TYPE_FLOAT32_ARRAY);
    EXPECT_EQ(RdUtils::TransferGrdTypeToColType(GRD_DB_DATATYPE_NULL), ColumnType::TYPE_NULL);
}

/**
 * @tc.name: RdUtils_Test_003
 * @tc.desc: Test RdSqlRegistryThreadPool
 * @tc.type: FUNC
 */
HWTEST_F(RdUtilsTest, RdUtils_Test_003, TestSize.Level1)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    std::string dbPath = "/data/test/execute_test.db";
    std::string configStr = "{}";
    RdbHelper::DeleteRdbStore(dbPath);

    GRD_DB *db = nullptr;
    EXPECT_EQ(RdUtils::RdDbOpen(dbPath.c_str(), configStr.c_str(), GRD_DB_OPEN_CREATE, &db), E_OK);
    ASSERT_EQ(RdUtils::RdSqlRegistryThreadPool(db), E_OK);

    ASSERT_NE(RdUtils::threadPool_.schedule, nullptr);
    ASSERT_NE(RdUtils::threadPool_.remove, nullptr);

    TaskExecutor::TaskId taskId = RdUtils::threadPool_.schedule(reinterpret_cast<void *>(ScheduleMock), nullptr);
    ASSERT_NE(static_cast<uint64_t>(taskId), TaskExecutor::INVALID_TASK_ID);

    int sleepTime = 2;
    std::this_thread::sleep_for(std::chrono::seconds(sleepTime));

    bool ret = RdUtils::threadPool_.remove(static_cast<uint64_t>(taskId), false);
    // expect false because this task is running, will remove from exec list
    ASSERT_FALSE(ret);

    EXPECT_EQ(RdUtils::RdDbClose(db, 0), E_OK);
    RdbHelper::DeleteRdbStore(dbPath);
}

/**
 * @tc.name: RdUtils_Test_004
 * @tc.desc: Test bind empty string
 * @tc.type: FUNC
 */
HWTEST_F(RdUtilsTest, RdUtils_Test_004, TestSize.Level1)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    GRD_SqlStmt *stmt = nullptr;
    uint32_t idx = 0;
    const char *str = "";
    EXPECT_EQ(RdUtils::RdSqlBindText(stmt, idx, str, -1, nullptr), E_INVALID_ARGS);
    EXPECT_EQ(RdUtils::RdSqlBindText(stmt, idx, str, 0, nullptr), E_INVALID_ARGS);
}

/**
 * @tc.name: RdUtils_Test_005
 * @tc.desc: Test RdSqlBindBlob
 * @tc.type: FUNC
 */
HWTEST_F(RdUtilsTest, RdUtils_Test_005, TestSize.Level0)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    GRD_SqlStmt *stmtHandle = nullptr;
    const uint8_t testData[] = { 0x05, 0x06 };
    const int32_t dataLen = sizeof(testData);
    auto ret = RdUtils::RdSqlBindBlob(stmtHandle, 1, testData, dataLen, nullptr);
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(allocatedAddresses.empty());
}

/**
 * @tc.name: RdUtils_Test_006
 * @tc.desc: Test RdSqlBindBlob
 * @tc.type: FUNC
 */
HWTEST_F(RdUtilsTest, RdUtils_Test_006, TestSize.Level0)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    GRD_SqlStmt *stmtHandle = nullptr;
    const char *testStr = "Test";
    auto ret = RdUtils::RdSqlBindText(stmtHandle, 1, testStr, strlen(testStr), nullptr);
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(allocatedAddresses.empty());
}

/**
 * @tc.name: RdUtils_Test_007
 * @tc.desc: Test RdSqlBindFloatVector
 * @tc.type: FUNC
 */
HWTEST_F(RdUtilsTest, RdUtils_Test_007, TestSize.Level0)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    GRD_SqlStmt *stmtHandle = nullptr;
    float testData[] = { 1.1f, 2.2f, 3.3f };
    uint32_t dim = sizeof(testData) / sizeof(float);
    auto ret = RdUtils::RdSqlBindFloatVector(stmtHandle, 2, testData, dim, nullptr);
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(allocatedAddresses.empty());
}
} // namespace Test
