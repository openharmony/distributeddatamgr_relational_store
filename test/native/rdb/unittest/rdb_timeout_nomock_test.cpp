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

#include "rdb_store_impl.h"

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS;

namespace {
constexpr int DEFAULT_BLOB_SIZE = 4096;
}

class RdbTimeoutNoMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string databaseName;

protected:
    std::shared_ptr<RdbStore> store_;
};

class RdbTimeoutNoMockTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override { return E_OK; }
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override { return E_OK; }
};

const std::string RdbTimeoutNoMockTest::databaseName = RDB_TEST_PATH + "timeout_nomock_test.db";

void RdbTimeoutNoMockTest::SetUpTestCase(void) {}

void RdbTimeoutNoMockTest::TearDownTestCase(void) {}

void RdbTimeoutNoMockTest::SetUp(void)
{
    store_ = nullptr;
    int errCode = RdbHelper::DeleteRdbStore(databaseName);
    EXPECT_EQ(E_OK, errCode);
    RdbStoreConfig config(RdbTimeoutNoMockTest::databaseName);
    RdbTimeoutNoMockTestOpenCallback helper;
    store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store_, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbTimeoutNoMockTest::TearDown(void)
{
    store_ = nullptr;
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(databaseName);
}

static ValuesBuckets BuildRows(int rowCount)
{
    std::vector<uint8_t> blobData(DEFAULT_BLOB_SIZE, 1);
    ValuesBuckets rows;
    for (int i = 0; i < rowCount; i++) {
        ValuesBucket row;
        row.Put("name", "test_" + std::to_string(i));
        row.PutBlob("data", blobData);
        rows.Put(row);
    }
    return rows;
}

/* *
 * @tc.name: BatchInsert_NoMock_001
 * @tc.desc: BatchInsert with timeoutMs=500(<1000), real SqlTimeoutGuard bumps to 1000ms.
 *           Small batch completes within 1000ms, expect E_OK.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutNoMockTest, BatchInsert_NoMock_001, TestSize.Level1)
{
    std::string tableName = "NoMockBatchTest";
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
    auto res = store_->Execute(
        "CREATE TABLE " + tableName + " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data BLOB)");
    ASSERT_EQ(res.first, E_OK);

    auto rows = BuildRows(100);

    BatchInsertConfig config;
    config.timeoutMs = 500; // < 1000, bumped to 1000 internally by SqlTimeoutGuard
    auto start = std::chrono::steady_clock::now();
    auto [errCode, result] = store_->BatchInsert(tableName, rows, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("BatchInsert_NoMock_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_EQ(errCode, E_OK) << "Small batch should succeed within bumped 1000ms timeout, errCode=" << errCode;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: BatchInsert_NoMock_002
 * @tc.desc: BatchInsert with timeoutMs=-1(<0), real SqlTimeoutGuard treats as no timeout.
 *           Expect E_OK.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutNoMockTest, BatchInsert_NoMock_002, TestSize.Level1)
{
    std::string tableName = "NoMockBatchTest";
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
    auto res = store_->Execute(
        "CREATE TABLE " + tableName + " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data BLOB)");
    ASSERT_EQ(res.first, E_OK);

    auto rows = BuildRows(100);

    BatchInsertConfig config;
    config.timeoutMs = -1; // < 0, no guard
    auto [errCode, result] = store_->BatchInsert(tableName, rows, config);
    printf("BatchInsert_NoMock_002: errCode=%d, timeoutMs=%lld\n", errCode,
        static_cast<long long>(config.timeoutMs));

    EXPECT_EQ(errCode, E_OK) << "Negative timeout should be treated as no timeout, errCode=" << errCode;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: BatchInsert_NoMock_003
 * @tc.desc: BatchInsert with timeoutMs=0, no timeout guard. Expect E_OK.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutNoMockTest, BatchInsert_NoMock_003, TestSize.Level1)
{
    std::string tableName = "NoMockBatchTest";
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
    auto res = store_->Execute(
        "CREATE TABLE " + tableName + " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data BLOB)");
    ASSERT_EQ(res.first, E_OK);

    auto rows = BuildRows(100);

    BatchInsertConfig config;
    config.timeoutMs = 0; // no timeout
    auto [errCode, result] = store_->BatchInsert(tableName, rows, config);
    printf("BatchInsert_NoMock_003: errCode=%d, timeoutMs=%lld\n", errCode,
        static_cast<long long>(config.timeoutMs));

    EXPECT_EQ(errCode, E_OK) << "No timeout should always succeed, errCode=" << errCode;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}
