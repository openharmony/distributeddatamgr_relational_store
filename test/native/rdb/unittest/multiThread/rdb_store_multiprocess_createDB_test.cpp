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
#include <gtest/gtest.h>
#include <gtest/hwext/gtest-multithread.h>
#include <sys/types.h>

#include <chrono>
#include <cstdint>
#include <future>
#include <map>
#include <memory>
#include <ostream>
#include <string>
#include <thread>

#include "../common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_impl.h"

using namespace testing::ext;
using namespace testing::mt;
using namespace OHOS::NativeRdb;

class RdbMultiProcessCreateDBTest : public testing::Test {
public:
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
    void SetUp(){};
    void TearDown(){};
    static const std::string databaseName;
    static const std::string createTabSql;
    static void Create();

    class Callback : public RdbOpenCallback {
    public:
        int OnCreate(RdbStore &rdbStore) override;
        int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;
    };
};
const std::string RdbMultiProcessCreateDBTest::databaseName = "multi_process_create_test.db";
const std::string RdbMultiProcessCreateDBTest::createTabSql =
    "CREATE TABLE IF NOT EXISTS test "
    "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)";

static constexpr uint32_t RETRY_COUNT = 2;
static constexpr int32_t SLEEP_TIME = 500;

int RdbMultiProcessCreateDBTest::Callback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(createTabSql);
}

int RdbMultiProcessCreateDBTest::Callback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void CheckAge(std::shared_ptr<ResultSet> &resultSet)
{
    int columnIndex;
    int intVal;
    ColumnType columnType;
    int ret = resultSet->GetColumnIndex("age", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_INTEGER);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    // 18: age is 18
    EXPECT_EQ(18, intVal);
}

void CheckSalary(std::shared_ptr<ResultSet> &resultSet)
{
    int columnIndex;
    double dVal;
    ColumnType columnType;
    int ret = resultSet->GetColumnIndex("salary", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_FLOAT);
    ret = resultSet->GetDouble(columnIndex, dVal);
    EXPECT_EQ(ret, E_OK);
    // 100.5: salary is 100.5
    EXPECT_EQ(100.5, dVal);
}

void CheckBlob(std::shared_ptr<ResultSet> &resultSet)
{
    int columnIndex;
    std::vector<uint8_t> blob;
    ColumnType columnType;
    int ret = resultSet->GetColumnIndex("blobType", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_BLOB);
    ret = resultSet->GetBlob(columnIndex, blob);
    EXPECT_EQ(ret, E_OK);
    // 3: blob size
    EXPECT_EQ(3, static_cast<int>(blob.size()));
    // 1: blob[0] is 1
    EXPECT_EQ(1, blob[0]);
    // 2: blob[1] is 2
    EXPECT_EQ(2, blob[1]);
    // 3: blob[2] is 3
    EXPECT_EQ(3, blob[2]);
}

void CheckResultSet(std::shared_ptr<RdbStore> &store)
{
    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    EXPECT_NE(resultSet, nullptr);

    int columnIndex;
    int intVal;
    std::string strVal;
    ColumnType columnType;
    int position;
    int ret = resultSet->GetRowIndex(position);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(position, -1);

    ret = resultSet->GetColumnType(0, columnType);
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);

    ret = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnIndex, 0);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_INTEGER);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, intVal);

    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_STRING);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("zhangsan", strVal);

    CheckAge(resultSet);
    CheckSalary(resultSet);
    CheckBlob(resultSet);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

void RdbMultiProcessCreateDBTest::Create()
{
    int errCode = E_OK;
    RdbStoreConfig config(RDB_TEST_PATH + RdbMultiProcessCreateDBTest::databaseName);
    config.SetEncryptStatus(true);
    RdbMultiProcessCreateDBTest::Callback helper;
    for (uint32_t retry = 0; retry < RETRY_COUNT; ++retry) {
        auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
        EXPECT_TRUE(errCode == E_SQLITE_BUSY || errCode == E_OK);
        if (errCode != E_SQLITE_BUSY) {
            EXPECT_NE(store, nullptr);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    }
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_TRUE(errCode == E_SQLITE_BUSY || errCode == E_OK);
    ASSERT_NE(store, nullptr);

    int64_t id;
    ValuesBucket values;
    values.Put("name", "zhangsan");
    // 18: age is 18
    values.Put("age", 18);
    // 100.5: salary is 100.5
    values.Put("salary", 100.5);
    values.Put("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);

    CheckResultSet(store);
    // 2: await 2s
    std::this_thread::sleep_for(std::chrono::seconds(2));
    RdbHelper::DeleteRdbStore(RDB_TEST_PATH + RdbMultiProcessCreateDBTest::databaseName);
}

/* *
 * @tc.name: Rdb_ConcurrentCreate_001
 * @tc.desc: tow processes create database at the same time
 * @tc.type: FUNC
 */
HWTEST_F(RdbMultiProcessCreateDBTest, Rdb_ConcurrentCreate_001, TestSize.Level1)
{
    Create();
}

int32_t main(int32_t argc, char *argv[])
{
    testing::GTEST_FLAG(output) = "xml:./";
    testing::InitGoogleTest(&argc, argv);
    pid_t pid = fork();
    if (pid == 0) {
        RdbMultiProcessCreateDBTest::Create();
        exit(0);
    } else if (pid < 0) {
        return 1;
    }
    int res = RUN_ALL_TESTS();
    if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
    return res;
}