/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <iostream>
#include <string>
#include <string_view>

#include "../common.h"
#include "block_data.h"
#include "executor_pool.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "shared_block.h"
#include "sqlite_shared_result_set.h"
#include "step_result_set.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::NativeRdb;
class RdbMultiThreadConnectionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void GenerateData();

protected:
    class Callback : public RdbOpenCallback {
    public:
        int OnCreate(RdbStore &rdbStore) override;
        int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;
    };

    static constexpr const char *DATABASE_NAME = "connection_test.db";
    static constexpr const char *CREATE_TABLE_SQL = "CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, name "
                                                    "TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)";
    static constexpr int32_t MAX_THREAD = 5;
    static constexpr int32_t MIN_THREAD = 0;

    std::shared_ptr<RdbStore> store_;
    std::shared_ptr<ExecutorPool> executors_;
};

int RdbMultiThreadConnectionTest::Callback::OnCreate(RdbStore &rdbStore)
{
    return E_OK;
}

int RdbMultiThreadConnectionTest::Callback::OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbMultiThreadConnectionTest::SetUpTestCase(void)
{
}

void RdbMultiThreadConnectionTest::TearDownTestCase(void)
{
}

void RdbMultiThreadConnectionTest::SetUp()
{
    executors_ = std::make_shared<ExecutorPool>(MAX_THREAD, MIN_THREAD);
    store_ = nullptr;
    RdbHelper::DeleteRdbStore(RDB_TEST_PATH + DATABASE_NAME);
    RdbStoreConfig sqliteSharedRstConfig(RDB_TEST_PATH + DATABASE_NAME);
    RdbMultiThreadConnectionTest::Callback sqliteSharedRstHelper;
    int errCode = E_OK;
    store_ = RdbHelper::GetRdbStore(sqliteSharedRstConfig, 1, sqliteSharedRstHelper, errCode);
    EXPECT_NE(store_, nullptr);

    auto ret = store_->ExecuteSql(CREATE_TABLE_SQL);
    EXPECT_EQ(ret, E_OK);
    GenerateData();
}

void RdbMultiThreadConnectionTest::TearDown()
{
    executors_ = nullptr;
    store_ = nullptr;
    RdbHelper::DeleteRdbStore(RDB_TEST_PATH + DATABASE_NAME);
}

void RdbMultiThreadConnectionTest::GenerateData()
{
    int64_t id;
    // 0 represent that get first data
    auto ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(E_OK, ret);
    // id is 1
    EXPECT_EQ(1, id);

    // 1 represent that get second data
    ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(E_OK, ret);
    // id is 2
    EXPECT_EQ(2, id);

    // 2 represent that get third data
    ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[2]));
    EXPECT_EQ(E_OK, ret);
    // id is 3
    EXPECT_EQ(3, id);
}

/**
 * @tc.name: MultiThread_Connection_0001
 *           if connect is not nullptr when query by calling function querySql while creating table.
 * @tc.desc: 1.thread 1: query
 *           2.thread 2: create table
 * @tc.type: FUNC
 * @tc.author: leiyanbo
 */
HWTEST_F(RdbMultiThreadConnectionTest, MultiThread_Connection_0001, TestSize.Level2)
{
    std::shared_ptr<BlockData<int32_t>> block1 = std::make_shared<BlockData<int32_t>>(3, false);
    auto taskId1 = executors_->Execute([store = store_, block1]() {
        constexpr const char *createTable = "CREATE TABLE test";
        constexpr const char *createTableColumn = " (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                          "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                          "blobType BLOB)";
        int32_t errCode = E_ERROR;
        for (uint32_t i = 0; i < 2000; i++) {
            errCode = store->ExecuteSql(createTable + std::to_string(i) + createTableColumn);
            if (errCode != E_OK) {
                break;
            }
        }
        block1->SetValue(errCode);
    });

    std::shared_ptr<BlockData<int32_t>> block2 = std::make_shared<BlockData<int32_t>>(3, false);
    auto taskId2 = executors_->Execute([store = store_, block2]() {
        int32_t errCode = E_ERROR;
        for (uint32_t i = 0; i < 2000; i++) {
            auto resultSet = store->QuerySql("SELECT * FROM test");
            int rowCount = -1;
            errCode = resultSet->GetRowCount(rowCount);
            resultSet->Close();
            if (errCode != E_OK) {
                break;
            }
        }
        block2->SetValue(errCode);
    });

    EXPECT_EQ(block1->GetValue(), E_OK);
    EXPECT_EQ(block2->GetValue(), E_OK);
    EXPECT_NE(taskId1, taskId2);
}

/**
 * @tc.name: MultiThread_Connection_0002
 *           if connect is not nullptr when query by calling function queryByStep while creating table.
 * @tc.desc: 1.thread 1: query
 *           2.thread 2: create table
 * @tc.type: FUNC
 * @tc.author: leiyanbo
 */
HWTEST_F(RdbMultiThreadConnectionTest, MultiThread_Connection_0002, TestSize.Level2)
{
    std::shared_ptr<BlockData<int32_t>> block1 = std::make_shared<BlockData<int32_t>>(3, false);
    auto taskId1 = executors_->Execute([store = store_, block1]() {
        constexpr const char *createTable = "CREATE TABLE test";
        constexpr const char *createTableColumn = " (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                          "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                          "blobType BLOB)";
        int32_t errCode = E_ERROR;
        for (uint32_t i = 0; i < 2000; i++) {
            errCode = store->ExecuteSql(createTable + std::to_string(i) + createTableColumn);
            if (errCode != E_OK) {
                break;
            }
        }
        block1->SetValue(errCode);
    });

    std::shared_ptr<BlockData<int32_t>> block2 = std::make_shared<BlockData<int32_t>>(3, false);
    auto taskId2 = executors_->Execute([store = store_, block2]() {
        int32_t errCode = E_ERROR;
        for (uint32_t i = 0; i < 2000; i++) {
            auto resultSet = store->QueryByStep("SELECT * FROM test");
            int rowCount = -1;
            errCode = resultSet->GetRowCount(rowCount);
            resultSet->Close();
            if (errCode != E_OK) {
                break;
            }
        }
        block2->SetValue(errCode);
    });

    EXPECT_EQ(block1->GetValue(), E_OK);
    EXPECT_EQ(block2->GetValue(), E_OK);
    EXPECT_NE(taskId1, taskId2);
}
