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

#include <unistd.h>

#include <iostream>
#include <string>
#include <string_view>

#include "common.h"
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

constexpr const char *FILL_RELEASE_TABLE =
    "WITH RECURSIVE cnt(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM cnt WHERE x<2000) "
    "INSERT INTO test(name, age) SELECT 'name_' || x, x FROM cnt;";
constexpr const char *LONG_QUERY_PART = "SELECT count(*) FROM test a, test b WHERE a.id <= 50";
constexpr int RELEASE_INTERRUPT_DELAY_US = 200 * 1000;

static RdbStore::ReleaseOption InterruptReleaseOption()
{
    RdbStore::ReleaseOption option;
    option.interrupt = true;
    return option;
}

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
            if (errCode != E_OK && errCode != E_SQLITE_SCHEMA) {
                break;
            }
        }
        auto code = (errCode == E_OK || errCode == E_SQLITE_SCHEMA) ? E_OK : errCode;
        block2->SetValue(code);
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
            if (errCode != E_OK && errCode != E_SQLITE_SCHEMA) {
                break;
            }
        }
        auto code = (errCode == E_OK || errCode == E_SQLITE_SCHEMA) ? E_OK : errCode;
        block2->SetValue(code);
    });

    EXPECT_EQ(block1->GetValue(), E_OK);
    EXPECT_EQ(block2->GetValue(), E_OK);
    EXPECT_NE(taskId1, taskId2);
}

/**
 * @tc.name: MultiThread_Release_OldHandle_0001
 *           After one thread fully releases the store and clears the cache, another thread holding its
 *           own shared_ptr copy still sees the stale handle alive but its pool gone.
 * @tc.desc: 1.thread A (main): store->Release() + RdbHelper::ClearStoreCache(), then store.reset()
 *           2.thread B (executor): with its own shared_ptr copy, Insert returns E_ALREADY_CLOSED and
 *                       QuerySql returns nullptr after A finishes, with no crash.
 * @tc.type: FUNC
 */
HWTEST_F(RdbMultiThreadConnectionTest, MultiThread_Release_OldHandle_0001, TestSize.Level2)
{
    // gate: A -> B "release finished"; writeBlock/readBlock: B -> A results.
    auto gate = std::make_shared<BlockData<int32_t>>(3, false);
    auto writeBlock = std::make_shared<BlockData<int32_t>>(3, false);
    auto readBlock = std::make_shared<BlockData<int32_t>>(3, false);

    // Thread B captures its own shared_ptr copy, so the RdbStoreImpl object stays alive even after
    // thread A drops its reference; only the connection pool is gone after Release.
    auto taskIdB = executors_->Execute([store = store_, gate, writeBlock, readBlock]() {
        gate->GetValue(); // wait until thread A has fully finished Release + ClearStoreCache
        int64_t rowId = -1;
        ValuesBucket row;
        row.Put("name", "nameX");
        row.Put("age", 99);
        writeBlock->SetValue(store->Insert(rowId, "test", row));
        // The query API has no error-code slot; report success when it returns nullptr.
        readBlock->SetValue(store->QuerySql("SELECT * FROM test") == nullptr ? E_OK : E_ERROR);
    });

    // Thread A (main): fully release and clear the cache, then drop the reference.
    EXPECT_EQ(E_OK, store_->Release());
    EXPECT_EQ(E_OK, RdbHelper::ClearStoreCache(RDB_TEST_PATH + DATABASE_NAME));
    store_ = nullptr;
    gate->SetValue(E_OK); // signal thread B that release is finished

    EXPECT_EQ(E_ALREADY_CLOSED, writeBlock->GetValue());
    EXPECT_EQ(E_OK, readBlock->GetValue());
    EXPECT_NE(taskIdB, 0);
}

/**
 * @tc.name: MultiThread_Release_Interrupt_Query_0001
 * @tc.desc: 1.thread A: traverses a resultSet row by row and holds it unclosed
 *           2.thread B (main): Release with interrupt returns E_OK; thread A observes
 *           E_SQLITE_INTERRUPT and the resultSet closes itself in its owning thread.
 * @tc.type: FUNC
 */
HWTEST_F(RdbMultiThreadConnectionTest, MultiThread_Release_Interrupt_Query_0001, TestSize.Level2)
{
    EXPECT_EQ(E_OK, store_->ExecuteSql(FILL_RELEASE_TABLE));
    auto started = std::make_shared<BlockData<int32_t>>(3, false);
    auto queryBlock = std::make_shared<BlockData<int32_t>>(3, false);
    executors_->Execute([store = store_, started, queryBlock]() {
        OHOS::DistributedRdb::QueryOptions options;
        options.preCount = false;
        options.isGotoNextRowReturnLastError = false;
        auto resultSet = store->QueryByStep("SELECT * FROM test", std::vector<ValueObject>(), options);
        if (resultSet == nullptr) {
            queryBlock->SetValue(E_ERROR);
            return;
        }
        int err = resultSet->GoToNextRow(); // row 0; the traversal is now in progress
        started->SetValue(E_OK);            // signal: an in-use resultSet is being held
        while (err == E_OK) {
            usleep(1000);                   // the release may land on a running or resumed step
            err = resultSet->GoToNextRow();
        }
        queryBlock->SetValue(err);
        resultSet->Close();
    });

    // Release right after the traversal is confirmed in progress; the next step of thread A is
    // interrupted and the resultSet closes itself, so the connection is returned in budget.
    EXPECT_EQ(E_OK, started->GetValue());
    EXPECT_EQ(E_OK, store_->Release(InterruptReleaseOption()));
    EXPECT_EQ(E_SQLITE_INTERRUPT, queryBlock->GetValue());
    EXPECT_EQ(nullptr, store_->QueryByStep("SELECT * FROM test"));
}

/**
 * @tc.name: MultiThread_Release_Interrupt_Write_0001
 * @tc.desc: 1.thread A: keeps inserting rows
 *           2.thread B (main): Release with interrupt returns E_OK; thread A stops with
 *           E_ALREADY_CLOSED.
 * @tc.type: FUNC
 */
HWTEST_F(RdbMultiThreadConnectionTest, MultiThread_Release_Interrupt_Write_0001, TestSize.Level2)
{
    auto writeBlock = std::make_shared<BlockData<int32_t>>(3, false);
    executors_->Execute([store = store_, writeBlock]() {
        int lastErr = E_OK;
        int64_t rowId = -1;
        for (int32_t i = 0; i < 2000; i++) {
            ValuesBucket row;
            row.PutString("name", "name_" + std::to_string(i));
            row.PutInt("age", i);
            lastErr = store->Insert(rowId, "test", row);
            if (lastErr != E_OK) {
                break;
            }
            usleep(1000);
        }
        writeBlock->SetValue(lastErr);
    });

    usleep(RELEASE_INTERRUPT_DELAY_US);
    EXPECT_EQ(E_OK, store_->Release(InterruptReleaseOption()));
    EXPECT_EQ(E_ALREADY_CLOSED, writeBlock->GetValue());
    int64_t rowId = -1;
    ValuesBucket row;
    row.PutString("name", "name_after");
    row.PutInt("age", 1);
    EXPECT_EQ(E_ALREADY_CLOSED, store_->Insert(rowId, "test", row));

    // Update and delete on the released store fail as well.
    AbsRdbPredicates predicates("test");
    predicates.EqualTo("name", "name_0");
    ValuesBucket updateRow;
    updateRow.PutString("name", "name_updated");
    updateRow.PutInt("age", 2);
    int changedRows = -1;
    EXPECT_EQ(E_ALREADY_CLOSED, store_->Update(changedRows, updateRow, predicates));
    EXPECT_EQ(E_ALREADY_CLOSED, store_->Delete(changedRows, predicates));
}

/**
 * @tc.name: MultiThread_Release_Interrupt_QuerySql_0001
 * @tc.desc: 1.thread A: one confirmed QuerySql round, then keeps querying
 *           2.thread B (main): Release with interrupt returns E_OK; later rounds of thread A
 *           get nullptr (E_ALREADY_CLOSED) and every connection is returned within budget.
 * @tc.type: FUNC
 */
HWTEST_F(RdbMultiThreadConnectionTest, MultiThread_Release_Interrupt_QuerySql_0001, TestSize.Level2)
{
    EXPECT_EQ(E_OK, store_->ExecuteSql(FILL_RELEASE_TABLE));
    auto started = std::make_shared<BlockData<int32_t>>(3, false);
    auto queryBlock = std::make_shared<BlockData<int32_t>>(3, false);
    executors_->Execute([store = store_, started, queryBlock]() {
        auto resultSet = store->QuerySql(LONG_QUERY_PART);
        if (resultSet == nullptr) {
            queryBlock->SetValue(E_ERROR);
            return;
        }
        int lastErr = resultSet->GoToNextRow(); // the first round succeeds
        resultSet->Close();
        started->SetValue(E_OK);                // signal: the QuerySql path is confirmed working
        for (int32_t i = 0; i < 20 && lastErr == E_OK; i++) {
            resultSet = store->QuerySql(LONG_QUERY_PART);
            if (resultSet == nullptr) {         // the pool is gone after the release
                lastErr = E_ALREADY_CLOSED;
                break;
            }
            lastErr = resultSet->GoToNextRow();
            resultSet->Close();
        }
        queryBlock->SetValue(lastErr);
    });

    // Release right after the first round is confirmed; later rounds get nullptr and the loop
    // stops with E_ALREADY_CLOSED, with every connection returned within budget.
    EXPECT_EQ(E_OK, started->GetValue());
    EXPECT_EQ(E_OK, store_->Release(InterruptReleaseOption()));
    EXPECT_EQ(E_ALREADY_CLOSED, queryBlock->GetValue());
    EXPECT_EQ(nullptr, store_->QuerySql("SELECT * FROM test"));
}

/**
 * @tc.name: MultiThread_Release_Interrupt_Gap_0001
 * @tc.desc: 1.thread A: steps once, sleeps between two GoToNextRow calls (the interrupt lands in
 *                     this gap), then steps again
 *           2.thread B (main): Release with interrupt returns E_OK; the resumed step observes
 *           the pending SQLITE_INTERRUPT immediately and the resultSet closes itself.
 * @tc.type: FUNC
 */
HWTEST_F(RdbMultiThreadConnectionTest, MultiThread_Release_Interrupt_Gap_0001, TestSize.Level2)
{
    EXPECT_EQ(E_OK, store_->ExecuteSql(FILL_RELEASE_TABLE));
    auto started = std::make_shared<BlockData<int32_t>>(3, false);
    auto gapBlock = std::make_shared<BlockData<int32_t>>(3, false);
    auto afterBlock = std::make_shared<BlockData<int32_t>>(3, false);
    executors_->Execute([store = store_, started, gapBlock, afterBlock]() {
        OHOS::DistributedRdb::QueryOptions options;
        options.preCount = false;
        options.isGotoNextRowReturnLastError = false;
        auto resultSet = store->QueryByStep("SELECT * FROM test", std::vector<ValueObject>(), options);
        if (resultSet == nullptr) {
            gapBlock->SetValue(E_ERROR);
            afterBlock->SetValue(E_ERROR);
            return;
        }
        (void)resultSet->GoToNextRow();  // row 0; the statement pauses mid-traversal
        started->SetValue(E_OK);         // signal: entering the gap right away
        usleep(500 * 1000);              // the interrupt lands inside this gap
        gapBlock->SetValue(resultSet->GoToNextRow());       // resumed step: interrupted at once
        afterBlock->SetValue(resultSet->GoToNextRow());     // resultSet already closed itself
        resultSet->Close();              // idempotent
    });

    // Thread A has stepped once and is now sleeping between statements.
    EXPECT_EQ(E_OK, started->GetValue());
    usleep(100 * 1000); // make sure the interrupt falls inside the gap
    EXPECT_EQ(E_OK, store_->Release(InterruptReleaseOption()));
    EXPECT_EQ(E_SQLITE_INTERRUPT, gapBlock->GetValue());
    EXPECT_EQ(E_ALREADY_CLOSED, afterBlock->GetValue());
}
