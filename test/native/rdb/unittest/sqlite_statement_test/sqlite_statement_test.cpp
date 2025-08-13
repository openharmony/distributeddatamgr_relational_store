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
#include "sqlite_statement.h"

#include <gtest/gtest.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <thread>

#include "block_data.h"
#include "common.h"
#include "executor_pool.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_sql_log.h"
#include "rdb_store.h"
#include "rdb_store_manager.h"
#include "rdb_types.h"
#include "sqlite_utils.h"
#include "values_bucket.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb;

class RdbSqliteStatementTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RdbSqliteStatementTest::SetUpTestCase(void)
{
}

void RdbSqliteStatementTest::TearDownTestCase(void)
{
}

void RdbSqliteStatementTest::SetUp(void)
{
}

void RdbSqliteStatementTest::TearDown(void)
{
}
/**
 * @tc.name: SqliteStatement001
 * @tc.desc: RdbSqliteStatementTest FillBlockInfo
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteStatementTest, SqliteStatement001, TestSize.Level0)
{
    sqlite3 *db = nullptr;
    int rc = sqlite3_open("/data/test/SqliteStatement001.db", &db);
    ASSERT_NE(db, nullptr);
    EXPECT_EQ(rc, SQLITE_OK);
    const char *sqlCreate = "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY)";
    char *errMsg = nullptr;
    rc = sqlite3_exec(db, sqlCreate, NULL, NULL, &errMsg);
    sqlite3_stmt *stmt;
    const char *sql = "select id from users;";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    SharedBlockInfo info(nullptr);
    info.isCountAllRows = true;
    info.isFull = true;
    info.totalRows = -1;
    SqliteStatement statem;
    statem.stmt_ = stmt;
    int errCode = statem.FillBlockInfo(&info);
    EXPECT_EQ(errCode, E_ERROR);
    statem.stmt_ = nullptr;
    sqlite3_finalize(stmt);
    rc = sqlite3_close(db);
    EXPECT_EQ(rc, SQLITE_OK);
}

/**
 * @tc.name: SqliteStatement002
 * @tc.desc: RdbSqliteStatementTest FillBlockInfo
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteStatementTest, SqliteStatement002, TestSize.Level0)
{
    const char *dbPath = "/data/test/SqliteStatement002.db";
    RdbStoreConfig rdbConfig(dbPath);
    sqlite3 *db = nullptr;
    int rc = sqlite3_open(dbPath, &db);
    ASSERT_NE(db, nullptr);
    EXPECT_EQ(rc, SQLITE_OK);
    const char *sqlCreate = "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY)";
    char *errMsg = nullptr;
    rc = sqlite3_exec(db, sqlCreate, NULL, NULL, &errMsg);
    sqlite3_stmt *stmt;
    const char *sql = "select id from users;";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    SharedBlockInfo info(nullptr);
    info.isCountAllRows = true;
    info.isFull = true;
    info.totalRows = -1;
    SqliteStatement statem(&rdbConfig);
    statem.stmt_ = stmt;
    int errCode = statem.FillBlockInfo(&info);
    EXPECT_EQ(errCode, E_ERROR);
    statem.stmt_ = nullptr;
    sqlite3_finalize(stmt);
    rc = sqlite3_close(db);
    EXPECT_EQ(rc, SQLITE_OK);
}