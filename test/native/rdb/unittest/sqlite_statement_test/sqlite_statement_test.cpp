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
#include "connection.h"
#include "executor_pool.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_sql_log.h"
#include "rdb_store.h"
#include "rdb_store_manager.h"
#include "rdb_types.h"
#include "sqlite_global_config.h"
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

/**
 * @tc.name: SqliteStatement003
 * @tc.desc: Test CheckValueObjectValid with normal bind args
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteStatementTest, SqliteStatement003, TestSize.Level0)
{
    const char *dbPath = "/data/test/SqliteStatement003.db";
    RdbStoreConfig rdbConfig(dbPath);
    sqlite3 *db = nullptr;
    int rc = sqlite3_open(dbPath, &db);
    ASSERT_NE(db, nullptr);
    EXPECT_EQ(rc, SQLITE_OK);
    const char *sqlCreate = "CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY, data TEXT)";
    char *errMsg = nullptr;
    rc = sqlite3_exec(db, sqlCreate, NULL, NULL, &errMsg);

    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO test(id, data) VALUES(?, ?)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    SqliteStatement statem(&rdbConfig);
    statem.stmt_ = stmt;
    statem.sql_ = sql;
    statem.numParameters_ = 2;

    std::vector<ValueObject> bindArgs;
    bindArgs.push_back(ValueObject(1));
    bindArgs.push_back(ValueObject(std::string("test")));

    int errCode = statem.BindArgs(bindArgs);
    EXPECT_EQ(errCode, E_OK);

    statem.stmt_ = nullptr;
    sqlite3_finalize(stmt);
    rc = sqlite3_close(db);
    EXPECT_EQ(rc, SQLITE_OK);
}

/**
 * @tc.name: S_ErrMsg_001
 * @tc.desc: Verify SqliteStatement GetLastErrorMsg returns "not an error" when no error occurred.
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteStatementTest, S_ErrMsg_001, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "S_ErrMsg_001.db";
    RdbHelper::DeleteRdbStore(dbPath);
    SqliteGlobalConfig::InitSqliteGlobalConfig();
    RdbStoreConfig config(dbPath);
    config.SetDBType(OHOS::NativeRdb::DBType::DB_SQLITE);
    auto [errCode, conn] = Connection::Create(config, true);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_NE(conn, nullptr);

    // Create a valid statement — no error on the connection
    auto [stmtErr, statement] = conn->CreateStatement("CREATE TABLE IF NOT EXISTS test(id INTEGER)", conn);
    ASSERT_EQ(stmtErr, E_OK);
    ASSERT_NE(statement, nullptr);

    // GetLastErrorMsg delegates to sqlite3_errmsg which returns "not an error"
    std::string result = statement->GetLastErrorMsg();
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("not an error"), std::string::npos);

    conn = nullptr;
    RdbHelper::DeleteRdbStore(dbPath);
}

/**
 * @tc.name: S_ErrMsg_002
 * @tc.desc: Verify SqliteStatement GetLastErrorMsg returns syntax error after a failed prepare on the same connection.
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteStatementTest, S_ErrMsg_002, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "S_ErrMsg_002.db";
    RdbHelper::DeleteRdbStore(dbPath);
    SqliteGlobalConfig::InitSqliteGlobalConfig();
    RdbStoreConfig config(dbPath);
    config.SetDBType(OHOS::NativeRdb::DBType::DB_SQLITE);
    auto [errCode, conn] = Connection::Create(config, true);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_NE(conn, nullptr);

    // Create a valid statement first (shares the same db handle)
    auto [stmtErr, statement] = conn->CreateStatement("CREATE TABLE IF NOT EXISTS test(id INTEGER)", conn);
    ASSERT_EQ(stmtErr, E_OK);
    ASSERT_NE(statement, nullptr);

    // Trigger a syntax error by preparing invalid SQL on the same connection
    auto [badErr, badStmt] = conn->CreateStatement("SELCT * FROM test", conn);
    EXPECT_NE(badErr, E_OK);
    EXPECT_EQ(badStmt, nullptr);

    // The valid statement's GetLastErrorMsg reads sqlite3_errmsg on the shared db handle
    std::string result = statement->GetLastErrorMsg();
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("syntax"), std::string::npos);

    conn = nullptr;
    RdbHelper::DeleteRdbStore(dbPath);
}

/**
 * @tc.name: S_ErrMsg_003
 * @tc.desc: Verify SqliteStatement GetLastErrorMsg returns "no such table" after a failed prepare referencing a
 *           non-existent table.
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteStatementTest, S_ErrMsg_003, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "S_ErrMsg_003.db";
    RdbHelper::DeleteRdbStore(dbPath);
    SqliteGlobalConfig::InitSqliteGlobalConfig();
    RdbStoreConfig config(dbPath);
    config.SetDBType(OHOS::NativeRdb::DBType::DB_SQLITE);
    auto [errCode, conn] = Connection::Create(config, true);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_NE(conn, nullptr);

    // Create a valid statement first
    auto [stmtErr, statement] = conn->CreateStatement("CREATE TABLE IF NOT EXISTS test(id INTEGER)", conn);
    ASSERT_EQ(stmtErr, E_OK);
    ASSERT_NE(statement, nullptr);

    // Trigger "no such table" by preparing INSERT into a non-existent table
    auto [badErr, badStmt] = conn->CreateStatement("INSERT INTO no_such_table VALUES(1)", conn);
    EXPECT_NE(badErr, E_OK);
    EXPECT_EQ(badStmt, nullptr);

    std::string result = statement->GetLastErrorMsg();
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("no such table"), std::string::npos);

    conn = nullptr;
    RdbHelper::DeleteRdbStore(dbPath);
}

/**
 * @tc.name: S_ErrMsg_004
 * @tc.desc: Verify SqliteStatement GetLastErrorMsg returns "already exists" after executing a duplicate CREATE TABLE.
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteStatementTest, S_ErrMsg_004, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "S_ErrMsg_004.db";
    RdbHelper::DeleteRdbStore(dbPath);
    SqliteGlobalConfig::InitSqliteGlobalConfig();
    RdbStoreConfig config(dbPath);
    config.SetDBType(OHOS::NativeRdb::DBType::DB_SQLITE);
    auto [errCode, conn] = Connection::Create(config, true);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_NE(conn, nullptr);

    // Create a statement for CREATE TABLE and execute it — table created
    auto [stmtErr, statement] = conn->CreateStatement("CREATE TABLE dup_tbl(id INTEGER PRIMARY KEY)", conn);
    ASSERT_EQ(stmtErr, E_OK);
    ASSERT_NE(statement, nullptr);

    int execRet = statement->Execute();
    EXPECT_EQ(execRet, E_OK);

    // Reset and execute again — fails with "table already exists"
    statement->Reset();
    execRet = statement->Execute();
    EXPECT_NE(execRet, E_OK);

    std::string result = statement->GetLastErrorMsg();
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("already exists"), std::string::npos);

    conn = nullptr;
    RdbHelper::DeleteRdbStore(dbPath);
}