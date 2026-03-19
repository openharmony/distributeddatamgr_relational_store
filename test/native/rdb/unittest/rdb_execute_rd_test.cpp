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

#include <string>

#include "common.h"
#include "grd_api_manager.h"
#include "rd_utils.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbExecuteRdTest : public testing::TestWithParam<bool> {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string databaseName;
    static std::shared_ptr<RdbStore> store;
    static const std::string restoreDatabaseName;
    static const std::string backupDatabaseName;
};

INSTANTIATE_TEST_CASE_P(, RdbExecuteRdTest, testing::Values(false, true));

const std::string RdbExecuteRdTest::databaseName = RDB_TEST_PATH + "execute_test.db";
const std::string RdbExecuteRdTest::restoreDatabaseName = RDB_TEST_PATH + "execute_test_restore.db";
const std::string RdbExecuteRdTest::backupDatabaseName = RDB_TEST_PATH + "execute_test_backup.db";
std::shared_ptr<RdbStore> RdbExecuteRdTest::store = nullptr;

class ExecuteTestOpenRdCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int ExecuteTestOpenRdCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int ExecuteTestOpenRdCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbExecuteRdTest::SetUpTestCase(void)
{
}

void RdbExecuteRdTest::TearDownTestCase(void)
{
}

void RdbExecuteRdTest::SetUp(void)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(RdbExecuteRdTest::databaseName);
    RdbStoreConfig config(RdbExecuteRdTest::databaseName);
    config.SetIsVector(true);
    config.SetEncryptStatus(GetParam());
    ExecuteTestOpenRdCallback helper;
    RdbExecuteRdTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbExecuteRdTest::store, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbExecuteRdTest::TearDown(void)
{
    RdbExecuteRdTest::store = nullptr;
    RdbHelper::DeleteRdbStore(RdbExecuteRdTest::databaseName);
}

/**
 * @tc.name: RdbStore_Execute_006
 * @tc.desc: test RdbStore Execute in vector mode
 * @tc.type: FUNC
 */
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_006, TestSize.Level1)
{
    if (GetParam()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    std::string sqlCreateTable = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, repr floatvector(8));";
    std::string sqlInsert = "INSERT INTO test VALUES(1, '[1.2, 0.3, 3.2, 1.6, 2.5, 3.1, 0.8, 0.4]');";
    std::string sqlBeginTrans = "begin;";

    std::string dbPath = "/data/test/execute_test.db";
    std::string configStr =
    "{\"pageSize\":8, \"crcCheckEnable\":0, \"redoFlushByTrx\":1, \"bufferPoolSize\":10240,"
    "\"sharedModeEnable\":1, \"metaInfoBak\":1, \"maxConnNum\":500, \"defaultIsolationLevel\":2 }";

    GRD_DB *db2 = nullptr;
    GRD_DB *db4 = nullptr;
    EXPECT_EQ(RdUtils::RdDbOpen(dbPath.c_str(), configStr.c_str(),
        GRD_DB_OPEN_CREATE | GRD_DB_OPEN_IGNORE_DATA_CORRPUPTION, &db2), E_OK);
    EXPECT_EQ(RdUtils::RdDbOpen(dbPath.c_str(), configStr.c_str(),
        GRD_DB_OPEN_CREATE | GRD_DB_OPEN_IGNORE_DATA_CORRPUPTION, &db4), E_OK);

    GRD_SqlStmt *stmt = nullptr;
    EXPECT_EQ(RdUtils::RdSqlPrepare(db2, sqlCreateTable.c_str(), sqlCreateTable.size(), &stmt, nullptr), E_OK);
    EXPECT_EQ(RdUtils::RdSqlStep(stmt), E_OK);
    EXPECT_EQ(RdUtils::RdSqlFinalize(stmt), E_OK);

    stmt = nullptr;
    EXPECT_EQ(RdUtils::RdSqlPrepare(db4, sqlBeginTrans.c_str(), sqlBeginTrans.size(), &stmt, nullptr), E_OK);
    EXPECT_EQ(RdUtils::RdSqlStep(stmt), E_OK);
    EXPECT_EQ(RdUtils::RdSqlFinalize(stmt), E_OK);

    stmt = nullptr;
    EXPECT_EQ(RdUtils::RdSqlPrepare(db4, sqlInsert.c_str(), sqlInsert.size(), &stmt, nullptr), E_OK);
    EXPECT_EQ(RdUtils::RdSqlStep(stmt), E_OK);
    EXPECT_EQ(RdUtils::RdSqlFinalize(stmt), E_OK);
    EXPECT_EQ(RdUtils::RdDbClose(db2, 0), E_OK);
    EXPECT_EQ(RdUtils::RdDbClose(db4, 0), E_OK);
}