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

#include "rdb_helper.h"

#include <gtest/gtest.h>

#include <string>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class OpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override
    {
        return E_OK;
    }
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

class RdbHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static const std::string rdbStorePath;
};
const std::string RdbHelperTest::rdbStorePath = RDB_TEST_PATH + std::string("rdbhelper.db");

void RdbHelperTest::SetUpTestCase(void)
{
}

void RdbHelperTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(rdbStorePath);
}

void RdbHelperTest::SetUp(void)
{
}

void RdbHelperTest::TearDown(void)
{
}

class RdbHelperTestWrongSqlOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string WRONG_SQL_TEST;
};

class RdbHelperTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

const std::string RdbHelperTestWrongSqlOpenCallback::WRONG_SQL_TEST = "CREATE TABL IF NOT EXISTS test "
                                                                      "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                      "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                                                      "blobType BLOB)";
const std::string RdbHelperTestOpenCallback::CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test "
                                                                 "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                 "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                                                 "blobType BLOB)";

int RdbHelperTestWrongSqlOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(WRONG_SQL_TEST);
}

int RdbHelperTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int RdbHelperTestWrongSqlOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

int RdbHelperTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

/**
 * @tc.name: DeleteDatabaseCache_001
 * @tc.desc: delete db cache
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbHelperTest, DeleteDatabaseCache_001, TestSize.Level1)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbHelperTest::rdbStorePath);
    RdbHelperTestWrongSqlOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(rdbStore, nullptr);
}

/**
 * @tc.name: DeleteDatabase_001
 * @tc.desc: delete db file
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_001, TestSize.Level1)
{
    int errCode = E_OK;
    RdbStoreConfig config1(RdbHelperTest::rdbStorePath);
    RdbStoreConfig config2("test");
    RdbStoreConfig config3("");
    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config1, 1, helper, errCode);
    EXPECT_NE(rdbStore, nullptr);
    int ret1 = RdbHelper::DeleteRdbStore(config1);
    EXPECT_EQ(ret1, E_OK);
    int ret2 = RdbHelper::DeleteRdbStore(config2);
    EXPECT_EQ(ret2, E_OK);
    int ret3 = RdbHelper::DeleteRdbStore(config3);
    EXPECT_EQ(ret3, E_INVALID_FILE_PATH);
}

/**
 * @tc.name: DeleteDatabase_002
 * @tc.desc: DeleteRdbStore if the dbFile is not exists
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_002, TestSize.Level1)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbHelperTest::rdbStorePath);
    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(rdbStore, nullptr);

    remove(rdbStorePath.c_str());

    int ret = RdbHelper::DeleteRdbStore("rdbhelper.db");
    EXPECT_EQ(ret, E_OK);
    std::string shmFileName = rdbStorePath + "-shm";
    std::string walFileName = rdbStorePath + "-wal";
    EXPECT_NE(access(shmFileName.c_str(), F_OK), 0);
    EXPECT_NE(access(walFileName.c_str(), F_OK), 0);
}

/**
 * @tc.name: DeleteDatabase_003
 * @tc.desc: DeleteRdbStore if the dbFile is not exists
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_003, TestSize.Level1)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbHelperTest::rdbStorePath);
    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(rdbStore, nullptr);

    remove(rdbStorePath.c_str());

    int ret = RdbHelper::DeleteRdbStore(config);
    EXPECT_EQ(ret, E_OK);
    std::string shmFileName = rdbStorePath + "-shm";
    std::string walFileName = rdbStorePath + "-wal";
    EXPECT_NE(access(shmFileName.c_str(), F_OK), 0);
    EXPECT_NE(access(walFileName.c_str(), F_OK), 0);
}

/**
 * @tc.name: getrdbstore_001
 * @tc.desc: get db file with a invalid path
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, GetDatabase_001, TestSize.Level0)
{
    int errCode = E_OK;
    RdbStoreConfig config("/invalid/invalid/test.db");
    OpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_INVALID_FILE_PATH);
}

HWTEST_F(RdbHelperTest, GetDatabase_002, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "GetDatabase.db";
    RdbStoreConfig config(dbPath);
    std::string bundleName = "com.ohos.config.GetDatabase";
    config.SetBundleName(bundleName);
    config.SetArea(1);
    config.SetEncryptStatus(true);

    RdbHelper::DeleteRdbStore(config);

    int errCode = E_OK;

    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(rdbStore1, nullptr);

    std::shared_ptr<RdbStore> rdbStore2 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(rdbStore2, nullptr);

    EXPECT_EQ(rdbStore1, rdbStore2);
}

HWTEST_F(RdbHelperTest, GetDatabase_003, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "GetDatabase.db";
    RdbStoreConfig config(dbPath);
    std::string bundleName = "com.ohos.config.GetDatabase";
    config.SetBundleName(bundleName);
    config.SetArea(1);
    config.SetEncryptStatus(true);

    RdbHelper::DeleteRdbStore(config);

    // Ensure that the database returns OK when it is successfully opened
    int errCode = E_ERROR;

    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore1, nullptr);

    config.SetEncryptStatus(false);
    std::shared_ptr<RdbStore> rdbStore2 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    // Ensure that the database can be opened after the encryption parameters are changed
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore2, nullptr);

    // Ensure that two databases will not be opened after the encrypt parameters are changed
    errCode = rdbStore1->BeginTransaction();
    EXPECT_EQ(errCode, E_OK);
    errCode = rdbStore2->BeginTransaction();
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(RdbHelperTest, GetDatabase_004, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "GetDatabase.db";
    RdbStoreConfig config(dbPath);
    std::string bundleName = "com.ohos.config.GetDatabase";
    config.SetBundleName(bundleName);
    config.SetArea(1);
    config.SetEncryptStatus(true);

    RdbHelper::DeleteRdbStore(config);

    int errCode = E_OK;

    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(rdbStore1, nullptr);

    config.SetVisitorDir(dbPath);
    config.SetRoleType(RoleType::VISITOR_WRITE);
    std::shared_ptr<RdbStore> rdbStore2 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(errCode, E_OK);
    EXPECT_EQ(rdbStore2, nullptr);
}