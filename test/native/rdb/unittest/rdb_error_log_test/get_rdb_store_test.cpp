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
#include <unistd.h>

#include <memory>
#include <string>
#include <thread>

#include "common.h"
#include "block_data.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_sql_log.h"
#include "rdb_store.h"
#include "rdb_store_manager.h"
#include "rdb_types.h"
#include "executor_pool.h"
#include "shared_block.h"
#include "sqlite_utils.h"
#include "values_bucket.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb;

static constexpr int32_t MAX_THREAD = 8;
static constexpr int32_t MID_THREAD = 4;
static constexpr int32_t SLEEP_TIME = 500;
static constexpr int32_t MAX_SLEEP_TIME = 2000;
static constexpr int32_t JOURNAL_MAX_SIZE = 4096;
static constexpr int32_t JOURNAL_MIN_SIZE = 1024;
static constexpr double DEFAULT_SALARY = 100.5;
static constexpr int32_t AGE_NUM = 18;

class RdbStoreStoreMultiTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static std::shared_ptr<RdbStore> CreateRDB(const std::string &path,
        bool encrypt = false, const std::string &bundleName = "");
    static std::shared_ptr<RdbStore> CreateRDBSleep(const std::string &path,
        bool encrypt = false, const std::string &bundleName = "");
    static void InsertData(std::shared_ptr<RdbStore> rdbStore);
    static void QueryData(std::shared_ptr<RdbStore> rdbStore);
};


void RdbStoreStoreMultiTest::SetUpTestCase(void)
{
}

void RdbStoreStoreMultiTest::TearDownTestCase(void)
{
}

void RdbStoreStoreMultiTest::SetUp()
{
}

void RdbStoreStoreMultiTest::TearDown()
{
}

class RDBCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int RDBCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int RDBCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

class CallbackSleep : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int CallbackSleep::OnCreate(RdbStore &store)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    return E_OK;
}

int CallbackSleep::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    return E_OK;
}

std::shared_ptr<RdbStore> RdbStoreStoreMultiTest::CreateRDB(const std::string &path,
    bool encrypt, const std::string &bundleName)
{
    int version = 1;
    RdbStoreConfig config(path);
    config.SetEncryptStatus(encrypt);
    config.SetBundleName(bundleName);
    RDBCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, version, helper, errCode);
    EXPECT_NE(store, nullptr);
    return store;
}

std::shared_ptr<RdbStore> RdbStoreStoreMultiTest::CreateRDBSleep(const std::string &path,
    bool encrypt, const std::string &bundleName)
{
    int version = 1;
    RdbStoreConfig config(path);
    config.SetEncryptStatus(encrypt);
    config.SetBundleName(bundleName);
    CallbackSleep helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, version, helper, errCode);
    EXPECT_NE(store, nullptr);
    return store;
}

void RdbStoreStoreMultiTest::InsertData(std::shared_ptr<RdbStore> rdbStore)
{
    const std::string createTable =
    std::string("CREATE TABLE IF NOT EXISTS test ") + std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                  "name TEXT NOT NULL, age INTEGER, salary "
                                                                  "REAL, blobType BLOB)");
    rdbStore->Execute(createTable);
    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", AGE_NUM);
    values.PutDouble("salary", DEFAULT_SALARY);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = rdbStore->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);
}

void RdbStoreStoreMultiTest::QueryData(std::shared_ptr<RdbStore> rdbStore)
{
    std::shared_ptr<ResultSet> resultSet = rdbStore->QuerySql("select * from test");
    int ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    int columnIndex;
    std::string strVal;

    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("zhangsan", strVal);
}

std::string g_dbPaths[MAX_THREAD] = { "/data/test/store1.db", "/data/test/store2.db",
    "/data/test/store3.db", "/data/test/store4.db", "/data/test/store5.db",
    "/data/test/store6.db", "/data/test/store7.db", "/data/test/store8.db" };

std::string g_dbBundlenames[MAX_THREAD] = { "com.ohos.test1", "com.ohos.test2",
    "com.ohos.test3", "com.ohos.test4", "com.ohos.test5",
    "com.ohos.test6", "com.ohos.test7", "com.ohos.test8" };

/**
 * @tc.name: GetRdbStoreTest_001
 * @tc.desc: test Multithreading calls GetRdbStore with same store
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreStoreMultiTest, GetRdbStoreTest_001, TestSize.Level1)
{
    std::string path = "/data/test/store.db";
    std::shared_ptr<RdbStore> stores[MAX_THREAD];
    std::thread threads[MAX_THREAD];
    for (int i = 0; i < MAX_THREAD; ++i) {
        threads[i] = std::thread([i, &stores, &path]() {
            stores[i] = RdbStoreStoreMultiTest::CreateRDB(path);
        });
    }
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    EXPECT_EQ(stores[0], stores[1]);
    EXPECT_EQ(stores[1], stores[2]);
    EXPECT_EQ(stores[2], stores[3]);
    EXPECT_EQ(stores[3], stores[4]);
    EXPECT_EQ(stores[4], stores[5]);
    EXPECT_EQ(stores[5], stores[6]);
    EXPECT_EQ(stores[6], stores[7]);
    RdbHelper::DeleteRdbStore(path);
}

/**
 * @tc.name: GetRdbStoreTest_002
 * @tc.desc: test Multithreading calls GetRdbStore with same encrypt store
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreStoreMultiTest, GetRdbStoreTest_002, TestSize.Level1)
{
    std::string path = "/data/test/encryptStore.db";
    std::string bundleName = "com.ohos.test";
    std::shared_ptr<RdbStore> stores[MAX_THREAD];
    std::thread threads[MAX_THREAD];
    for (int i = 0; i < MAX_THREAD; ++i) {
        threads[i] = std::thread([i, &stores, &path, &bundleName]() {
            stores[i] = RdbStoreStoreMultiTest::CreateRDB(path, true, bundleName);
        });
    }
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    EXPECT_EQ(stores[0], stores[1]);
    EXPECT_EQ(stores[1], stores[2]);
    EXPECT_EQ(stores[2], stores[3]);
    EXPECT_EQ(stores[3], stores[4]);
    EXPECT_EQ(stores[4], stores[5]);
    EXPECT_EQ(stores[5], stores[6]);
    EXPECT_EQ(stores[6], stores[7]);
    RdbHelper::DeleteRdbStore(path);
}

/**
 * @tc.name: GetRdbStoreTest_003
 * @tc.desc: test Multithreading calls GetRdbStore with diff store
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreStoreMultiTest, GetRdbStoreTest_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> stores[MAX_THREAD];
    std::thread threads[MAX_THREAD];
    for (int i = 0; i < MID_THREAD; ++i) {
        threads[i] = std::thread([i, &stores]() {
            stores[i] = RdbStoreStoreMultiTest::CreateRDB(g_dbPaths[i]);
        });
    }
    for (int i = MID_THREAD; i < MAX_THREAD; ++i) {
        threads[i] = std::thread([i, &stores]() {
            stores[i] = RdbStoreStoreMultiTest::CreateRDBSleep(g_dbPaths[i]);
        });
    }
    for (int i = 0; i < MAX_THREAD; ++i) {
        if (threads[i].joinable()) {
            threads[i].join();
        }
        EXPECT_NE(stores[i], nullptr);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(MAX_SLEEP_TIME));
    for (int i = 0; i < MAX_THREAD; ++i) {
        RdbHelper::DeleteRdbStore(g_dbPaths[i]);
    }
}

/**
 * @tc.name: GetRdbStoreTest_004
 * @tc.desc: test Multithreading calls GetRdbStore with diff encrypt store
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreStoreMultiTest, GetRdbStoreTest_004, TestSize.Level1)
{
    std::string bundleName = "com.ohos.test";
    std::shared_ptr<RdbStore> stores[MAX_THREAD];
    std::thread threads[MAX_THREAD];
    for (int i = 0; i < MID_THREAD; ++i) {
        threads[i] = std::thread([i, &stores, &bundleName]() {
            stores[i] = RdbStoreStoreMultiTest::CreateRDB(g_dbPaths[i], true, bundleName);
        });
    }
    for (int i = MID_THREAD; i < MAX_THREAD; ++i) {
        threads[i] = std::thread([i, &stores, &bundleName]() {
            stores[i] = RdbStoreStoreMultiTest::CreateRDBSleep(g_dbPaths[i], true, bundleName);
        });
    }
    for (int i = 0; i < MAX_THREAD; ++i) {
        if (threads[i].joinable()) {
            threads[i].join();
        }
        EXPECT_NE(stores[i], nullptr);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(MAX_SLEEP_TIME));
    for (int i = 0; i < MAX_THREAD; ++i) {
        RdbHelper::DeleteRdbStore(g_dbPaths[i]);
    }
}

/**
 * @tc.name: GetRdbStoreTest_005
 * @tc.desc: test Multithreading calls GetRdbStore with diff encrypt store and store
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreStoreMultiTest, GetRdbStoreTest_005, TestSize.Level1)
{
    std::string bundleName = "com.ohos.test";
    std::shared_ptr<RdbStore> stores[MAX_THREAD];
    std::thread threads[MAX_THREAD];
    for (int i = 0; i < MID_THREAD; ++i) {
        threads[i] = std::thread([i, &stores, &bundleName]() {
            stores[i] = RdbStoreStoreMultiTest::CreateRDB(g_dbPaths[i]);
        });
    }
    for (int i = MID_THREAD; i < MAX_THREAD; ++i) {
        threads[i] = std::thread([i, &stores, &bundleName]() {
            stores[i] = RdbStoreStoreMultiTest::CreateRDBSleep(g_dbPaths[i], true, bundleName);
        });
    }
    for (int i = 0; i < MAX_THREAD; ++i) {
        if (threads[i].joinable()) {
            threads[i].join();
        }
        EXPECT_NE(stores[i], nullptr);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(MAX_SLEEP_TIME));
    for (int i = 0; i < MAX_THREAD; ++i) {
        RdbHelper::DeleteRdbStore(g_dbPaths[i]);
    }
}

/**
 * @tc.name: GetRdbStoreTest_006
 * @tc.desc: test Multithreading calls GetRdbStore with diff encrypt store with diff bundlename
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreStoreMultiTest, GetRdbStoreTest_006, TestSize.Level1)
{
    std::shared_ptr<RdbStore> stores[MAX_THREAD];
    std::thread threads[MAX_THREAD];
    for (int i = 0; i < MAX_THREAD; ++i) {
        threads[i] = std::thread([i, &stores]() {
            stores[i] = RdbStoreStoreMultiTest::CreateRDB(g_dbPaths[i], true, g_dbBundlenames[i]);
        });
    }
    for (int i = 0; i < MAX_THREAD; ++i) {
        if (threads[i].joinable()) {
            threads[i].join();
        }
        EXPECT_NE(stores[i], nullptr);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(MAX_SLEEP_TIME));
    for (int i = 0; i < MAX_THREAD; ++i) {
        RdbHelper::DeleteRdbStore(g_dbPaths[i]);
    }
}

/**
 * @tc.name: GetRdbStoreTest_007
 * @tc.desc: test Multithreading calls GetRdbStore with diff config
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreStoreMultiTest, GetRdbStoreTest_007, TestSize.Level1)
{
    std::string path = "/data/test/encrypt07store.db";
    int version = 1;
    RdbStoreConfig configA(path);
    configA.SetEncryptStatus(true);
    configA.SetBundleName("com.ohos.test");
    RDBCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> storeA = RdbHelper::GetRdbStore(configA, version, helper, errCode);
    EXPECT_NE(storeA, nullptr);
    RdbStoreStoreMultiTest::InsertData(storeA);
    storeA = nullptr;

    RdbStoreConfig configB(path);
    configB.SetEncryptStatus(false);
    configB.SetBundleName("com.ohos.test");
    std::shared_ptr<RdbStore> storeB = RdbHelper::GetRdbStore(configB, version, helper, errCode);
    EXPECT_NE(storeB, nullptr);
    RdbStoreStoreMultiTest::QueryData(storeB);
    
    RdbHelper::DeleteRdbStore(path);
}

/**
 * @tc.name: GetRdbStoreTest_008
 * @tc.desc: test Multithreading calls GetRdbStore with diff config
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreStoreMultiTest, GetRdbStoreTest_008, TestSize.Level1)
{
    std::string path = "/data/test/store.db";
    int version = 1;
    RdbStoreConfig configA(path);
    configA.SetJournalSize(JOURNAL_MAX_SIZE);
    configA.SetBundleName("com.ohos.test");
    RDBCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> storeA = RdbHelper::GetRdbStore(configA, version, helper, errCode);
    EXPECT_NE(storeA, nullptr);

    RdbStoreConfig configB(path);
    configB.SetBundleName("com.ohos.test");
    configB.SetJournalSize(JOURNAL_MIN_SIZE);
    std::shared_ptr<RdbStore> storeB = RdbHelper::GetRdbStore(configB, version, helper, errCode);
    EXPECT_NE(storeB, nullptr);
    EXPECT_NE(storeA, storeB);

    std::shared_ptr<RdbStore> storeC = RdbHelper::GetRdbStore(configB, version, helper, errCode);
    EXPECT_EQ(storeB, storeC);
    RdbHelper::DeleteRdbStore(path);
}

/**
 * @tc.name: GetRdbStoreTest_009
 * @tc.desc: test Multithreading calls GetRdbStore with diff config and allowRebuild
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreStoreMultiTest, GetRdbStoreTest_009, TestSize.Level1)
{
    std::string path = "/data/test/encrypt09store.db";
    int version = 1;
    RdbStoreConfig configA(path);
    configA.SetEncryptStatus(false);
    configA.SetAllowRebuild(true);
    configA.SetBundleName("com.ohos.test");
    RDBCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> storeA = RdbHelper::GetRdbStore(configA, version, helper, errCode);
    ASSERT_NE(storeA, nullptr);
    RdbStoreStoreMultiTest::InsertData(storeA);
    storeA = nullptr;

    RdbStoreConfig configB(path);
    configB.SetEncryptStatus(true);
    configB.SetAllowRebuild(true);
    configB.SetBundleName("com.ohos.test");
    std::shared_ptr<RdbStore> storeB = RdbHelper::GetRdbStore(configB, version, helper, errCode);
    ASSERT_NE(storeB, nullptr);
    auto rebuilt = RebuiltType::NONE;
    storeB->GetRebuilt(rebuilt);
    EXPECT_EQ(rebuilt, RebuiltType::NONE);
    RdbStoreStoreMultiTest::QueryData(storeB);
    
    RdbHelper::DeleteRdbStore(path);
}

/**
 * @tc.name: GetRdbStoreTest_010
 * @tc.desc: 1. Create encrypted and non-encrypted databases
 *           2. Insert a piece of data into a non-encrypted database
 *           3. Delete encrypted database
 *           4. Rename the non-encrypted database as an encrypted database
 *           5. Open with non-encrypted parameters to query data
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreStoreMultiTest, GetRdbStoreTest_010, TestSize.Level1)
{
    std::string path1 = "/data/test/encrypt10store.db";
    std::string path1Wal = "/data/test/encrypt10store.db-wal";
    std::string path1Shm = "/data/test/encrypt10store.db-shm";
    std::string path2 = "/data/test/10store.db";
    std::string path2Wal = "/data/test/10store.db-wal";
    std::string path2Shm = "/data/test/10store.db-shm";
    int version = 1;
    RdbStoreConfig configA(path1);
    configA.SetEncryptStatus(true);
    configA.SetAllowRebuild(true);
    configA.SetBundleName("com.ohos.test");
    RDBCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> storeA = RdbHelper::GetRdbStore(configA, version, helper, errCode);
    ASSERT_NE(storeA, nullptr);
    storeA = nullptr;

    RdbStoreConfig configB(path2);
    configB.SetEncryptStatus(false);
    configB.SetAllowRebuild(true);
    configB.SetBundleName("com.ohos.test");
    std::shared_ptr<RdbStore> storeB = RdbHelper::GetRdbStore(configB, version, helper, errCode);
    ASSERT_NE(storeB, nullptr);
    RdbStoreStoreMultiTest::InsertData(storeB);
    storeB = nullptr;
    // Delete the encrypted database path1, rename the database path2 to path1.
    SqliteUtils::DeleteFile(path1);
    SqliteUtils::DeleteFile(path1Wal);
    SqliteUtils::DeleteFile(path1Shm);
    SqliteUtils::RenameFile(path2, path1);
    SqliteUtils::RenameFile(path2Wal, path1Wal);
    SqliteUtils::RenameFile(path2Shm, path1Shm);
    // The current database of path1 is actually a non-encrypted database,
    // and the data content is the original data content of path2.
    configA.SetEncryptStatus(false);
    storeA = RdbHelper::GetRdbStore(configA, version, helper, errCode);
    ASSERT_NE(storeA, nullptr);
    RdbStoreStoreMultiTest::QueryData(storeA);
    storeA = nullptr;

    RdbHelper::DeleteRdbStore(path1);
}


/**
 * @tc.name: GetRdbStoreTest_011
 * @tc.desc: 1. Create encrypted and non-encrypted databases
 *           2. Insert a piece of data into a non-encrypted database
 *           3. Delete encrypted database
 *           4. Rename the non-encrypted database as an encrypted database
 *           5. Open with encrypted parameters to query data
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreStoreMultiTest, GetRdbStoreTest_011, TestSize.Level1)
{
    std::string path1 = "/data/test/encrypt11store.db";
    std::string path1Wal = "/data/test/encrypt11store.db-wal";
    std::string path1Shm = "/data/test/encrypt11store.db-shm";
    std::string path2 = "/data/test/11store.db";
    std::string path2Wal = "/data/test/11store.db-wal";
    std::string path2Shm = "/data/test/11store.db-shm";
    int version = 1;
    RdbStoreConfig configA(path1);
    configA.SetEncryptStatus(true);
    configA.SetAllowRebuild(true);
    configA.SetBundleName("com.ohos.test");
    RDBCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> storeA = RdbHelper::GetRdbStore(configA, version, helper, errCode);
    ASSERT_NE(storeA, nullptr);
    storeA = nullptr;

    RdbStoreConfig configB(path2);
    configB.SetEncryptStatus(false);
    configB.SetAllowRebuild(true);
    configB.SetBundleName("com.ohos.test");
    std::shared_ptr<RdbStore> storeB = RdbHelper::GetRdbStore(configB, version, helper, errCode);
    ASSERT_NE(storeB, nullptr);
    RdbStoreStoreMultiTest::InsertData(storeB);
    storeB = nullptr;
    // Delete the encrypted database path1, rename the database path2 to path1, and open path1.
    SqliteUtils::DeleteFile(path1);
    SqliteUtils::DeleteFile(path1Wal);
    SqliteUtils::DeleteFile(path1Shm);
    SqliteUtils::RenameFile(path2, path1);
    SqliteUtils::RenameFile(path2Wal, path1Wal);
    SqliteUtils::RenameFile(path2Shm, path1Shm);
    // The current database of path1 is actually a non-encrypted database, and it cannot be opened
    // using encryption parameters. The reconstruction was successful, but there is no data in the table.
    storeA = RdbHelper::GetRdbStore(configA, version, helper, errCode);
    ASSERT_NE(storeA, nullptr);
    std::shared_ptr<ResultSet> resultSet = storeA->QuerySql("select * from test");
    int ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_SQLITE_ERROR);
    storeA = nullptr;

    RdbHelper::DeleteRdbStore(path1);
}