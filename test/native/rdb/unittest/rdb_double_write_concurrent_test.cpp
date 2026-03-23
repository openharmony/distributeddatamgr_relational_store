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
#define LOG_TAG "RdbDoubleWriteConcurrentTest"
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <string>

#include "common.h"
#include "file_ex.h"
#include "logger.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "sqlite_utils.h"
#include "sys/types.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;

class RdbDoubleWriteConcurrentTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void CheckNumber(
        std::shared_ptr<RdbStore> &store, int num, int errCode = E_OK, const std::string &tableName = "test");
    void Insert(int64_t start, int count, bool isSlave = false, int dataSize = 0);
    void WaitForBackupFinish(int32_t expectStatus, int maxTimes = 400);
    void TryInterruptBackup();
    void InitDb();

protected:
    const std::string DATABASE_NAME = RDB_TEST_PATH + "dual_concurrent.db";
    const std::string SLAVE_DATABASE_NAME = RDB_TEST_PATH + "dual_concurrent_slave.db";
    std::shared_ptr<RdbStore> store = nullptr;
    std::shared_ptr<RdbStore> slaveStore = nullptr;

    class Callback : public RdbOpenCallback {
    public:
        int OnCreate(RdbStore &store) override;
        int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;

    protected:
        const std::string CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                              "name TEXT NOT NULL, age INTEGER, salary "
                                              "REAL, blobType BLOB)";
    };

    enum SlaveStatus : uint32_t {
        UNDEFINED,
        BACKING_UP,
        BACKUP_INTERRUPT,
        BACKUP_FINISHED,
        DB_CLOSING,
    };
};

int RdbDoubleWriteConcurrentTest::Callback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int RdbDoubleWriteConcurrentTest::Callback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbDoubleWriteConcurrentTest::SetUpTestCase(void)
{
}

void RdbDoubleWriteConcurrentTest::TearDownTestCase(void)
{
}

void RdbDoubleWriteConcurrentTest::SetUp(void)
{
}

void RdbDoubleWriteConcurrentTest::TearDown(void)
{
    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteConcurrentTest::DATABASE_NAME);
}

void RdbDoubleWriteConcurrentTest::InitDb()
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteConcurrentTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    RdbDoubleWriteConcurrentTest::Callback helper;
    RdbDoubleWriteConcurrentTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbDoubleWriteConcurrentTest::store, nullptr);

    RdbStoreConfig slaveConfig(RdbDoubleWriteConcurrentTest::SLAVE_DATABASE_NAME);
    RdbDoubleWriteConcurrentTest::Callback slaveHelper;
    RdbDoubleWriteConcurrentTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(RdbDoubleWriteConcurrentTest::slaveStore, nullptr);
    store->ExecuteSql("DELETE FROM test");
    slaveStore->ExecuteSql("DELETE FROM test");
}

void RdbDoubleWriteConcurrentTest::Insert(int64_t start, int count, bool isSlave, int dataSize)
{
    ValuesBucket values;
    int64_t id = start;
    int ret = E_OK;
    for (int i = 0; i < count; i++) {
        values.Clear();
        values.PutInt("id", id);
        if (dataSize > 0) {
            values.PutString("name", std::string(dataSize, 'a'));
        } else {
            values.PutString("name", std::string("zhangsan"));
        }
        values.PutInt("age", 18);          // 18 is data
        values.PutDouble("salary", 100.5); // 100.5 is data
        values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
        if (isSlave) {
            ret = slaveStore->Insert(id, "test", values);
        } else {
            ret = store->Insert(id, "test", values);
        }
        EXPECT_EQ(ret, E_OK);
        id++;
    }
}

void RdbDoubleWriteConcurrentTest::WaitForBackupFinish(int32_t expectStatus, int maxTimes)
{
    int32_t curStatus = store->GetBackupStatus();
    int tryTimes = 0;
    while (curStatus != expectStatus && (++tryTimes <= maxTimes)) {
        usleep(50000); // 50000 delay
        curStatus = store->GetBackupStatus();
    }
    LOG_INFO("----------cur backup Status:%{public}d---------", curStatus);
    ASSERT_EQ(curStatus, expectStatus);
}

void RdbDoubleWriteConcurrentTest::TryInterruptBackup()
{
    int err = store->InterruptBackup();
    int tryTimes = 0;
    while (err != E_OK && (++tryTimes <= 1000)) { // 1000 is try time
        usleep(10000);                            // 10000 delay
        err = store->InterruptBackup();
    }
    EXPECT_EQ(err, E_OK);
    LOG_INFO("----------interrupt backup---------");
}

void RdbDoubleWriteConcurrentTest::CheckNumber(
    std::shared_ptr<RdbStore> &store, int num, int errCode, const std::string &tableName)
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM " + tableName);
    ASSERT_NE(resultSet, nullptr);
    int countNum;
    int ret = resultSet->GetRowCount(countNum);
    EXPECT_EQ(ret, errCode);
    EXPECT_EQ(num, countNum);
}

/**
* @tc.name: RdbStore_DoubleWrite_022
* @tc.desc: open SINGLE db, write, close, reopen MAIN_REPLICA db, wait for backup, insert, check count
* @tc.type: FUNC
*/
HWTEST_F(RdbDoubleWriteConcurrentTest, RdbStore_DoubleWrite_022, TestSize.Level1)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteConcurrentTest::DATABASE_NAME);
    config.SetHaMode(HAMode::SINGLE);
    RdbDoubleWriteConcurrentTest::Callback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    int64_t id = 10;
    int strSize = 1024 * 100;
    int count = 1000;
    Insert(id, count, false, strSize);
    LOG_INFO("RdbStore_DoubleWrite_022 insert finish");

    store = nullptr;
    config.SetHaMode(HAMode::MAIN_REPLICA);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_022 reopen db finish");

    WaitForBackupFinish(BACKUP_FINISHED);

    id = 6666;
    Insert(id, count);
    LOG_INFO("RdbStore_DoubleWrite_022 insert db finish");

    RdbStoreConfig slaveConfig(RdbDoubleWriteConcurrentTest::SLAVE_DATABASE_NAME);
    RdbDoubleWriteConcurrentTest::Callback slaveHelper;
    RdbDoubleWriteConcurrentTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(RdbDoubleWriteConcurrentTest::slaveStore, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_022 reopen slave db finish");

    RdbDoubleWriteConcurrentTest::CheckNumber(store, count + count);
    RdbDoubleWriteConcurrentTest::CheckNumber(slaveStore, count + count);
}

/**
* @tc.name: RdbStore_DoubleWrite_023
* @tc.desc: open MANUAL_TRIGGER db, write, backup async, interrupt, backup async, wait finish, check count
* @tc.type: FUNC
*/
HWTEST_F(RdbDoubleWriteConcurrentTest, RdbStore_DoubleWrite_023, TestSize.Level1)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteConcurrentTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    RdbDoubleWriteConcurrentTest::Callback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    ASSERT_TRUE(store->IsSlaveDiffFromMaster());
    LOG_INFO("RdbStore_DoubleWrite_023 reopen finish");

    int64_t id = 10;
    int strSize = 1024 * 100;
    int count = 1000;
    Insert(id, count, false, strSize);
    LOG_INFO("RdbStore_DoubleWrite_023 insert finish");

    std::thread thread([this]() {
        LOG_INFO("RdbStore_DoubleWrite_023 t1 backup begin");
        EXPECT_EQ(store->Backup(std::string(""), {}), E_CANCEL);
        LOG_INFO("RdbStore_DoubleWrite_023 t1 backup end");
    });
    LOG_INFO("RdbStore_DoubleWrite_023 begin interrupt");
    TryInterruptBackup();
    LOG_INFO("RdbStore_DoubleWrite_023 interrupt end");
    EXPECT_EQ(store->GetBackupStatus(), SlaveStatus::BACKUP_INTERRUPT);
    thread.join();

    std::thread thread1([this]() {
        LOG_INFO("RdbStore_DoubleWrite_023 t2 backup begin");
        EXPECT_EQ(store->Backup(std::string(""), {}), E_OK);
        LOG_INFO("RdbStore_DoubleWrite_023 t2 backup end");
    });
    WaitForBackupFinish(BACKUP_FINISHED);
    LOG_INFO("RdbStore_DoubleWrite_023 wait finish");
    thread1.join();

    RdbStoreConfig slaveConfig(RdbDoubleWriteConcurrentTest::SLAVE_DATABASE_NAME);
    RdbDoubleWriteConcurrentTest::Callback slaveHelper;
    RdbDoubleWriteConcurrentTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(RdbDoubleWriteConcurrentTest::slaveStore, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_023 reopen slave db finish");

    RdbDoubleWriteConcurrentTest::CheckNumber(store, count);
    RdbDoubleWriteConcurrentTest::CheckNumber(slaveStore, count);
}

/**
* @tc.name: RdbStore_DoubleWrite_024
* @tc.desc: open SINGLE db, write, close, reopen MAIN_REPLICA db, wait for backup, insert, check count
* @tc.type: FUNC
*/
HWTEST_F(RdbDoubleWriteConcurrentTest, RdbStore_DoubleWrite_024, TestSize.Level1)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteConcurrentTest::DATABASE_NAME);
    config.SetHaMode(HAMode::SINGLE);
    RdbDoubleWriteConcurrentTest::Callback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    int64_t id = 10;
    int strSize = 1024 * 100;
    int count = 1000;
    Insert(id, count, false, strSize);
    LOG_INFO("RdbStore_DoubleWrite_024 insert finish");

    store = nullptr;
    LOG_INFO("RdbStore_DoubleWrite_024 close finish");
    config.SetHaMode(HAMode::MAIN_REPLICA);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_024 reopen db finish");

    usleep(200000); // 200000 us delay
    store = nullptr;
    LOG_INFO("RdbStore_DoubleWrite_024 close again");

    RdbStoreConfig slaveConfig(RdbDoubleWriteConcurrentTest::SLAVE_DATABASE_NAME);
    RdbDoubleWriteConcurrentTest::Callback slaveHelper;
    RdbDoubleWriteConcurrentTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(RdbDoubleWriteConcurrentTest::slaveStore, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_024 reopen slave");
    RdbDoubleWriteConcurrentTest::CheckNumber(slaveStore, count);
}

/**
* @tc.name: RdbStore_DoubleWrite_025
* @tc.desc: open SINGLE db, write, close, reopen MAIN_REPLICA db, insert, wait for backup, check count
* @tc.type: FUNC
*/
HWTEST_F(RdbDoubleWriteConcurrentTest, RdbStore_DoubleWrite_025, TestSize.Level1)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteConcurrentTest::DATABASE_NAME);
    config.SetHaMode(HAMode::SINGLE);
    RdbDoubleWriteConcurrentTest::Callback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    int64_t id = 10;
    int strSize = 1024 * 100;
    int count = 1000;
    Insert(id, count, false, strSize);
    LOG_INFO("RdbStore_DoubleWrite_025 insert finish");

    store = nullptr;
    LOG_INFO("RdbStore_DoubleWrite_025 close finish");
    config.SetHaMode(HAMode::MAIN_REPLICA);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_025 reopen db finish");

    id = 6666;
    LOG_INFO("RdbStore_DoubleWrite_025 begin insert");
    Insert(id, count, false, strSize);
    LOG_INFO("RdbStore_DoubleWrite_025 insert end");

    WaitForBackupFinish(BACKUP_FINISHED, 1000); // 1000 is max retry time
    LOG_INFO("RdbStore_DoubleWrite_025 wait finish");

    RdbStoreConfig slaveConfig(RdbDoubleWriteConcurrentTest::SLAVE_DATABASE_NAME);
    RdbDoubleWriteConcurrentTest::Callback slaveHelper;
    RdbDoubleWriteConcurrentTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(RdbDoubleWriteConcurrentTest::slaveStore, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_025 reopen slave");

    RdbDoubleWriteConcurrentTest::CheckNumber(store, count + count);
    std::shared_ptr<ResultSet> resultSet = slaveStore->QuerySql("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int countNum;
    EXPECT_EQ(resultSet->GetRowCount(countNum), errCode);
    EXPECT_GT(countNum, count);
    EXPECT_LE(countNum, count + count);
}