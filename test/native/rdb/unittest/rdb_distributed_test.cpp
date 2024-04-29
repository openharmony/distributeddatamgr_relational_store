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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <string>

#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

static std::shared_ptr<RdbStore> rdbStore;

class RdbStoreDistributedTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown() {}

    void InsertValue(std::shared_ptr<RdbStore> &store);
    void CheckResultSet(std::shared_ptr<RdbStore> &store);

    static constexpr int ddmsGroupId_ = 1000;
    static const std::string DRDB_NAME;
    static const  std::string DRDB_PATH;
};

const std::string RdbStoreDistributedTest::DRDB_NAME = "distributed_rdb.db";
const std::string RdbStoreDistributedTest::DRDB_PATH = "/data/test/";

class TestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore& store) override
    {
        std::string sql = "CREATE TABLE IF NOT EXISTS employee ("
                          "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                          "name TEXT NOT NULL,"
                          "age INTEGER,"
                          "salary REAL,"
                          "data BLOB)";
        store.ExecuteSql(sql);
        return 0;
    }

    int OnOpen(RdbStore& store) override
    {
        return 0;
    }

    int OnUpgrade(RdbStore& store, int currentVersion, int targetVersion) override
    {
        return 0;
    }
};

void RdbStoreDistributedTest::SetUpTestCase()
{
    int errCode = 0;
    std::string path = RdbStoreDistributedTest::DRDB_PATH + RdbStoreDistributedTest::DRDB_NAME;
    RdbHelper::DeleteRdbStore(path);
    int fd = open(path.c_str(), O_CREAT, S_IRWXU | S_IRWXG);
    if (fd < 0) {
        return;
    }
    if (fd > 0) {
        close(fd);
    }
    chown(path.c_str(), 0, ddmsGroupId_);

    RdbStoreConfig config(path);
    config.SetBundleName("com.example.distributed.rdb");
    config.SetName(RdbStoreDistributedTest::DRDB_NAME);
    TestOpenCallback callback;
    rdbStore = RdbHelper::GetRdbStore(config, 1, callback, errCode);
    EXPECT_NE(nullptr, rdbStore);
}

void RdbStoreDistributedTest::TearDownTestCase()
{
    RdbHelper::DeleteRdbStore(RdbStoreDistributedTest::DRDB_PATH + RdbStoreDistributedTest::DRDB_NAME);
}

void RdbStoreDistributedTest::SetUp()
{
    EXPECT_NE(nullptr, rdbStore);
    rdbStore->ExecuteSql("DELETE FROM test");
}

void RdbStoreDistributedTest::InsertValue(std::shared_ptr<RdbStore> &store)
{
    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18); // 18 age
    values.PutDouble("salary", 100.5); // 100.5
    values.PutBlob("data", std::vector<uint8_t>{ 1, 2, 3 });
    EXPECT_EQ(E_OK, store->Insert(id, "employee", values));
    EXPECT_EQ(1, id);
}

void RdbStoreDistributedTest::CheckResultSet(std::shared_ptr<RdbStore> &store)
{
    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM employee WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    EXPECT_NE(nullptr, resultSet);

    int columnIndex;
    int intVal;
    std::string strVal;
    ColumnType columnType;
    int position;
    int ret = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(-1, position);

    ret = resultSet->GetColumnType(0, columnType);
    EXPECT_EQ(E_ROW_OUT_RANGE, ret);

    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(E_OK, ret);

    ret = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(0, columnIndex);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(columnType, ColumnType::TYPE_INTEGER);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(1, intVal);

    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(E_OK, ret);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(ColumnType::TYPE_STRING, columnType);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ("zhangsan", strVal);
}

/**
 * @tc.name: RdbStore_Distributed_Test_001
 * @tc.desc: test RdbStore set distributed tables
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreDistributedTest, RdbStore_Distributed_001, TestSize.Level1)
{
    EXPECT_NE(nullptr, rdbStore);
    InsertValue(rdbStore);
    CheckResultSet(rdbStore);
}

/**
 * @tc.name: RdbStore_Distributed_Test_002
 * @tc.desc: Abnormal testCase of ObtainDistributedTableName, if networkId is ""
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreDistributedTest, RdbStore_Distributed_002, TestSize.Level2)
{
    EXPECT_NE(nullptr, rdbStore);
    int errCode;
    EXPECT_EQ("", rdbStore->ObtainDistributedTableName("", "employee", errCode));
    EXPECT_EQ(-1, errCode);
}

/**
 * @tc.name: RdbStore_Distributed_Test_003
 * @tc.desc: Abnormal testCase of ObtainDistributedTableName, if networkId is invalid
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreDistributedTest, RdbStore_Distributed_003, TestSize.Level2)
{
    EXPECT_NE(nullptr, rdbStore);
    int errCode;
    EXPECT_EQ("", rdbStore->ObtainDistributedTableName("123456", "employee", errCode));
    EXPECT_EQ(-1, errCode);
}

/**
 * @tc.name: RdbStore_Distributed_Test_004
 * @tc.desc: Abnormal testCase of SetDistributedTables
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreDistributedTest, RdbStore_Distributed_Test_004, TestSize.Level2)
{
    int errCode;
    std::vector<std::string> tables;
    OHOS::DistributedRdb::DistributedConfig distributedConfig;

    // if tabels empty, return ok
    errCode = rdbStore->SetDistributedTables(tables, 1, distributedConfig);
    EXPECT_EQ(E_OK, errCode);

    // if tabels not empty, IPC_SEND failed
    tables.push_back("employee");
    errCode = rdbStore->SetDistributedTables(tables, 1, distributedConfig);
    EXPECT_NE(E_OK, errCode);

    std::string path = RdbStoreDistributedTest::DRDB_PATH + "test.db";
    RdbStoreConfig config(path);
    TestOpenCallback callback;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, callback, errCode);
    EXPECT_NE(nullptr, store);

    // if tabels not empty, bundleName empty
    errCode = store->SetDistributedTables(tables, 1, distributedConfig);
    EXPECT_EQ(E_INVALID_ARGS, errCode);

    RdbHelper::DeleteRdbStore(path);
}

/**
 * @tc.name: RdbStore_Distributed_Test_005
 * @tc.desc: Normal testCase of Sync
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreDistributedTest, RdbStore_Distributed_Test_005, TestSize.Level2)
{
    int errCode;
    OHOS::DistributedRdb::SyncOption option = { OHOS::DistributedRdb::TIME_FIRST, false };
    AbsRdbPredicates predicate("employee");
    std::vector<std::string> tables;

    // get rdb service succeeded, if configuration file has already been configured
    errCode = rdbStore->Sync(option, predicate, OHOS::DistributedRdb::AsyncBrief());
    EXPECT_EQ(E_OK, errCode);

    errCode = rdbStore->Sync(option, tables, OHOS::DistributedRdb::AsyncDetail());
    EXPECT_EQ(E_OK, errCode);

    errCode = rdbStore->Sync(option, predicate, OHOS::DistributedRdb::AsyncDetail());
    EXPECT_EQ(E_OK, errCode);

    std::string path = RdbStoreDistributedTest::DRDB_PATH + "test.db";
    RdbStoreConfig config(path);
    TestOpenCallback callback;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, callback, errCode);
    EXPECT_NE(nullptr, store);

    // get rdb service failed, if not configured
    errCode = store->Sync(option, predicate, OHOS::DistributedRdb::AsyncBrief());
    EXPECT_EQ(E_INVALID_ARGS, errCode);
    errCode = store->Sync(option, tables, nullptr);
    EXPECT_EQ(E_INVALID_ARGS, errCode);

    RdbHelper::DeleteRdbStore(path);
}