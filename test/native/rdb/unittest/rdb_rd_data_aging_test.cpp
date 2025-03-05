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

#include <random>
#include <string>
#include <sys/time.h>

#include "common.h"
#include "grd_api_manager.h"
#include "rdb_errno.h"
#include "rdb_helper.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbRdDataAgingTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void InsertData(uint64_t second, int startId, int endId);

    static const std::string databaseName;
    static std::shared_ptr<RdbStore> store;
};

class ExecuteTestOpenRdCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

const std::string RdbRdDataAgingTest::databaseName = RDB_TEST_PATH + "data_aging_test.db";
std::shared_ptr<RdbStore> RdbRdDataAgingTest::store = nullptr;

void RdbRdDataAgingTest::SetUpTestCase(void)
{
}

void RdbRdDataAgingTest::TearDownTestCase(void)
{
}

void RdbRdDataAgingTest::SetUp(void)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(RdbRdDataAgingTest::databaseName);
    RdbStoreConfig config(RdbRdDataAgingTest::databaseName);
    config.SetIsVector(true);
    ExecuteTestOpenRdCallback helper;
    RdbRdDataAgingTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(RdbRdDataAgingTest::store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    string sql1 = "create table test (id integer, start_time integer not null) with "
                  "(time_col='start_time', ttl='1 hour', data_limit='100 KB', interval='5 second', max_num='100');";
    store->Execute(sql1);
}

void RdbRdDataAgingTest::TearDown(void)
{
    RdbRdDataAgingTest::store = nullptr;
    RdbHelper::DeleteRdbStore(RdbRdDataAgingTest::databaseName);
}

void RdbRdDataAgingTest::InsertData(uint64_t second, int startId, int endId)
{
    for (int i = startId; i <= endId; i++) {
        struct timeval timestamp;
        (void)gettimeofday(&timestamp, nullptr);
        uint64_t startTime = timestamp.tv_sec - second;
        string sql = "insert into test values(" + std::to_string(i) + ", " + std::to_string(startTime) + ");";
        auto ret = store->Execute(sql);
        ASSERT_EQ(ret.first, E_OK);
    }
}

/**
@tc.name: RdbStore_Data_Aging_001
@tc.desc: test RdbStore_Data_Aging
@tc.type: FUNC
*/
HWTEST_F(RdbRdDataAgingTest, RdbStore_Data_Aging_001, TestSize.Level1)
{
    InsertData(3595, 1, 100);
    sleep(2);
    InsertData(0, 101, 101);
    sleep(2);
    auto resultSet = store->QueryByStep("select * from test;");
    int count = 0;
    resultSet->GetRowCount(count);
    resultSet->Close();
    ASSERT_EQ(count, 101);
}

/**
@tc.name: RdbStore_Data_Aging_002
@tc.desc: test RdbStore_Data_Aging
@tc.type: FUNC
*/
HWTEST_F(RdbRdDataAgingTest, RdbStore_Data_Aging_002, TestSize.Level1)
{
    InsertData(3600, 1, 99);
    sleep(5);
    InsertData(0, 100, 100);
    sleep(2);
    auto resultSet = store->QueryByStep("select * from test;");
    int count = 0;
    resultSet->GetRowCount(count);
    resultSet->Close();
    ASSERT_EQ(count, 1);
}

/**
@tc.name: RdbStore_Data_Aging_003
@tc.desc: test RdbStore_Data_Aging
@tc.type: FUNC
*/
HWTEST_F(RdbRdDataAgingTest, RdbStore_Data_Aging_003, TestSize.Level1)
{
    InsertData(3595, 1, 50);
    InsertData(0, 51, 100);
    sleep(5);
    auto resultSet = store->QueryByStep("select * from test;");
    int count = 0;
    resultSet->GetRowCount(count);
    resultSet->Close();
    ASSERT_EQ(count, 100);
}

/**
@tc.name: RdbStore_Data_Aging_004
@tc.desc: test RdbStore_Data_Aging
@tc.type: FUNC
*/
HWTEST_F(RdbRdDataAgingTest, RdbStore_Data_Aging_004, TestSize.Level1)
{
    InsertData(3595, 1, 100);
    InsertData(0, 101, 149);
    sleep(5);
    auto resultSet = store->QueryByStep("select * from test;");
    int count = 0;
    resultSet->GetRowCount(count);
    resultSet->Close();
    ASSERT_EQ(count, 149);

    InsertData(0, 150, 150);
    sleep(2);

    resultSet = store->QueryByStep("select * from test;");
    resultSet->GetRowCount(count);
    resultSet->Close();
    ASSERT_EQ(count, 50);
}

/**
@tc.name: RdbStore_Data_Aging_005
@tc.desc: test RdbStore_Data_Aging
@tc.type: FUNC
*/
HWTEST_F(RdbRdDataAgingTest, RdbStore_Data_Aging_005, TestSize.Level1)
{
    InsertData(3595, 1, 100);
    InsertData(3592, 101, 130);
    InsertData(3590, 131, 200);

    auto resultSet = store->QueryByStep("select * from test;");
    int count = 0;
    resultSet->GetRowCount(count);
    resultSet->Close();
    ASSERT_EQ(count, 200);
    sleep(5);
    InsertData(0, 201, 201);

    sleep(2);
    resultSet = store->QueryByStep("select * from test;");
    resultSet->GetRowCount(count);
    resultSet->Close();
    ASSERT_EQ(count, 71);

    sleep(5);
    InsertData(0, 202, 202);

    sleep(2);
    resultSet = store->QueryByStep("select * from test;");
    resultSet->GetRowCount(count);
    resultSet->Close();
    ASSERT_EQ(count, 2);
}

/**
@tc.name: RdbStore_Data_Aging_006
@tc.desc: test RdbStore_Data_Aging
@tc.type: FUNC
*/
HWTEST_F(RdbRdDataAgingTest, RdbStore_Data_Aging_006, TestSize.Level1)
{
    InsertData(3600, 1, 99);
    InsertData(0, 100, 100);
    auto ret = store->Execute("drop table test;");
    ASSERT_EQ(ret.first, E_OK);
}
