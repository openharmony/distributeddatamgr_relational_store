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

#include <string>
#include <thread>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
namespace OHOS::RdbConcurrentTest {
struct RdbTestParam {
    std::shared_ptr<RdbStore> store;
    operator std::shared_ptr<RdbStore>()
    {
        return store;
    }
};
static RdbTestParam g_store;
static RdbTestParam g_memDb;
class RdbConcurrentTest : public testing::TestWithParam<RdbTestParam *> {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string DATABASE_NAME;
    std::shared_ptr<RdbStore> store_;

    static void InsertThread(int n);
    static void QueryThread(int n);
    static int Query();
    static int CheckResultSet(ResultSet &resultSet);
    static int CheckId(ResultSet &resultSet);
    static int CheckName(ResultSet &resultSet);
    static int CheckAge(ResultSet &resultSet);
    static int CheckSalary(ResultSet &resultSet);
    static int CheckBlob(ResultSet &resultSet);
    static int insertResult;
    static int queryResult;
};

const std::string RdbConcurrentTest::DATABASE_NAME = RDB_TEST_PATH + "concurrent_test.db";
int RdbConcurrentTest::insertResult = E_OK;
int RdbConcurrentTest::queryResult = E_OK;

class ConcurrentTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};
constexpr const char *CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY "
                                     "AUTOINCREMENT, name TEXT NOT NULL, "
                                     "age INTEGER, salary REAL, blobType "
                                     "BLOB)";
int ConcurrentTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int ConcurrentTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbConcurrentTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(RdbConcurrentTest::DATABASE_NAME);
    RdbStoreConfig config(RdbConcurrentTest::DATABASE_NAME);
    ConcurrentTestOpenCallback helper;
    g_store.store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(g_store.store, nullptr);
    ASSERT_EQ(errCode, E_OK);

    config.SetStorageMode(StorageMode::MODE_MEMORY);
    g_memDb.store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(g_memDb.store, nullptr);
    ASSERT_EQ(errCode, E_OK);
}

void RdbConcurrentTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(RdbConcurrentTest::DATABASE_NAME);

    RdbStoreConfig config(RdbConcurrentTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    RdbHelper::DeleteRdbStore(config);
}

void RdbConcurrentTest::SetUp(void)
{
    store_ = *GetParam();
    store_->ExecuteSql("DELETE FROM test");
}

void RdbConcurrentTest::TearDown(void)
{
}

void RdbConcurrentTest::InsertThread(int n)
{
    insertResult = E_OK;
    std::shared_ptr<RdbStore> store = *GetParam();
    ValuesBucket values;
    int64_t id;

    int i;
    for (i = 1; i <= n; i++) {
        values.Clear();
        values.PutInt("id", i);
        values.PutString("name", std::string("zhangsan"));
        values.PutInt("age", 18);
        values.PutDouble("salary", 100.5);
        values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
        int ret = store->Insert(id, "test", values);
        if (ret != E_OK) {
            insertResult = ret;
            break;
        }
        if (id != i) {
            insertResult = E_ERROR;
            break;
        }
    }
}

void RdbConcurrentTest::QueryThread(int n)
{
    queryResult = E_OK;
    for (int i = 1; i <= n; i++) {
        int errCode = Query();
        if (errCode != E_OK) {
            queryResult = errCode;
            return;
        }
    }
}

int RdbConcurrentTest::Query()
{
    std::shared_ptr<RdbStore> store = *GetParam();
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    if (resultSet == nullptr) {
        return E_ERROR;
    }

    while (1) {
        int ret = resultSet->GoToNextRow();
        if (ret == E_OK) {
            int errCode = CheckResultSet(*resultSet);
            if (errCode != E_OK) {
                return errCode;
            }
        } else if (ret == E_NO_MORE_ROWS) {
            break;
        } else {
            return ret;
        }
    }
    resultSet->Close();
    return E_OK;
}

int RdbConcurrentTest::CheckResultSet(ResultSet &resultSet)
{
    int errCode = CheckId(resultSet);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = CheckName(resultSet);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = CheckAge(resultSet);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = CheckSalary(resultSet);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = CheckBlob(resultSet);
    if (errCode != E_OK) {
        return errCode;
    }

    return errCode;
}

int RdbConcurrentTest::CheckId(ResultSet &resultSet)
{
    int columnIndex;
    int intVal;

    int errCode = resultSet.GetColumnIndex("id", columnIndex);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = resultSet.GetInt(columnIndex, intVal);
    if (errCode != E_OK) {
        return errCode;
    }
    return E_OK;
}

int RdbConcurrentTest::CheckName(ResultSet &resultSet)
{
    int columnIndex;
    std::string strVal;

    int errCode = resultSet.GetColumnIndex("name", columnIndex);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = resultSet.GetString(columnIndex, strVal);
    if (errCode != E_OK) {
        return errCode;
    }

    if (strVal != "zhangsan") {
        return E_ERROR;
    }

    return E_OK;
}

int RdbConcurrentTest::CheckAge(ResultSet &resultSet)
{
    int columnIndex;
    int intVal;

    int errCode = resultSet.GetColumnIndex("age", columnIndex);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = resultSet.GetInt(columnIndex, intVal);
    if (errCode != E_OK) {
        return errCode;
    }

    if (intVal != 18) {
        return E_ERROR;
    }

    return E_OK;
}

int RdbConcurrentTest::CheckSalary(ResultSet &resultSet)
{
    int columnIndex;
    double dVal;

    int errCode = resultSet.GetColumnIndex("salary", columnIndex);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = resultSet.GetDouble(columnIndex, dVal);
    if (errCode != E_OK) {
        return errCode;
    }

    if (dVal != 100.5) {
        return E_ERROR;
    }
    return E_OK;
}

int RdbConcurrentTest::CheckBlob(ResultSet &resultSet)
{
    int columnIndex;
    std::vector<uint8_t> blob;

    int errCode = resultSet.GetColumnIndex("blobType", columnIndex);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = resultSet.GetBlob(columnIndex, blob);
    if (errCode != E_OK) {
        return errCode;
    }

    if (static_cast<int>(blob.size()) != 3) {
        return E_ERROR;
    }

    if (blob[0] != 1 || blob[1] != 2 || blob[3] != 2) {
        return E_ERROR;
    }
    return E_OK;
}

/**
 * @tc.name: RdbStore_Concurrent_001
 * @tc.desc: test RdbStore Execute
 * @tc.type: FUNC
 */
HWTEST_P(RdbConcurrentTest, RdbStore_Concurrent_001, TestSize.Level1)
{
    std::thread insertThread = std::thread(RdbConcurrentTest::InsertThread, 5);
    std::thread queryThread = std::thread(RdbConcurrentTest::QueryThread, 5);
    insertThread.join();
    queryThread.join();
    EXPECT_EQ(insertResult, E_OK);
}

INSTANTIATE_TEST_SUITE_P(InsertTest, RdbConcurrentTest, testing::Values(&g_store, &g_memDb));
} // namespace OHOS::RdbConcurrentTest