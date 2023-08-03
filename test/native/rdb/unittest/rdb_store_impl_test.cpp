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
#include <map>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store_impl.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbStoreImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
};

const std::string RdbStoreImplTest::DATABASE_NAME = RDB_TEST_PATH + "stepResultSet_impl_test.db";
std::shared_ptr<RdbStore> RdbStoreImplTest::store = nullptr;

class RdbStoreImplTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int RdbStoreImplTestOpenCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int RdbStoreImplTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStoreImplTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    RdbStoreConfig config(RdbStoreImplTest::DATABASE_NAME);
    RdbStoreImplTestOpenCallback helper;
    RdbStoreImplTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbStoreImplTest::store, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbStoreImplTest::TearDownTestCase(void)
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(RdbStoreImplTest::DATABASE_NAME);
}

void RdbStoreImplTest::SetUp(void)
{
    store->ExecuteSql("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, "
                      "data2 INTEGER, data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
}

void RdbStoreImplTest::TearDown(void)
{
    store->ExecuteSql("DROP TABLE IF EXISTS test");
}


/* *
 * @tc.name: GetModifyTimeByRowIdTest_001
 * @tc.desc: Get ModifyTime By RowId
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, GetModifyTimeByRowIdTest_001, TestSize.Level1)
{
    RdbStoreImplTest::store->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_rdbstoreimpltest_integer_log (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "timestamp INTEGER, data_key INTEGER, data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(1));
    valuesBucket.PutInt("timestamp", ValueObject(1691116758));
    int errorCode = RdbStoreImplTest::store->Insert(rowId, "naturalbase_rdb_aux_rdbstoreimpltest_integer_log", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    std::vector<RdbStore::PRIKey> PKey = {1};
    std::map<RdbStore::PRIKey, RdbStore::Date> result = RdbStoreImplTest::store->GetModifyTime("rdbstoreimpltest_integer", "ROWID", PKey);
    int size = result.size();
    EXPECT_EQ(1, size);
    EXPECT_EQ(169111, int64_t(result[1]));

    RdbStoreImplTest::store->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log");
}


/* *
 * @tc.name: GetModifyTimeByRowIdTest_002
 * @tc.desc: Get ModifyTime By RowId
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, GetModifyTimeByRowIdTest_002, TestSize.Level1)
{
    RdbStoreImplTest::store->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_rdbstoreimpltest_integer_log (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "timestamp INTEGER, data_key INTEGER, data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(2));
    int errorCode = RdbStoreImplTest::store->Insert(rowId, "naturalbase_rdb_aux_rdbstoreimpltest_integer_log", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    std::vector<RdbStore::PRIKey> PKey = {1};
    std::map<RdbStore::PRIKey, RdbStore::Date> result = RdbStoreImplTest::store->GetModifyTime("rdbstoreimpltest_integer", "ROWID", PKey);
    int size = result.size();
    EXPECT_EQ(0, size);

    RdbStoreImplTest::store->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log");
}