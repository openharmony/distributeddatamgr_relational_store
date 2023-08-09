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
HWTEST_F(RdbStoreImplTest, GetModifyTimeByRowIdTest_001, TestSize.Level4)
{
    RdbStoreImplTest::store->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_rdbstoreimpltest_integer_log "
        "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
        "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(1));
    valuesBucket.PutInt("timestamp", ValueObject(1000000000));
    int errorCode = RdbStoreImplTest::store->Insert(rowId,
        "naturalbase_rdb_aux_rdbstoreimpltest_integer_log", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    std::vector<RdbStore::PRIKey> PKey = {1};
    auto result = RdbStoreImplTest::store->GetModifyTime("rdbstoreimpltest_integer", "ROWID", PKey);
    int size = result.size();
    EXPECT_EQ(1, size);
    EXPECT_EQ(100000, int64_t(result[1]));

    RdbStoreImplTest::store->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log");
}


/* *
 * @tc.name: GetModifyTimeByRowIdTest_002
 * @tc.desc: Get ModifyTime By RowId
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, GetModifyTimeByRowIdTest_002, TestSize.Level4)
{
    RdbStoreImplTest::store->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_rdbstoreimpltest_integer_log "
        "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
        "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(2));
    int errorCode = RdbStoreImplTest::store->Insert(rowId,
        "naturalbase_rdb_aux_rdbstoreimpltest_integer_log", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    std::vector<RdbStore::PRIKey> PKey = {1};
    auto result = RdbStoreImplTest::store->GetModifyTime("rdbstoreimpltest_integer", "ROWID", PKey);
    int size = result.size();
    EXPECT_EQ(0, size);

    RdbStoreImplTest::store->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log");
}

/* *
 * @tc.name: GetModifyTime_001
 * @tc.desc: Get ModifyTime
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, GetModifyTime_001, TestSize.Level4)
{
    std::vector<RdbStore::PRIKey> PKey = {1};
    std::map<RdbStore::PRIKey, RdbStore::Date> result = RdbStoreImplTest::store->GetModifyTime("", "", PKey);
    int size = result.size();
    EXPECT_EQ(0, size);
}

/* *
 * @tc.name: GetModifyTime_002
 * @tc.desc: Get ModifyTime
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, GetModifyTime_002, TestSize.Level4)
{
    RdbStoreImplTest::store->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_rdbstoreimpltest_integer_log "
        "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, hash_key INTEGER, "
        "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");

    std::vector<RdbStore::PRIKey> PKey = {1};
    auto result = RdbStoreImplTest::store->GetModifyTime("rdbstoreimpltest_integer", "ROWID", PKey);
    int size = result.size();
    EXPECT_EQ(0, size);

    RdbStoreImplTest::store->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log");
}

/* *
 * @tc.name: Rdb_BatchInsertTest_001
 * @tc.desc: test batchinsert empty valuesBuckets
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_BatchInsertTest_001, TestSize.Level4)
{
    std::vector<ValuesBucket> valuesBuckets;
    int64_t insertNum = 1;
    int ret = store->BatchInsert(insertNum, "test", valuesBuckets);
    EXPECT_EQ(0, insertNum);
    EXPECT_EQ(E_OK, ret);
}

/* *
 * @tc.name: Rdb_QueryTest_001
 * @tc.desc: query the inexistent table
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_QueryTest_001, TestSize.Level4)
{
    int errCode = E_OK;
    RdbStoreImplTest::store->Query(errCode, true, "", std::vector<std::string> {}, "",
        std::vector<ValueObject> {}, "", "", "", 1, 0);
    EXPECT_NE(E_OK, errCode);
}

/* *
 * @tc.name: Rdb_QueryTest_002
 * @tc.desc: query test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_QueryTest_002, TestSize.Level4)
{
    int errCode = E_OK;
    RdbStoreImplTest::store->Query(errCode, true, "test", std::vector<std::string> {},
        "", std::vector<ValueObject> {}, "", "", "", 1, 0);
    EXPECT_EQ(E_OK, errCode);
}

/* *
 * @tc.name: Rdb_RemoteQueryTest_001
 * @tc.desc: remote query test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_RemoteQueryTest_001, TestSize.Level4)
{
    int errCode = E_OK;
    AbsRdbPredicates predicate("test");
    predicate.EqualTo("id", 1);
    RdbStoreImplTest::store->RemoteQuery("", predicate, std::vector<std::string> {}, errCode);
    EXPECT_NE(E_OK, errCode);
}

/* *
 * @tc.name: Rdb_IsHoldingConnectionTset_001
 * @tc.desc: test holding connection
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_IsHoldingConnectionTset_001, TestSize.Level4)
{
    bool ret = RdbStoreImplTest::store->IsHoldingConnection();
    EXPECT_EQ(true, ret);
}
