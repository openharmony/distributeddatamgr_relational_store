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
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#include "accesstoken_kit.h"
#include "common.h"
#include "grd_api_manager.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::RdbNdk;

class RdbVectorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static OH_Rdb_ConfigV2 *InitRdbConfig()
    {
        OH_Rdb_ConfigV2 *config = OH_Rdb_CreateConfig();
        EXPECT_NE(config, nullptr);
        OH_Rdb_SetDatabaseDir(config, RDB_TEST_PATH);
        OH_Rdb_SetStoreName(config, "rdb_vector_test.db");
        OH_Rdb_SetBundleName(config, "com.ohos.example.distributedndk");
        OH_Rdb_SetEncrypted(config, false);
        OH_Rdb_SetSecurityLevel(config, OH_Rdb_SecurityLevel::S1);
        OH_Rdb_SetArea(config, RDB_SECURITY_AREA_EL1);

        EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetDbType(config, RDB_CAYLEY));
        return config;
    }
};

OH_Rdb_Store *store_;
OH_Rdb_ConfigV2 *config_;
float test_[] = { 1.2, 2.3 };

void RdbVectorTest::SetUpTestCase(void)
{
    config_ = InitRdbConfig();
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = 0;
    store_ = OH_Rdb_CreateOrOpen(config_, &errCode);
    EXPECT_NE(store_, NULL);
}

void RdbVectorTest::TearDownTestCase(void)
{
    int errCode = OH_Rdb_CloseStore(store_);
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Rdb_DeleteStoreV2(config_);
    EXPECT_EQ(errCode, RDB_OK);
}

void RdbVectorTest::SetUp(void)
{
    if (!OHOS::NativeRdb::IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
    }
    char createTableSql[] = "CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 floatvector(2));";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store_, 0, createTableSql));
    OH_Data_Values *values = OH_Values_Create();
    OH_Values_PutInt(values, 1);
    size_t len = sizeof(test_) / sizeof(test_[0]);
    OH_Values_PutFloatVector(values, test_, len);
    char insertSql[] = "INSERT INTO test (id, data1) VALUES (?, ?);";
    auto errCode = OH_Rdb_ExecuteV2(store_, insertSql, values, nullptr);
    EXPECT_EQ(errCode, RDB_OK);
    OH_Values_Destroy(values);
}

void RdbVectorTest::TearDown(void)
{
    char dropTableSql[] = "DROP TABLE IF EXISTS test";
    int errCode = OH_Rdb_ExecuteByTrxId(store_, 0, dropTableSql);
    EXPECT_EQ(errCode, RDB_OK);
}

/**
 * @tc.name: RDB_vector_test_001
 * @tc.desc: Normal testCase of queryV2.
 * @tc.type: FUNC
 */
HWTEST_F(RdbVectorTest, RDB_vector_001, TestSize.Level1)
{
    char querySql[] = "select * from test where id = ?;";
    OH_Data_Values *values = OH_Values_Create();
    OH_Values_PutInt(values, 1);
    OH_Cursor *cursor = OH_Rdb_ExecuteQueryV2(store_, querySql, values);
    EXPECT_NE(cursor, NULL);
    
    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    cursor->goToNextRow(cursor);
    size_t count = 0;
    auto errCode = OH_Cursor_GetFloatVectorCount(cursor, 1, &count);
    EXPECT_EQ(errCode, RDB_OK);
    float test[count];
    size_t outLen;
    OH_Cursor_GetFloatVector(cursor, 1, test, count, &outLen);
    EXPECT_EQ(outLen, 2);
    EXPECT_EQ(test[0], test_[0]);
    EXPECT_EQ(test[1], test_[1]);

    float test1[10];
    OH_Cursor_GetFloatVector(cursor, 1, test1, 10, &outLen);
    EXPECT_EQ(outLen, 2);
    EXPECT_EQ(test1[0], test_[0]);
    EXPECT_EQ(test1[1], test_[1]);

    OH_Values_Destroy(values);
}

/**
 * @tc.name: RDB_vector_test_002
 * @tc.desc: Abnormal testCase of queryV2.
 * @tc.type: FUNC
 */
HWTEST_F(RdbVectorTest, RDB_vector_002, TestSize.Level1)
{
    char querySql[] = "select * from test where id = ?;";
    OH_Data_Values *values = OH_Values_Create();
    OH_Values_PutInt(values, 1);
    OH_Cursor *cursor = OH_Rdb_ExecuteQueryV2(nullptr, querySql, values);
    EXPECT_EQ(cursor, NULL);

    cursor = OH_Rdb_ExecuteQueryV2(store_, nullptr, values);
    EXPECT_EQ(cursor, NULL);

    cursor = OH_Rdb_ExecuteQueryV2(store_, querySql, nullptr);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 0);

    OH_Values_PutInt(values, 1);
    cursor = OH_Rdb_ExecuteQueryV2(store_, querySql, values);
    EXPECT_NE(cursor, NULL);
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, -1);

    OH_Values_Destroy(values);
}

/**
 * @tc.name: RDB_vector_test_003
 * @tc.desc: Abnormal testCase of getFloatVector.
 * @tc.type: FUNC
 */
HWTEST_F(RdbVectorTest, RDB_vector_003, TestSize.Level1)
{
    char querySql[] = "select * from test where id = ?;";
    OH_Data_Values *values = OH_Values_Create();
    OH_Values_PutInt(values, 1);
    OH_Cursor *cursor = OH_Rdb_ExecuteQueryV2(store_, querySql, values);
    EXPECT_NE(cursor, NULL);
    
    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    cursor->goToNextRow(cursor);
    size_t count = 0;
    auto errCode = OH_Cursor_GetFloatVectorCount(cursor, 0, &count);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    float test[count];
    size_t outLen;
    errCode = OH_Cursor_GetFloatVector(cursor, 0, test, count, &outLen);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    OH_Values_Destroy(values);
}

/**
 * @tc.name: RDB_vector_test_004
 * @tc.desc: Normal testCase of executeV2.
 * @tc.type: FUNC
 */
HWTEST_F(RdbVectorTest, RDB_vector_004, TestSize.Level1)
{
    char querySql[] = "select * from test where id = ?;";
    OH_Data_Values *values = OH_Values_Create();
    OH_Values_PutInt(values, 1);
    OH_Cursor *cursor = OH_Rdb_ExecuteQueryV2(store_, querySql, values);
    EXPECT_NE(cursor, NULL);
    
    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    
    float test[2] = { 5.5, 6.6 };
    OH_Data_Values *values1 = OH_Values_Create();
    OH_Values_PutFloatVector(values1, test, 2);
    OH_Values_PutInt(values1, 1);
    auto errCode = OH_Rdb_ExecuteV2(store_, "update test set data1 = ? where id = ?", values1, nullptr);
    EXPECT_EQ(errCode, RDB_OK);

    cursor = OH_Rdb_ExecuteQueryV2(store_, querySql, values);
    EXPECT_NE(cursor, NULL);
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    cursor->goToNextRow(cursor);
    size_t count = 0;
    errCode = OH_Cursor_GetFloatVectorCount(cursor, 1, &count);
    EXPECT_EQ(errCode, RDB_OK);
    float test1[count];
    size_t outLen;
    OH_Cursor_GetFloatVector(cursor, 1, test1, count, &outLen);
    EXPECT_EQ(outLen, 2);
    EXPECT_EQ(test1[0], test[0]);
    EXPECT_EQ(test1[1], test[1]);

    errCode = OH_Rdb_ExecuteV2(store_, "delete from test where id = ?", values, nullptr);
    EXPECT_EQ(errCode, RDB_OK);
    cursor = OH_Rdb_ExecuteQueryV2(store_, querySql, values);
    EXPECT_NE(cursor, NULL);
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 0);

    OH_Values_Destroy(values);
    OH_Values_Destroy(values1);
}

/**
 * @tc.name: RDB_vector_test_005
 * @tc.desc: Abnormal testCase of executeV2.
 * @tc.type: FUNC
 */
HWTEST_F(RdbVectorTest, RDB_vector_005, TestSize.Level1)
{
    OH_Data_Values *values = OH_Values_Create();
    OH_Values_PutFloatVector(values, test_, 2);
    OH_Values_PutInt(values, 1);
    auto errCode = OH_Rdb_ExecuteV2(nullptr, "update test set data1 = ? where id = ?",
        values, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    errCode = OH_Rdb_ExecuteV2(store_, nullptr, values, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    errCode = OH_Rdb_ExecuteV2(store_, "update test set data1 = ? where id = ?", nullptr, nullptr);
    EXPECT_EQ(errCode, RDB_OK);

    OH_Values_PutInt(values, 2);
    errCode = OH_Rdb_ExecuteV2(store_, "update test set data1 = ? where id = ?", values, nullptr);
    EXPECT_EQ(errCode, RDB_E_ERROR);
}

/**
 * @tc.name: RDB_vector_test_006
 * @tc.desc: Normal testCase of executeQueryV2.
 * @tc.type: FUNC
 */
HWTEST_F(RdbVectorTest, RDB_vector_006, TestSize.Level1)
{
    char querySql1[] = "select id, data1 <-> ? from test where id = ?;";
    OH_Data_Values *values = OH_Values_Create();
    float test[] = { 2.1, 3.0 };
    OH_Values_PutFloatVector(values, test, 2);
    OH_Values_PutInt(values, 1);
    OH_Cursor *cursor = OH_Rdb_ExecuteQueryV2(store_, querySql1, values);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    char querySql2[] = "select id, data1 <=> ? from test where id = ?;";
    cursor = OH_Rdb_ExecuteQueryV2(store_, querySql2, values);
    EXPECT_NE(cursor, NULL);
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    char querySql3[] = "select id, data1 <-> '[ 2.1, 3.0 ]' from test;";
    cursor = OH_Rdb_ExecuteQueryV2(store_, querySql3, nullptr);
    EXPECT_NE(cursor, NULL);
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    char querySql4[] = "select id, data1 <=> '[ 2.1, 3.0 ]' from test;";
    cursor = OH_Rdb_ExecuteQueryV2(store_, querySql4, nullptr);
    EXPECT_NE(cursor, NULL);
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    OH_Values_Destroy(values);
}

/**
 * @tc.name: RDB_vector_test_007
 * @tc.desc: Normal testCase of executeQueryV2.
 * @tc.type: FUNC
 */
HWTEST_F(RdbVectorTest, RDB_vector_007, TestSize.Level1)
{
    char createTableSql[] = "CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 floatvector(2));";
    auto errCode = OH_Rdb_ExecuteV2(store_, createTableSql, nullptr, nullptr);
    EXPECT_EQ(errCode, RDB_OK);
    char insertSql[] = "INSERT INTO test1 (id, data1) VALUES (1, '[3.1, 2.2]');";
    errCode = OH_Rdb_ExecuteV2(store_, insertSql, nullptr, nullptr);
    EXPECT_EQ(errCode, RDB_OK);

    char querySql[] = "select id, data1 <=> '[ 2.1, 3.0 ]' from test where id in (select id from test1);";
    OH_Cursor *cursor = OH_Rdb_ExecuteQueryV2(store_, querySql, nullptr);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    char updateSql[] = "update test1 set data1 = '[2.0, 1.0]' where id = 1;";
    errCode = OH_Rdb_ExecuteV2(store_, updateSql, nullptr, nullptr);
    EXPECT_EQ(errCode, RDB_OK);
    cursor = OH_Rdb_ExecuteQueryV2(store_, "select * from test1 where id = 1;", nullptr);
    EXPECT_NE(cursor, NULL);
    cursor->goToNextRow(cursor);
    float test1[2];
    size_t outLen;
    OH_Cursor_GetFloatVector(cursor, 1, test1, 2, &outLen);
    EXPECT_EQ(outLen, 2);
    EXPECT_EQ(test1[0], 2.0);
    EXPECT_EQ(test1[1], 1.0);

    errCode = OH_Rdb_ExecuteV2(store_, "delete from test1 where id = 1", nullptr, nullptr);
    EXPECT_EQ(errCode, RDB_OK);

    char dropTableSql[] = "DROP TABLE IF EXISTS test1";
    errCode = OH_Rdb_ExecuteV2(store_, dropTableSql, nullptr, nullptr);
    EXPECT_EQ(errCode, RDB_OK);
}

/**
 * @tc.name: RDB_vector_test_008
 * @tc.desc: Normal testCase of executeQueryV2.
 * @tc.type: FUNC
 */
HWTEST_F(RdbVectorTest, RDB_vector_008, TestSize.Level1)
{
    char insertSql[] = "INSERT INTO test (id, data1) VALUES (2, '[3.1, 2.2]');";
    auto errCode = OH_Rdb_ExecuteV2(store_, insertSql, nullptr, nullptr);
    EXPECT_EQ(errCode, RDB_OK);

    char querySql[] = "select id, data1 from test where id > ? group by id having "
                      "max(data1<=>?);";
    float test[] = { 2.1, 3.0 };
    OH_Data_Values *values = OH_Values_Create();
    OH_Values_PutInt(values, 0);
    OH_Values_PutFloatVector(values, test, 2);
    OH_Cursor *cursor = OH_Rdb_ExecuteQueryV2(store_, querySql, values);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    OH_Values_Destroy(values);
}