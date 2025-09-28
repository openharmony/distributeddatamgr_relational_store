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
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#include "common.h"
#include "data_asset.h"
#include "oh_data_utils.h"
#include "relational_store.h"
#include "relational_store_error_code.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbCursorGetSizeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void InitRdbConfig()
    {
        config_.dataBaseDir = RDB_TEST_PATH;
        config_.storeName = "rdb_cursor_getSize_test.db";
        config_.bundleName = "com.ohos.example.distributedndk";
        config_.moduleName = "";
        config_.securityLevel = OH_Rdb_SecurityLevel::S1;
        config_.isEncrypt = false;
        config_.area = Rdb_SecurityArea::RDB_SECURITY_AREA_EL1;
        config_.selfSize = sizeof(OH_Rdb_Config);
    }
    static OH_Rdb_Config config_;
};

OH_Rdb_Store *rdbStore_;
OH_Rdb_Config RdbCursorGetSizeTest::config_ = { 0 };
void RdbCursorGetSizeTest::SetUpTestCase(void)
{
    InitRdbConfig();
    mkdir(config_.dataBaseDir, 0770);
    int errCode = 0;
    char table[] = "test";
    rdbStore_ = OH_Rdb_GetOrOpen(&config_, &errCode);
    EXPECT_NE(rdbStore_, NULL);
    char createTableSql[] = "CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    errCode = OH_Rdb_Execute(rdbStore_, createTableSql);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    valueBucket->putInt64(valueBucket, "data2", 12800);
    valueBucket->putReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = { 1, 2, 3, 4, 5 };
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(rdbStore_, table, valueBucket);
    EXPECT_EQ(errCode, 1);
    valueBucket->destroy(valueBucket);
}

void RdbCursorGetSizeTest::TearDownTestCase(void)
{
    delete rdbStore_;
    rdbStore_ = NULL;
    OH_Rdb_DeleteStore(&config_);
}

void RdbCursorGetSizeTest::SetUp(void)
{
}

void RdbCursorGetSizeTest::TearDown(void)
{
}

/**
 * @tc.name: Normal_cursor_GetSize_test_001
 * @tc.desc: Normal testCase of cursor for GetSize.
 * @tc.type: FUNC
 */
HWTEST_F(RdbCursorGetSizeTest, Normal_cursor_GetSize_test_001, TestSize.Level0)
{
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");

    const char *columnNames[] = { "data1", "data2", "data3", "data4" };
    int len = sizeof(columnNames) / sizeof(columnNames[0]);
    OH_Cursor *cursor = OH_Rdb_Query(rdbStore_, predicates, columnNames, len);
    EXPECT_NE(cursor, NULL);

    cursor->goToNextRow(cursor);

    size_t size = 0;
    cursor->getSize(cursor, 0, &size);
    EXPECT_EQ(size, 9);

    cursor->getSize(cursor, 3, &size);
    EXPECT_EQ(size, 5);
    predicates->destroy(predicates);
    cursor->destroy(cursor);

    char querySql[] = "SELECT * FROM test";
    OH_Cursor *cursor1 = OH_Rdb_ExecuteQuery(rdbStore_, querySql);
    EXPECT_NE(cursor1, NULL);

    cursor1->goToNextRow(cursor1);

    cursor->getSize(cursor1, 0, &size);
    EXPECT_EQ(size, 9);

    cursor->getSize(cursor1, 3, &size);
    EXPECT_EQ(size, 5);
    cursor->destroy(cursor1);
}

/**
 * @tc.name: Normal_cursor_GetSize_test_002
 * @tc.desc: Normal testCase of cursor for GetSize.
 * @tc.type: FUNC
 */
HWTEST_F(RdbCursorGetSizeTest, Normal_cursor_GetSize_test_002, TestSize.Level0)
{
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");

    OHOS::RdbNdk::Utils::flag_ = false;
    const char *columnNames[] = { "data1", "data2", "data3", "data4" };
    int len = sizeof(columnNames) / sizeof(columnNames[0]);

    OH_Cursor *cursor = OH_Rdb_Query(rdbStore_, predicates, columnNames, len);
    EXPECT_NE(cursor, NULL);

    cursor->goToNextRow(cursor);

    size_t size = 0;
    cursor->getSize(cursor, 0, &size);
    EXPECT_EQ(size, 9);

    cursor->getSize(cursor, 3, &size);
    EXPECT_EQ(size, 5);
    predicates->destroy(predicates);
    cursor->destroy(cursor);

    char querySql[] = "SELECT * FROM test";
    OH_Cursor *cursor1 = OH_Rdb_ExecuteQuery(rdbStore_, querySql);
    EXPECT_NE(cursor1, NULL);

    cursor1->goToNextRow(cursor1);

    cursor->getSize(cursor1, 0, &size);
    EXPECT_EQ(size, 9);

    cursor->getSize(cursor1, 3, &size);
    EXPECT_EQ(size, 5);
    cursor->destroy(cursor1);
}

/**
 * @tc.name: Normal_cursor_GetSize_test_003
 * @tc.desc: Normal testCase of cursor for GetSize.
 * @tc.type: FUNC
 */
HWTEST_F(RdbCursorGetSizeTest, Normal_cursor_GetSize_test_003, TestSize.Level0)
{
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");

    OHOS::RdbNdk::Utils::flag_ = true;
    const char *columnNames[] = { "data1", "data2", "data3", "data4" };
    int len = sizeof(columnNames) / sizeof(columnNames[0]);

    OH_Cursor *cursor = OH_Rdb_Query(rdbStore_, predicates, columnNames, len);
    EXPECT_NE(cursor, NULL);

    cursor->goToNextRow(cursor);

    size_t size = 0;
    cursor->getSize(cursor, 0, &size);
    EXPECT_EQ(size, 8);

    cursor->getSize(cursor, 3, &size);
    EXPECT_EQ(size, 5);
    predicates->destroy(predicates);
    cursor->destroy(cursor);

    char querySql[] = "SELECT * FROM test";
    OH_Cursor *cursor1 = OH_Rdb_ExecuteQuery(rdbStore_, querySql);
    EXPECT_NE(cursor1, NULL);

    cursor1->goToNextRow(cursor1);

    cursor->getSize(cursor1, 0, &size);
    EXPECT_EQ(size, 9);

    cursor->getSize(cursor1, 3, &size);
    EXPECT_EQ(size, 5);
    cursor->destroy(cursor1);
}