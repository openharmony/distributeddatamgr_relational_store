/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "common.h"
#include "relational_store.h"
#include "relational_error_code.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbNdkStoreOpenCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

std::string storeOpenCallbackTestPath_ = RDB_TEST_PATH + "rdb_store_callback_test.db";

void RdbNdkStoreOpenCallbackTest::SetUpTestCase(void)
{
}

void RdbNdkStoreOpenCallbackTest::TearDownTestCase(void)
{
    int errCode = OH_Rdb_DeleteStore(storeOpenCallbackTestPath_.c_str());
    EXPECT_EQ(errCode, 0);
}

void RdbNdkStoreOpenCallbackTest::SetUp(void)
{
}

void RdbNdkStoreOpenCallbackTest::TearDown(void)
{
    int errCode = OH_Rdb_ClearCache();
    EXPECT_EQ(errCode, 0);
}

int OnCreate(OH_Rdb_Store *store)
{
    char createTableSql[] = "CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    return OH_Rdb_Execute(store, createTableSql);
}

int OnUpgrade(OH_Rdb_Store *store, int oldVersion, int newVersion)
{
    if (oldVersion < newVersion) {
        if (oldVersion <= 1) {
            char createTableSql[] = "CREATE TABLE test2 (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                                    "data3 FLOAT, data4 BLOB, data5 TEXT);";
            return OH_Rdb_Execute(store, createTableSql);
        }
    }
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OnDowngrade(OH_Rdb_Store *store, int oldVersion, int newVersion)
{
    if (oldVersion > newVersion) {
        if (oldVersion >= 2) {
            char dropTableSql[] = "DROP TABLE IF EXISTS test2";
            OH_Rdb_Execute(store, dropTableSql);
        }
    }
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OnOpen(OH_Rdb_Store *store)
{
    OH_Rdb_ValuesBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutText(valueBucket, "data1", "zhangSan");
    OH_VBucket_PutInt64(valueBucket, "data2", 12800);
    OH_VBucket_PutReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    OH_VBucket_PutBlob(valueBucket, "data4", arr, len);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFG");
    int errCode = OH_Rdb_Insert(store, "test1", valueBucket);
    if (errCode == -1) {
        return errCode;
    }

    OH_VBucket_Clear(valueBucket);
    OH_VBucket_PutText(valueBucket, "data1", "liSi");
    OH_VBucket_PutInt64(valueBucket, "data2", 13800);
    OH_VBucket_PutReal(valueBucket, "data3", 200.1);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFGH");
    errCode = OH_Rdb_Insert(store, "test1", valueBucket);
    if (errCode == -1) {
        return errCode;
    }
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OnCorruption(const char *databaseFile)
{
    int errCode = OH_Rdb_DeleteStore(databaseFile);
    if (errCode != OH_Rdb_ErrCode::RDB_ERR_OK) {
        return errCode;
    }
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

void InitRdbOpenCallback(OH_Rdb_OpenCallback *rdbOpenCallback)
{
    rdbOpenCallback->OH_Callback_OnCreate = OnCreate;
    rdbOpenCallback->OH_Callback_OnUpgrade = OnUpgrade;
    rdbOpenCallback->OH_Callback_OnDowngrade = OnDowngrade;
    rdbOpenCallback->OH_Callback_OnOpen = OnOpen;
    rdbOpenCallback->OH_Callback_OnCorruption = OnCorruption;
}

/**
 * @tc.name: RDB_NDK_store_open_callback_test_001
 * @tc.desc: Normal testCase of NDK store for store openCallback OnCreate OnOpen.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreOpenCallbackTest, RDB_NDK_store_open_callback_test_001, TestSize.Level1)
{
    OH_Rdb_OpenCallback callback;
    InitRdbOpenCallback(&callback);

    OH_Rdb_Config config;
    config.path = storeOpenCallbackTestPath_.c_str();
    config.securityLevel = OH_Rdb_SecurityLevel::RDB_S1;
    config.isEncrypt = OH_Rdb_Bool::RDB_FALSE;

    int errCode = 0;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(&config, 1, &callback, &errCode);
    EXPECT_NE(store, NULL);

    int version = 0;
    errCode = OH_Rdb_GetVersion(store, &version);
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(version, 1);

    OH_Rdb_ValuesBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutText(valueBucket, "data1", "wangWu");
    OH_VBucket_PutInt64(valueBucket, "data2", 14800);
    OH_VBucket_PutReal(valueBucket, "data3", 300.1);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFGHI");
    errCode = OH_Rdb_Insert(store, "test1", valueBucket);
    EXPECT_EQ(errCode, 3);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test1");
    const char *columnNames[] = {"data1", "data2", "data3", "data4"};
    int len = sizeof(columnNames) / sizeof(columnNames[0]);
    OH_Cursor *cursor = OH_Rdb_Query(store, predicates, columnNames, len);
    EXPECT_NE(cursor, NULL);

    int rowCount = 0;
    cursor->OH_Cursor_GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 3);

    cursor->OH_Cursor_Close(cursor);
}

/**
 * @tc.name: RDB_NDK_store_open_callback_test_002
 * @tc.desc: Normal testCase of NDK store for store openCallback OnOpen OnUpgrade.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreOpenCallbackTest, RDB_NDK_store_open_callback_test_002, TestSize.Level1)
{
    OH_Rdb_OpenCallback callback;
    InitRdbOpenCallback(&callback);

    OH_Rdb_Config config;
    config.path = storeOpenCallbackTestPath_.c_str();
    config.securityLevel = OH_Rdb_SecurityLevel::RDB_S1;
    config.isEncrypt = OH_Rdb_Bool::RDB_FALSE;

    int errCode = 0;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(&config, 2, &callback, &errCode);
    EXPECT_NE(store, NULL);

    int version = 0;
    errCode = OH_Rdb_GetVersion(store, &version);
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(version, 2);

    OH_Rdb_ValuesBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutText(valueBucket, "data1", "zhangSan");
    OH_VBucket_PutInt64(valueBucket, "data2", 12800);
    OH_VBucket_PutReal(valueBucket, "data3", 100.1);
    uint8_t arr1[] = {1, 2, 3, 4, 5, 6};
    int len = sizeof(arr1) / sizeof(arr1[0]);
    OH_VBucket_PutBlob(valueBucket, "data4", arr1, len);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(store, "test2", valueBucket);
    EXPECT_EQ(errCode, 1);

    char querySql[] = "SELECT * FROM test2";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(store, querySql);
    int rowCount = 0;
    cursor->OH_Cursor_GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    cursor->OH_Cursor_Close(cursor);
}

/**
 * @tc.name: RDB_NDK_store_open_callback_test_003
 * @tc.desc: Normal testCase of NDK store for store openCallback OnOpen OnDowngrade.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreOpenCallbackTest, RDB_NDK_store_open_callback_test_003, TestSize.Level1)
{
    OH_Rdb_OpenCallback callback;
    InitRdbOpenCallback(&callback);

    OH_Rdb_Config config;
    config.path = storeOpenCallbackTestPath_.c_str();
    config.securityLevel = OH_Rdb_SecurityLevel::RDB_S1;
    config.isEncrypt = OH_Rdb_Bool::RDB_FALSE;

    int errCode = 0;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(&config, 1, &callback, &errCode);
    EXPECT_NE(store, NULL);

    int version = 0;
    errCode = OH_Rdb_GetVersion(store, &version);
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(version, 1);

    OH_Rdb_ValuesBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutText(valueBucket, "data1", "zhangSan");
    OH_VBucket_PutInt64(valueBucket, "data2", 12800);
    OH_VBucket_PutReal(valueBucket, "data3", 100.1);
    uint8_t arr1[] = {1, 2, 3, 4, 5, 6};
    int len = sizeof(arr1) / sizeof(arr1[0]);
    OH_VBucket_PutBlob(valueBucket, "data4", arr1, len);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(store, "test2", valueBucket);
    EXPECT_EQ(errCode, -1);
}