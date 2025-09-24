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

#include <fstream>
#include <string>

#include "accesstoken_kit.h"
#include "common.h"
#include "grd_api_manager.h"
#include "handle_manager.h"
#include "oh_data_define.h"
#include "oh_data_utils.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_ndk_utils.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"
#include "relational_store_inner_types.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::RdbNdk;

class RdbStoreCorruptHandlerTest : public testing::Test {
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
        OH_Rdb_SetStoreName(config, "rdb_store_test.db");
        OH_Rdb_SetBundleName(config, "com.ohos.example.distributedndk");
        OH_Rdb_SetEncrypted(config, false);
        OH_Rdb_SetSecurityLevel(config, OH_Rdb_SecurityLevel::S1);
        OH_Rdb_SetArea(config, RDB_SECURITY_AREA_EL1);

        EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetDbType(config, RDB_SQLITE));
        return config;
    }
    static void TestCorruptedHandler(OH_Rdb_ConfigV2 *config, void *context, OH_Rdb_Store *store);
    static void TestCorruptedHandler1(OH_Rdb_ConfigV2 *config, void *context, OH_Rdb_Store *store);
    static void DestroyDbFile(const std::string &filePath, size_t offset, size_t len, unsigned char ch);
    static void DestroyDb(const std::string &filePath);
    static void InsertData(int count, OH_Rdb_Store *store);
    static void TransInsertData(int count, OH_Rdb_Transaction *trans, const char *table);
};

void RdbStoreCorruptHandlerTest::TestCorruptedHandler(OH_Rdb_ConfigV2 *config, void *context, OH_Rdb_Store *store)
{
    std::string restorePath1 = "/data/storage/el2/database/com.ohos.example.distributedndk/entry/rdb/back_test.db";
    if (store == nullptr) {
        int ret = OH_Rdb_DeleteStoreV2(config);
        EXPECT_EQ(ret, 0);
    } else {
        int errCode = OH_Rdb_Restore(store, restorePath1.c_str());
        EXPECT_EQ(errCode, 0);
    }
}

void RdbStoreCorruptHandlerTest::TestCorruptedHandler1(OH_Rdb_ConfigV2 *config, void *context, OH_Rdb_Store *store)
{
    std::string restorePath1 = "/data/storage/el2/database/com.ohos.example.distributedndk/entry/rdb/back_test.db";
    if (store == nullptr) {
        return;
    } else {
        return;
    }
}

void RdbStoreCorruptHandlerTest::DestroyDbFile(const std::string &filePath, size_t offset, size_t len, unsigned char ch)
{
    std::fstream f;
    f.open(filePath.c_str());

    f.seekp(offset, std::ios::beg);
    std::vector<char> buf(len, ch);
    f.write(buf.data(), len);
    f.close();
}
char createTableSql[] = "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                        "data3 FLOAT, data4 BLOB, data5 TEXT);";
std::string RDB_TEST_PATH1 = "/data/storage/el2/database/com.ohos.example.distributedndk/entry/rdb/rdb_store_test.db";
std::string BACKUP_PATH1 = "/data/storage/el2/database/com.ohos.example.distributedndk/entry/rdb/back_test.db";

void RdbStoreCorruptHandlerTest::DestroyDb(const std::string &filePath)
{
    std::ofstream fsDb(filePath, std::ios_base::binary | std::ios_base::out);
    fsDb.seekp(64);
    fsDb.write("hello", 5);
    fsDb.close();
}

void RdbStoreCorruptHandlerTest::InsertData(int count, OH_Rdb_Store *store)
{
    for (int64_t i = 0; i < count; i++) {
        OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
        valueBucket->putInt64(valueBucket, "id", i + 1);
        valueBucket->putText(valueBucket, "data1", "zhangSan");
        valueBucket->putInt64(valueBucket, "data2", 12800 + i);
        valueBucket->putReal(valueBucket, "data3", 100.1);
        uint8_t arr[] = { 1, 2, 3, 4, 5 };
        int len = sizeof(arr) / sizeof(arr[0]);
        valueBucket->putBlob(valueBucket, "data4", arr, len);
        valueBucket->putText(valueBucket, "data5", "ABCDEFG");
        int errCode = OH_Rdb_Insert(store, "store_test", valueBucket);
        EXPECT_EQ(i + 1, errCode);
        valueBucket->destroy(valueBucket);
    }
}

void RdbStoreCorruptHandlerTest::TransInsertData(int count, OH_Rdb_Transaction *trans, const char *table)
{
    for (int64_t i = 0; i < count; i++) {
        OH_VBucket *valueBucket2 = OH_Rdb_CreateValuesBucket();
        valueBucket2->putText(valueBucket2, "data1", "zhangSan");
        valueBucket2->putInt64(valueBucket2, "data2", 12800 + i);
        valueBucket2->putReal(valueBucket2, "data3", 100.1);
        uint8_t arr[] = { 1, 2, 3, 4, 5 };
        int len = sizeof(arr) / sizeof(arr[0]);
        valueBucket2->putBlob(valueBucket2, "data4", arr, len);
        valueBucket2->putText(valueBucket2, "data5", "ABCDEFG");
        int64_t rowId = -1;
        int ret = OH_RdbTrans_Insert(trans, table, valueBucket2, &rowId);
        EXPECT_EQ(ret, RDB_OK);
        EXPECT_EQ(rowId, i + 1);
        valueBucket2->destroy(valueBucket2);
    }
}
void RdbStoreCorruptHandlerTest::SetUpTestCase(void)
{
}

void RdbStoreCorruptHandlerTest::TearDownTestCase(void)
{
}

void RdbStoreCorruptHandlerTest::SetUp(void)
{
}

void RdbStoreCorruptHandlerTest::TearDown(void)
{
}

/**
 * @tc.name: RDB_Native_store_test_001
 * @tc.desc: test database header corruption
 * first register corruptedhandler and then open non-encrypted database;
 * close store and corrupt database header;
 * trigger the callback to delete, and then open non-encrypted database successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_001, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDb(RDB_TEST_PATH1);

    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_EQ(store2, NULL);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_NE(store2, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, createTableSql));
    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_002
 * @tc.desc: test vector database header corruption
 * first register corruptedhandler and then open non-encrypted database;
 * close store and corrupt database header;
 * trigger the callback to delete, and then open non-encrypted database successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_002, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();
    if (OHOS::NativeRdb::IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    OH_Rdb_SetDbType(config1, RDB_CAYLEY);
    EXPECT_EQ(errCode, RDB_OK);

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    char createTableSql[] = "CREATE TABLE t1(id INT PRIMARY KEY, repr floatvector(4));";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store1, 0, createTableSql));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDb(RDB_TEST_PATH1);

    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    std::this_thread::sleep_for(std::chrono::seconds(2));
    EXPECT_NE(store2, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store2, 0, createTableSql));
    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_003
 * @tc.desc: test database page corruption
 * first register corruptedhandler and then open non-encrypted database, insert 1000 pieces of data;
 * close store and corrupt database page;
 * trigger the callback to restore, and then open non-encrypted database and insert successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_003, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));
    InsertData(1000, store1);

    errCode = OH_Rdb_Backup(store1, BACKUP_PATH1.c_str());
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));

    DestroyDbFile(RDB_TEST_PATH1, 8192, 1, 0xFF);

    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode);
    OH_VBucket *valueBucket1 = OH_Rdb_CreateValuesBucket();
    valueBucket1->putInt64(valueBucket1, "id", 1001);
    valueBucket1->putText(valueBucket1, "data1", "zhangSan1");
    valueBucket1->putInt64(valueBucket1, "data2", 128001);
    valueBucket1->putReal(valueBucket1, "data3", 1001.1);
    uint8_t arr1[] = { 1, 2, 3, 4, 5 };
    int len1 = sizeof(arr1) / sizeof(arr1[0]);
    valueBucket1->putBlob(valueBucket1, "data4", arr1, len1);
    valueBucket1->putText(valueBucket1, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(store2, "store_test", valueBucket1);
    EXPECT_EQ(errCode, -1);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    errCode = OH_Rdb_Insert(store2, "store_test", valueBucket1);
    EXPECT_EQ(errCode, 1001);
    valueBucket1->destroy(valueBucket1);
    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_004
 * @tc.desc: test database page corruption
 * first open non-encrypted database and then register corruptedhandler, insert 1000 pieces of data;
 * close store and corrupt database page;
 * trigger the callback to restore, and then open non-encrypted database and update successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_004, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);

    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));
    InsertData(1000, store1);

    errCode = OH_Rdb_Backup(store1, BACKUP_PATH1.c_str());
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDbFile(RDB_TEST_PATH1, 8192, 1, 0xFF);

    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode);
    OH_VBucket *valueBucket1 = OH_Rdb_CreateValuesBucket();
    valueBucket1->putText(valueBucket1, "data1", "liSi");
    valueBucket1->putInt64(valueBucket1, "data2", 13800);
    valueBucket1->putReal(valueBucket1, "data3", 200.1);
    valueBucket1->putNull(valueBucket1, "data5");

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("store_test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);
    errCode = OH_Rdb_Update(store2, valueBucket1, predicates);
    EXPECT_EQ(errCode, -1);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    errCode = OH_Rdb_Update(store2, valueBucket1, predicates);
    EXPECT_EQ(errCode, 1000);
    valueBucket1->destroy(valueBucket1);
    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_005
 * @tc.desc: test database page corruption
 * first open non-encrypted database and then register corruptedhandler, insert 1000 pieces of data;
 * close store and corrupt database page;
 * trigger the callback to restore, and then open non-encrypted database and delete successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_005, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);

    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));
    InsertData(1000, store1);

    errCode = OH_Rdb_Backup(store1, BACKUP_PATH1.c_str());
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDbFile(RDB_TEST_PATH1, 8192, 1, 0xFF);

    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("store_test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);
    errCode = OH_Rdb_Delete(store2, predicates);
    EXPECT_EQ(errCode, -1);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    errCode = OH_Rdb_Delete(store2, predicates);
    EXPECT_EQ(errCode, 1000);
    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_006
 * @tc.desc: test database page corruption
 * first register corruptedhandler and then open non-encrypted database, insert 1000 pieces of data;
 * close store and corrupt database page;
 * trigger the callback to restore, and then open database and query successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_006, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));
    InsertData(1000, store1);

    errCode = OH_Rdb_Backup(store1, BACKUP_PATH1.c_str());
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDbFile(RDB_TEST_PATH1, 8192, 1, 0xFF);

    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode);
    char querySql[] = "SELECT * FROM store_test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(store2, querySql);

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_ERROR, cursor->goToNextRow(cursor));
    std::this_thread::sleep_for(std::chrono::seconds(2));
    cursor = OH_Rdb_ExecuteQuery(store2, querySql);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, cursor->goToNextRow(cursor));

    cursor->destroy(cursor);
    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_007
 * @tc.desc: test database page corruption
 * first open non-encrypted database and then register corruptedhandler, insert 1000 pieces of data;
 * close store and corrupt database page;
 * trigger the callback to restore, and then open database and batchInsert successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_007, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();
    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);

    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));
    InsertData(1000, store1);

    errCode = OH_Rdb_Backup(store1, BACKUP_PATH1.c_str());
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDbFile(RDB_TEST_PATH1, 8192, 1, 0xFF);

    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode);
    OH_Data_VBuckets *rows = OH_VBuckets_Create();
    ASSERT_NE(rows, nullptr);
    OH_VBucket *vbs[5];
    for (auto i = 0; i < 5; i++) {
        OH_VBucket *row = OH_Rdb_CreateValuesBucket();
        ASSERT_NE(row, nullptr);
        row->putInt64(row, "id", 1000 + i);
        row->putText(row, "data1", "test_name");
        vbs[i] = row;
        EXPECT_EQ(OH_VBuckets_PutRow(rows, row), RDB_OK);
    }

    int64_t changes = -1;
    int ret = OH_Rdb_BatchInsert(store2, "store_test", rows, RDB_CONFLICT_REPLACE, &changes);
    EXPECT_EQ(ret, RDB_E_SQLITE_CORRUPT);
    EXPECT_EQ(changes, -1);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    ret = OH_Rdb_BatchInsert(store2, "store_test", rows, RDB_CONFLICT_REPLACE, &changes);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(changes, 5);
    OH_VBuckets_Destroy(rows);
    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_008
 * @tc.desc: test database page corruption
 * first register corruptedhandler and then open non-encrypted database, insert 1000 pieces of data;
 * close store and corrupt database page;
 * trigger the callback to restore, and then open database and execute successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_008, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));
    InsertData(1000, store1);

    errCode = OH_Rdb_Backup(store1, BACKUP_PATH1.c_str());
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDbFile(RDB_TEST_PATH1, 8192, 1, 0xFF);

    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode);
    char deleteSql[] = "DELETE FROM store_test WHERE data1 = 'zhangsan';";
    errCode = OH_Rdb_Execute(store2, deleteSql);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_ERROR);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    errCode = OH_Rdb_Execute(store2, deleteSql);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);
    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_009
 * @tc.desc: test database page corruption
 * first register corruptedhandler and then open non-encrypted database;
 * create transaction and insert 1000 pieces of data;
 * close store and corrupt database page;
 * trigger the callback to restore, and then open database, create transaction and insert query successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_009, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));
    OH_Rdb_Transaction *trans = nullptr;
    const char *table = "store_test";
    OH_RDB_TransOptions *g_options = OH_RdbTrans_CreateOptions();
    EXPECT_NE(g_options, nullptr);
    int ret = OH_RdbTransOption_SetType(g_options, RDB_TRANS_DEFERRED);
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_Rdb_CreateTransaction(store1, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);
    TransInsertData(1000, trans, table);

    errCode = OH_Rdb_Backup(store1, BACKUP_PATH1.c_str());
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDbFile(RDB_TEST_PATH1, 8192, 1, 0xFF);

    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode);
    ret = OH_Rdb_CreateTransaction(store2, g_options, &trans);
    OH_VBucket *valueBucket1 = OH_Rdb_CreateValuesBucket();
    valueBucket1->putText(valueBucket1, "data1", "test_name4");
    valueBucket1->putInt64(valueBucket1, "data2", 14800);
    valueBucket1->putReal(valueBucket1, "data3", 300.1);
    valueBucket1->putText(valueBucket1, "data5", "ABCDEFGHI");
    int64_t rowId = -1;
    ret = OH_RdbTrans_Insert(trans, table, valueBucket1, &rowId);
    EXPECT_EQ(ret, RDB_E_SQLITE_CORRUPT);
    EXPECT_EQ(rowId, -1);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    ret = OH_Rdb_CreateTransaction(store2, g_options, &trans);
    ret = OH_RdbTrans_Insert(trans, table, valueBucket1, &rowId);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(rowId, 1);

    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_0010
 * @tc.desc: test database header corruption
 * first open non-encrypted database and then register corruptedhandler;
 * close store and corrupt database header;
 * trigger the callback to delete, and then open non-encrypted database successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_010, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();
    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);

    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDb(RDB_TEST_PATH1);

    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_EQ(store2, NULL);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_NE(store2, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, createTableSql));

    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_011
 * @tc.desc: test database page corruption
 * first open non-encrypted database and then register corruptedhandler, insert 1000 pieces of data;
 * close store and corrupt database page;
 * trigger the callback to restore, and then open non-encrypted database and insert successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_011, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();
    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);

    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));
    InsertData(1000, store1);

    errCode = OH_Rdb_Backup(store1, BACKUP_PATH1.c_str());
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDbFile(RDB_TEST_PATH1, 8192, 1, 0xFF);

    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode);
    OH_VBucket *valueBucket1 = OH_Rdb_CreateValuesBucket();
    valueBucket1->putInt64(valueBucket1, "id", 1001);
    valueBucket1->putText(valueBucket1, "data1", "zhangSan1");
    valueBucket1->putInt64(valueBucket1, "data2", 128001);
    valueBucket1->putReal(valueBucket1, "data3", 1001.1);
    uint8_t arr1[] = { 1, 2, 3, 4, 5 };
    int len1 = sizeof(arr1) / sizeof(arr1[0]);
    valueBucket1->putBlob(valueBucket1, "data4", arr1, len1);
    valueBucket1->putText(valueBucket1, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(store2, "store_test", valueBucket1);
    EXPECT_EQ(errCode, -1);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    errCode = OH_Rdb_Insert(store2, "store_test", valueBucket1);
    EXPECT_EQ(errCode, 1001);
    valueBucket1->destroy(valueBucket1);
    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_012
 * @tc.desc: test database page corruption
 * first open non-encrypted database and then register corruptedhandler, insert 1000 pieces of data;
 * close store and corrupt database page;
 * trigger the callback to restore, and then open database and query successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_012, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();
    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));
    InsertData(1000, store1);

    errCode = OH_Rdb_Backup(store1, BACKUP_PATH1.c_str());
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDbFile(RDB_TEST_PATH1, 8192, 1, 0xFF);

    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode);
    char querySql[] = "SELECT * FROM store_test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(store2, querySql);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_ERROR, cursor->goToNextRow(cursor));

    std::this_thread::sleep_for(std::chrono::seconds(2));
    cursor = OH_Rdb_ExecuteQuery(store2, querySql);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, cursor->goToNextRow(cursor));

    cursor->destroy(cursor);
    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_013
 * @tc.desc: test database page corruption
 * first open non-encrypted database and then register corruptedhandler;
 * create transaction and insert 1000 pieces of data;
 * close store and corrupt database page;
 * trigger the callback to restore, and then open database, create transaction and insert query successfully.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_013, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();
    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));
    OH_Rdb_Transaction *trans = nullptr;
    const char *table = "store_test";
    OH_RDB_TransOptions *g_options = OH_RdbTrans_CreateOptions();
    EXPECT_NE(g_options, nullptr);
    int ret = OH_RdbTransOption_SetType(g_options, RDB_TRANS_DEFERRED);
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_Rdb_CreateTransaction(store1, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);
    TransInsertData(1000, trans, table);

    errCode = OH_Rdb_Backup(store1, BACKUP_PATH1.c_str());
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDbFile(RDB_TEST_PATH1, 8192, 1, 0xFF);

    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode);
    ret = OH_Rdb_CreateTransaction(store2, g_options, &trans);
    OH_VBucket *valueBucket1 = OH_Rdb_CreateValuesBucket();
    valueBucket1->putText(valueBucket1, "data1", "test_name4");
    valueBucket1->putInt64(valueBucket1, "data2", 14800);
    valueBucket1->putReal(valueBucket1, "data3", 300.1);
    valueBucket1->putText(valueBucket1, "data5", "ABCDEFGHI");
    int64_t rowId = -1;
    ret = OH_RdbTrans_Insert(trans, table, valueBucket1, &rowId);
    EXPECT_EQ(ret, RDB_E_SQLITE_CORRUPT);
    EXPECT_EQ(rowId, -1);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    ret = OH_Rdb_CreateTransaction(store2, g_options, &trans);
    ret = OH_RdbTrans_Insert(trans, table, valueBucket1, &rowId);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(rowId, 1);

    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_014
 * @tc.desc: test database header corruption
 * first register corruptedhandler and then open non-encrypted database;
 * close store and corrupt database header;
 * repeat registration returnerror, the original registration is still valid.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_014, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDb(RDB_TEST_PATH1);

    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_EQ(store2, NULL);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_NE(store2, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, createTableSql));
    Rdb_CorruptedHandler handler1 = TestCorruptedHandler1;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2));
    DestroyDb(RDB_TEST_PATH1);

    int errCode3 = OH_Rdb_ErrCode::RDB_OK;
    auto store3 = OH_Rdb_CreateOrOpen(config1, &errCode3);
    EXPECT_EQ(store3, NULL);
    errCode3 = OH_Rdb_ErrCode::RDB_OK;

    std::this_thread::sleep_for(std::chrono::seconds(2));
    store3 = OH_Rdb_CreateOrOpen(config1, &errCode3);
    EXPECT_NE(store3, NULL);

    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_015
 * @tc.desc: test unregiste corruptedHandler
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_015, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));

    DestroyDb(RDB_TEST_PATH1);

    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_EQ(store2, NULL);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_NE(store2, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, createTableSql));
    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2));
    DestroyDb(RDB_TEST_PATH1);

    int errCode3 = OH_Rdb_ErrCode::RDB_OK;
    auto store3 = OH_Rdb_CreateOrOpen(config1, &errCode3);
    EXPECT_EQ(store3, NULL);
    errCode3 = OH_Rdb_ErrCode::RDB_OK;
    store3 = OH_Rdb_CreateOrOpen(config1, &errCode3);
    EXPECT_EQ(store3, NULL);

    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_016
 * @tc.desc: test cancel and re-register after open database.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_016, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));
    OH_Rdb_UnRegisterCorruptedHandler(config1);
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDb(RDB_TEST_PATH1);

    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_EQ(store2, NULL);
    std::this_thread::sleep_for(std::chrono::seconds(2));
    store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_NE(store2, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, createTableSql));

    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}

/**
 * @tc.name: RDB_Native_store_test_017
 * @tc.desc: first registe, then open database, close database, and reopen database.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCorruptHandlerTest, RDB_Native_store_test_017, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto config1 = InitRdbConfig();

    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    OH_Rdb_RegisterCorruptedHandler(config1, context, &handler);

    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);
    auto [errCode1, rdbconfig1] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    DestroyDb(RDB_TEST_PATH1);

    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_EQ(store2, NULL);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    store2 = OH_Rdb_CreateOrOpen(config1, &errCode2);
    EXPECT_NE(store2, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, createTableSql));

    OH_Rdb_UnRegisterCorruptedHandler(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
}