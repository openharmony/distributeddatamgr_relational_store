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

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbNdkTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

RDB_Store *rdbStore_;

void RdbNdkTest::SetUpTestCase(void)
{

}

void RdbNdkTest::TearDownTestCase(void)
{
}

void RdbNdkTest::SetUp(void)
{
    RDB_Config config;
    std::string path = RDB_TEST_PATH + "main.db";
    config.name = path.c_str();
    config.securityLevel = SecurityLevel::S1;
    config.isEncrypt = false;
    config.isCreateNecessary = true;
    int version = 1;
    int errCode = 0;
    rdbStore_ = OH_Rdb_GetOrOpen(&config, version, &errCode);
    std::cout << "get ndk rdb store " << errCode << std::endl;

    char sql[] = "CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY AUTOINCREMENT, age INTEGER)";

    errCode = OH_Rdb_Execute(rdbStore_, sql);
    std::cout << "rdb ndk execute sql " << errCode << std::endl;
}

void RdbNdkTest::TearDown(void)
{
}

/**
 * @tc.name: RDB_NDK_test_001
 * @tc.desc: NDK test
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkTest, RDB_NDK_test_001, TestSize.Level1)
{
    int errCode = 0;
    char table[] = "test";
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table);
    errCode = OH_Rdb_Delete(rdbStore_, predicates);
    std::cout << "rdb ndk delete sql result is" << errCode << std::endl;

    RDB_ValuesBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutInt64(valueBucket, "age", 10);
    errCode = OH_Rdb_Insert(rdbStore_, table, valueBucket);
    std::cout << "rdb ndk insert sql result is" << errCode << std::endl;

    RDB_ValuesBucket* valueBucket1 = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutInt64(valueBucket1, "age", 20);
    errCode = OH_Rdb_Insert(rdbStore_, table, valueBucket1);
    std::cout << "rdb ndk insert sql result is" << errCode << std::endl;

    OH_Predicates *predicates1 = OH_Rdb_CreatePredicates("test");
    OH_Predicates_EqualTo(predicates1, "age", "10");
    RDB_ValuesBucket* valueBucket2 = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutInt64(valueBucket2, "age", 300);
    errCode = OH_Rdb_Update(rdbStore_, valueBucket2, predicates1);
    std::cout << "rdb ndk update sql result is" << errCode << std::endl;

    OH_Predicates *predicates2 = OH_Rdb_CreatePredicates("test");
    const char *columnNames[2] = {"id", "age"};
    OH_Cursor *cursor = OH_Rdb_Query(rdbStore_, predicates2, columnNames, 2);
    EXPECT_NE(cursor, nullptr);
    errCode = OH_Cursor_GoToNextRow(cursor);
    std::cout << "rdb ndk GoToNextRow errCode " << errCode << std::endl;
    int rowCount=0;
    errCode = OH_Cursor_GetRowCount(cursor, &rowCount);
    std::cout << "rdb ndk rowCount is " << rowCount << std::endl;
    errCode = OH_Cursor_Close(cursor);
    std::cout << "rdb ndk close errCode " << errCode << std::endl;
}


/**
 * @tc.name: RDB_NDK_test_002
 * @tc.desc: NDK test
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkTest, RDB_NDK_test_002, TestSize.Level1)
{
    int errCode = 0;
    char table[] = "test";
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table);
    errCode = OH_Rdb_Delete(rdbStore_, predicates);
    std::cout << "rdb ndk delete sql result is" << errCode << std::endl;

    OH_Rdb_Transaction(rdbStore_);

    RDB_ValuesBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutInt64(valueBucket, "age", 10);
    errCode = OH_Rdb_Insert(rdbStore_, table, valueBucket);
    std::cout << "rdb ndk insert sql result is" << errCode << std::endl;

    RDB_ValuesBucket* valueBucket1 = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutInt64(valueBucket1, "age", 20);
    errCode = OH_Rdb_Insert(rdbStore_, table, valueBucket1);
    std::cout << "rdb ndk insert sql result is" << errCode << std::endl;

    OH_Rdb_Commit(rdbStore_);

    OH_Predicates *predicates2 = OH_Rdb_CreatePredicates("test");
    const char *columnNames[2] = {"id", "age"};
    OH_Cursor *cursor = OH_Rdb_Query(rdbStore_, predicates2, columnNames, 2);
    EXPECT_NE(cursor, nullptr);
    errCode = OH_Cursor_GoToNextRow(cursor);
    std::cout << "rdb ndk GoToNextRow errCode " << errCode << std::endl;
    int rowCount=0;
    errCode = OH_Cursor_GetRowCount(cursor, &rowCount);
    std::cout << "rdb ndk rowCount is " << rowCount << std::endl;
    errCode = OH_Cursor_Close(cursor);
    std::cout << "rdb ndk close errCode " << errCode << std::endl;
}

/**
 * @tc.name: RDB_NDK_test_003
 * @tc.desc: NDK test
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkTest, RDB_NDK_test_003, TestSize.Level1)
{
    int errCode = 0;
    char table[] = "test";
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table);
    errCode = OH_Rdb_Delete(rdbStore_, predicates);
    std::cout << "rdb ndk delete sql result is" << errCode << std::endl;

    OH_Rdb_Transaction(rdbStore_);

    RDB_ValuesBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutInt64(valueBucket, "age", 10);
    errCode = OH_Rdb_Insert(rdbStore_, table, valueBucket);
    std::cout << "rdb ndk insert sql result is" << errCode << std::endl;

    RDB_ValuesBucket *valueBucket1 = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutInt64(valueBucket1, "age", 20);
    errCode = OH_Rdb_Insert(rdbStore_, table, valueBucket1);
    std::cout << "rdb ndk insert sql result is" << errCode << std::endl;

    OH_Rdb_RollBack(rdbStore_);

    OH_Predicates *predicates2 = OH_Rdb_CreatePredicates("test");
    const char *columnNames[2] = {"id", "age"};
    OH_Cursor *cursor = OH_Rdb_Query(rdbStore_, predicates2, columnNames, 2);
    EXPECT_NE(cursor, nullptr);
    errCode = OH_Cursor_GoToNextRow(cursor);
    std::cout << "rdb ndk GoToNextRow errCode " << errCode << std::endl;
    int rowCount=0;
    errCode = OH_Cursor_GetRowCount(cursor, &rowCount);
    std::cout << "rdb ndk rowCount is " << rowCount << std::endl;
    errCode = OH_Cursor_Close(cursor);
    std::cout << "rdb ndk close errCode " << errCode << std::endl;
}

/**
 * @tc.name: RDB_NDK_test_004
 * @tc.desc: NDK test
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkTest, RDB_NDK_test_004, TestSize.Level1)
{
    int errCode = 0;
    int version = 0;
    int setVersion = 3;
    errCode = OH_Rdb_GetVersion(rdbStore_, &version);
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(version, 1);

    errCode = OH_Rdb_SetVersion(rdbStore_, setVersion);
    errCode = OH_Rdb_GetVersion(rdbStore_, &version);
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(version, 3);
    std::string storeName = RDB_TEST_PATH + "main.db";
    OH_Rdb_DeleteStore(storeName.c_str());
    std::cout << "rdb ndk GetVersion " << errCode << std::endl;
}

/**
 * @tc.name: RDB_NDK_test_005
 * @tc.desc: NDK test
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkTest, RDB_NDK_test_005, TestSize.Level1)
{
    int errCode = 0;
    char table[] = "test";
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table);
    errCode = OH_Rdb_Delete(rdbStore_, predicates);
    std::cout << "rdb ndk delete sql result is" << errCode << std::endl;

    RDB_ValuesBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutInt64(valueBucket, "age", 10);
    errCode = OH_Rdb_Insert(rdbStore_, table, valueBucket);
    std::cout << "rdb ndk insert sql result is" << errCode << std::endl;

    OH_Predicates *predicates2 = OH_Rdb_CreatePredicates("test");
    const char *columnNames[2] = {"id", "age"};
    OH_Cursor *cursor = OH_Rdb_Query(rdbStore_, predicates2, columnNames, 2);
    EXPECT_NE(cursor, nullptr);
    errCode = OH_Cursor_GoToNextRow(cursor);
    EXPECT_EQ(errCode, 0);
    int rowCount=0;
    errCode = OH_Cursor_GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    errCode = OH_Cursor_Close(cursor);
    EXPECT_EQ(errCode, 0);

    std::string backupPath = RDB_TEST_PATH + "backup.db";
    errCode = OH_Rdb_Backup(rdbStore_, backupPath.c_str(), nullptr);
    EXPECT_EQ(errCode, 0);

    errCode = OH_Rdb_Restore(rdbStore_, backupPath.c_str(), nullptr);
    EXPECT_EQ(errCode, 0);

    cursor = OH_Rdb_Query(rdbStore_, predicates2, columnNames, 2);
    EXPECT_NE(cursor, nullptr);
    errCode = OH_Cursor_GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    errCode = OH_Cursor_Close(cursor);
    EXPECT_EQ(errCode, 0);
}