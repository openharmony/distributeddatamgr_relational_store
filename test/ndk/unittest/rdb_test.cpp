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
    rdbStore_ = RDB_GetOrOpen(&config, version, &errCode);
    std::cout << "get ndk rdb store " << errCode << std::endl;

    char sql[] = "CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY AUTOINCREMENT, age INTEGER)";

    errCode = RDB_Execute(rdbStore_, sql);
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
    RDB_Predicates *predicates = RDB_CreatePredicates(table);
    errCode = RDB_Delete(rdbStore_, predicates);
    std::cout << "rdb ndk delete sql result is" << errCode << std::endl;

    RDB_ValuesBucket* valueBucket = RDB_CreateValuesBucket();
    VBUCKET_PutInt64(valueBucket, "age", 10);
    errCode = RDB_Insert(rdbStore_, table, valueBucket);
    std::cout << "rdb ndk insert sql result is" << errCode << std::endl;

    RDB_ValuesBucket* valueBucket1 = RDB_CreateValuesBucket();
    VBUCKET_PutInt64(valueBucket1, "age", 20);
    errCode = RDB_Insert(rdbStore_, table, valueBucket1);
    std::cout << "rdb ndk insert sql result is" << errCode << std::endl;

    RDB_Predicates *predicates1 = RDB_CreatePredicates("test");
    PREDICATES_EqualTo(predicates1, "age", "10");
    RDB_ValuesBucket* valueBucket2 = RDB_CreateValuesBucket();
    VBUCKET_PutInt64(valueBucket2, "age", 300);
    errCode = RDB_Update(rdbStore_, valueBucket2, predicates1);
    std::cout << "rdb ndk update sql result is" << errCode << std::endl;

    RDB_Predicates *predicates2 = RDB_CreatePredicates("test");
    const char *columnNames[2] = {"id", "age"};
    RDB_Cursor *cursor = RDB_Query(rdbStore_, predicates2, columnNames, 2);
    EXPECT_NE(cursor, nullptr);
    errCode = CURSOR_GoToNextRow(cursor);
    std::cout << "rdb ndk GoToNextRow errCode " << errCode << std::endl;
    int rowCount=0;
    CURSOR_GetRowCount(cursor, &rowCount);
    std::cout << "rdb ndk rowCount is " << rowCount << std::endl;
    errCode = CURSOR_Close(cursor);
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
    RDB_Predicates *predicates = RDB_CreatePredicates(table);
    errCode = RDB_Delete(rdbStore_, predicates);
    std::cout << "rdb ndk delete sql result is" << errCode << std::endl;

    RDB_Transaction(rdbStore_);

    RDB_ValuesBucket* valueBucket = RDB_CreateValuesBucket();
    VBUCKET_PutInt64(valueBucket, "age", 10);
    errCode = RDB_Insert(rdbStore_, table, valueBucket);
    std::cout << "rdb ndk insert sql result is" << errCode << std::endl;

    RDB_ValuesBucket* valueBucket1 = RDB_CreateValuesBucket();
    VBUCKET_PutInt64(valueBucket1, "age", 20);
    errCode = RDB_Insert(rdbStore_, table, valueBucket1);
    std::cout << "rdb ndk insert sql result is" << errCode << std::endl;

    RDB_Commit(rdbStore_);

    RDB_Predicates *predicates2 = RDB_CreatePredicates("test");
    const char *columnNames[2] = {"id", "age"};
    RDB_Cursor *cursor = RDB_Query(rdbStore_, predicates2, columnNames, 2);
    EXPECT_NE(cursor, nullptr);
    errCode = CURSOR_GoToNextRow(cursor);
    std::cout << "rdb ndk GoToNextRow errCode " << errCode << std::endl;
    int rowCount=0;
    CURSOR_GetRowCount(cursor, &rowCount);
    std::cout << "rdb ndk rowCount is " << rowCount << std::endl;
    errCode = CURSOR_Close(cursor);
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
    RDB_Predicates *predicates = RDB_CreatePredicates(table);
    errCode = RDB_Delete(rdbStore_, predicates);
    std::cout << "rdb ndk delete sql result is" << errCode << std::endl;

    RDB_Transaction(rdbStore_);

    RDB_ValuesBucket *valueBucket = RDB_CreateValuesBucket();
    VBUCKET_PutInt64(valueBucket, "age", 10);
    errCode = RDB_Insert(rdbStore_, table, valueBucket);
    std::cout << "rdb ndk insert sql result is" << errCode << std::endl;

    RDB_ValuesBucket *valueBucket1 = RDB_CreateValuesBucket();
    VBUCKET_PutInt64(valueBucket1, "age", 20);
    errCode = RDB_Insert(rdbStore_, table, valueBucket1);
    std::cout << "rdb ndk insert sql result is" << errCode << std::endl;

    RDB_RollBack(rdbStore_);

    RDB_Predicates *predicates2 = RDB_CreatePredicates("test");
    const char *columnNames[2] = {"id", "age"};
    RDB_Cursor *cursor = RDB_Query(rdbStore_, predicates2, columnNames, 2);
    EXPECT_NE(cursor, nullptr);
    errCode = CURSOR_GoToNextRow(cursor);
    std::cout << "rdb ndk GoToNextRow errCode " << errCode << std::endl;
    int rowCount=0;
    CURSOR_GetRowCount(cursor, &rowCount);
    std::cout << "rdb ndk rowCount is " << rowCount << std::endl;
    errCode = CURSOR_Close(cursor);
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
    errCode = RDB_GetVersion(rdbStore_, &version);
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(version, 1);

    errCode = RDB_SetVersion(rdbStore_, setVersion);
    errCode = RDB_GetVersion(rdbStore_, &version);
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(version, 3);
    std::string storeName = RDB_TEST_PATH + "main.db";
    RDB_DeleteStore(storeName.c_str());
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
    RDB_Predicates *predicates = RDB_CreatePredicates(table);
    errCode = RDB_Delete(rdbStore_, predicates);
    std::cout << "rdb ndk delete sql result is" << errCode << std::endl;

    RDB_ValuesBucket *valueBucket = RDB_CreateValuesBucket();
    VBUCKET_PutInt64(valueBucket, "age", 10);
    errCode = RDB_Insert(rdbStore_, table, valueBucket);
    std::cout << "rdb ndk insert sql result is" << errCode << std::endl;

    RDB_Predicates *predicates2 = RDB_CreatePredicates("test");
    const char *columnNames[2] = {"id", "age"};
    RDB_Cursor *cursor = RDB_Query(rdbStore_, predicates2, columnNames, 2);
    EXPECT_NE(cursor, nullptr);
    errCode = CURSOR_GoToNextRow(cursor);
    EXPECT_EQ(errCode, 0);
    int rowCount=0;
    errCode = CURSOR_GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    errCode = CURSOR_Close(cursor);
    EXPECT_EQ(errCode, 0);

    std::string backupPath = RDB_TEST_PATH + "backup.db";
    errCode = RDB_Backup(rdbStore_, backupPath.c_str(), nullptr);
    EXPECT_EQ(errCode, 0);

    errCode = RDB_Restore(rdbStore_, backupPath.c_str(), nullptr);
    EXPECT_EQ(errCode, 0);

    cursor = RDB_Query(rdbStore_, predicates2, columnNames, 2);
    EXPECT_NE(cursor, nullptr);
    errCode = CURSOR_GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    errCode = CURSOR_Close(cursor);
    EXPECT_EQ(errCode, 0);
}