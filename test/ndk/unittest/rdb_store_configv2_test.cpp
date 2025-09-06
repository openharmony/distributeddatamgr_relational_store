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

class RdbNativeStoreConfigV2Test : public testing::Test {
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
};

void RdbNativeStoreConfigV2Test::SetUpTestCase(void)
{
}

void RdbNativeStoreConfigV2Test::TearDownTestCase(void)
{
}

void RdbNativeStoreConfigV2Test::SetUp(void)
{
}

void RdbNativeStoreConfigV2Test::TearDown(void)
{
}

/**
 * @tc.name: RDB_Native_store_test_001
 * @tc.desc: Normal testCase of store for Update、Query.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_001, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = 0;
    auto config = InitRdbConfig();
    auto storeConfigV2TestRdbStore = OH_Rdb_CreateOrOpen(config, &errCode);
    EXPECT_NE(storeConfigV2TestRdbStore, NULL);
    char createTableSql[] = "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(storeConfigV2TestRdbStore, createTableSql));
    char dropTableSql[] = "DROP TABLE IF EXISTS store_test";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(storeConfigV2TestRdbStore, dropTableSql));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(storeConfigV2TestRdbStore));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config));
    OH_Rdb_DestroyConfig(config);
}

void VdbTest002(const OH_Rdb_ConfigV2 *config)
{
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto store = OH_Rdb_CreateOrOpen(config, &errCode);
    EXPECT_NE(store, nullptr);

    char createTableSql[] = "CREATE TABLE t1(id INT PRIMARY KEY, repr floatvector(4));";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store, 0, createTableSql));

    int64_t trxId = 0;
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_BeginTransWithTrxId(store, &trxId));
    char insertSql[] = "INSERT INTO t1 VALUES(2, '[1, 2, 3, 4]');";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store, trxId, insertSql));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CommitByTrxId(store, trxId));

    char querySql[] = "SELECT * FROM t1;";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(store, querySql);
    EXPECT_NE(cursor, nullptr);
    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(1, rowCount);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, cursor->goToNextRow(cursor));
    int64_t intVal = 0;
    cursor->getInt64(cursor, 0, &intVal);
    EXPECT_EQ(2, intVal); // Expect to get 2 as the result
    cursor->destroy(cursor);

    char dropSql[] = "DROP TABLE IF EXISTS t1;";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store, 0, dropSql));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config));
}

HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_002, TestSize.Level1)
{
    auto config = InitRdbConfig();
    int errCode = OH_Rdb_SetDbType(config, RDB_CAYLEY);
    EXPECT_TRUE(((!OHOS::NativeRdb::IsUsingArkData()) && errCode == OH_Rdb_ErrCode::RDB_E_NOT_SUPPORTED) ||
                (OHOS::NativeRdb::IsUsingArkData() && errCode == OH_Rdb_ErrCode::RDB_OK));
    if (OHOS::NativeRdb::IsUsingArkData()) {
        VdbTest002(config);
    }
    OH_Rdb_DestroyConfig(config);
}

HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_003, TestSize.Level1)
{
    int numType = 0;
    const int *supportTypeList = OH_Rdb_GetSupportedDbType(&numType);
    EXPECT_NE(supportTypeList, nullptr);
    EXPECT_TRUE(((!OHOS::NativeRdb::IsUsingArkData()) && numType == 1) || // 1 means only contain RDB_SQLITE
        ((OHOS::NativeRdb::IsUsingArkData()) && numType == 2)); // 2 means both contain RDB_SQLITE and RDB_CAYLEY
    EXPECT_EQ(RDB_SQLITE, supportTypeList[0]);
    if (OHOS::NativeRdb::IsUsingArkData()) {
        EXPECT_EQ(RDB_CAYLEY, supportTypeList[1]); // 1st element must be RDB_CAYLEY
    }
}

HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_004, TestSize.Level1)
{
    auto config = InitRdbConfig();
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetDatabaseDir(config, nullptr));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetStoreName(config, nullptr));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetBundleName(config, nullptr));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetModuleName(config, nullptr));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetDatabaseDir(config, ""));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetStoreName(config, ""));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetBundleName(config, ""));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetModuleName(config, ""));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetEncrypted(config, false));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetEncrypted(config, true));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetSecurityLevel(config, S1));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetSecurityLevel(config, S2));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetSecurityLevel(config, S3));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetSecurityLevel(config, S4));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetSecurityLevel(config, 0));  // 0 is invalid secure level
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetSecurityLevel(config, -1)); // -1 is invalid secure level
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetSecurityLevel(config, 5));  // 5 is invalid secure level

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetArea(config, RDB_SECURITY_AREA_EL1));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetArea(config, RDB_SECURITY_AREA_EL2));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetArea(config, RDB_SECURITY_AREA_EL3));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetArea(config, RDB_SECURITY_AREA_EL4));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetArea(config, RDB_SECURITY_AREA_EL5));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetArea(config, -1)); // -1 is invalid area level
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetArea(config, 0));  // 0 is invalid area level
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetArea(config, 8));  // 8 is invalid area level

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetDbType(config, RDB_SQLITE));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetDbType(config, 0));  // 0 is invalid db type level
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetDbType(config, 6));  // 6 is invalid db type level
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetDbType(config, -1)); // -1 is invalid db type level
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetSemanticIndex(config, true));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetSemanticIndex(config, false));

    const int *supportList = OH_Rdb_GetSupportedDbType(nullptr);
    EXPECT_EQ(nullptr, supportList);

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_DestroyConfig(nullptr));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DestroyConfig(config));
}

void VdbTest003(const OH_Rdb_ConfigV2 *config)
{
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto store = OH_Rdb_CreateOrOpen(config, &errCode);
    EXPECT_NE(store, nullptr);

    char createTableSql[] = "CREATE TABLE t1(id INT PRIMARY KEY, repr floatvector(4));";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store, 0, createTableSql));

    char createIndexSql[] = "CREATE INDEX diskann_idx ON t1 USING GSDISKANN(repr L2);";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store, 0, createIndexSql));

    int64_t trxId = 0;
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_BeginTransWithTrxId(store, &trxId));
    char insertSql[] = "INSERT INTO t1 VALUES(1, '[1, 2, 3, 4]');";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store, trxId, insertSql));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CommitByTrxId(store, trxId));

    char insertSql2[] = "INSERT INTO t1 VALUES(2, '[2, 2, 3, 4]');";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store, 0, insertSql2));

    char deleteSql[] = "DELETE FROM t1 WHERE id = 1;";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store, 0, deleteSql));

    char dropSql[] = "DROP TABLE IF EXISTS t1;";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store, 0, dropSql));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config));
}

HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_005, TestSize.Level1)
{
    auto config = InitRdbConfig();
    int errCode = OH_Rdb_SetDbType(config, RDB_CAYLEY);
    EXPECT_TRUE(((!OHOS::NativeRdb::IsUsingArkData()) && errCode == OH_Rdb_ErrCode::RDB_E_NOT_SUPPORTED) ||
                (OHOS::NativeRdb::IsUsingArkData() && errCode == OH_Rdb_ErrCode::RDB_OK));
    if (OHOS::NativeRdb::IsUsingArkData()) {
        VdbTest003(config);
    }
    OH_Rdb_DestroyConfig(config);
}

string GetRandVector(uint32_t maxElementNum, uint16_t dim)
{
    auto now = std::chrono::high_resolution_clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    unsigned int randomNumberSeed = static_cast<unsigned int>(ns);
    std::string res = "[";
    for (uint16_t i = 0; i < dim; i++) {
        uint32_t intPart = maxElementNum == 0 ? 0 : (rand_r(&randomNumberSeed) % maxElementNum);
        intPart += 1;
        // 10 is used to limit the number after the decimal point to a maximum of 10.
        uint32_t tenths = (rand_r(&randomNumberSeed) % 10);
        res += std::to_string(intPart);
        res += ".000";
        res += std::to_string(tenths);
        res += ", ";
    }
    res.pop_back();
    res.pop_back();
    res += "]";
    return res;
}

void VdbTest004(const OH_Rdb_ConfigV2 *config)
{
    int errCode = OH_Rdb_ErrCode::RDB_OK;
    auto store = OH_Rdb_CreateOrOpen(config, &errCode);
    EXPECT_NE(store, nullptr);

    char createTableSql[] = "CREATE TABLE t1(id INT PRIMARY KEY, repr floatvector(4));";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store, 0, createTableSql));

    char createIndexSql[] = "CREATE INDEX diskann_idx ON t1 USING GSDISKANN(repr L2);";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store, 0, createIndexSql));

    uint32_t maxIntPart = 100;
    uint32_t numSamples = 100;
    uint32_t dim = 4;

    for (uint16_t i = 0; i < numSamples; i++) {
        std::string sqlInsert =
            "INSERT INTO t1 VALUES(" + std::to_string(i) + ", '" + GetRandVector(maxIntPart, dim) + "');";
        EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store, 0, sqlInsert.data()));
    }
    for (uint16_t i = 0; i < numSamples; i++) {
        std::string sqlDelete = "DELETE FROM t1 WHERE id = " + std::to_string(i) + ";";
        EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store, 0, sqlDelete.data()));
    }

    char dropSql[] = "DROP TABLE IF EXISTS t1;";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_ExecuteByTrxId(store, 0, dropSql));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config));
}

HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_006, TestSize.Level1)
{
    auto config = InitRdbConfig();
    int errCode = OH_Rdb_SetDbType(config, RDB_CAYLEY);
    EXPECT_TRUE(((!OHOS::NativeRdb::IsUsingArkData()) && errCode == OH_Rdb_ErrCode::RDB_E_NOT_SUPPORTED) ||
                (OHOS::NativeRdb::IsUsingArkData() && errCode == OH_Rdb_ErrCode::RDB_OK));
    if (OHOS::NativeRdb::IsUsingArkData()) {
        VdbTest004(config);
    }
    OH_Rdb_DestroyConfig(config);
}

HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_007, TestSize.Level1)
{
    auto config = InitRdbConfig();
    int errCode = OH_Rdb_SetPersistent(config, true);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);
    errCode = OH_Rdb_SetPersistent(config, false);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);
    OH_Rdb_DestroyConfig(config);
}

/**
 * @tc.name: RDB_Native_store_test_008
 * @tc.desc: invalid args test.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_008, TestSize.Level1)
{
    int errCode = 0;
    auto config = InitRdbConfig();
    EXPECT_EQ(OH_Rdb_DeleteStoreV2(nullptr), OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    EXPECT_EQ(OH_Rdb_CreateOrOpen(nullptr, &errCode), nullptr);
    EXPECT_EQ(OH_Rdb_CreateOrOpen(config, nullptr), nullptr);

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetPersistent(nullptr, true));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetTokenizer(nullptr, Rdb_Tokenizer::RDB_NONE_TOKENIZER));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetArea(nullptr, false));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetEncrypted(nullptr, false));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetDbType(nullptr, RDB_SQLITE));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetSecurityLevel(nullptr, S1));
    OH_Rdb_DestroyConfig(config);
}

/**
 * @tc.name: RDB_ICU_TEST001
 * @tc.desc: test apis of icu
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_ICU_TEST001, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    auto config = InitRdbConfig();

    // invalid param test
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS,
        OH_Rdb_SetTokenizer(config, static_cast<Rdb_Tokenizer>(Rdb_Tokenizer::RDB_NONE_TOKENIZER - 1)));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS,
        OH_Rdb_SetTokenizer(config, static_cast<Rdb_Tokenizer>(Rdb_Tokenizer::RDB_CUSTOM_TOKENIZER + 1)));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetTokenizer(config, Rdb_Tokenizer::RDB_NONE_TOKENIZER));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetTokenizer(config, Rdb_Tokenizer::RDB_CUSTOM_TOKENIZER));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetTokenizer(config, Rdb_Tokenizer::RDB_ICU_TOKENIZER));

    int numType = 0;
    const int *supportTypeList = OH_Rdb_GetSupportedDbType(&numType);
    EXPECT_NE(supportTypeList, nullptr);
    if (numType == 2) {
        EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetDbType(config, RDB_CAYLEY));
        EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_NOT_SUPPORTED,
            OH_Rdb_SetTokenizer(config, Rdb_Tokenizer::RDB_ICU_TOKENIZER));
    }

    OH_Rdb_DestroyConfig(config);
}

/**
 * @tc.name: RDB_ICU_TEST002
 * @tc.desc: test apis of icu
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_ICU_TEST002, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = 0;
    auto config = InitRdbConfig();

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetTokenizer(config, Rdb_Tokenizer::RDB_ICU_TOKENIZER));
    auto storeConfigV2TestRdbStore = OH_Rdb_CreateOrOpen(config, &errCode);
    EXPECT_NE(storeConfigV2TestRdbStore, NULL);

    char createTableSql[] = "CREATE VIRTUAL TABLE example USING fts4(name, content, tokenize=icu zh_CN);";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(storeConfigV2TestRdbStore, createTableSql));

    char insertSql1[] =
        "INSERT INTO example(name, content) VALUES('文档1', '这是一个测试文档，用于测试中文文本的分词和索引。');";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(storeConfigV2TestRdbStore, insertSql1));

    char insertSql2[] =
        "INSERT INTO example(name, content) VALUES('文档2', '我们将使用这个示例来演示如何在SQLite中进行全文搜索。');";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(storeConfigV2TestRdbStore, insertSql2));

    char insertSql3[] =
        "INSERT INTO example(name, content) VALUES('文档3', 'ICU分词器能够很好地处理中文文本的分词和分析。');";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(storeConfigV2TestRdbStore, insertSql3));

    char querySql[] = "SELECT * FROM example WHERE example MATCH '测试';";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(storeConfigV2TestRdbStore, querySql));

    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeConfigV2TestRdbStore, querySql);
    EXPECT_NE(cursor, nullptr);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, cursor->goToNextRow(cursor));

    int columnIndex = -1;
    errCode = cursor->getColumnIndex(cursor, "name", &columnIndex);
    EXPECT_EQ(columnIndex, 0);
    char name[10];
    errCode = cursor->getColumnName(cursor, columnIndex, name, 10);
    EXPECT_EQ(strcmp(name, "name"), 0);

    size_t size = 0;
    cursor->getSize(cursor, columnIndex, &size);
    char data1Value[size + 1];
    cursor->getText(cursor, columnIndex, data1Value, size + 1);
    EXPECT_EQ(strcmp(data1Value, "文档1"), 0);

    errCode = cursor->getColumnIndex(cursor, "content", &columnIndex);
    char name2[10];
    errCode = cursor->getColumnName(cursor, columnIndex, name2, 10);
    EXPECT_EQ(strcmp(name2, "content"), 0);

    cursor->getSize(cursor, columnIndex, &size);
    char data2Value[size + 1];
    cursor->getText(cursor, columnIndex, data2Value, size + 1);
    EXPECT_EQ(strcmp(data2Value, "这是一个测试文档，用于测试中文文本的分词和索引。"), 0);

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(storeConfigV2TestRdbStore));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config));
    OH_Rdb_DestroyConfig(config);
}

/**
 * @tc.name: RDB_Native_store_test_009
 * @tc.desc: test apis of config interface OH_Rdb_SetCustomDir.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_009, TestSize.Level1)
{
    const char *customDir = "test";
    auto ret = OH_Rdb_SetCustomDir(nullptr, customDir);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret =  OH_Rdb_SetCustomDir(nullptr, "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    OH_Rdb_ConfigV2 *confg = OH_Rdb_CreateConfig();
    EXPECT_NE(confg, nullptr);
    ret = OH_Rdb_SetCustomDir(confg, nullptr);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Rdb_SetCustomDir(confg, customDir);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Rdb_DestroyConfig(confg);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Native_store_test_010
 * @tc.desc: test apis of config interface OH_Rdb_SetReadOnly.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_010, TestSize.Level1)
{
    OH_Rdb_ConfigV2 *confg = OH_Rdb_CreateConfig();
    EXPECT_NE(confg, nullptr);

    auto ret = OH_Rdb_SetReadOnly(nullptr, true);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Rdb_SetReadOnly(confg, true);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Rdb_SetReadOnly(confg, false);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Rdb_DestroyConfig(confg);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Native_store_test_011
 * @tc.desc: test apis of config interface OH_Rdb_SetPlugins.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_011, TestSize.Level1)
{
    OH_Rdb_ConfigV2 *confg = OH_Rdb_CreateConfig();
    EXPECT_NE(confg, nullptr);

    const char *plugins[] = { "1" };
    auto ret = OH_Rdb_SetPlugins(nullptr, plugins, 1);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Rdb_SetPlugins(confg, nullptr, 1);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Rdb_SetPlugins(confg, plugins, 0);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Rdb_SetPlugins(confg, plugins, 1);
    EXPECT_EQ(ret, RDB_OK);

    const char *pluginsNew[] = { "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "0", "x" };
    ret = OH_Rdb_SetPlugins(confg, pluginsNew, sizeof(pluginsNew) / sizeof(pluginsNew[0]) - 1);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Rdb_SetPlugins(confg, pluginsNew, sizeof(pluginsNew) / sizeof(pluginsNew[0]));
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Rdb_DestroyConfig(confg);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Native_store_test_012
 * @tc.desc: test apis of config interface OH_Rdb_SetCryptoParam.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_012, TestSize.Level1)
{
    OH_Rdb_ConfigV2 *confg = OH_Rdb_CreateConfig();
    EXPECT_NE(confg, nullptr);

    OH_Rdb_CryptoParam *crypto = OH_Rdb_CreateCryptoParam();
    EXPECT_NE(crypto, NULL);

    auto ret = OH_Rdb_SetCryptoParam(nullptr, crypto);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Rdb_SetCryptoParam(confg, nullptr);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Rdb_SetCryptoParam(confg, crypto);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Rdb_DestroyCryptoParam(crypto);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Rdb_DestroyConfig(confg);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Native_store_test_013
 * @tc.desc: abnormal test of RdbNdkUtils::GetRdbStoreConfig, when config is null.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_013, TestSize.Level1)
{
    auto [errCode, rdbConfig] = RdbNdkUtils::GetRdbStoreConfig(nullptr);
    EXPECT_EQ(errCode, OHOS::NativeRdb::E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_store_test_014
 * @tc.desc: abnormal test of RdbNdkUtils::GetRdbStoreConfig, when securityLevel overlimit.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_014, TestSize.Level1)
{
    OH_Rdb_ConfigV2 *config = OH_Rdb_CreateConfig();
    EXPECT_NE(config, nullptr);
    std::shared_ptr<const char> autoRelease = std::shared_ptr<const char>("RDB_Native_store_test_014",
        [config](const char *) {
            OH_Rdb_DestroyConfig(config);
        });
    EXPECT_EQ(OH_Rdb_SetDatabaseDir(config, RDB_TEST_PATH), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetStoreName(config, "rdb_store_test.db"), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetBundleName(config, "com.ohos.example.distributedndk"), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetPersistent(config, true), RDB_OK);
    config->securityLevel = -1;
    auto [errCode1, _] = RdbNdkUtils::GetRdbStoreConfig(config);
    EXPECT_EQ(errCode1, OHOS::NativeRdb::E_INVALID_ARGS);

    config->securityLevel = 10;
    auto [errCode2, __] = RdbNdkUtils::GetRdbStoreConfig(config);
    EXPECT_EQ(errCode2, OHOS::NativeRdb::E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_store_test_015
 * @tc.desc: abnormal test of RdbNdkUtils::GetRdbStoreConfig, when securityLevel overlimit.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_015, TestSize.Level1)
{
    OH_Rdb_ConfigV2 *config = OH_Rdb_CreateConfig();
    EXPECT_NE(config, nullptr);
    std::shared_ptr<const char> autoRelease = std::shared_ptr<const char>("RDB_Native_store_test_015",
        [config](const char *) {
            OH_Rdb_DestroyConfig(config);
        });
    EXPECT_EQ(OH_Rdb_SetDatabaseDir(config, RDB_TEST_PATH), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetStoreName(config, "rdb_store_test.db"), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetBundleName(config, "com.ohos.example.distributedndk"), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetPersistent(config, false), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetSecurityLevel(config, S1), RDB_OK);
    config->area = -1;
    auto [errCode1, _] = RdbNdkUtils::GetRdbStoreConfig(config);
    EXPECT_EQ(errCode1, OHOS::NativeRdb::E_INVALID_ARGS);

    config->area = 10;
    auto [errCode2, __] = RdbNdkUtils::GetRdbStoreConfig(config);
    EXPECT_EQ(errCode2, OHOS::NativeRdb::E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_store_test_016
 * @tc.desc: abnormal test of RdbNdkUtils::GetRdbStoreConfig, when dbType overlimit.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_016, TestSize.Level1)
{
    OH_Rdb_ConfigV2 *config = OH_Rdb_CreateConfig();
    EXPECT_NE(config, nullptr);
    std::shared_ptr<const char> autoRelease = std::shared_ptr<const char>("RDB_Native_store_test_016",
        [config](const char *) {
            OH_Rdb_DestroyConfig(config);
        });
    EXPECT_EQ(OH_Rdb_SetDatabaseDir(config, RDB_TEST_PATH), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetStoreName(config, "rdb_store_test.db"), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetBundleName(config, "com.ohos.example.distributedndk"), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetPersistent(config, true), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetSecurityLevel(config, S1), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetArea(config, RDB_SECURITY_AREA_EL1), RDB_OK);
    config->dbType = -1;
    auto [errCode1, _] = RdbNdkUtils::GetRdbStoreConfig(config);
    EXPECT_EQ(errCode1, OHOS::NativeRdb::E_INVALID_ARGS);

    config->dbType = 10;
    auto [errCode2, __] = RdbNdkUtils::GetRdbStoreConfig(config);
    EXPECT_EQ(errCode2, OHOS::NativeRdb::E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_store_test_017
 * @tc.desc: abnormal test of RdbNdkUtils::GetRdbStoreConfig, when token overlimit.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_017, TestSize.Level1)
{
    OH_Rdb_ConfigV2 *config = OH_Rdb_CreateConfig();
    EXPECT_NE(config, nullptr);
    std::shared_ptr<const char> autoRelease = std::shared_ptr<const char>("RDB_Native_store_test_017",
        [config](const char *) {
            OH_Rdb_DestroyConfig(config);
        });
    EXPECT_EQ(OH_Rdb_SetDatabaseDir(config, RDB_TEST_PATH), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetStoreName(config, "rdb_store_test.db"), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetBundleName(config, "com.ohos.example.distributedndk"), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetPersistent(config, true), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetSecurityLevel(config, S1), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetArea(config, RDB_SECURITY_AREA_EL1), RDB_OK);
    config->token = -1;
    auto [errCode1, _] = RdbNdkUtils::GetRdbStoreConfig(config);
    EXPECT_EQ(errCode1, OHOS::NativeRdb::E_INVALID_ARGS);

    config->token = 10;
    auto [errCode2, __] = RdbNdkUtils::GetRdbStoreConfig(config);
    EXPECT_EQ(errCode2, OHOS::NativeRdb::E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_store_test_018
 * @tc.desc: abnormal test of RdbNdkUtils::GetRdbStoreConfig, when magicNum error.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_018, TestSize.Level1)
{
    OH_Rdb_ConfigV2 *config = OH_Rdb_CreateConfig();
    EXPECT_NE(config, nullptr);
    std::shared_ptr<const char> autoRelease = std::shared_ptr<const char>("RDB_Native_store_test_018",
        [config](const char *) {
            OH_Rdb_DestroyConfig(config);
        });
    EXPECT_EQ(OH_Rdb_SetDatabaseDir(config, RDB_TEST_PATH), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetStoreName(config, "rdb_store_test.db"), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetBundleName(config, "com.ohos.example.distributedndk"), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetPersistent(config, true), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetSecurityLevel(config, S1), RDB_OK);
    EXPECT_EQ(OH_Rdb_SetArea(config, RDB_SECURITY_AREA_EL1), RDB_OK);
    config->magicNum = 0;
    auto [errCode1, _] = RdbNdkUtils::GetRdbStoreConfig(config);
    EXPECT_EQ(errCode1, OHOS::NativeRdb::E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_store_test_019
 * @tc.desc: abnormal test of RdbNdkUtils::GetRdbStoreConfig, when magicNum error.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_019, TestSize.Level1)
{
    OH_Rdb_ConfigV2 *config = OH_Rdb_CreateConfig();
    EXPECT_NE(config, nullptr);
    std::shared_ptr<const char> autoRelease = std::shared_ptr<const char>("RDB_Native_store_test_019",
        [config](const char *) {
            OH_Rdb_DestroyConfig(config);
        });
    EXPECT_EQ(OH_Rdb_SetSemanticIndex(config, true), RDB_OK);
    EXPECT_NE(OH_Rdb_SetSemanticIndex(nullptr, true), RDB_OK);
}

/**
 * @tc.name: RDB_Native_store_test_020
 * @tc.desc: abnormal test of OH_Rdb_SetModuleName,
 * when config or modleName is nullptr or magicNum is not RDB_CONFIG_V2_MAGIC_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_020, TestSize.Level1)
{
    OH_Rdb_ConfigV2 *config = OH_Rdb_CreateConfig();
    EXPECT_NE(config, nullptr);

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetModuleName(nullptr, "entry"));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetModuleName(config, nullptr));

    config->magicNum = 0;
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_E_INVALID_ARGS, OH_Rdb_SetModuleName(config, "entry"));
    OH_Rdb_DestroyConfig(config);
}

/**
 * @tc.name: RDB_Native_store_test_021
 * @tc.desc: normal test of config,
 * open encrypted database when moduleName is "entry" and close store, expected success,
 * open non-encrypted database when moduleName is "entry" and close store, expected success,
 * open non-encrypted database when moduleName is "entry1" and close store, expected fail.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_021, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;

    auto config1 = InitRdbConfig();
    OH_Rdb_SetEncrypted(config1, true);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetModuleName(config1, "entry"));
    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);

    char createTableSql[] = "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));

    auto config2 = InitRdbConfig();
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetModuleName(config2, "entry"));
    auto store2 = OH_Rdb_CreateOrOpen(config2, &errCode);
    EXPECT_NE(store2, NULL);

    char dropTableSql[] = "DROP TABLE store_test";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, dropTableSql));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2));

    auto config3 = InitRdbConfig();
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetModuleName(config3, "entry1"));
    auto store3 = OH_Rdb_CreateOrOpen(config3, &errCode);
    EXPECT_EQ(store3, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
    OH_Rdb_DestroyConfig(config2);
    OH_Rdb_DestroyConfig(config3);
}

/**
 * @tc.name: RDB_Native_store_test_022
 * @tc.desc: normal test of config,
 * open database when moduleName is "", expected success,
 * open database when moduleName is "entry", expected success.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_022, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;

    auto config1 = InitRdbConfig();
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetModuleName(config1, ""));
    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);

    char createTableSql[] = "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));

    auto config2 = InitRdbConfig();
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetModuleName(config2, "entry"));
    auto store2 = OH_Rdb_CreateOrOpen(config2, &errCode);
    EXPECT_NE(store2, NULL);

    char dropTableSql[] = "DROP TABLE store_test";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, dropTableSql));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
    OH_Rdb_DestroyConfig(config2);
}

/**
 * @tc.name: RDB_Native_store_test_023
 * @tc.desc: normal test of config,
 * open database when moduleName is "entry", expected success,
 * open database when moduleName is "entry1", expected success.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_023, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;

    auto config1 = InitRdbConfig();
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetModuleName(config1, "entry"));
    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);

    char createTableSql[] = "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));

    auto config2 = InitRdbConfig();
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetModuleName(config2, "entry1"));
    auto store2 = OH_Rdb_CreateOrOpen(config2, &errCode);
    EXPECT_NE(store2, NULL);

    char dropTableSql[] = "DROP TABLE store_test";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, dropTableSql));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
    OH_Rdb_DestroyConfig(config2);
}

/**
 * @tc.name: RDB_Native_store_test_024
 * @tc.desc: normal test of config,
 * open encrypted database when moduleName is "", expected success,
 * open non-encrypted database when moduleName is "entry", expected success.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_024, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;

    auto config1 = InitRdbConfig();
    OH_Rdb_SetEncrypted(config1, true);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetModuleName(config1, ""));
    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);

    char createTableSql[] = "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));

    auto config2 = InitRdbConfig();
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetModuleName(config2, "entry"));
    auto store2 = OH_Rdb_CreateOrOpen(config2, &errCode);
    EXPECT_NE(store2, NULL);

    char dropTableSql[] = "DROP TABLE store_test";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, dropTableSql));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
    OH_Rdb_DestroyConfig(config2);
}

/**
 * @tc.name: RDB_Native_store_test_025
 * @tc.desc: normal test of config,
 * open encrypted database when moduleName is "entry", expected success,
 * open non-encrypted database when moduleName is "entry1", expected success.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_025, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    int errCode = OH_Rdb_ErrCode::RDB_OK;

    auto config1 = InitRdbConfig();
    OH_Rdb_SetEncrypted(config1, true);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetModuleName(config1, "entry"));
    auto store1 = OH_Rdb_CreateOrOpen(config1, &errCode);
    EXPECT_NE(store1, NULL);

    char createTableSql[] = "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1, createTableSql));

    auto config2 = InitRdbConfig();
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetModuleName(config2, "entry1"));
    auto store2 = OH_Rdb_CreateOrOpen(config2, &errCode);
    EXPECT_NE(store2, NULL);

    char dropTableSql[] = "DROP TABLE store_test";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2, dropTableSql));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStoreV2(config1));
    OH_Rdb_DestroyConfig(config1);
    OH_Rdb_DestroyConfig(config2);
}

/**
 * @tc.name: RDB_Native_store_test_026
 * @tc.desc: normal test of OH_Rdb_SetModuleName,
   check the properties of RdbStoreConfig are consistent with OH_Rdb_ConfigV2.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreConfigV2Test, RDB_Native_store_test_026, TestSize.Level1)
{
    mkdir(RDB_TEST_PATH, 0770);
    auto config1 = InitRdbConfig();
    OH_Rdb_SetEncrypted(config1, true);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_SetModuleName(config1, "entry2"));
    auto [ret, rdbStoreConfig] = RdbNdkUtils::GetRdbStoreConfig(config1);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, ret);
    EXPECT_EQ(rdbStoreConfig.GetName(), "rdb_store_test.db");
    EXPECT_EQ(rdbStoreConfig.GetBundleName(), "com.ohos.example.distributedndk");
    EXPECT_EQ(rdbStoreConfig.GetModuleName(), "entry2");
    EXPECT_EQ(rdbStoreConfig.IsEncrypt(), true);
    EXPECT_EQ(rdbStoreConfig.GetSecurityLevel(), SecurityLevel::S1);
    EXPECT_EQ(rdbStoreConfig.GetArea(), 1);
    EXPECT_EQ(rdbStoreConfig.GetDBType(), DB_SQLITE);
    EXPECT_EQ(rdbStoreConfig.GetTokenizer(), NONE_TOKENIZER);
    EXPECT_EQ(rdbStoreConfig.GetCustomDir(), "");
    EXPECT_EQ(rdbStoreConfig.IsReadOnly(), false);
    OH_Rdb_DestroyConfig(config1);
}