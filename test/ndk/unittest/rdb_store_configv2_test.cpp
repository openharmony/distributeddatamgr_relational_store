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
