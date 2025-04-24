/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
#include <chrono>
#include "accesstoken_kit.h"
#include "common.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::RdbNdk;

static constexpr int64_t BASE_COUNT = 1000; // loop times
static constexpr int64_t RDB_INSERT_BASELINE = 3000;
static constexpr int64_t RDB_UPDATE_BASELINE = 3000;
static constexpr int64_t TRANS_INSERT_BASELINE = 3000;
static constexpr int64_t TRANS_UPDATE_BASELINE = 3000;
static constexpr int64_t RDB_ATTACH_BASELINE = 6000; // attach and detach two interfaces together.

class RdbPerformanceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void InitRdbConfig()
    {
        config_.dataBaseDir = RDB_TEST_PATH;
        config_.storeName = "rdb_store_test.db";
        config_.bundleName = "com.ohos.example.distributedndk";
        config_.moduleName = "";
        config_.securityLevel = OH_Rdb_SecurityLevel::S1;
        config_.isEncrypt = false;
        config_.selfSize = sizeof(OH_Rdb_Config);
        config_.area = RDB_SECURITY_AREA_EL1;
    }
    static OH_Rdb_Config config_;
    static void MockHap(void);
};

static OH_Rdb_Store *g_performanStore = nullptr;
static OH_RDB_TransOptions *g_options = nullptr;
OH_Rdb_Config RdbPerformanceTest::config_ = { 0 };

void RdbPerformanceTest::MockHap(void)
{
    HapInfoParams info = {
        .userID = 100,
        .bundleName = "com.example.distributed",
        .instIndex = 0,
        .appIDDesc = "com.example.distributed"
    };
    PermissionDef infoManagerTestPermDef = {
        .permissionName = "ohos.permission.test",
        .bundleName = "com.example.distributed",
        .grantMode = 1,
        .availableLevel = APL_NORMAL,
        .label = "label",
        .labelId = 1,
        .description = "open the door",
        .descriptionId = 1
    };
    PermissionStateFull infoManagerTestState = {
        .permissionName = "ohos.permission.test",
        .isGeneral = true,
        .resDeviceID = { "local" },
        .grantStatus = { PermissionState::PERMISSION_GRANTED },
        .grantFlags = { 1 }
    };
    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = { infoManagerTestPermDef },
        .permStateList = { infoManagerTestState }
    };
    AccessTokenKit::AllocHapToken(info, policy);
}

void RdbPerformanceTest::SetUpTestCase(void)
{
    MockHap();
    InitRdbConfig();
    // 0770 is permission
    mkdir(config_.dataBaseDir, 0770);
    int errCode = 0;
    g_performanStore = OH_Rdb_GetOrOpen(&config_, &errCode);
    EXPECT_NE(g_performanStore, NULL);

    g_options = OH_RdbTrans_CreateOptions();
    EXPECT_NE(g_options, nullptr);
    int ret = OH_RdbTransOption_SetType(g_options, RDB_TRANS_BUTT);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_RdbTransOption_SetType(g_options, RDB_TRANS_DEFERRED);
    EXPECT_EQ(ret, RDB_OK);
}

void RdbPerformanceTest::TearDownTestCase(void)
{
    int errCode = OH_Rdb_CloseStore(g_performanStore);
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_DeleteStore(&config_);
    EXPECT_EQ(errCode, 0);

    OH_RdbTrans_DestroyOptions(g_options);
    g_options = nullptr;
}

void RdbPerformanceTest::SetUp(void)
{
    char createTableSql[] = "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
        "data3 FLOAT, data4 BLOB, data5 TEXT);";
    int errCode = OH_Rdb_Execute(g_performanStore, createTableSql);
    EXPECT_EQ(errCode, 0);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    // 12800 test value.
    valueBucket->putInt64(valueBucket, "data2", 12800);
    // 100.1 test value.
    valueBucket->putReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = { 1, 2, 3, 4, 5 };
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(g_performanStore, "store_test", valueBucket);
    EXPECT_EQ(errCode, 1);

    char querySql[] = "SELECT * FROM store_test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(g_performanStore, querySql);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    cursor->destroy(cursor);
    valueBucket->destroy(valueBucket);
}

void RdbPerformanceTest::TearDown(void)
{
    char dropTableSql[] = "DROP TABLE IF EXISTS store_test";
    int errCode = OH_Rdb_Execute(g_performanStore, dropTableSql);
    EXPECT_EQ(errCode, 0);
}

/* *
 * @tc.name: Trans_InsertWithConflictResolution_test_001
 * @tc.desc: test OH_RdbTrans_InsertWithConflictResolution interface performance.
 * @tc.type: FUNC
 */
HWTEST_F(RdbPerformanceTest, Trans_InsertWithConflictResolution_test_001, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    const char *table = "store_test";
    int ret = OH_Rdb_CreateTransaction(g_performanStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putText(valueBucket, "data1", "test_name4");
    // init is data2 is 14800
    valueBucket->putInt64(valueBucket, "data2", 14800);
    // init is data2 is 300.1
    valueBucket->putReal(valueBucket, "data3", 300.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGHI");
    int64_t rowId = -1;

    auto now = std::chrono::system_clock::now().time_since_epoch();
    int64_t start = std::chrono::duration_cast<std::chrono::microseconds>(now).count();

    for (int i = 0; i < BASE_COUNT; i++) {
        ret = OH_RdbTrans_InsertWithConflictResolution(trans, table, valueBucket, RDB_CONFLICT_ROLLBACK, &rowId);
        EXPECT_EQ(ret, RDB_OK);
    }

    now = std::chrono::system_clock::now().time_since_epoch();
    int64_t summaryTime = (std::chrono::duration_cast<std::chrono::microseconds>(now).count() - start);
    int64_t averageTime = summaryTime / BASE_COUNT;

    EXPECT_LE(averageTime, RDB_INSERT_BASELINE);

    valueBucket->destroy(valueBucket);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/* *
 * @tc.name: Trans_UpdateWithConflictResolution_test_002
 * @tc.desc: test OH_RdbTrans_UpdateWithConflictResolution interface performance.
 * @tc.type: FUNC
 */
HWTEST_F(RdbPerformanceTest, Trans_UpdateWithConflictResolution_test_002, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    const char *table = "store_test";
    int ret = OH_Rdb_CreateTransaction(g_performanStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    // new row
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putText(valueBucket, "data1", "liSi");
    // init data2 value is 13800
    valueBucket->putInt64(valueBucket, "data2", 13800);
    // init data3 value is 200.1
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putNull(valueBucket, "data5");

    // create predicates
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table);
    // create match data
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);

    // update
    int64_t changes = -1;
    auto now = std::chrono::system_clock::now().time_since_epoch();
    int64_t start = std::chrono::duration_cast<std::chrono::microseconds>(now).count();

    for (int i = 0; i < BASE_COUNT; i++) {
        ret = OH_RdbTrans_UpdateWithConflictResolution(trans, valueBucket, predicates, RDB_CONFLICT_REPLACE, &changes);
        EXPECT_EQ(ret, RDB_OK);
    }

    now = std::chrono::system_clock::now().time_since_epoch();
    int64_t summaryTime = (std::chrono::duration_cast<std::chrono::microseconds>(now).count() - start);
    int64_t averageTime = summaryTime / BASE_COUNT;

    EXPECT_LE(averageTime, RDB_UPDATE_BASELINE);

    // destroy
    valueObject->destroy(valueObject);
    valueBucket->destroy(valueBucket);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/* *
 * @tc.name: RDB_InsertWithConflictResolution_test_003
 * @tc.desc: test OH_Rdb_InsertWithConflictResolution interface performance.
 * @tc.type: FUNC
 */
HWTEST_F(RdbPerformanceTest, RDB_InsertWithConflictResolution_test_003, TestSize.Level1)
{
    int ret = 0;
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800);
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGH");
    int64_t rowId = 0;

    auto now = std::chrono::system_clock::now().time_since_epoch();
    int64_t start = std::chrono::duration_cast<std::chrono::microseconds>(now).count();

    for (int i = 0; i < BASE_COUNT; i++) {
        ret = OH_Rdb_InsertWithConflictResolution(g_performanStore, "store_test", valueBucket, RDB_CONFLICT_ROLLBACK,
            &rowId);
        EXPECT_EQ(ret, RDB_OK);
    }

    now = std::chrono::system_clock::now().time_since_epoch();
    int64_t summaryTime = (std::chrono::duration_cast<std::chrono::microseconds>(now).count() - start);
    int64_t averageTime = summaryTime / BASE_COUNT;

    EXPECT_LE(averageTime, TRANS_INSERT_BASELINE);

    valueBucket->destroy(valueBucket);
}

/* *
 * @tc.name: RDB_UpdateWithConflictResolution_test_004
 * @tc.desc: test OH_Rdb_UpdateWithConflictResolution interface performance.
 * @tc.type: FUNC
 */
HWTEST_F(RdbPerformanceTest, RDB_UpdateWithConflictResolution_test_004, TestSize.Level1)
{
    int ret = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("store_test");
    EXPECT_NE(predicates, NULL);

    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    EXPECT_NE(valueObject, NULL);
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);

    predicates->equalTo(predicates, "data1", valueObject);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    EXPECT_NE(valueBucket, NULL);
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800);
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putNull(valueBucket, "data5");

    int64_t chgs = 0;
    auto now = std::chrono::system_clock::now().time_since_epoch();
    int64_t start = std::chrono::duration_cast<std::chrono::microseconds>(now).count();

    for (int i = 0; i < BASE_COUNT; i++) {
        ret = OH_Rdb_UpdateWithConflictResolution(g_performanStore, valueBucket, predicates, RDB_CONFLICT_ROLLBACK,
            &chgs);
        EXPECT_EQ(ret, RDB_OK);
    }

    now = std::chrono::system_clock::now().time_since_epoch();
    int64_t summaryTime = (std::chrono::duration_cast<std::chrono::microseconds>(now).count() - start);
    int64_t averageTime = summaryTime / BASE_COUNT;

    EXPECT_LE(averageTime, TRANS_UPDATE_BASELINE);

    valueObject->destroy(valueObject);
    valueBucket->destroy(valueBucket);
    predicates->destroy(predicates);
}

/* *
 * @tc.name: RDB_AttachAndDetach_test_005
 * @tc.desc: Normal testCase of OH_Rdb_InsertWithConflictResolution errcode.
 * @tc.type: FUNC
 */
HWTEST_F(RdbPerformanceTest, RDB_AttachAndDetach_test_005, TestSize.Level1)
{
    auto attachConfig = OH_Rdb_CreateConfig();
    ASSERT_NE(attachConfig, nullptr);
    OH_Rdb_SetDatabaseDir(attachConfig, RDB_TEST_PATH);
    OH_Rdb_SetStoreName(attachConfig, "rdb_attach_store_test.db");
    OH_Rdb_SetBundleName(attachConfig, "com.ohos.example.distributedndk");
    OH_Rdb_SetEncrypted(attachConfig, false);
    OH_Rdb_SetSecurityLevel(attachConfig, OH_Rdb_SecurityLevel::S1);
    OH_Rdb_SetArea(attachConfig, RDB_SECURITY_AREA_EL1);

    int errCode = 0;
    auto tmpStore = OH_Rdb_CreateOrOpen(attachConfig, &errCode);
    EXPECT_NE(tmpStore, NULL);
    OH_Rdb_CloseStore(tmpStore);

    size_t attachedNumber = 0;
    auto now = std::chrono::system_clock::now().time_since_epoch();
    int64_t start = std::chrono::duration_cast<std::chrono::microseconds>(now).count();
    for (int i = 0; i < BASE_COUNT; i++) {
        auto ret = OH_Rdb_Attach(g_performanStore, attachConfig, "rdb_attach_test", 3, &attachedNumber);
        EXPECT_EQ(ret, RDB_OK);

        ret = OH_Rdb_Detach(g_performanStore, "rdb_attach_test", 3, &attachedNumber);
        EXPECT_EQ(ret, RDB_OK);
    }

    now = std::chrono::system_clock::now().time_since_epoch();
    int64_t summaryTime = (std::chrono::duration_cast<std::chrono::microseconds>(now).count() - start);
    int64_t averageTime = summaryTime / BASE_COUNT;

    EXPECT_LE(averageTime, RDB_ATTACH_BASELINE);
}