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

#include "accesstoken_kit.h"
#include "common.h"
#include "oh_data_value.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::RdbNdk;

class RdbStoreConfigTest : public testing::Test {
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
        config_.securityLevel = OH_Rdb_SecurityLevel::S1;
        config_.isEncrypt = false;
        config_.selfSize = sizeof(OH_Rdb_Config);
        config_.area = RDB_SECURITY_AREA_EL1;
    }
    static void InitRdbConfig1()
    {
        config1_.dataBaseDir = RDB_TEST_PATH;
        config1_.storeName = "rdb_store_test.db";
        config1_.bundleName = "com.ohos.example.distributedndk";
        config1_.moduleName = "";
        config1_.securityLevel = OH_Rdb_SecurityLevel::S1;
        config1_.isEncrypt = false;
        config1_.selfSize = sizeof(OH_Rdb_Config);
        config1_.area = RDB_SECURITY_AREA_EL1;
    }
    static void InitRdbConfig2()
    {
        config2_.dataBaseDir = RDB_TEST_PATH;
        config2_.storeName = "rdb_store_test.db";
        config2_.bundleName = "com.ohos.example.distributedndk";
        config2_.moduleName = "";
        config2_.securityLevel = OH_Rdb_SecurityLevel::S1;
        config2_.isEncrypt = false;
        config2_.selfSize = sizeof(OH_Rdb_Config);
        config2_.area = RDB_SECURITY_AREA_EL1;
    }
    static void InitRdbConfig3()
    {
        config3_.dataBaseDir = RDB_TEST_PATH;
        config3_.storeName = "rdb_store_test.db";
        config3_.bundleName = "com.ohos.example.distributedndk";
        config3_.moduleName = "";
        config3_.securityLevel = OH_Rdb_SecurityLevel::S1;
        config3_.isEncrypt = false;
        config3_.selfSize = sizeof(OH_Rdb_Config);
        config3_.area = RDB_SECURITY_AREA_EL1;
    }
    static OH_Rdb_Config config_;
    static OH_Rdb_Config config1_;
    static OH_Rdb_Config config2_;
    static OH_Rdb_Config config3_;
    static void MockHap(void);
};

OH_Rdb_Store *store1_;
OH_Rdb_Store *store2_;
OH_Rdb_Config RdbStoreConfigTest::config_ = { 0 };
OH_Rdb_Config RdbStoreConfigTest::config1_ = { 0 };
OH_Rdb_Config RdbStoreConfigTest::config2_ = { 0 };
OH_Rdb_Config RdbStoreConfigTest::config3_ = { 0 };

void RdbStoreConfigTest::SetUpTestCase(void)
{
}

void RdbStoreConfigTest::TearDownTestCase(void)
{
}

void RdbStoreConfigTest::SetUp(void)
{
    InitRdbConfig1();
    InitRdbConfig2();
}

void RdbStoreConfigTest::TearDown(void)
{
}

/**
 * @tc.name: RDB_store_config_test_001
 * @tc.desc: normal test of config, open the same database
   when moduleName is "entry" and encrypt is true, or moduleName is "entry" and encrypt is false,
   or moduleName is "entry1" and encrypt is false.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RDB_store_config_test_001, TestSize.Level1)
{
    mkdir(config1_.dataBaseDir, 0770);
    mkdir(config2_.dataBaseDir, 0770);

    int errCode = 0;
    config1_.moduleName = "entry";
    config1_.isEncrypt = true;
    store1_ = OH_Rdb_GetOrOpen(&config1_, &errCode);
    EXPECT_NE(store1_, NULL);

    char createTableSql[] = "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1_, createTableSql));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1_));

    config2_.moduleName = "entry";
    store2_ = OH_Rdb_GetOrOpen(&config2_, &errCode);
    EXPECT_NE(store2_, NULL);

    char dropTableSql[] = "DROP TABLE store_test";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2_, dropTableSql));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2_));

    InitRdbConfig3();
    config3_.moduleName = "entry1";
    OH_Rdb_Store *store3 = OH_Rdb_GetOrOpen(&config3_, &errCode);
    EXPECT_EQ(store3, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStore(&config1_));
}

/**
 * @tc.name: RDB_store_config_test_002
 * @tc.desc: normal test of config, open the same database when moduleName is "" or "entry".
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RDB_store_config_test_002, TestSize.Level1)
{
    mkdir(config1_.dataBaseDir, 0770);
    mkdir(config2_.dataBaseDir, 0770);

    int errCode = 0;
    store1_ = OH_Rdb_GetOrOpen(&config1_, &errCode);
    EXPECT_NE(store1_, NULL);

    char createTableSql[] = "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1_, createTableSql));

    config2_.moduleName = "entry";
    store2_ = OH_Rdb_GetOrOpen(&config2_, &errCode);
    EXPECT_NE(store2_, NULL);

    char dropTableSql[] = "DROP TABLE store_test";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2_, dropTableSql));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1_));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2_));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStore(&config1_));
}

/**
 * @tc.name: RDB_store_config_test_003
 * @tc.desc: normal test of config, open the same database when moduleName is "entry" or "entry1".
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RDB_store_config_test_003, TestSize.Level1)
{
    mkdir(config1_.dataBaseDir, 0770);
    mkdir(config2_.dataBaseDir, 0770);

    int errCode = 0;
    config1_.moduleName = "entry";
    store1_ = OH_Rdb_GetOrOpen(&config1_, &errCode);
    EXPECT_NE(store1_, NULL);

    char createTableSql[] = "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1_, createTableSql));

    config2_.moduleName = "entry1";
    store2_ = OH_Rdb_GetOrOpen(&config2_, &errCode);
    EXPECT_NE(store2_, NULL);

    char dropTableSql[] = "DROP TABLE store_test";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2_, dropTableSql));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1_));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2_));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStore(&config1_));
}

/**
 * @tc.name: RDB_store_config_test_004
 * @tc.desc: normal test of config, open the same database
   when moduleName is "" and encrypt is true, or moduleName is "entry" and encrypt is false.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RDB_store_config_test_004, TestSize.Level1)
{
    mkdir(config1_.dataBaseDir, 0770);
    mkdir(config2_.dataBaseDir, 0770);

    int errCode = 0;
    config1_.isEncrypt = true;
    store1_ = OH_Rdb_GetOrOpen(&config1_, &errCode);
    EXPECT_NE(store1_, NULL);

    char createTableSql[] = "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1_, createTableSql));

    config2_.moduleName = "entry";
    store2_ = OH_Rdb_GetOrOpen(&config2_, &errCode);
    EXPECT_NE(store2_, NULL);

    char dropTableSql[] = "DROP TABLE store_test";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2_, dropTableSql));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1_));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2_));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStore(&config1_));
}

/**
 * @tc.name: RDB_store_config_test_005
 * @tc.desc: normal test of config, open the same database
   when moduleName is "entry" and encrypt is true, or moduleName is "entry1" and encrypt is false.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RDB_store_config_test_005, TestSize.Level1)
{
    mkdir(config1_.dataBaseDir, 0770);
    mkdir(config2_.dataBaseDir, 0770);

    int errCode = 0;
    config1_.moduleName = "entry";
    config1_.isEncrypt = true;
    store1_ = OH_Rdb_GetOrOpen(&config1_, &errCode);
    EXPECT_NE(store1_, NULL);

    char createTableSql[] = "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1_, createTableSql));

    config2_.moduleName = "entry1";
    store2_ = OH_Rdb_GetOrOpen(&config2_, &errCode);
    EXPECT_NE(store2_, NULL);

    char dropTableSql[] = "DROP TABLE store_test";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2_, dropTableSql));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1_));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2_));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStore(&config1_));
}

/**
 * @tc.name: RDB_store_config_test_006
 * @tc.desc: normal test of config, when moduleName is nullptr, or moduleName is "entry1" and encrypt is false.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RDB_store_config_test_006, TestSize.Level1)
{
    InitRdbConfig();
    mkdir(config_.dataBaseDir, 0770);

    int errCode = 0;
    EXPECT_EQ(config_.moduleName, nullptr);
    store1_ = OH_Rdb_GetOrOpen(&config_, &errCode);
    EXPECT_NE(store1_, NULL);

    char createTableSql[] = "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store1_, createTableSql));

    config2_.moduleName = "entry1";
    store2_ = OH_Rdb_GetOrOpen(&config2_, &errCode);
    EXPECT_NE(store2_, NULL);

    char dropTableSql[] = "DROP TABLE store_test";
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_Execute(store2_, dropTableSql));

    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store1_));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_CloseStore(store2_));
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, OH_Rdb_DeleteStore(&config_));
}