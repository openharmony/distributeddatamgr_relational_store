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
#include <sys/stat.h>
#include <sys/types.h>

#include "common.h"
#include "relational_store.h"
#include "relational_store_error_code.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbNativeAssetTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void InitRdbConfig()
    {
        config_.dataBaseDir = RDB_TEST_PATH;
        config_.storeName = "rdb_cursor_test.db";
        config_.bundleName = "";
        config_.moduleName = "";
        config_.securityLevel = OH_Rdb_SecurityLevel::S1;
        config_.isEncrypt = false;
        config_.area = Rdb_SecurityArea::RDB_SECURITY_AREA_EL1;
        config_.selfSize = sizeof(OH_Rdb_Config);
    }
    static void CreateAssetTable();
    static OH_Rdb_Config config_;
};

OH_Rdb_Store *assetTestRdbStore_;
OH_Rdb_Config RdbNativeAssetTest::config_ = { 0 };
void RdbNativeAssetTest::SetUpTestCase(void)
{
    InitRdbConfig();
    mkdir(config_.dataBaseDir, 0770);
    int errCode = 0;
    assetTestRdbStore_ = OH_Rdb_GetOrOpen(&config_, &errCode);
    EXPECT_NE(assetTestRdbStore_, NULL);
    CreateAssetTable();
}

void RdbNativeAssetTest::TearDownTestCase(void)
{
    char dropTableSql[] = "DROP TABLE IF EXISTS asset_table";
    int errCode = OH_Rdb_Execute(assetTestRdbStore_, dropTableSql);
    EXPECT_EQ(errCode, 0);
    delete assetTestRdbStore_;
    assetTestRdbStore_ = NULL;
    OH_Rdb_DeleteStore(&config_);
}

void RdbNativeAssetTest::SetUp(void) {}

void RdbNativeAssetTest::TearDown(void) {}

void RdbNativeAssetTest::CreateAssetTable()
{
    char createTableSql[] = "CREATE TABLE IF NOT EXISTS asset_table (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 "
                            "asset, data2 assets );";
    int errCode = OH_Rdb_Execute(assetTestRdbStore_, createTableSql);
    EXPECT_EQ(errCode, RDB_OK);
}

/**
 * @tc.name: RDB_Native_asset_test_001
 * @tc.desc: Abnormal testCase of asset for setName.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, RDB_Native_asset_test_001, TestSize.Level1)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    std::string name;
    name.append("name");
    int errcode = OH_Data_Asset_SetName(nullptr, nullptr);
    EXPECT_EQ(errcode, RDB_E_INVALID_ARGS);
    errcode = OH_Data_Asset_SetName(asset, nullptr);
    EXPECT_EQ(errcode, RDB_E_INVALID_ARGS);
    errcode = OH_Data_Asset_SetName(nullptr, name.c_str());
    EXPECT_EQ(errcode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_asset_test_002
 * @tc.desc: Abnormal testCase of asset for setUri.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, RDB_Native_asset_test_002, TestSize.Level1)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    std::string uri;
    uri.append("uri");
    int errcode = OH_Data_Asset_SetUri(nullptr, nullptr);
    EXPECT_EQ(errcode, RDB_E_INVALID_ARGS);
    errcode = OH_Data_Asset_SetUri(asset, nullptr);
    EXPECT_EQ(errcode, RDB_E_INVALID_ARGS);
    errcode = OH_Data_Asset_SetUri(nullptr, uri.c_str());
    EXPECT_EQ(errcode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_asset_test_003
 * @tc.desc: Abnormal testCase of asset for setPath.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, RDB_Native_asset_test_003, TestSize.Level1)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    std::string path;
    path.append("path");
    int errcode = OH_Data_Asset_SetPath(nullptr, nullptr);
    EXPECT_EQ(errcode, RDB_E_INVALID_ARGS);
    errcode = OH_Data_Asset_SetPath(asset, nullptr);
    EXPECT_EQ(errcode, RDB_E_INVALID_ARGS);
    errcode = OH_Data_Asset_SetPath(nullptr, path.c_str());
    EXPECT_EQ(errcode, RDB_E_INVALID_ARGS);
}