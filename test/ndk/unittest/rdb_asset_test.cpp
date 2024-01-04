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
        config_.storeName = "rdb_asset_test.db";
        config_.bundleName = "com.ohos.example.distributedndk";
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
    //0770表示文件拥有者及其所在群组成员有对该文件读写的权限
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
    errCode = OH_Rdb_CloseStore(assetTestRdbStore_);
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_DeleteStore(&config_);
    EXPECT_EQ(errCode, 0);
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
 * @tc.number: RDB_Native_asset_test_001
 * @tc.name: Abnormal testCase of asset for setName.
 * @tc.desc: 1.Create asset
 *           2.Execute SetName (nullptr, nullptr)
 *           3.Execute SetName (asset, nullptr)
 *           4.Execute SetName (nullptr, name.c_str())
 *           5.Destroy asset
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, Abnormal_testCase_of_asset_for_setName, TestSize.Level1)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    int errCode = OH_Data_Asset_SetName(nullptr, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Data_Asset_SetName(asset, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Data_Asset_SetName(nullptr, "name");
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    OH_Data_Asset_DestroyOne(asset);
}

/**
 * @tc.number: RDB_Native_asset_test_002
 * @tc.name: Abnormal testCase of asset for setUri.
 * @tc.desc: 1.Create asset
 *           2.Execute SetUri (nullptr, nullptr)
 *           3.Execute SetUri (asset, nullptr)
 *           4.Execute SetUri (nullptr, uri.c_str())
 *           5.Destroy asset
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, Abnormal_testCase_of_asset_for_setUri, TestSize.Level1)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    int errCode = OH_Data_Asset_SetUri(nullptr, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Data_Asset_SetUri(asset, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Data_Asset_SetUri(nullptr, "uri");
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    OH_Data_Asset_DestroyOne(asset);
}

/**
 * @tc.number: RDB_Native_asset_test_003
 * @tc.name: Abnormal testCase of asset for setPath.
 * @tc.desc: 1.Create asset
 *           2.Execute SetPath (nullptr, nullptr)
 *           3.Execute SetPath (asset, nullptr)
 *           4.Execute SetPath (nullptr, path.c_str())
 *           5.Destroy asset
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, Abnormal_testCase_of_asset_for_setPath, TestSize.Level1)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    int errCode = OH_Data_Asset_SetPath(nullptr, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Data_Asset_SetPath(asset, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Data_Asset_SetPath(nullptr, "path");
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    OH_Data_Asset_DestroyOne(asset);
}

/**
 * @tc.number: RDB_Native_asset_test_004
 * @tc.name: Abnormal testCase of asset for setCreateTime, setModifyTime, setSize, setStatus.
 * @tc.desc: 1.Execute SetCreateTime (nullptr, 1)
 *           2.Execute SetModifyTime (nullptr, 1)
 *           3.Execute SetSize (nullptr, 1)
 *           4.Execute SetStatus (nullptr, Data_AssetStatus::ASSET_NORMAL)
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, Abnormal_testCase_for_setCreateTime_setModifyTime_setSize_setStatus, TestSize.Level1)
{
    int errCode = OH_Data_Asset_SetCreateTime(nullptr, 1);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Data_Asset_SetModifyTime(nullptr, 1);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Data_Asset_SetSize(nullptr, 1);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Data_Asset_SetStatus(nullptr, Data_AssetStatus::ASSET_NORMAL);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.number: RDB_Native_asset_test_005
 * @tc.name: Abnormal testCase of asset for getName.
 * @tc.desc: 1.Create asset
 *           2.Execute GetName (asset == nullptr)
 *           3.Execute GetName (nameLength >= *length)
 *           4.Destroy asset
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, Abnormal_testCase_of_asset_for_getName, TestSize.Level1)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    int errCode = OH_Data_Asset_SetName(asset, "name");
    EXPECT_EQ(errCode, RDB_OK);
    char name[10] = "";
    size_t nameLength = 10;
    errCode = OH_Data_Asset_GetName(nullptr, name, &nameLength);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    errCode = OH_Data_Asset_SetName(asset, "0123456789");
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Data_Asset_GetName(asset, name, &nameLength);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    OH_Data_Asset_DestroyOne(asset);
}

/**
 * @tc.number: RDB_Native_asset_test_006
 * @tc.name: Abnormal testCase of asset for getUri.
 * @tc.desc: 1.Create asset
 *           2.Execute GetUri (asset == nullptr)
 *           3.Execute GetUri (uriLength >= *length)
 *           4.Destroy asset
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, Abnormal_testCase_of_asset_for_getUri, TestSize.Level1)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    int errCode = OH_Data_Asset_SetUri(asset, "uri");
    EXPECT_EQ(errCode, RDB_OK);
    char uri[10] = "";
    size_t uriLength = 10;
    errCode = OH_Data_Asset_GetUri(nullptr, uri, &uriLength);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    errCode = OH_Data_Asset_SetUri(asset, "0123456789");
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Data_Asset_GetUri(asset, uri, &uriLength);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    OH_Data_Asset_DestroyOne(asset);
}

/**
 * @tc.number: RDB_Native_asset_test_007
 * @tc.name: Abnormal testCase of asset for getPath.
 * @tc.desc: 1.Create asset
 *           2.Execute GetPath (asset == nullptr)
 *           3.Execute GetPath (pathLength >= *length)
 *           4.Destroy asset
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, Abnormal_testCase_of_asset_for_getPath, TestSize.Level1)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    int errCode = OH_Data_Asset_SetPath(asset, "path");
    EXPECT_EQ(errCode, RDB_OK);
    char path[10] = "";
    size_t pathLength = 10;
    errCode = OH_Data_Asset_GetPath(nullptr, path, &pathLength);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    errCode = OH_Data_Asset_SetPath(asset, "0123456789");
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Data_Asset_GetPath(asset, path, &pathLength);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    OH_Data_Asset_DestroyOne(asset);
}

/**
 * @tc.number: RDB_Native_asset_test_008
 * @tc.name: Abnormal testCase of asset for getCreatTime.
 * @tc.desc: Execute GetCreateTime (asset == nullptr)
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, Abnormal_testCase_of_asset_for_getCreatTime, TestSize.Level1)
{
    int64_t createTime = 0;
    int errCode = OH_Data_Asset_GetCreateTime(nullptr, &createTime);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.number: RDB_Native_asset_test_009
 * @tc.name: Abnormal testCase of asset for getModifyTime.
 * @tc.desc: Execute GetModifyTime (asset == nullptr)
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, Abnormal_testCase_of_asset_for_getModifyTime, TestSize.Level1)
{
    int64_t modifyTime = 0;
    int errCode = OH_Data_Asset_GetModifyTime(nullptr, &modifyTime);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.number: RDB_Native_asset_test_0010
 * @tc.name: Abnormal testCase of asset for getSize.
 * @tc.desc: Execute GetSize (asset == nullptr)
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, Abnormal_testCase_of_asset_for_getSize, TestSize.Level1)
{
    size_t size = 0;
    int errCode = OH_Data_Asset_GetSize(nullptr, &size);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.number: RDB_Native_asset_test_0011
 * @tc.name: Abnormal testCase of asset for getStatus.
 * @tc.desc: Execute GetStatus (asset == nullptr)
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, Abnormal_testCase_of_asset_for_getStatus, TestSize.Level1)
{
    Data_AssetStatus status = Data_AssetStatus::ASSET_NORMAL;
    int errCode = OH_Data_Asset_GetStatus(nullptr, &status);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
}