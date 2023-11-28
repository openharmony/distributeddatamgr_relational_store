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
    int errCode = OH_Data_Asset_SetName(nullptr, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Data_Asset_SetName(asset, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Data_Asset_SetName(nullptr, name.c_str());
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
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
    int errCode = OH_Data_Asset_SetUri(nullptr, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Data_Asset_SetUri(asset, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Data_Asset_SetUri(nullptr, uri.c_str());
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
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
    int errCode = OH_Data_Asset_SetPath(nullptr, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Data_Asset_SetPath(asset, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Data_Asset_SetPath(nullptr, path.c_str());
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_asset_test_004
 * @tc.desc: Abnormal testCase of asset for setCreateTime, setModifyTime, setSize, setStatus.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, RDB_Native_asset_test_004, TestSize.Level1)
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
 * @tc.name: RDB_Native_asset_test_005
 * @tc.desc: Abnormal testCase of asset for getName.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, RDB_Native_asset_test_005, TestSize.Level1)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    std::string name1;
    name1.append("name");
    int errCode = OH_Data_Asset_SetName(asset, name1.c_str());
    EXPECT_EQ(errCode, RDB_OK);
    char name[10] = "";
    size_t nameLength = 10;
    errCode = OH_Data_Asset_GetName(nullptr, name, &nameLength);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    std::string name2;
    name2.append("0123456789");
    errCode = OH_Data_Asset_SetName(asset, name2.c_str());
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Data_Asset_GetName(asset, name, &nameLength);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_asset_test_006
 * @tc.desc: Abnormal testCase of asset for getUri.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, RDB_Native_asset_test_006, TestSize.Level1)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    std::string uri1;
    uri1.append("uri");
    int errCode = OH_Data_Asset_SetUri(asset, uri1.c_str());
    EXPECT_EQ(errCode, RDB_OK);
    char uri[10] = "";
    size_t uriLength = 10;
    errCode = OH_Data_Asset_GetUri(nullptr, uri, &uriLength);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    std::string uri2;
    uri2.append("0123456789");
    errCode = OH_Data_Asset_SetUri(asset, uri2.c_str());
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Data_Asset_GetUri(asset, uri, &uriLength);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_asset_test_007
 * @tc.desc: Abnormal testCase of asset for getPath.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, RDB_Native_asset_test_007, TestSize.Level1)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    std::string path1;
    path1.append("path");
    int errCode = OH_Data_Asset_SetPath(asset, path1.c_str());
    EXPECT_EQ(errCode, RDB_OK);
    char path[10] = "";
    size_t pathLength = 10;
    errCode = OH_Data_Asset_GetPath(nullptr, path, &pathLength);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    std::string path2;
    path2.append("0123456789");
    errCode = OH_Data_Asset_SetPath(asset, path2.c_str());
    EXPECT_EQ(errCode, RDB_OK);
    errCode = OH_Data_Asset_GetPath(asset, path, &pathLength);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_asset_test_008
 * @tc.desc: Abnormal testCase of asset for getCreatTime.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, RDB_Native_asset_test_008, TestSize.Level1)
{
    int64_t createTime = 0;
    int errCode = OH_Data_Asset_GetCreateTime(nullptr, &createTime);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_asset_test_009
 * @tc.desc: Abnormal testCase of asset for getModifyTime.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, RDB_Native_asset_test_009, TestSize.Level1)
{
    int64_t modifyTime = 0;
    int errCode = OH_Data_Asset_GetModifyTime(nullptr, &modifyTime);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_asset_test_0010
 * @tc.desc: Abnormal testCase of asset for getSize.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, RDB_Native_asset_test_0010, TestSize.Level1)
{
    size_t size = 0;
    int errCode = OH_Data_Asset_GetSize(nullptr, &size);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_asset_test_0011
 * @tc.desc: Abnormal testCase of asset for getStatus.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeAssetTest, RDB_Native_asset_test_0011, TestSize.Level1)
{
    Data_AssetStatus status = Data_AssetStatus::ASSET_NORMAL;
    int errCode = OH_Data_Asset_GetStatus(nullptr, &status);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
}