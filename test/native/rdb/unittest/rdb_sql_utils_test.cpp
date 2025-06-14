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

#define LOG_TAG "RdbSqlUtilsTest"
#include "rdb_sql_utils.h"

#include <gtest/gtest.h>

#include <climits>
#include <string>

#include "grd_type_export.h"
#include "rd_utils.h"
#include "logger.h"
#include "sqlite_sql_builder.h"
#include "values_buckets.h"
#include "rdb_predicates.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;

class RdbSqlUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) {};
    void TearDown(void) {};
};

void RdbSqlUtilsTest::SetUpTestCase(void)
{
}

void RdbSqlUtilsTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: RdbStore_SqliteUtils_001
 * @tc.desc: Normal testCase of sqlite_utils for IsSpecial, if sqlType is special
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, RdbSqlUtils_Test_001, TestSize.Level1)
{
    auto [dataBasePath, errCode] = RdbSqlUtils::GetDefaultDatabasePath("/data/test", "RdbTest.db");
    EXPECT_EQ(dataBasePath, "/data/test/rdb/RdbTest.db");
    EXPECT_EQ(errCode, E_OK);

    auto [dataBasePath1, errCode1] = RdbSqlUtils::GetDefaultDatabasePath("/data/test", "RdbTest.db", "myself");
    EXPECT_EQ(dataBasePath1, "/data/test/rdb/myself/RdbTest.db");
    EXPECT_EQ(errCode1, E_OK);
}

/**
 * @tc.name: RdbStore_GetInsertSqlInfo_001
 * @tc.desc: test RdbStore GetInsertSqlInfo
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, RdbSqlUtils_GetInsertSqlInfo_001, TestSize.Level1)
{
    ValuesBucket values;
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    std::pair<int, SqlInfo> result = RdbSqlUtils::GetInsertSqlInfo("", values, ConflictResolution::ON_CONFLICT_NONE);
    EXPECT_EQ(result.first, E_EMPTY_TABLE_NAME);
}

/**
 * @tc.name: RdbStore_GetInsertSqlInfo_002
 * @tc.desc: test RdbStore GetInsertSqlInfo
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, RdbSqlUtils_GetInsertSqlInfo_002, TestSize.Level1)
{
    ValuesBucket values;
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    ValuesBucket emptyValues;

    std::pair<int, SqlInfo> result =
        RdbSqlUtils::GetInsertSqlInfo("temp", emptyValues, ConflictResolution::ON_CONFLICT_NONE);
    EXPECT_EQ(result.first, E_EMPTY_VALUES_BUCKET);
}

/**
 * @tc.name: RdbStore_GetInsertSqlInfo_003
 * @tc.desc: test RdbStore GetInsertSqlInfo
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, RdbSqlUtils_GetInsertSqlInfo_003, TestSize.Level1)
{
    ValuesBucket values;
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);

    std::pair<int, SqlInfo> result =
        RdbSqlUtils::GetInsertSqlInfo("temp", values, ConflictResolution::ON_CONFLICT_NONE);
    LOG_INFO("INSERT SQL is %{public}s", result.second.sql.c_str());
    EXPECT_EQ(result.first, E_OK);
}

/**
 * @tc.name: RdbStore_GetInsertSqlInfo_004
 * @tc.desc: test RdbStore GetInsertSqlInfo
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, RdbSqlUtils_GetInsertSqlInfo_004, TestSize.Level1)
{
    ValuesBucket values;
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);

    AssetValue assetVal;
    assetVal.id = "123";
    assetVal.name = "kkk";
    std::vector<AssetValue> assets;
    assets.emplace_back(assetVal);

    ValueObject vo(assets);
    values.Put("kkk", vo);
    std::pair<int, SqlInfo> result =
        RdbSqlUtils::GetInsertSqlInfo("temp", values, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(result.first, E_INVALID_ARGS);
}

/**
 * @tc.name: RdbStore_GetUpdateSqlInfo_001
 * @tc.desc: test RdbStore GetUpdateSqlInfo
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, RdbSqlUtils_GetUpdateSqlInfo_001, TestSize.Level1)
{
    std::vector<std::string> returningFields;
    RdbPredicates predicates("");
    ValuesBucket bucketValues;
    bucketValues.PutString("name", std::string("zhangsan"));
    bucketValues.PutInt("age", 20);
    bucketValues.PutDouble("salary", 300.5);
    std::vector<ValueObject> emptyValues;
    std::pair<int, SqlInfo> result = RdbSqlUtils::GetUpdateSqlInfo(
        predicates, bucketValues, ConflictResolution::ON_CONFLICT_NONE, returningFields);
    EXPECT_EQ(result.first, E_EMPTY_TABLE_NAME);
}

/**
 * @tc.name: RdbStore_GetUpdateSqlInfo_002
 * @tc.desc: test RdbStore GetUpdateSqlInfo
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, RdbSqlUtils_GetUpdateSqlInfo_002, TestSize.Level1)
{
    std::vector<std::string> returningFields;
    RdbPredicates predicates("temp");
    ValuesBucket bucketValues;
    bucketValues.PutString("name", std::string("zhangsan"));
    bucketValues.PutInt("age", 20);
    bucketValues.PutDouble("salary", 300.5);
    ValuesBucket emptyBucketValues;
    std::vector<ValueObject> emptyValues;

    std::pair<int, SqlInfo> result = RdbSqlUtils::GetUpdateSqlInfo(
        predicates, emptyBucketValues, ConflictResolution::ON_CONFLICT_NONE, returningFields);
    EXPECT_EQ(result.first, E_EMPTY_VALUES_BUCKET);
}

/**
 * @tc.name: RdbStore_GetUpdateSqlInfo_003
 * @tc.desc: test RdbStore GetUpdateSqlInfo
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, RdbSqlUtils_GetUpdateSqlInfo_003, TestSize.Level1)
{
    std::vector<std::string> returningFields;
    RdbPredicates predicates("temp");
    ValuesBucket bucketValues;
    bucketValues.PutString("name", std::string("zhangsan"));
    bucketValues.PutInt("age", 20);
    bucketValues.PutDouble("salary", 300.5);
    std::vector<ValueObject> values;
    ValueObject object;
    values.push_back(object);
    predicates.EqualTo("name", "wangwu");
    predicates.SetBindArgs(values);
    std::pair<int, SqlInfo> result = RdbSqlUtils::GetUpdateSqlInfo(
        predicates, bucketValues, ConflictResolution::ON_CONFLICT_NONE, returningFields);
    LOG_INFO("UPDATE SQL is %{public}s", result.second.sql.c_str());
    EXPECT_EQ(result.first, E_OK);
}

/**
 * @tc.name: RdbStore_GetDeleteSqlInfo_001
 * @tc.desc: test RdbStore GetDeleteSqlInfo
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, RdbSqlUtils_GetDeleteSqlInfo_001, TestSize.Level1)
{
    std::vector<std::string> returningFields;
    RdbPredicates predicates("");
    std::pair<int, SqlInfo> result = RdbSqlUtils::GetDeleteSqlInfo(predicates, returningFields);
    EXPECT_EQ(result.first, E_EMPTY_TABLE_NAME);
}

/**
 * @tc.name: RdbStore_GetDeleteSqlInfo_002
 * @tc.desc: test RdbStore GetDeleteSqlInfo
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, GetDeleteSqlInfo_002, TestSize.Level1)
{
    std::vector<std::string> returningFields;
    std::vector<ValueObject> emptyValues;
    RdbPredicates predicates("temp");
    predicates.EqualTo("name", "wangwu");
    predicates.SetBindArgs(emptyValues);
    std::pair<int, SqlInfo> result =
        RdbSqlUtils::GetDeleteSqlInfo(predicates, returningFields);
    LOG_INFO("DELETE SQL is %{public}s", result.second.sql.c_str());
    EXPECT_EQ(result.first, E_OK);
}