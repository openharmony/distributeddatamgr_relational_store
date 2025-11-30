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
    RdbPredicates predicates("");
    ValuesBucket bucketValues;
    bucketValues.PutString("name", std::string("zhangsan"));
    bucketValues.PutInt("age", 20);
    bucketValues.PutDouble("salary", 300.5);
    std::vector<ValueObject> emptyValues;
    std::pair<int, SqlInfo> result = RdbSqlUtils::GetUpdateSqlInfo(
        predicates, bucketValues, ConflictResolution::ON_CONFLICT_NONE);
    EXPECT_EQ(result.first, E_EMPTY_TABLE_NAME);
}

/**
 * @tc.name: RdbStore_GetUpdateSqlInfo_002
 * @tc.desc: test RdbStore GetUpdateSqlInfo
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, RdbSqlUtils_GetUpdateSqlInfo_002, TestSize.Level1)
{
    RdbPredicates predicates("temp");
    ValuesBucket bucketValues;
    bucketValues.PutString("name", std::string("zhangsan"));
    bucketValues.PutInt("age", 20);
    bucketValues.PutDouble("salary", 300.5);
    ValuesBucket emptyBucketValues;
    std::vector<ValueObject> emptyValues;

    std::pair<int, SqlInfo> result = RdbSqlUtils::GetUpdateSqlInfo(
        predicates, emptyBucketValues, ConflictResolution::ON_CONFLICT_NONE);
    EXPECT_EQ(result.first, E_EMPTY_VALUES_BUCKET);
}

/**
 * @tc.name: RdbStore_GetUpdateSqlInfo_003
 * @tc.desc: test RdbStore GetUpdateSqlInfo
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, RdbSqlUtils_GetUpdateSqlInfo_003, TestSize.Level1)
{
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
        predicates, bucketValues, ConflictResolution::ON_CONFLICT_NONE);
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
    RdbPredicates predicates("");
    std::pair<int, SqlInfo> result = RdbSqlUtils::GetDeleteSqlInfo(predicates);
    EXPECT_EQ(result.first, E_EMPTY_TABLE_NAME);
}

/**
 * @tc.name: RdbStore_GetDeleteSqlInfo_002
 * @tc.desc: test RdbStore GetDeleteSqlInfo
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, GetDeleteSqlInfo_002, TestSize.Level1)
{
    std::vector<ValueObject> emptyValues;
    RdbPredicates predicates("temp");
    predicates.EqualTo("name", "wangwu");
    predicates.SetBindArgs(emptyValues);
    std::pair<int, SqlInfo> result =
        RdbSqlUtils::GetDeleteSqlInfo(predicates);
    LOG_INFO("DELETE SQL is %{public}s", result.second.sql.c_str());
    EXPECT_EQ(result.first, E_OK);
}

/**
 * @tc.name: GetDataBaseDir_001
 * @tc.desc: test RdbStore GetDataBaseDirFromRealPath
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, GetDataBaseDir_001, TestSize.Level1)
{
    auto dataBaseDir = RdbSqlUtils::GetDataBaseDirFromRealPath("/data/app/rdb/test.db", false, "", "test.db");
    EXPECT_EQ(dataBaseDir, "/data/app/rdb/test.db");
    dataBaseDir = RdbSqlUtils::GetDataBaseDirFromRealPath("/data/app/rdb/test.db", true, "", "test.db");
    EXPECT_EQ(dataBaseDir, "/data/app");
    dataBaseDir = RdbSqlUtils::GetDataBaseDirFromRealPath("/data/app/rdb/custom/test.db", true, "custom", "test.db");
    EXPECT_EQ(dataBaseDir, "/data/app");
    dataBaseDir =
        RdbSqlUtils::GetDataBaseDirFromRealPath("/data/app/rdb/custom/rdb/test.db", true, "custom/rdb", "test.db");
    EXPECT_EQ(dataBaseDir, "/data/app");
    dataBaseDir = RdbSqlUtils::GetDataBaseDirFromRealPath(
        "/data/app/rdb/custom/rdb/rdbtest.db", true, "custom/rdb", "rdbtest.db");
    EXPECT_EQ(dataBaseDir, "/data/app");
}

/**
 * @tc.name: GetDataBaseDir_002
 * @tc.desc: test RdbStore GetDataBaseDirFromRealPath
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, GetDataBaseDir_002, TestSize.Level1)
{
    auto dataBaseDir = RdbSqlUtils::GetDataBaseDirFromRealPath("", true, "custom", "test.db");
    EXPECT_EQ(dataBaseDir, "");
    dataBaseDir = RdbSqlUtils::GetDataBaseDirFromRealPath("/data/app/rdb/test.db", true, "", "");
    EXPECT_EQ(dataBaseDir, "");
    dataBaseDir = RdbSqlUtils::GetDataBaseDirFromRealPath("test.db", true, "", "test.db");
    EXPECT_EQ(dataBaseDir, "");
    dataBaseDir = RdbSqlUtils::GetDataBaseDirFromRealPath("/data/app/rdb/abc.db", true, "", "test.db");
    EXPECT_EQ(dataBaseDir, "");
    dataBaseDir = RdbSqlUtils::GetDataBaseDirFromRealPath("data/app/rdb/cs/test.db", true, "custom", "test.db");
    EXPECT_EQ(dataBaseDir, "");
    dataBaseDir = RdbSqlUtils::GetDataBaseDirFromRealPath("/data/app/rdb/other/test.db", true, "custom", "test.db");
    EXPECT_EQ(dataBaseDir, "");
    dataBaseDir = RdbSqlUtils::GetDataBaseDirFromRealPath("/rd/custom/test.db", true, "custom", "test.db");
    EXPECT_EQ(dataBaseDir, "");
    dataBaseDir = RdbSqlUtils::GetDataBaseDirFromRealPath("/data/app/custom/test.db", true, "custom", "test.db");
    EXPECT_EQ(dataBaseDir, "");
}

/**
 * @tc.name: IsValidTableName_ValidateFormat
 * @tc.desc: Test validation of table name format in IsValidTableName function
 * @tc.type: FUNC
 * Test Point:
 * Verify that IsValidTableName correctly validates table name formats according to SQL standards
 * Test Steps:
 * 1. Test with empty string - should return false
 * 2. Test with numeric string "12345" - should return false
 * 3. Test with invalid double dot format "a..b" - should return false
 * 4. Test with leading dot ".a" - should return false
 * 5. Test with trailing dot "a." - should return false
 * 6. Test with valid underscore format "abc_def" - should return true
 * 7. Test with valid dot notation "abc.def" - should return true
 * 8. Test with alphanumeric string "abc123" - should return true
 */
HWTEST_F(RdbSqlUtilsTest, IsValidTableName_ValidateFormat, TestSize.Level1)
{
    auto res = RdbSqlUtils::IsValidTableName("");
    EXPECT_FALSE(res);
    res = RdbSqlUtils::IsValidTableName("12345");
    EXPECT_FALSE(res);
    res = RdbSqlUtils::IsValidTableName("a..b");
    EXPECT_FALSE(res);
    res = RdbSqlUtils::IsValidTableName(".a");
    EXPECT_FALSE(res);
    res = RdbSqlUtils::IsValidTableName("a.");
    EXPECT_FALSE(res);
    res = RdbSqlUtils::IsValidTableName("abc_def");
    EXPECT_TRUE(res);
    res = RdbSqlUtils::IsValidTableName("abc.def");
    EXPECT_TRUE(res);
    res = RdbSqlUtils::IsValidTableName("abc123");
    EXPECT_TRUE(res);
}

/**
 * @tc.name: IsValidFields_ValidateNames
 * @tc.desc: Test validation of field names in IsValidFields function
 * @tc.type: FUNC
 * Test Point:
 * Verify that IsValidFields correctly validates field names according to SQL standards
 * Test Steps:
 * 1. Test with empty fields vector - should return false
 * 2. Test with fields exceeding limit - should return false
 * 3. Test with illegal field names containing special characters - should return false
 * 4. Test with field names containing spaces - should return false
 * 5. Test with field names containing commas - should return false
 * 6. Test with valid field names including duplicates - should return true
 */
HWTEST_F(RdbSqlUtilsTest, IsValidFields_ValidateNames, TestSize.Level1)
{
    const int32_t FIELDS_LIMIT = 4;
    EXPECT_FALSE(RdbSqlUtils::IsValidFields(std::vector<std::string>()));
    EXPECT_FALSE(RdbSqlUtils::IsValidFields(std::vector<std::string>(FIELDS_LIMIT + 1, "")));
    EXPECT_FALSE(RdbSqlUtils::IsValidFields({"field1", "field2", "***illegal_field"}));
    EXPECT_FALSE(RdbSqlUtils::IsValidFields({"field1", "field2", "illegal field"}));
    EXPECT_FALSE(RdbSqlUtils::IsValidFields({"field1", "field2", "illegal,field"}));
    EXPECT_TRUE(RdbSqlUtils::IsValidFields({"field1", "field2", "field2"}));
}

/**
 * @tc.name: HasDuplicateAssets_CheckDuplicates
 * @tc.desc: Test detection of duplicate assets in ValueObject
 * @tc.type: FUNC
 * Test Point:
 * Verify that HasDuplicateAssets correctly detects duplicate assets within a ValueObject
 * Test Steps:
 * 1. Test with empty ValueObject - should return false
 * 2. Create two assets with identical names
 * 3. Put them into a ValueObject
 * 4. Check if HasDuplicateAssets detects duplicates - should return true
 * 5. Test with duplicated ValueObjects - should return true
 * 6. Test with ValuesBucket containing duplicate assets - should return true
 * 7. Test with ValuesBuckets containing duplicate assets - should return true
 */
HWTEST_F(RdbSqlUtilsTest, HasDuplicateAssets_CheckDuplicates, TestSize.Level1)
{
    ValueObject value;
    auto res = RdbSqlUtils::HasDuplicateAssets(value);
    EXPECT_FALSE(res);
    AssetValue asset1;
    asset1.name = "asset1";
    AssetValue asset2;
    asset2.name = "asset1";
    value = ValueObject({asset1, asset2});
    res = RdbSqlUtils::HasDuplicateAssets(value);
    EXPECT_TRUE(res);
    res = RdbSqlUtils::HasDuplicateAssets({value, value});
    EXPECT_TRUE(res);
    ValuesBucket bucket;
    bucket.PutDouble("double", 2.2);
    bucket.Put("assets", value);
    res = RdbSqlUtils::HasDuplicateAssets(bucket);
    EXPECT_TRUE(res);
    ValuesBuckets Buckets({bucket, bucket});
    res = RdbSqlUtils::HasDuplicateAssets(Buckets);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: HasDuplicateAssets_CheckNonDuplicates
 * @tc.desc: Test detection of non-duplicate assets in ValueObject
 * @tc.type: FUNC
 * Test Point:
 * Verify that HasDuplicateAssets correctly identifies when there are no duplicate assets within a ValueObject
 * Test Steps:
 * 1. Test with empty ValueObject - should return false
 * 2. Create two assets with different names
 * 3. Put them into a ValueObject
 * 4. Check if HasDuplicateAssets detects duplicates - should return false
 * 5. Test with non-duplicated ValueObjects - should return false
 * 6. Test with ValuesBucket containing non-duplicate assets - should return false
 * 7. Test with ValuesBuckets containing non-duplicate assets - should return false
 */
HWTEST_F(RdbSqlUtilsTest, HasDuplicateAssets_CheckNonDuplicates, TestSize.Level1)
{
    ValueObject value;
    auto res = RdbSqlUtils::HasDuplicateAssets(value);
    EXPECT_FALSE(res);
    AssetValue asset1;
    asset1.name = "asset1";
    AssetValue asset2;
    asset2.name = "asset2";
    value = ValueObject({asset1, asset2});
    res = RdbSqlUtils::HasDuplicateAssets(value);
    EXPECT_FALSE(res);
    res = RdbSqlUtils::HasDuplicateAssets({value, value});
    EXPECT_FALSE(res);
    ValuesBucket bucket;
    bucket.PutDouble("double", 2.2);
    bucket.Put("assets", value);
    res = RdbSqlUtils::HasDuplicateAssets(bucket);
    EXPECT_FALSE(res);
    ValuesBuckets Buckets({bucket, bucket});
    res = RdbSqlUtils::HasDuplicateAssets(Buckets);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: BatchTrim_TrimWhitespace
 * @tc.desc: Test trimming whitespace from strings in BatchTrim function
 * @tc.type: FUNC
 * Test Point:
 * Verify that BatchTrim correctly trims whitespace from a vector of strings
 *
 * Test Steps:
 * 1. Create a vector of strings with various whitespace patterns
 * 2. Apply BatchTrim to the vector
 * 3. Verify that whitespace is correctly trimmed from each string
 * 4. Verify that empty strings remain empty
 */
HWTEST_F(RdbSqlUtilsTest, BatchTrim_TrimWhitespace, TestSize.Level1)
{
    std::vector<std::string> strs = {" str1 ", "str2", ""};
    std::vector<std::string> res = RdbSqlUtils::BatchTrim(strs);
    EXPECT_EQ(res.size(), 3);
    EXPECT_EQ(res[0], "str1");
    EXPECT_EQ(res[1], "str2");
    EXPECT_EQ(res[2], "");
}

/**
 * @tc.name: IsValidMaxCount_ValidateValues
 * @tc.desc: Test RdbSqlUtils IsValidMaxCount function with various max returning count values
 * @tc.type: FUNC
 * Test Point:
 * Verify that IsValidMaxCount correctly validates maximum count values for returning operations
 * Test Steps:
 * 1. Test with a positive valid count (5) - should return true
 * 2. Test with a negative count (-5) - should return false
 * 3. Test with zero count (0) - should return false
 * 4. Test with maximum allowed count (ReturningConfig::MAX_RETURNING_COUNT) - should return true
 * 5. Test with exceeding maximum count (ReturningConfig::MAX_RETURNING_COUNT + 1) - should return false
 */
HWTEST_F(RdbSqlUtilsTest, IsValidMaxCount_ValidateValues, TestSize.Level1)
{
    EXPECT_TRUE(RdbSqlUtils::IsValidMaxCount(5));
    EXPECT_FALSE(RdbSqlUtils::IsValidMaxCount(-5));
    EXPECT_FALSE(RdbSqlUtils::IsValidMaxCount(0));
    EXPECT_TRUE(RdbSqlUtils::IsValidMaxCount(ReturningConfig::MAX_RETURNING_COUNT));
    EXPECT_FALSE(RdbSqlUtils::IsValidMaxCount(ReturningConfig::MAX_RETURNING_COUNT + 1));
}