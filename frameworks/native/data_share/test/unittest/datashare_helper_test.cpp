/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "ability.h"
#include "ability_context.h"
#include "context.h"
#include "datashare_helper.h"
#include "datashare_operation.h"
#include "data_ability_observer_interface.h"
#include "datashare_log.h"
#include "datashare_predicates.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;
using Uri = OHOS::Uri;
namespace OHOS {
namespace DataShare {
std::string URI = "datashare:///com.ohos.data.datasharetest.DataShare";

class DataShareHelperTest : public testing::Test {
public:
    DataShareHelperTest() {}
    virtual ~DataShareHelperTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DataShareHelperTest::SetUpTestCase(void)
{
}

void DataShareHelperTest::TearDownTestCase(void)
{
}

void DataShareHelperTest::SetUp(void)
{
}

void DataShareHelperTest::TearDown(void)
{
}

class IDataShareObserverTest : public AAFwk::IDataAbilityObserver {
public:
    IDataShareObserverTest();
    ~IDataShareObserverTest()
    {}
    void OnChange()
    {
        GTEST_LOG_(INFO) << "OnChange enter";
    }
};

/**
 * @tc.name: DataShare_Release_001
 * @tc.desc: test DataShareHelper Release
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Release_001, TestSize.Level1)
{
    LOG_INFO("DataShare_Release_001 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::string mimeTypeFilter("mimeTypeFiltertest");
    bool result = dataShareHelper->Release();
    EXPECT_EQ(result, true);
    LOG_INFO("DataShare_Release_001 end");
}

/**
 * @tc.name: DataShare_GetFileTypes_001
 * @tc.desc: test DataShareHelper GetFileTypes
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_GetFileTypes_001, TestSize.Level1)
{
    LOG_INFO("DataShare_GetFileTypes_001 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::string mimeTypeFilter("mimeTypeFiltertest");
    std::vector<std::string> result = dataShareHelper->GetFileTypes(uri, mimeTypeFilter);
    EXPECT_EQ(result.size(), 0);
    LOG_INFO("DataShare_GetFileTypes_001 end");
}

/**
 * @tc.name: DataShare_OpenFile_001
 * @tc.desc: test DataShareHelper OpenFile
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_OpenFile_001, TestSize.Level1)
{
    LOG_INFO("DataShare_OpenFile_001 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::string mode("modetest");
    int result = dataShareHelper->OpenFile(uri, mode);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_OpenFile_001 end");
}

/**
 * @tc.name: DataShare_OpenRawFile_001
 * @tc.desc: test DataShareHelper OpenRawFile
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_OpenRawFile_001, TestSize.Level1)
{
    LOG_INFO("DataShare_OpenRawFile_001 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::string mode("modetest");
    int result = dataShareHelper->OpenRawFile(uri, mode);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_OpenRawFile_001 end");
}

/**
 * @tc.name: DataShare_Insert_001
 * @tc.desc: test DataShareHelper Insert Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Insert_001, TestSize.Level1)
{
    LOG_INFO("DataShare_Insert_001 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    std::string name = "Wangwu";
    val.PutString("name", name);
    int result = dataShareHelper->Insert(uri, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Insert_001 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Insert_002
 * @tc.desc: test DataShareHelper Insert Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Insert_002, TestSize.Level1)
{
    LOG_INFO("DataShare_Insert_002 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    val.PutInt("age", 20);
    int result = dataShareHelper->Insert(uri, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Insert_002 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Insert_003
 * @tc.desc: test DataShareHelper Insert Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Insert_003, TestSize.Level1)
{
    LOG_INFO("DataShare_Insert_003 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    int64_t i = 18;
    val.PutLong("age", i);
    int result = dataShareHelper->Insert(uri, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Insert_003 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Insert_004
 * @tc.desc: test DataShareHelper Insert Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Insert_004, TestSize.Level1)
{
    LOG_INFO("DataShare_Insert_004 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    val.PutDouble("weight", 108.7);
    int result = dataShareHelper->Insert(uri, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Insert_004 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Insert_005
 * @tc.desc: test DataShareHelper Insert Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Insert_005, TestSize.Level1)
{
    LOG_INFO("DataShare_Insert_005 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    val.PutBool("isStudent", true);
    int result = dataShareHelper->Insert(uri, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Insert_005 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Insert_006
 * @tc.desc: test DataShareHelper Insert Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Insert_006, TestSize.Level1)
{
    LOG_INFO("DataShare_Insert_006 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    std::vector<uint8_t> value {20, 30};
    val.PutBlob("Blob", value);
    int result = dataShareHelper->Insert(uri, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Insert_006 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Insert_007
 * @tc.desc: test DataShareHelper Insert Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Insert_007, TestSize.Level1)
{
    LOG_INFO("DataShare_Insert_007 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    val.PutNull("NULL");
    int result = dataShareHelper->Insert(uri, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Insert_007 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Insert_101
 * @tc.desc: test DataShareHelper Insert Abnormal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Insert_101, TestSize.Level1)
{
    LOG_INFO("DataShare_Insert_101 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    int result = dataShareHelper->Insert(uri, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Insert_101 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Update_001
 * @tc.desc: test DataShareHelper Update Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Update_001, TestSize.Level1)
{
    LOG_INFO("DataShare_Update_001 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    std::string testname = "Lisa";
    std::vector<int64_t> age {67, 34};
    std::vector<int> intage {56, 23};
    val.PutString("name", testname);
    DataSharePredicates predicates;
    predicates.EqualTo("name", testname);
    predicates.OrderByAsc("age");
    predicates.GreaterThan("age", 18);
    predicates.NotIn("age", age);
    predicates.NotIn("age", intage);
    int result = dataShareHelper->Update(uri, predicates, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Update_001 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Update_002
 * @tc.desc: test DataShareHelper Update Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Update_002, TestSize.Level1)
{
    LOG_INFO("DataShare_Update_002 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    int64_t i = 33;
    int number = 32;
    int offset = 36;
    val.PutLong("age", i);
    DataSharePredicates predicates;
    std::string str = "ZhangSan";
    predicates.NotEqualTo("name", str);
    predicates.Limit(number, offset);
    int result = dataShareHelper->Update(uri, predicates, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Update_002 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Update_003
 * @tc.desc: test DataShareHelper Update Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Update_003, TestSize.Level1)
{
    LOG_INFO("DataShare_Update_003 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    std::string name = "Wangwu";
    std::vector<string> namevector {"Wangwu", "Zhaosi"};
    val.PutString("name", name);
    DataSharePredicates predicates;
    predicates.IsNotNull("age");
    predicates.OrderByDesc("age");
    predicates.IsNull("name");
    predicates.In("name", namevector);
    int result = dataShareHelper->Update(uri, predicates, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Update_003 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Update_004
 * @tc.desc: test DataShareHelper Update Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Update_004, TestSize.Level1)
{
    LOG_INFO("DataShare_Update_004 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    val.PutBool("isStudent", true);
    DataSharePredicates predicates;
    predicates.LessThanOrEqualTo("age", 20);
    predicates.EqualTo("isStudent",false);
    predicates.NotEqualTo("weight", 54.3);
    int result = dataShareHelper->Update(uri, predicates, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Update_004 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Update_005
 * @tc.desc: test DataShareHelper Update Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Update_005, TestSize.Level1)
{
    LOG_INFO("DataShare_Update_005 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    val.PutNull("NULL");
    DataSharePredicates predicates;
    std::string str = "ZhangSan";
    predicates.LessThan("name", str);
    predicates.LessThan("age", 35);
    predicates.LessThan("weight", 67.9);
    int result = dataShareHelper->Update(uri, predicates, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Update_005 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Update_006
 * @tc.desc: test DataShareHelper Update Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Update_006, TestSize.Level1)
{
    LOG_INFO("DataShare_Update_006 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    std::string name = "ZhangSan";
    val.PutString("name", name);
    DataSharePredicates predicates;
    predicates.And();
    predicates.Or();
    predicates.BeginWrap();
    predicates.EndWrap();
    predicates.Distinct();
    int result = dataShareHelper->Update(uri, predicates, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Update_006 end");
}

/**
 * @tc.name: DataShare_Update_007
 * @tc.desc: test DataShareHelper Update Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Update_007, TestSize.Level1)
{
    LOG_INFO("DataShare_Update_007 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    std::string name = "ZhangSan";
    val.PutString("name", name);
    DataSharePredicates predicates;
    std::string str = "Zhang";
    std::vector<string> value {"device", "id"};
    predicates.KeyPrefix(str);
    int result = dataShareHelper->Update(uri, predicates, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Update_007 end");
}

/**
 * @tc.name: DataShare_Update_008
 * @tc.desc: test DataShareHelper Update Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Update_008, TestSize.Level1)
{
    LOG_INFO("DataShare_Update_005 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    val.PutNull("NULL");
    DataSharePredicates predicates;
    std::string str = "ZhangSan";
    predicates.LessThan("name", str);
    predicates.LessThan("age", 35);
    predicates.LessThan("weight", 67.9);
    int result = dataShareHelper->Update(uri, predicates, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Update_008 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Update_101
 * @tc.desc: test DataShareHelper Update Abnormal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Update_101, TestSize.Level1)
{
    LOG_INFO("DataShare_Update_101 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    std::string name = "ZhangSan";
    val.PutString("name", name);
    DataSharePredicates predicates;
    predicates.And();
    int result = dataShareHelper->Update(uri, predicates, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Update_101 end");
}

/**
 * @tc.name: DataShare_Delete_001
 * @tc.desc: test DataShareHelper Delete Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Delete_001, TestSize.Level1)
{
    LOG_INFO("DataShare_Delete_001 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataSharePredicates predicates;
    std::string str = "ZhangSan";
    predicates.EqualTo("age", 18);
    predicates.GreaterThan("age",67.3);
    predicates.GreaterThan("name", str);
    int result = dataShareHelper->Delete(uri, predicates);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Delete_001 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Delete_002
 * @tc.desc: test DataShareHelper Delete Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Delete_002, TestSize.Level1)
{
    LOG_INFO("DataShare_Delete_002 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataSharePredicates predicates;
    predicates.IsNull("name");
    int result = dataShareHelper->Delete(uri, predicates);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Delete_002 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Delete_003
 * @tc.desc: test DataShareHelper Delete Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Delete_003, TestSize.Level1)
{
    LOG_INFO("DataShare_Delete_003 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataSharePredicates predicates;
    std::string str = "ZhangSan";
    int64_t i = 65;
    predicates.Like("name", str);
    predicates.NotEqualTo("age", 18);
    predicates.GreaterThanOrEqualTo("age", 17);
    predicates.LessThan("weight", i);
    int result = dataShareHelper->Delete(uri, predicates);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Delete_003 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Delete_004
 * @tc.desc: test DataShareHelper Delete Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Delete_004, TestSize.Level1)
{
    LOG_INFO("DataShare_Delete_004 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataSharePredicates predicates;
    int64_t i = 57;
    std::string str = "Wangwu";
    predicates.NotEqualTo("age", i);
    predicates.LessThanOrEqualTo("age", i);
    predicates.NotEqualTo("isStudent", true);
    predicates.Unlike("name", str);
    predicates.GreaterThanOrEqualTo("weight", 89.7);
    int result = dataShareHelper->Delete(uri, predicates);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Delete_004 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Delete_005
 * @tc.desc: test DataShareHelper Delete Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Delete_005, TestSize.Level1)
{
    LOG_INFO("DataShare_Delete_005 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::vector<int> age {18, 20};
    std::string str = "hongmeng";
    DataSharePredicates predicates;
    predicates.In("age", age);
    predicates.GreaterThanOrEqualTo("name", str);
    int result = dataShareHelper->Delete(uri, predicates);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Delete_005 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Delete_006
 * @tc.desc: test DataShareHelper Delete Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Delete_006, TestSize.Level1)
{
    LOG_INFO("DataShare_Delete_005 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataSharePredicates predicates;
    std::string str = "ZhangSan";
    int64_t i = 67;
    predicates.GreaterThanOrEqualTo("age", i);
    predicates.LessThanOrEqualTo("weight", 67.9);
    predicates.LessThanOrEqualTo("name", str);
    int result = dataShareHelper->Delete(uri, predicates);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Delete_006 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Delete_101
 * @tc.desc: test DataShareHelper Delete Abnormal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Delete_101, TestSize.Level1)
{
    LOG_INFO("DataShare_Delete_101 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataSharePredicates predicates;
    std::string str = "ZhangSan";
    int64_t i = 67;
    predicates.GreaterThanOrEqualTo("age", i);
    int result = dataShareHelper->Delete(uri, predicates);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Delete_101 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Query_001
 * @tc.desc: test DataShareHelper Query Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Query_001, TestSize.Level1)
{
    LOG_INFO("DataShare_Query_001 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::vector<std::string> columns {"Querytest1", "Querytest2"};
    DataSharePredicates predicates;
    int64_t age = 23;
    std::string str = "Li";
    predicates.BeginsWith("name", str);
    predicates.EqualTo("weight", 108.7);
    predicates.GreaterThan("age", age);
    std::shared_ptr<DataShareResultSet> resultSet = dataShareHelper->Query(uri, predicates, columns);
    int result = 0;
    std::vector<std::string> columnOrKeyNames;
    std::vector<uint8_t> blob {20, 30};
    if (resultSet != nullptr) {
        resultSet->GetRowCount(result);
        resultSet->GetBlob(2 ,blob);
        resultSet->GetAllColumnNames(columnOrKeyNames);
    }
    EXPECT_EQ(result, 0);
    LOG_INFO("DataShare_Query_001 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Query_002
 * @tc.desc: test DataShareHelper Query Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Query_002, TestSize.Level1)
{
    LOG_INFO("DataShare_Query_002 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::vector<std::string> columns {"Querytest1","Querytest2"};
    DataSharePredicates predicates;
    std::string str = "si";
    int64_t i = 18;
    predicates.EqualTo("age", i);
    predicates.EndsWith("name", str);
    std::shared_ptr<DataShareResultSet> resultSet = dataShareHelper->Query(uri, predicates, columns);
    int rowindex = 0;
    bool isStartResult = false;
    AppDataFwk::SharedBlock *block = nullptr;
    if (resultSet != nullptr) {
        resultSet->GoToRow(2);
        resultSet->GetRowIndex(rowindex);
        resultSet->SetBlock(block);
    }
    EXPECT_EQ(isStartResult, false);
    EXPECT_EQ(rowindex, 0);
    LOG_INFO("DataShare_Query_002 end, rowindex : %{public}d", rowindex);
}

/**
 * @tc.name: DataShare_Query_003
 * @tc.desc: test DataShareHelper Query Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Query_003, TestSize.Level1)
{
    LOG_INFO("DataShare_Query_003 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::vector<std::string> columns {"Querytest1", "Querytest2"};
    DataSharePredicates predicates;
    predicates.EqualTo("weight", 108.7);
    std::shared_ptr<DataShareResultSet> resultSet = dataShareHelper->Query(uri, predicates, columns);
    int result = 0;
    int count = 2;
    bool lastRowResult = false;
    if (resultSet != nullptr) {
        resultSet->GoToLastRow();
        resultSet->GetColumnCount(count);
    }
    EXPECT_EQ(result, 0);
    EXPECT_EQ(lastRowResult, 0);
    LOG_INFO("DataShare_Query_003 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Query_004
 * @tc.desc: test DataShareHelper Query Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Query_004, TestSize.Level1)
{
    LOG_INFO("DataShare_Query_004 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::vector<std::string> columns {"Querytest1", "Querytest2"};
    DataSharePredicates predicates;
    std::vector<std::string> keys {"name", "weight"};
    predicates.GroupBy(keys);
    predicates.EqualTo("weight", 108.7);
    predicates.InKeys(keys);
    std::shared_ptr<DataShareResultSet> resultSet = dataShareHelper->Query(uri, predicates, columns);
    double result = 1.0;
    if (resultSet != nullptr) {
        resultSet->GoToFirstRow();
        resultSet->GetDouble(2, result);
        resultSet->HasBlock();
    }
    LOG_INFO("DataShare_Query_004 end");
}

/**
 * @tc.name: DataShare_Query_005
 * @tc.desc: test DataShareHelper Query Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Query_005, TestSize.Level1)
{
    LOG_INFO("DataShare_Query_005 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::vector<std::string> columns {"Querytest4", "Querytest5"};
    DataSharePredicates predicates;
    std::vector<double> weight {98.8, 109.4};
    predicates.In("weight", weight);
    predicates.IndexedBy("name");
    std::shared_ptr<DataShareResultSet> resultSet = dataShareHelper->Query(uri, predicates, columns);
    int64_t result = 0;
    std::string stringResult = "";
    if (resultSet != nullptr) {
        resultSet->GoToPreviousRow();
        resultSet->GetLong(3, result);
        resultSet->GetString(2, stringResult);
    }
    EXPECT_EQ(result, 0);
    LOG_INFO("DataShare_Query_005 end");
}

/**
 * @tc.name: DataShare_Query_006
 * @tc.desc: test DataShareHelper Query Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Query_006, TestSize.Level1)
{
    LOG_INFO("DataShare_Query_006 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::vector<std::string> columns {"Querytest4", "Querytest5"};
    DataSharePredicates predicates;
    std::vector<int64_t> age {12, 57};
    predicates.In("age", age);
    std::shared_ptr<DataShareResultSet> resultSet = dataShareHelper->Query(uri, predicates, columns);
    bool result = true;
    if (resultSet != nullptr) {
        resultSet->GoToNextRow();
        resultSet->GoTo(2);
        resultSet->OnGo(1,4);
    }
    LOG_INFO("DataShare_Query_006 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_Query_007
 * @tc.desc: test DataShareHelper Query Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Query_007, TestSize.Level1)
{
    LOG_INFO("DataShare_Query_007 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::vector<std::string> columns {"Querytest4", "Querytest5"};
    DataSharePredicates predicates;
    std::vector<int64_t> age {12, 57};
    std::vector<string> name {"Zhaosi", "LiMing"};
    std::vector<double> weight {67.7, 56.9};
    predicates.NotIn("age", age);
    predicates.NotIn("name", name);
    predicates.NotIn("weight", weight);
    std::shared_ptr<DataShareResultSet> resultSet = dataShareHelper->Query(uri, predicates, columns);
    if (resultSet != nullptr) {
        bool closeresult = resultSet->IsClosed();
        if(closeresult == false){
            resultSet->Close();
        }
    }
    LOG_INFO("DataShare_Query_007 end");
}

/**
 * @tc.name: DataShare_Query_008
 * @tc.desc: test DataShareHelper Query Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Query_008, TestSize.Level1)
{
    LOG_INFO("DataShare_Query_008 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::vector<std::string> columns {"Querytest4", "Querytest5"};
    DataSharePredicates predicates;
    std::vector<int64_t> age {12, 57};
    std::vector<string> name {"Zhaosi", "LiMing"};
    std::vector<double> weight {67.7, 56.9};
    predicates.NotIn("age", age);
    predicates.NotIn("name", name);
    predicates.NotIn("weight", weight);
    std::shared_ptr<DataShareResultSet> resultSet = dataShareHelper->Query(uri, predicates, columns);
    DataType datatype;
    int columnIndex = 3;
    std::string columnname = "";
    if (resultSet != nullptr) {
        resultSet->GetColumnIndex("age", columnIndex);
        resultSet->GetColumnName(3, columnname);
        resultSet->GetDataType(2, datatype);
        resultSet->GetBlock();
    }
    LOG_INFO("DataShare_Query_008 end");
}

/**
 * @tc.name: DataShare_Query_101
 * @tc.desc: test DataShareHelper Query Abnormal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Query_101, TestSize.Level1)
{
    LOG_INFO("DataShare_Query_101 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::vector<std::string> columns {"Querytest4", "Querytest5"};
    DataSharePredicates predicates;
    std::vector<int64_t> age {12, 57};
    predicates.NotIn("age", age);
    std::shared_ptr<DataShareResultSet> resultSet = dataShareHelper->Query(uri, predicates, columns);
    int columnIndex = 3;
    if (resultSet != nullptr) {
        resultSet->GetColumnIndex("age", columnIndex);
    }
    LOG_INFO("DataShare_Query_101 end");
}

/**
 * @tc.name: DataShare_GetType_001
 * @tc.desc: test DataShareHelper GetType
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_GetType_001, TestSize.Level1)
{
    LOG_INFO("DataShare_GetType_001 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::string result = dataShareHelper->GetType(uri);
    EXPECT_NE(result.c_str(), "");
    LOG_INFO("DataShare_GetType_001 end, result : %{public}s", result.c_str());
}

/**
 * @tc.name: DataShare_BatchInsert_001
 * @tc.desc: test DataShareHelper BatchInsert
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_BatchInsert_001, TestSize.Level1)
{
    LOG_INFO("DataShare_BatchInsert_001 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    val.PutString("name", "ZhangSan");
    val.PutInt("age", 20);
    std::vector<DataShareValuesBucket> values;
    values.push_back(val);
    int result = dataShareHelper->BatchInsert(uri, values);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_BatchInsert_001 end");
}

/**
 * @tc.name: DataShare_BatchInsert_002
 * @tc.desc: test DataShareHelper BatchInsert
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_BatchInsert_002, TestSize.Level1)
{
    LOG_INFO("DataShare_BatchInsert_002 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    val.PutBool("isStudent", true);
    val.PutNull("age");
    std::vector<DataShareValuesBucket> values;
    values.push_back(val);
    int result = dataShareHelper->BatchInsert(uri, values);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_BatchInsert_002 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_BatchInsert_003
 * @tc.desc: test DataShareHelper BatchInsert
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_BatchInsert_003, TestSize.Level1)
{
    LOG_INFO("DataShare_BatchInsert_003 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    std::vector<uint8_t> value {20, 30};
    val.PutBlob("Blob", value);
    val.PutDouble("weight", 156.7);
    std::vector<DataShareValuesBucket> values;
    values.push_back(val);
    int result = dataShareHelper->BatchInsert(uri, values);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_BatchInsert_003 end, result : %{public}d", result);
}

/**
 * @tc.name: DataShare_RegisterObserver_001
 * @tc.desc: test DataShareHelper RegisterObserver Normal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_RegisterObserver_001, TestSize.Level1)
{
    LOG_INFO("DataShare_RegisterObserver_001 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    sptr<IDataShareObserverTest> dataObserver;
    dataObserver->OnChange();
    dataShareHelper->RegisterObserver(uri, dataObserver);
    LOG_INFO("DataShare_RegisterObserver_001 end");
}

/**
 * @tc.name: DataShare_RegisterObserver_101
 * @tc.desc: test DataShareHelper RegisterObserver Abnormal
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_RegisterObserver_101, TestSize.Level1)
{
    LOG_INFO("DataShare_RegisterObserver_101 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    dataShareHelper->RegisterObserver(uri, nullptr);
    LOG_INFO("DataShare_RegisterObserver_101 end");
}

/**
 * @tc.name: DataShare_UnregisterObserver_001
 * @tc.desc: test DataShareHelper UnregisterObserver
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_UnregisterObserver_001, TestSize.Level1)
{
    LOG_INFO("DataShare_UnregisterObserver_001 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    sptr<IDataShareObserverTest> dataObserver;
    dataObserver->OnChange();
    dataShareHelper->UnregisterObserver(uri, dataObserver);
    LOG_INFO("DataShare_UnregisterObserver_001 end");
}

/**
 * @tc.name: DataShare_NotifyChange_001
 * @tc.desc: test DataShareHelper NotifyChange
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_NotifyChange_001, TestSize.Level1)
{
    LOG_INFO("DataShare_NotifyChange_001 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    dataShareHelper->NotifyChange(uri);
    LOG_INFO("DataShare_NotifyChange_001 end");
}

/**
 * @tc.name: DataShare_NormalizeUri_001
 * @tc.desc: test DataShareHelper NormalizeUri
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_NormalizeUri_001, TestSize.Level1)
{
    LOG_INFO("DataShare_NormalizeUri_001 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    dataShareHelper->NormalizeUri(uri);
    LOG_INFO("DataShare_NormalizeUri_001 end");
}

/**
 * @tc.name: DataShare_DenormalizeUri_001
 * @tc.desc: test DataShareHelper DenormalizeUri
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_DenormalizeUri_001, TestSize.Level1)
{
    LOG_INFO("DataShare_DenormalizeUri_001 start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("uri : %{public}s", uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    dataShareHelper->DenormalizeUri(uri);
    LOG_INFO("DataShare_DenormalizeUri_001 end");
}
} // namespace DataShare
} // namespace OHOS