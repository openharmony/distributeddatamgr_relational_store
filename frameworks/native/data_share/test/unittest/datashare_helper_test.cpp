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
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Release_001, TestSize.Level1)
{
    LOG_INFO("DataShare_Release_001 ----- start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("addr : %{public}p, uri : %{public}s", &uri, uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::string mimeTypeFilter("mimeTypeFiltertest");
    bool result = dataShareHelper->Release();
    EXPECT_EQ(result, true);
    LOG_INFO("DataShare_Release_001 ----- end");
}

/**
 * @tc.name: DataShare_GetFileTypes_001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_GetFileTypes_001, TestSize.Level1)
{
    LOG_INFO("DataShare_GetFileTypes_001 ----- start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("addr : %{public}p, uri : %{public}s", &uri, uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::string mimeTypeFilter("mimeTypeFiltertest");
    std::vector<std::string> result = dataShareHelper->GetFileTypes(uri, mimeTypeFilter);
    EXPECT_EQ(result.size(), 0);
    LOG_INFO("DataShare_GetFileTypes_001 ----- end");
}

/**
 * @tc.name: DataShare_OpenFile_001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_OpenFile_001, TestSize.Level1)
{
    LOG_INFO("DataShare_OpenFile_001 ----- start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("addr : %{public}p, uri : %{public}s", &uri, uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI); 
    std::string mode("modetest");
    int result = dataShareHelper->OpenFile(uri, mode);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_OpenFile_001 ----- end");
}

/**
 * @tc.name: DataShare_OpenRawFile_001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_OpenRawFile_001, TestSize.Level1)
{
    LOG_INFO("DataShare_OpenRawFile_001 ----- start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("addr : %{public}p, uri : %{public}s", &uri, uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI); 
    std::string mode("modetest");
    int result = dataShareHelper->OpenRawFile(uri, mode);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_OpenRawFile_001 ----- end");
}

/**
 * @tc.name: DataShare_Insert_001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Insert_001, TestSize.Level1)
{
    LOG_INFO("DataShare_Insert_001 ----- start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("addr : %{public}p, uri : %{public}s", &uri, uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    std::vector<uint8_t> value {20, 30};
    val.PutString("name", "ZhangSan");
    val.PutInt("age", 20);
    int result = dataShareHelper->Insert(uri, val);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Insert_001 ----- end");
}

/**
 * @tc.name: DataShare_Update_001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Update_001, TestSize.Level1)
{
    LOG_INFO("DataShare_Update_001 ----- start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataShareValuesBucket val;
    val.PutString("name", "ZhangSan");
    val.PutInt("age", 30);
    DataSharePredicates predicates;
    predicates.EqualTo("age", 20);
    int result = dataShareHelper->Update(uri, val, predicates);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Update_001 ----- end");
}

/**
 * @tc.name: DataShare_Delete_001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Delete_001, TestSize.Level1)
{
    LOG_INFO("DataShare_Delete_001 ----- start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("addr : %{public}p, uri : %{public}s", &uri, uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    DataSharePredicates predicates;
    predicates.EqualTo("age", 20);
    int result = dataShareHelper->Delete(uri, predicates);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_Delete_001 ----- end");
}

/**
 * @tc.name: DataShare_Query_001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_Query_001, TestSize.Level1)
{
    LOG_INFO("DataShare_Query_001 ----- start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("addr : %{public}p, uri : %{public}s", &uri, uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::vector<std::string> columns {"Querytest1", "Querytest2"};
    DataSharePredicates predicates;
    predicates.EqualTo("predicatestest", 20);
    std::shared_ptr<DataShareResultSet> resultSet = dataShareHelper->Query(uri, columns, predicates);
    int result = 0;
    if (resultSet != nullptr) {
        resultSet->GetRowCount(result);
    }
    EXPECT_NE(result, -1);
    LOG_INFO("DataShare_Query_001 ----- end");
}

/**
 * @tc.name: DataShare_GetType_001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_GetType_001, TestSize.Level1)
{
    LOG_INFO("DataShare_GetType_001 ----- start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("addr : %{public}p, uri : %{public}s", &uri, uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::string result = dataShareHelper->GetType(uri);
    EXPECT_NE(result.c_str(), "");
    LOG_INFO("DataShare_GetType_001 ----- end, result : %{public}s", result.c_str());
}

/**
 * @tc.name: DataShare_BatchInsert_001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_BatchInsert_001, TestSize.Level1)
{
    LOG_INFO("DataShare_BatchInsert_001 ----- start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("addr : %{public}p, uri : %{public}s", &uri, uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    std::vector<DataShareValuesBucket> values;
    int result = dataShareHelper->BatchInsert(uri, values);
    EXPECT_NE(result, 0);
    LOG_INFO("DataShare_BatchInsert_001 ----- end");
}

/**
 * @tc.name: DataShare_RegisterObserver_001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_RegisterObserver_001, TestSize.Level1)
{
    LOG_INFO("DataShare_RegisterObserver_001 ----- start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("addr : %{public}p, uri : %{public}s", &uri, uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    sptr<IDataShareObserverTest> dataObserver;
    dataShareHelper->RegisterObserver(uri, dataObserver);
    LOG_INFO("DataShare_RegisterObserver_001 ----- end");
}

/**
 * @tc.name: DataShare_UnregisterObserver_001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_UnregisterObserver_001, TestSize.Level1)
{
    LOG_INFO("DataShare_UnregisterObserver_001 ----- start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("addr : %{public}p, uri : %{public}s", &uri, uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    sptr<IDataShareObserverTest> dataObserver;
    dataShareHelper->UnregisterObserver(uri, dataObserver);
    LOG_INFO("DataShare_UnregisterObserver_001 ----- end");
}

/**
 * @tc.name: DataShare_NotifyChange_001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_NotifyChange_001, TestSize.Level1)
{
    LOG_INFO("DataShare_NotifyChange_001 ----- start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("addr : %{public}p, uri : %{public}s", &uri, uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    dataShareHelper->NotifyChange(uri);
    LOG_INFO("DataShare_NotifyChange_001 ----- end");
}

/**
 * @tc.name: DataShare_NormalizeUri_001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_NormalizeUri_001, TestSize.Level1)
{
    LOG_INFO("DataShare_NormalizeUri_001 ----- start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("addr : %{public}p, uri : %{public}s", &uri, uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    dataShareHelper->NormalizeUri(uri);
    LOG_INFO("DataShare_NormalizeUri_001 ----- end");
}

/**
 * @tc.name: DataShare_DenormalizeUri_001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(DataShareHelperTest, DataShare_DenormalizeUri_001, TestSize.Level1)
{
    LOG_INFO("DataShare_DenormalizeUri_001 ----- start");
    std::shared_ptr<Ability> ability = std::make_shared<Ability>();
    std::shared_ptr<Context> context(ability);
    Uri uri(URI);
    LOG_INFO("addr : %{public}p, uri : %{public}s", &uri, uri.GetScheme().c_str());
    std::shared_ptr<DataShareHelper> dataShareHelper = DataShareHelper::Creator(context, URI);
    dataShareHelper->DenormalizeUri(uri);
    LOG_INFO("DataShare_DenormalizeUri_001 ----- end");
}
} // namespace DataShare
} // namespace OHOS