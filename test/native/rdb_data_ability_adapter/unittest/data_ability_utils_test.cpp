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
#include <vector>

#include "abs_rdb_predicates.h"
#include "abs_shared_result_set.h"
#include "accesstoken_kit.h"
#include "datashare_helper.h"
#include "datashare_value_object.h"
#include "datashare_values_bucket.h"
#include "hap_token_info.h"
#include "iservice_registry.h"
#include "rdb_data_ability_utils.h"
#include "refbase.h"
#include "result_set_proxy.h"
#include "system_ability_definition.h"
#include "token_setproc.h"
#include "values_bucket.h"

namespace OHOS {
namespace RdbDataAbilityAdapter {
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using namespace OHOS::Security::AccessToken;

constexpr int STORAGE_MANAGER_MANAGER_ID = 5003;
std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
std::string SLIENT_ACCESS_URI = "datashare:///com.acts.datasharetest/entry/DB00/TBL00?Proxy=true";
std::string TBL_STU_NAME = "name";
std::string TBL_STU_AGE = "age";

class DataAbilityUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(int32_t systemAbilityId, std::string uri)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, uri);
}

std::vector<PermissionStateFull> GetPermissionStateFulls()
{
    std::vector<PermissionStateFull> permissionStateFulls = {
        {
            .permissionName = "ohos.permission.WRITE_CONTACTS",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        },
        {
            .permissionName = "ohos.permission.WRITE_CALL_LOG",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        },
        {
            .permissionName = "ohos.permission.GET_BUNDLE_INFO",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        }
    };
    return permissionStateFulls;
}

void DataAbilityUtilsTest::SetUpTestCase(void)
{
    HapInfoParams info = {
        .userID = 100,
        .bundleName = "ohos.rdbdataabilityutilstest.demo",
        .instIndex = 0,
        .appIDDesc = "ohos.rdbdataabilityutilstest.demo"
    };
    auto permStateList = GetPermissionStateFulls();
    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {
            {
                .permissionName = "ohos.permission.test",
                .bundleName = "ohos.rdbdataabilityutilstest.demo",
                .grantMode = 1,
                .availableLevel = APL_NORMAL,
                .label = "label",
                .labelId = 1,
                .description = "ohos.rdbdataabilityutilstest.demo",
                .descriptionId = 1
            }
        },
        .permStateList = permStateList
    };
    AccessTokenKit::AllocHapToken(info, policy);
    auto testTokenId = Security::AccessToken::AccessTokenKit::GetHapTokenIDEx(
        info.userID, info.bundleName, info.instIndex);
    SetSelfTokenID(testTokenId.tokenIDEx);
}
void DataAbilityUtilsTest::TearDownTestCase(void) {}
void DataAbilityUtilsTest::SetUp(void) {}
void DataAbilityUtilsTest::TearDown(void) {}

/* *
 * @tc.name: DataAbilityUtilsTest_001
 * @tc.desc: test ToDataShareValuesBucket()
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DataAbilityUtilsTest, DataAbilityUtilsTest_001, TestSize.Level1)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutString("name", "Tom");
    valuesBucket.PutInt("age", 10);
    valuesBucket.PutDouble("weight", 50.5);
    valuesBucket.PutBlob("data", { 1, 2, 3 });

    auto dataShareValuesBucket = RdbDataAbilityUtils::ToDataShareValuesBucket(valuesBucket);

    bool isEmpty = dataShareValuesBucket.IsEmpty();
    EXPECT_EQ(isEmpty, false);

    auto iter = dataShareValuesBucket.valuesMap.find("name");
    if (iter != dataShareValuesBucket.valuesMap.end()) {
        std::string strValue = std::get<std::string>(iter->second);
        EXPECT_EQ(strValue, "Tom");
    } else {
        EXPECT_EQ(true, false);
    }

    if (iter != dataShareValuesBucket.valuesMap.end()) {
        iter = dataShareValuesBucket.valuesMap.find("age");
        int64_t intValue = std::get<int64_t>(iter->second);
        EXPECT_EQ(intValue, 10);
    } else {
        EXPECT_EQ(true, false);
    }

    if (iter != dataShareValuesBucket.valuesMap.end()) {
        iter = dataShareValuesBucket.valuesMap.find("weight");
        double doubleValue = std::get<double>(iter->second);
        EXPECT_EQ(doubleValue, 50.5);
    } else {
        EXPECT_EQ(true, false);
    }

    if (iter != dataShareValuesBucket.valuesMap.end()) {
        iter = dataShareValuesBucket.valuesMap.find("data");
        std::vector<uint8_t> uint8Vec = std::get<std::vector<uint8_t>>(iter->second);
        EXPECT_EQ(uint8Vec[0], 1);
    } else {
        EXPECT_EQ(true, false);
    }
}

/* *
 * @tc.name: DataAbilityUtilsTest_002
 * @tc.desc: test ToDataSharePredicates()
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DataAbilityUtilsTest, DataAbilityUtilsTest_002, TestSize.Level1)
{
    std::string order = "age";
    auto *predicates = new DataAbilityPredicates();
    predicates->EqualTo("name", "Tom")->OrderByDesc("id")->Limit(2);
    predicates->SetOrder(order);
    predicates->Distinct();

    std::string whereClause = "name = ? ";
    auto dataSharePredicates = RdbDataAbilityUtils::ToDataSharePredicates(*predicates);
    std::string dataShareWhereClause = dataSharePredicates.GetWhereClause();
    EXPECT_EQ(dataShareWhereClause, whereClause);

    std::string dataShareOrder = dataSharePredicates.GetOrder();
    EXPECT_EQ(dataShareOrder, order);
}

/* *
 * @tc.name: DataAbilityUtilsTest_003
 * @tc.desc: test ToAbsSharedResultSet()
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DataAbilityUtilsTest, DataAbilityUtilsTest_003, TestSize.Level1)
{
    dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID, SLIENT_ACCESS_URI);
    ASSERT_TRUE(dataShareHelper != nullptr);
    Uri uri(SLIENT_ACCESS_URI);

    DataShare::DataShareValuesBucket valuesBucket;
    std::string value = "lisi";
    valuesBucket.Put(TBL_STU_NAME, value);
    int age = 25;
    valuesBucket.Put(TBL_STU_AGE, age);
    int retVal = dataShareHelper->Insert(uri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(TBL_STU_NAME, "lisi");
    vector<string> columns;
    auto dsresultSet = dataShareHelper->Query(uri, predicates, columns);
    int result = 0;
    if (dsresultSet != nullptr) {
        dsresultSet->GetRowCount(result);
    }
    EXPECT_EQ(result, 1);

    std::shared_ptr<AbsSharedResultSet> rdbresultSet = RdbDataAbilityUtils::ToAbsSharedResultSet(dsresultSet);
    if (rdbresultSet != nullptr) {
        rdbresultSet->GetRowCount(result);
    }
    EXPECT_EQ(result, 1);
    EXPECT_EQ(0, rdbresultSet->OnGo(0, 1));
}
}
}