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
#include "datashare_value_object.h"
#include "datashare_values_bucket.h"
#include "rdb_data_ability_utils.h"
#include "refbase.h"
#include "values_bucket.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataAbilityAdapter;
using namespace OHOS::DataShare;

class DataAbilityUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DataAbilityUtilsTest::SetUpTestCase(void) {}
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
