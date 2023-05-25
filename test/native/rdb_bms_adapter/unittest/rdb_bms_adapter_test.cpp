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

#include "data_share_profile_info.h"

using namespace testing::ext;
using namespace OHOS::RdbBMSAdapter;

class RdbBMSAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void RdbBMSAdapterTest::SetUpTestCase(void)
{
}

void RdbBMSAdapterTest::TearDownTestCase(void)
{
}

void RdbBMSAdapterTest::SetUp(void)
{
}

void RdbBMSAdapterTest::TearDown(void)
{
}

HWTEST_F(RdbBMSAdapterTest, Rdb_BMS_Adapter_001, TestSize.Level1)
{
    OHOS::AppExecFwk::ExtensionAbilityInfo extensionInfo;
    std::vector<std::string> profileInfos;
    auto ret = DataShareProfileInfo::GetResConfigFile(extensionInfo, profileInfos);
    EXPECT_EQ(ret, false);
}

HWTEST_F(RdbBMSAdapterTest, Rdb_BMS_Adapter_002, TestSize.Level1)
{
    OHOS::AppExecFwk::ProxyData proxyData;
    DataProperties properties;
    auto ret = DataShareProfileInfo::GetDataPropertiesFromProxyDatas(proxyData, "", false, properties);
    EXPECT_EQ(ret, false);
}

HWTEST_F(RdbBMSAdapterTest, Rdb_BMS_Adapter_003, TestSize.Level1)
{
    Config config;
    config.uri = "uri";
    config.crossUserMode = 1;
    config.writePermission = "writePermission";
    config.readPermission = "readPermission";

    auto jstr = to_string(config.Marshall());
    Config config1;
    config1.Unmarshall(jstr);

    EXPECT_EQ(config.uri, config1.uri);
    EXPECT_EQ(config.crossUserMode, config1.crossUserMode);
    EXPECT_EQ(config.writePermission, config1.writePermission);
    EXPECT_EQ(config.readPermission, config1.readPermission);
}

HWTEST_F(RdbBMSAdapterTest, Rdb_BMS_Adapter_004, TestSize.Level1)
{
    ProfileInfo profileInfo;
    Config config;
    config.uri = "uri";
    config.crossUserMode = 1;
    config.writePermission = "writePermission";
    config.readPermission = "readPermission";
    profileInfo.tableConfig.emplace_back(config);

    auto jstr = to_string(profileInfo.Marshall());
    ProfileInfo profileInfo1;
    profileInfo1.Unmarshall(jstr);
    EXPECT_EQ(profileInfo.tableConfig.size(), profileInfo1.tableConfig.size());
}

HWTEST_F(RdbBMSAdapterTest, Rdb_BMS_Adapter_005, TestSize.Level1)
{
    DataProperties dataProperties;
    dataProperties.storeName = "store1";
    dataProperties.tableName = "table1";

    auto jstr = to_string(dataProperties.Marshall());
    DataProperties dataProperties1;
    dataProperties1.Unmarshall(jstr);

    EXPECT_EQ(dataProperties.storeName, dataProperties1.storeName);
    EXPECT_EQ(dataProperties.tableName, dataProperties1.tableName);
    EXPECT_EQ(dataProperties.scope, dataProperties1.scope);
    EXPECT_EQ(dataProperties.type, dataProperties1.type);
}

