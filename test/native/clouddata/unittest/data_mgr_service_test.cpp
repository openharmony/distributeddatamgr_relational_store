/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define LOG_TAG "DataMgrServiceTest"

#include <gtest/gtest.h>
#include <unistd.h>

#include "cloud_types_util.h"
#include "data_mgr_service.h"
#include "icloud_client_death_observer.h"
#include "iservice_registry.h"
#include "logger.h"
#include "system_ability_definition.h"

namespace OHOS::CloudData {
using namespace testing::ext;
using namespace OHOS::Rdb;
using namespace DistributedRdb;
static constexpr const char *CLOUD_SERVICE_NAME = "cloud";
class DataMgrServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp()
    {
    }
    void TearDown()
    {
    }
};

void DataMgrServiceTest::SetUpTestCase(void)
{
    LOG_INFO("SetUpTestCase in.");
}

void DataMgrServiceTest::TearDownTestCase(void)
{
    LOG_INFO("TearDownTestCase in.");
}

sptr<IRemoteObject> GetSystemAbility()
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        LOG_ERROR("Get system ability manager failed.");
        return nullptr;
    }
    auto dataMgrObject = saMgr->CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    if (dataMgrObject == nullptr) {
        LOG_ERROR("Get distributed data manager failed.");
    }
    return dataMgrObject;
}

/* *
 * @tc.name: RegisterClientDeathObserverTest_001
 * @tc.desc: Test the RegisterClientDeathObserver API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DataMgrServiceTest, RegisterClientDeathObserverTest_001, TestSize.Level0)
{
    sptr<IRemoteObject> service = nullptr;
    sptr<DataMgrService> dataMgr = new (std::nothrow) DataMgrService(service);
    auto status = dataMgr->RegisterClientDeathObserver("", nullptr);    // bundleName is empty
    EXPECT_EQ(status, CloudService::ERROR);

    status = dataMgr->RegisterClientDeathObserver("bundleName", nullptr);   // observer is nullptr
    EXPECT_EQ(status, CloudService::ERROR);

    sptr<IRemoteObject> observer = new (std::nothrow) CloudClientDeathObserverStub();
    status = dataMgr->RegisterClientDeathObserver("bundleName", observer);   // IPC error
    EXPECT_EQ(status, CloudService::IPC_ERROR);
}

/* *
 * @tc.name: RegisterClientDeathObserverTest_002
 * @tc.desc: Test the RegisterClientDeathObserver API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DataMgrServiceTest, RegisterClientDeathObserverTest_002, TestSize.Level0)
{
    auto service = GetSystemAbility();
    if (service != nullptr) {
        sptr<DataMgrService> dataMgr = new (std::nothrow) DataMgrService(service);
        sptr<IRemoteObject> observer = new (std::nothrow) CloudClientDeathObserverStub();
        auto status = dataMgr->RegisterClientDeathObserver("bundleName", observer);
        EXPECT_EQ(status, CloudService::SUCCESS);
    }
}

/* *
 * @tc.name: GetFeatureInterfaceTest_001
 * @tc.desc: Test the GetFeatureInterface API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DataMgrServiceTest, GetFeatureInterfaceTest_001, TestSize.Level0)
{
    sptr<IRemoteObject> service = nullptr;
    sptr<DataMgrService> dataMgr = new (std::nothrow) DataMgrService(service);
    auto cloudObject = dataMgr->GetFeatureInterface("");    // featureName is empty
    EXPECT_EQ(cloudObject, nullptr);

    cloudObject = dataMgr->GetFeatureInterface("featureName");   // featureName is invalid
    EXPECT_EQ(cloudObject, nullptr);

    cloudObject = dataMgr->GetFeatureInterface(CLOUD_SERVICE_NAME);   // IPC error
    EXPECT_EQ(cloudObject, nullptr);
}

/* *
 * @tc.name: GetFeatureInterfaceTest_002
 * @tc.desc: Test the GetFeatureInterface API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DataMgrServiceTest, GetFeatureInterfaceTest_002, TestSize.Level0)
{
    auto service = GetSystemAbility();
    if (service != nullptr) {
        sptr<DataMgrService> dataMgr = new (std::nothrow) DataMgrService(service);
        auto cloudObject = dataMgr->GetFeatureInterface("featureName");   // featureName is invalid
        EXPECT_EQ(cloudObject, nullptr);

        cloudObject = dataMgr->GetFeatureInterface(CLOUD_SERVICE_NAME);   // featureName is valid
        EXPECT_NE(cloudObject, nullptr);
    }
}
}
