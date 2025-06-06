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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "rdb_helper.h"

#include "mock_global_resource.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::NativeRdb;

class GlobalResourceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static inline std::shared_ptr<MockGlobalResource> mockGlobalResource;
};

void GlobalResourceTest::SetUpTestCase(void)
{
    mockGlobalResource = std::make_shared<MockGlobalResource>();
}

void GlobalResourceTest::TearDownTestCase(void)
{
    mockGlobalResource = nullptr;
}

void GlobalResourceTest::SetUp()
{
}

void GlobalResourceTest::TearDown()
{
}

/**
* @tc.name: GlobalResourceTest_CleanUp01
* @tc.desc: No Mock All Symbols
* @tc.type: FUNC
*/
HWTEST_F(GlobalResourceTest, GlobalResourceTest_CleanUp01, TestSize.Level2)
{
    EXPECT_CALL(*mockGlobalResource, CleanUp(_)).WillRepeatedly(Return(E_ERROR));
    OHOS::NativeRdb::RdbHelper::DestroyOption destroyOption;
    destroyOption.cleanICU = true;
    destroyOption.cleanOpenSSL = true;
    EXPECT_FALSE(RdbHelper::Destroy(destroyOption));
}
