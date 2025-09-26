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

#include "delay_actuator.h"
#include "block_data.h"

#include <gtest/gtest.h>
using namespace testing::ext;
namespace OHOS::Test {
class DelayActuatorTest : public testing::Test {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp(){};
    void TearDown(){};
};

/**
* @tc.name: Execute_001
* @tc.desc: Execute normally
* @tc.type: FUNC
* @tc.require:
* @tc.author: ht
*/
HWTEST_F(DelayActuatorTest, Execute_001, TestSize.Level0)
{
    auto delayActuator = std::make_shared<DelayActuator>(ActuatorBase::DEFAULT_MIN_EXECUTE_INTERVAL);
    delayActuator->SetExecutorPool(std::make_shared<ExecutorPool>(1, 1));
    auto blockData = std::make_shared<BlockData<int>>(2, 0);
    delayActuator->SetTask([blockData]() {
        blockData->SetValue(1);
        return 0;
    });
    delayActuator->Execute();
    EXPECT_EQ(blockData->GetValue(), 1);
}

/**
* @tc.name: Execute_002
* @tc.desc: When triggered once, the Task is executed normally with delayInterval_ delay
* @tc.type: FUNC
* @tc.require:
* @tc.author: ht
*/
HWTEST_F(DelayActuatorTest, Execute_002, TestSize.Level0)
{
    uint32_t firstDelay = 1500;
    uint32_t minInterval = 2000;
    uint32_t maxInterval = 3000;
    auto delayActuator = std::make_shared<DelayActuator>(firstDelay, minInterval, maxInterval);
    delayActuator->SetExecutorPool(std::make_shared<ExecutorPool>(1, 1));
    auto blockData = std::make_shared<BlockData<int>>(1, 0);
    delayActuator->SetTask([blockData]() {
        blockData->SetValue(1);
        return 0;
    });
    delayActuator->Execute();
    EXPECT_EQ(blockData->GetValue(), 0);
    EXPECT_EQ(blockData->GetValue(), 1);
}
} // namespace OHOS::Test
