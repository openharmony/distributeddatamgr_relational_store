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
    auto delayActuator = std::make_shared<DelayActuator<int>>(nullptr, ActuatorBase::DEFAULT_MIN_EXECUTE_INTERVAL);
    delayActuator->SetExecutorPool(std::make_shared<ExecutorPool>(1, 1));
    auto blockData = std::make_shared<BlockData<int>>(2, 0);
    delayActuator->SetTask([blockData](int data) {
        blockData->SetValue(data);
        return 0;
    });
    delayActuator->Execute(1);
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
    auto delayActuator = std::make_shared<DelayActuator<int>>(nullptr, firstDelay, minInterval, maxInterval);
    delayActuator->SetExecutorPool(std::make_shared<ExecutorPool>(1, 1));
    auto blockData = std::make_shared<BlockData<int>>(1, 0);
    delayActuator->SetTask([blockData](int data) {
        blockData->SetValue(data);
        return 0;
    });
    delayActuator->Execute(1);
    EXPECT_EQ(blockData->GetValue(), 0);
    EXPECT_EQ(blockData->GetValue(), 1);
}

/**
* @tc.name: Execute_003
* @tc.desc: When triggered multiple times, the Task is executed normally with forceInterval_ delay
* @tc.type: FUNC
* @tc.require:
* @tc.author: ht
*/
HWTEST_F(DelayActuatorTest, Execute_003, TestSize.Level0)
{
    uint32_t firstDelay = 200;
    uint32_t minInterval = 200;
    uint32_t maxInterval = 600;
    auto delayActuator = std::make_shared<DelayActuator<int>>(nullptr, firstDelay, minInterval, maxInterval);
    delayActuator->SetExecutorPool(std::make_shared<ExecutorPool>(1, 1));
    auto blockData = std::make_shared<BlockData<int>>(0, 0);
    delayActuator->SetTask([blockData](int data) {
        blockData->SetValue(data);
        return 0;
    });
    for (int i = 0; i < 5; i++) {
        delayActuator->Execute(i);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        EXPECT_EQ(blockData->GetValue(), 0);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(blockData->GetValue(), 4);
}

/**
* @tc.name: Execute_004
* @tc.desc: Execute task after Defer deconstruction
* @tc.type: FUNC
* @tc.require:
* @tc.author: ht
*/
HWTEST_F(DelayActuatorTest, Execute_004, TestSize.Level0)
{
    auto delayActuator = std::make_shared<DelayActuator<int>>(nullptr, ActuatorBase::DEFAULT_MIN_EXECUTE_INTERVAL);
    delayActuator->SetExecutorPool(std::make_shared<ExecutorPool>(1, 1));
    auto blockData = std::make_shared<BlockData<int>>(1, 0);
    delayActuator->SetTask([blockData](int data) {
        blockData->SetValue(data);
        return 0;
    });
    {
        ActuatorBase::Defer defer(delayActuator);
        for (int i = 0; i < 3; i++) {
            delayActuator->Execute(i);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            EXPECT_EQ(blockData->GetValue(), 0);
        }
    }
    EXPECT_EQ(blockData->GetValue(), 2);
}

/**
* @tc.name: Execute_005
* @tc.desc: When triggered multiple times, use mergeFunc to merge parameters
* @tc.type: FUNC
* @tc.require:
* @tc.author: ht
*/
HWTEST_F(DelayActuatorTest, Execute_005, TestSize.Level0)
{
    auto delayActuator = std::make_shared<DelayActuator<int>>(
        [](int& out, int&& input) {
            out += input;
        },
        100, 100, 300);
    delayActuator->SetExecutorPool(std::make_shared<ExecutorPool>(1, 1));
    auto blockData = std::make_shared<BlockData<int>>(0, 0);
    delayActuator->SetTask([blockData](int data) {
        blockData->SetValue(data);
        return 0;
    });
    for (int i = 0; i < 5; i++) {
        delayActuator->Execute(i);
        EXPECT_EQ(blockData->GetValue(), 0);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_EQ(blockData->GetValue(), 10);
}

/**
* @tc.name: Execute_006
* @tc.desc: Testing MergeFunc for complex types
* @tc.type: FUNC
* @tc.require:
* @tc.author: ht
*/
HWTEST_F(DelayActuatorTest, Execute_006, TestSize.Level0)
{
    using DelayActuatorT = DelayActuator<std::map<std::string, std::string>>;
    auto delayActuator = std::make_shared<DelayActuatorT>(
        [](auto& out, std::map<std::string, std::string>&& input) {
            for (auto& [k, v] : input) {
                out[k] += std::move(v);
            }
        },
        100);
    delayActuator->SetExecutorPool(std::make_shared<ExecutorPool>(1, 1));
    auto blockData = std::make_shared<BlockData<std::map<std::string, std::string>>>(3);
    delayActuator->SetTask([blockData](const std::map<std::string, std::string>& data) {
        blockData->SetValue(data);
        return 0;
    });
    std::map<std::string, std::string> data;
    int len = 10;
    for (int i = 0; i < len; i++) {
        data.insert_or_assign(std::to_string(i), "t");
        delayActuator->Execute(data);
    }
    auto val = blockData->GetValue();
    EXPECT_EQ(val.size(), len);
    for (auto& [k, v] : val) {
        EXPECT_EQ(v, std::string(len--, 't'));
    }
}

/**
* @tc.name: Execute_007
* @tc.desc: Testing delay of first execution and minimum interval
* @tc.type: FUNC
* @tc.require:
* @tc.author: ht
*/
HWTEST_F(DelayActuatorTest, Execute_007, TestSize.Level0)
{
    uint32_t firstDelay = 50;
    uint32_t minInterval = 1500;
    uint32_t maxInterval = 5000;
    auto delayActuator = std::make_shared<DelayActuator<int>>(nullptr, firstDelay, minInterval, maxInterval);
    delayActuator->SetExecutorPool(std::make_shared<ExecutorPool>(1, 1));
    auto blockData = std::make_shared<BlockData<int>>(1, 0);
    delayActuator->SetTask([blockData](int data) {
        blockData->SetValue(data);
        return 0;
    });
    delayActuator->Execute(1);
    EXPECT_EQ(blockData->GetValue(), 1);
    blockData->Clear(0);
    delayActuator->Execute(2);
    EXPECT_EQ(blockData->GetValue(), 0);
    blockData->Clear(0);
    EXPECT_EQ(blockData->GetValue(), 2);
}
} // namespace OHOS::Test
