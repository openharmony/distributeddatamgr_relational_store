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

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>

#include <gtest/gtest.h>
using namespace testing::ext;
namespace OHOS::Test {
namespace {
constexpr std::chrono::seconds WAIT_TIMEOUT(2);

struct TaskState {
    std::atomic<uint64_t> nextId = 1;
    std::atomic<uint64_t> executingId = 0;
    std::atomic_bool executingTaskDestroyed = false;
    std::mutex mutex;
    std::condition_variable condition;
    bool started = false;
    bool released = false;
    bool finished = false;
};

class TrackedTask final {
public:
    explicit TrackedTask(std::shared_ptr<TaskState> state) : state_(std::move(state)), id_(state_->nextId.fetch_add(1))
    {
    }

    TrackedTask(const TrackedTask &other) : state_(other.state_), id_(state_->nextId.fetch_add(1))
    {
    }

    TrackedTask(TrackedTask &&other) noexcept : state_(std::move(other.state_)), id_(other.id_)
    {
        other.id_ = 0;
    }

    ~TrackedTask()
    {
        if (state_ != nullptr && id_ != 0 && state_->executingId.load() == id_) {
            state_->executingTaskDestroyed = true;
        }
    }

    void operator()() const
    {
        auto state = state_;
        state->executingId = id_;
        std::unique_lock<std::mutex> lock(state->mutex);
        state->started = true;
        state->condition.notify_all();
        state->condition.wait(lock, [state]() { return state->released; });
        state->finished = true;
        state->executingId = 0;
        state->condition.notify_all();
    }

private:
    std::shared_ptr<TaskState> state_;
    uint64_t id_;
};
} // namespace

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

/**
* @tc.name: SetTask_001
* @tc.desc: Replacing the task does not destroy a task that is being executed
* @tc.type: FUNC
* @tc.require:
* @tc.author: ht
*/
HWTEST_F(DelayActuatorTest, SetTask_001, TestSize.Level0)
{
    auto state = std::make_shared<TaskState>();
    auto delayActuator = std::make_shared<DelayActuator>(0, 1, ActuatorBase::INVALID_INTERVAL);
    delayActuator->SetExecutorPool(std::make_shared<ExecutorPool>(1, 1));
    delayActuator->SetTask(TrackedTask(state));
    delayActuator->Execute();

    std::unique_lock<std::mutex> lock(state->mutex);
    bool started = state->condition.wait_for(lock, WAIT_TIMEOUT, [state]() { return state->started; });
    lock.unlock();
    delayActuator->SetTask([]() {});
    EXPECT_TRUE(started);
    EXPECT_FALSE(state->executingTaskDestroyed);

    lock.lock();
    state->released = true;
    state->condition.notify_all();
    bool finished = state->condition.wait_for(lock, WAIT_TIMEOUT, [state]() { return state->finished; });
    EXPECT_TRUE(finished);
}
} // namespace OHOS::Test
