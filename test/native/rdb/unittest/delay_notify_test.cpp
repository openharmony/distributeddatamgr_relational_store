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

#define LOG_TAG "DelayNotifyTest"
#include <gtest/gtest.h>

#include "logger.h"
#include "common.h"
#include "executor_pool.h"
#include "rdb_helper.h"
#include "rdb_store_impl.h"
#include "delay_notify.h"
#include "block_data.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;
using namespace OHOS::DistributedRdb;
class DelayNotifyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DelayNotifyTest::SetUpTestCase(void)
{
}

void DelayNotifyTest::TearDownTestCase(void)
{
}

void DelayNotifyTest::SetUp()
{
}

void DelayNotifyTest::TearDown()
{
}

/**
* @tc.name: StartTimer_Test_001
* @tc.desc: Check the normal process of starting the timer.
* @tc.type: FUNC
*/
HWTEST_F(DelayNotifyTest, StartTimer_Test_001, TestSize.Level1)
{
    auto delayNotifier = std::make_shared<DelayNotify>();
    delayNotifier->SetExecutorPool(std::make_shared<OHOS::ExecutorPool>(5, 0));
    auto block = std::make_shared<OHOS::BlockData<bool>>(1, false);
    delayNotifier->SetTask([block](const RdbChangedData &, const RdbNotifyConfig &){
        block->SetValue(true);
        return 0;
    });
    delayNotifier->isFull_ = true;
    delayNotifier->UpdateNotify(RdbChangedData());
    EXPECT_TRUE(block->GetValue());
}

/**
* @tc.name: StartTimer_Test_002
* @tc.desc: Check if the function ExecuteTask() can avoid crashing when the delayNotify is destructed prematurely
*           in the main process of starting the timer.
* @tc.type: FUNC
*/
HWTEST_F(DelayNotifyTest, StartTimer_Test_002, TestSize.Level1)
{
    auto delayNotifier = std::make_shared<DelayNotify>();
    delayNotifier->SetExecutorPool(std::make_shared<OHOS::ExecutorPool>(5, 0));
    auto pool = delayNotifier->pool_;
    auto block = std::make_shared<OHOS::BlockData<bool>>(1, false);
    delayNotifier->SetTask([block](const RdbChangedData &, const RdbNotifyConfig &){
        block->SetValue(true);
        return 0;
    });
    delayNotifier->UpdateNotify(RdbChangedData());
    delayNotifier->delaySyncTaskId_ = OHOS::ExecutorPool::INVALID_TASK_ID;
    delayNotifier.reset();
    ASSERT_NO_FATAL_FAILURE(EXPECT_FALSE(block->GetValue()));
}