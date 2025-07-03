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
     delayNotifier->pool_ = std::make_shared<OHOS::ExecutorPool>(5, 0);
     delayNotifier->changedData_ = RdbChangedData();
     delayNotifier->delaySyncTaskId_ = 0;
     delayNotifier->StartTimer();
     std::this_thread::sleep_for(std::chrono::milliseconds(1000));
     EXPECT_EQ(delayNotifier->delaySyncTaskId_, 0);
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
     auto pool = std::make_shared<OHOS::ExecutorPool>(5, 0);
     delayNotifier->pool_ = pool;
     delayNotifier->delaySyncTaskId_ = 0;
     delayNotifier->changedData_ = RdbChangedData();
     delayNotifier->autoSyncInterval_ = 500;
     delayNotifier->StartTimer();
     delayNotifier->delaySyncTaskId_ = 9999;
     delayNotifier.reset();
     std::this_thread::sleep_for(std::chrono::milliseconds(2000));
     EXPECT_EQ(delayNotifier, nullptr);
 }