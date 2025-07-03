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
 #include "rdb_helper.h"
 #include "rdb_store_impl.h"
 #include "delay_notify.h"
 
 using namespace testing::ext;
 using namespace OHOS::NativeRdb;
 using namespace OHOS::Rdb;
 using Asset = ValueObject::Asset;
 using Assets = ValueObject::Assets;
 class DelayNotifyTest : public testing::Test {
 public:
     static void SetUpTestCase(void);
     static void TearDownTestCase(void);
     void SetUp();
     void TearDown();
 
     static const std::string DATABASE_NAME;
     static std::shared_ptr<RdbStore> store;
 };
 
 const std::string DelayNotifyTest::DATABASE_NAME = RDB_TEST_PATH + "db_datamanager_encrypted_test11";
 std::shared_ptr<RdbStore> DelayNotifyTest::store = nullptr;
 
 class DelayNotifyTestCallback : public RdbOpenCallback {
 public:
     int OnCreate(RdbStore &rdbStore) override;
     int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;
     static const std::string CREATE_TABLE_TEST;
 };
 
 int DelayNotifyTestCallback::OnCreate(RdbStore &rdbStore)
 {
     return E_OK;
 }
 
 int DelayNotifyTestCallback::OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion)
 {
     return E_OK;
 }
 
 void DelayNotifyTest::SetUpTestCase(void)
 {
     LOG_ERROR("DelayNotifyTest SetUpTestCase start");
     RdbStoreConfig sqliteSharedRstConfig(DelayNotifyTest::DATABASE_NAME);
     DelayNotifyTestCallback sqliteSharedRstHelper;
     int errCode = E_OK;
     
     DelayNotifyTest::store = RdbHelper::GetRdbStore(sqliteSharedRstConfig, 1, sqliteSharedRstHelper, errCode);
     EXPECT_NE(DelayNotifyTest::store, nullptr);
     LOG_ERROR("DelayNotifyTest SetUpTestCase end");
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
  * @tc.desc: Check whether the null pointer check is successful in the normal process of starting the timer.
  * @tc.type: FUNC
  */
 HWTEST_F(DelayNotifyTest, StartTimer_Test_001, TestSize.Level1)
 {
     RdbStore *rdbStore = DelayNotifyTest::store.get();
     RdbStoreImpl *storeImpl = static_cast<RdbStoreImpl *>(rdbStore);
     storeImpl->InitDelayNotifier();
     // TaskExecutor::INVALID_TASK_ID is 0;
     storeImpl->delayNotifier_->delaySyncTaskId_ = 0;
     storeImpl->delayNotifier_->StartTimer();
     EXPECT_NE(storeImpl->delayNotifier_->delaySyncTaskId_, 0);
 }