/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <iostream>
#include <string>
#include <string_view>

#include "common.h"
#include "block_data.h"
#include "executor_pool.h"
#include "rd_utils.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "shared_block.h"
#include "sqlite_shared_result_set.h"
#include "step_result_set.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::NativeRdb;

namespace Test {
class RdbMultiThreadConnectionRdTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static const std::string databaseName;

    static constexpr int32_t MAX_THREAD = 5;
    static constexpr int32_t MIN_THREAD = 0;

    std::shared_ptr<RdbStore> store_;
    std::shared_ptr<ExecutorPool> executors_;

    RdbMultiThreadConnectionRdTest();
};

const std::string RdbMultiThreadConnectionRdTest::databaseName = RDB_TEST_PATH + "execute_test.db";

class Callback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int Callback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int Callback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

RdbMultiThreadConnectionRdTest::RdbMultiThreadConnectionRdTest()
{
    executors_ = std::make_shared<ExecutorPool>(MAX_THREAD, MIN_THREAD);
    store_ = nullptr;
    RdbHelper::DeleteRdbStore(databaseName);
    RdbStoreConfig config(databaseName);
    config.SetIsVector(true);
    config.SetSecurityLevel(SecurityLevel::S4);
    Callback helper;
    int errCode = E_OK;
    store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store_, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbMultiThreadConnectionRdTest::SetUpTestCase(void)
{
}

void RdbMultiThreadConnectionRdTest::TearDownTestCase(void)
{
}

void RdbMultiThreadConnectionRdTest::SetUp(void)
{
}

void RdbMultiThreadConnectionRdTest::TearDown(void)
{
    executors_ = nullptr;
    store_ = nullptr;
    RdbHelper::DeleteRdbStore(RdbMultiThreadConnectionRdTest::databaseName);
}

/**
 * @tc.name: MultiThread_Connection_0001
 *           test if two threads can begin trans and commit in order without conflicting
 * @tc.desc: 1.thread 1: begin trans and commit
 *           2.thread 2: begin trans and commit
 * @tc.type: FUNC
 * @tc.author: zhangjiaxi
 */
HWTEST_F(RdbMultiThreadConnectionRdTest, MultiThread_BeginTransTest_0001, TestSize.Level2)
{
    auto taskId1 = executors_->Execute([store = store_]() {
        std::pair<int, int64_t> res;
        int32_t errCode = E_OK;
        for (int i = 0; i < 2000; i++) {
            res = store->BeginTrans();
            EXPECT_EQ(res.first, E_OK);
            errCode = store->Commit(res.second);
            EXPECT_EQ(errCode, E_OK);
        }
    });

    auto taskId2 = executors_->Execute([store = store_]() {
        std::pair<int, int64_t> res;
        int32_t errCode = E_OK;
        for (int i = 0; i < 2000; i++) {
            res = store->BeginTrans();
            EXPECT_EQ(res.first, E_OK);
            errCode = store->Commit(res.second);
            EXPECT_EQ(errCode, E_OK);
        }
    });
    executors_->Remove(taskId1, true);
    executors_->Remove(taskId2, true);
    EXPECT_NE(taskId1, taskId2);
}

/**
 * @tc.name: MultiThread_Connection_0002
 *           test if two threads can begin trans and rollback in order without conflicting
 * @tc.desc: 1.thread 1: begin trans and rollback
 *           2.thread 2: begin trans and rollback
 * @tc.type: FUNC
 * @tc.author: zhangjiaxi
 */
HWTEST_F(RdbMultiThreadConnectionRdTest, MultiThread_BeginTransTest_0002, TestSize.Level2)
{
    auto taskId1 = executors_->Execute([store = store_]() {
        std::pair<int, int64_t> res;
        int32_t errCode = E_OK;
        for (int i = 0; i < 2000; i++) {
            res = store->BeginTrans();
            EXPECT_EQ(res.first, E_OK);
            errCode = store->RollBack(res.second);
            EXPECT_EQ(errCode, E_OK);
        }
    });

    auto taskId2 = executors_->Execute([store = store_]() {
        std::pair<int, int64_t> res;
        int32_t errCode = E_OK;
        for (int i = 0; i < 2000; i++) {
            res = store->BeginTrans();
            EXPECT_EQ(res.first, E_OK);
            errCode = store->RollBack(res.second);
            EXPECT_EQ(errCode, E_OK);
        }
    });
    executors_->Remove(taskId1, true);
    executors_->Remove(taskId2, true);
    EXPECT_NE(taskId1, taskId2);
}
} // namespace Test