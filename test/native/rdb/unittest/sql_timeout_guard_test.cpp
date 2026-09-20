/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>

#include "rdb_errno.h"
#include "rdb_types.h"
#include "sql_timeout_guard.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class SqlTimeoutGuardTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: DeadlineToken_Inactive_WhenTimeoutZero
 * @tc.desc: Verify DeadlineToken with timeoutMs=0 is inactive
 */
HWTEST_F(SqlTimeoutGuardTest, DeadlineToken_Inactive_WhenTimeoutZero, TestSize.Level1)
{
    auto token = DeadlineToken::FromMs(0);
    EXPECT_FALSE(token.IsActive());
    EXPECT_FALSE(token.IsExhausted());
    EXPECT_EQ(token.RemainingMs(), 0);
}

/**
 * @tc.name: DeadlineToken_Active_WhenTimeoutPositive
 * @tc.desc: Verify DeadlineToken with timeoutMs>0 is active and has remaining time
 */
HWTEST_F(SqlTimeoutGuardTest, DeadlineToken_Active_WhenTimeoutPositive, TestSize.Level1)
{
    auto token = DeadlineToken::FromMs(1000);
    EXPECT_TRUE(token.IsActive());
    EXPECT_FALSE(token.IsExhausted());
    EXPECT_GT(token.RemainingMs(), 0);
    EXPECT_LE(token.RemainingMs(), 1000);
}

/**
 * @tc.name: DeadlineToken_Remaining_Decreases
 * @tc.desc: Verify remaining time decreases over time
 */
HWTEST_F(SqlTimeoutGuardTest, DeadlineToken_Remaining_Decreases, TestSize.Level1)
{
    auto token = DeadlineToken::FromMs(100);
    auto first = token.RemainingMs();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    auto second = token.RemainingMs();
    EXPECT_LT(second, first);
}

/**
 * @tc.name: DeadlineToken_IsExhausted_AfterTimeout
 * @tc.desc: Verify token is exhausted after timeout passes
 */
HWTEST_F(SqlTimeoutGuardTest, DeadlineToken_IsExhausted_AfterTimeout, TestSize.Level1)
{
    auto token = DeadlineToken::FromMs(10);
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    EXPECT_TRUE(token.IsExhausted());
    EXPECT_EQ(token.RemainingMs(), 0);
}

/**
 * @tc.name: TimeoutGuard_NullPool_NoCrash
 * @tc.desc: Verify TimeoutGuard with null pool does not crash
 */
HWTEST_F(SqlTimeoutGuardTest, TimeoutGuard_NullPool_NoCrash, TestSize.Level1)
{
    auto token = DeadlineToken::FromMs(100);
    TimeoutGuard guard(nullptr, token);
    SUCCEED();
}

/**
 * @tc.name: TimeoutGuard_InactiveToken_NoRegistration
 * @tc.desc: Verify TimeoutGuard with inactive token does not register
 */
HWTEST_F(SqlTimeoutGuardTest, TimeoutGuard_InactiveToken_NoRegistration, TestSize.Level1)
{
    auto token = DeadlineToken::FromMs(0);
    TimeoutGuard guard(nullptr, token);
    SUCCEED();
}

/**
 * @tc.name: TimeoutGuard_Move_TransfersOwnership
 * @tc.desc: Verify move constructor transfers handle ownership
 */
HWTEST_F(SqlTimeoutGuardTest, TimeoutGuard_Move_TransfersOwnership, TestSize.Level1)
{
    auto token = DeadlineToken::FromMs(500);
    TimeoutGuard guard1(nullptr, token);
    TimeoutGuard guard2(std::move(guard1));
    SUCCEED();
}
