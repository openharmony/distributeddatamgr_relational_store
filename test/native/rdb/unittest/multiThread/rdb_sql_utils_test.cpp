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

#include <iostream>
#include <string>

#include "rdb_errno.h"
#include "rdb_sql_utils.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::NativeRdb;
class RdbSqlUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    static constexpr int32_t MAX_THREAD = 5;
    static constexpr int32_t MIN_THREAD = 0;

    std::shared_ptr<ExecutorPool> executors_;
};

void RdbSqlUtilsTest::SetUpTestCase(void)
{
}

void RdbSqlUtilsTest::TearDownTestCase(void)
{
}

void RdbSqlUtilsTest::SetUp()
{
    executors_ = std::make_shared<ExecutorPool>(MAX_THREAD, MIN_THREAD);
}

void RdbSqlUtilsTest::TearDown()
{
    executors_ = nullptr;
}

/**
 * @tc.name: Rdb_Sql_Utils_0001
 * @tc.desc: CreateDirectory 
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, Rdb_Sql_Utils_0001, TestSize.Level2)
{
    std::shared_ptr<BlockData<int32_t>> block1 = std::make_shared<BlockData<int32_t>>(3, false);
    auto taskId1 = executors_->Execute([block1]() {
        int32_t errCode = E_ERROR;
        for (uint32_t i = 0; i < 2000; i++) {
            errCode = RdbSqlUtils::CreateDirectory("/data/test/rdb");
            if (errCode != E_OK) {
                break;
            }
        }
        block1->SetValue(errCode);
    });

    std::shared_ptr<BlockData<int32_t>> block2 = std::make_shared<BlockData<int32_t>>(3, false);
    auto taskId2 = executors_->Execute([store = store_, block2]() {
        int32_t errCode = E_ERROR;
        for (uint32_t i = 0; i < 2000; i++) {
            errCode = RdbSqlUtils::CreateDirectory("/data/test/rdb");
            if (errCode != E_OK) {
                break;
            }
        }
        block2->SetValue(code);
    });

    EXPECT_EQ(block1->GetValue(), E_OK);
    EXPECT_EQ(block2->GetValue(), E_OK);
    EXPECT_NE(taskId1, taskId2);
}