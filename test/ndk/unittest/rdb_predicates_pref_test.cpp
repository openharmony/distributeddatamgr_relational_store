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
#define LOG_TAG "RdbNdkPredicatesPrefTest"
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#include "logger.h"
#include "relational_store.h"
using namespace testing::ext;
using namespace OHOS::Rdb;
class RdbNdkPredicatesPrefTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
const int BASE_COUNT = 2000;
const int HAVING_BASE_LINE = 10;
void RdbNdkPredicatesPrefTest::SetUpTestCase(void)
{
}

void RdbNdkPredicatesPrefTest::TearDownTestCase(void)
{
}

void RdbNdkPredicatesPrefTest::SetUp(void)
{
}

void RdbNdkPredicatesPrefTest::TearDown(void)
{
}

/**
 * @tc.name: RDB_predicates_pref_test_having
 * @tc.desc: Performance testing of basic scenarios for the Having interface
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesPrefTest, RDB_predicates_pref_test_having, TestSize.Level1)
{
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    const char *columnNames[] = { "data"};
    predicates->groupBy(predicates, columnNames, 1);
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < BASE_COUNT; i++) {
        OH_Predicates_Having(predicates, "data", nullptr);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto total = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double averageTime = static_cast<double>(total) / BASE_COUNT;
    LOG_INFO("the predicates_pref_test_having average time is %{public}f", averageTime);
    ASSERT_TRUE(averageTime < HAVING_BASE_LINE);
}