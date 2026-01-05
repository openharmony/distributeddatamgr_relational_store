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

#include <filesystem>
#include <future>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <vector>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_sql_utils.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::NativeRdb;
class RdbMultiThreadSqlUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static int ThreadFunction(const std::string& testDir, int iteration);
};

void RdbMultiThreadSqlUtilsTest::SetUpTestCase(void)
{
}

void RdbMultiThreadSqlUtilsTest::TearDownTestCase(void)
{
}

void RdbMultiThreadSqlUtilsTest::SetUp()
{
}

void RdbMultiThreadSqlUtilsTest::TearDown()
{
}

int RdbMultiThreadSqlUtilsTest::ThreadFunction(const std::string& testDir, int iteration)
{
    std::string dirPath = testDir + "iter_" + std::to_string(iteration);
    int ret = RdbSqlUtils::CreateDirectory(dirPath);
    return ret;
}

/**
 * @tc.name: MultiThread_Sql_Utils_0001
 *           Multi-threaded concurrent directory creation returns the system error code EEXIST.
 * @tc.desc: 1.thread 1: create directory
 *           2.other thread: create directory
 *           3.if the directory exists, creating the directory returns E_OK instead of E_CREATE_FOLDER_FAIL.
 * @tc.type: FUNC
 */
HWTEST_F(RdbMultiThreadSqlUtilsTest, MultiThread_Sql_Utils_0001, TestSize.Level1)
{
    int ret = E_ERROR;
    // the number of iterations is 1000
    for (int iteration = 0; iteration < 1000; ++iteration) {
        std::filesystem::remove_all(RDB_TEST_PATH);
        std::vector<std::future<int>> futures;
        // the number of threads is 10
        for (int i = 1; i <= 10; ++i) {
            futures.push_back(std::async(std::launch::async, ThreadFunction, RDB_TEST_PATH, iteration));
        }
        EXPECT_NE(0, futures.size());
        for (size_t i = 0; i < futures.size(); ++i) {
            ret = futures[i].get();
            if (ret != E_OK) {
                break;
            }
        }
        if (ret != E_OK) {
            break;
        }
    }
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(2, std::filesystem::remove_all(RDB_TEST_PATH)); // The number of directories deleted is 2
}