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
#include <climits>
#include <string>
#include "connection.h"
#include "grd_type_export.h"
#include "rdb_store_config.h"
#include "rdb_errno.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace Test {
class ConnectionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) {};
    void TearDown(void) {};
};
static constexpr std::string RDB_TEST_PATH = "/data/test/";
static constexpr std::string DATABASE_NAME = RDB_TEST_PATH + "connection_ut_test.db";

void ConnectionTest::SetUpTestCase(void)
{
}

void ConnectionTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: Connection_Test_001
 * @tc.desc: Normal testCase of sqlite_utils for IsSpecial, if sqlType is special
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionTest, Connection_Test_001, TestSize.Level1)
{
    RdbStoreConfig config(DATABASE_NAME);
    config.SetDBType(OHOS::NativeRdb::DBType::DB_BUTT);
    auto [errCode, connection] = Connection::Create(config, true);
    EXPECT_EQ(errCode, E_INVALID_ARGS);
    EXPECT_EQ(connection, nullptr);

    config.SetDBType(OHOS::NativeRdb::DBType::DB_SQLITE);
    auto [errCode1, connection1] = Connection::Create(config, true);
    EXPECT_EQ(errCode1, E_OK);
    EXPECT_NE(connection1, nullptr);
}


/**
 * @tc.name: Connection_Test_002
 * @tc.desc: Normal testCase of sqlite_utils for IsSpecial, if sqlType is special
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionTest, Connection_Test_002, TestSize.Level1)
{
    RdbStoreConfig config(DATABASE_NAME);
    config.SetDBType(-1);
    int ret= Connection::Repair(config);
    EXPECT_EQ(ret, E_INVALID_ARGS);

    config.SetDBType(OHOS::NativeRdb::DBType::DB_SQLITE);
    ret = Connection::Repair(config);
    EXPECT_EQ(ret, E_ERROR);
}
} // namespace Test