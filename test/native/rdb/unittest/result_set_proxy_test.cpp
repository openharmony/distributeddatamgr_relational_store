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
#include "result_set_proxy.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;


class ResultSetProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) {};
    void TearDown(void) {};
};

void ResultSetProxyTest::SetUpTestCase(void)
{
}

void ResultSetProxyTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: Connection_Test_001
 * @tc.desc: Normal testCase of sqlite_utils for IsSpecial, if sqlType is special
 * @tc.type: FUNC
 */
HWTEST_F(ResultSetProxyTest, ResultSetProxy_Test_001, TestSize.Level1)
{
    int errCode = 0;
    auto resultSet = std::make_shared<OHOS::NativeRdb::ResultSetProxy>(nullptr);

    int columnCount = 0;
    errCode = resultSet->GetColumnCount(columnCount);
    EXPECT_NE(E_OK, errCode);

    ColumnType columnType;
    errCode = resultSet->GetColumnType(1, columnType);
    EXPECT_NE(E_OK, errCode);

    int rowCount = 0;
    errCode = resultSet->GetRowCount(rowCount);
    EXPECT_NE(E_OK, errCode);

    int rowIndex = 0;
    errCode = resultSet->GetRowIndex(rowIndex);
    EXPECT_NE(E_OK, errCode);

    errCode = resultSet->GoTo(1);
    EXPECT_NE(E_OK, errCode);

    errCode = resultSet->GoToRow(1);
    EXPECT_NE(E_OK, errCode);

    errCode = resultSet->GoToFirstRow();
    EXPECT_NE(E_OK, errCode);

    errCode = resultSet->GoToLastRow();
    EXPECT_NE(E_OK, errCode);

    errCode = resultSet->GoToNextRow();
    EXPECT_NE(E_OK, errCode);

    errCode = resultSet->GoToPreviousRow();
    EXPECT_NE(E_OK, errCode);

    bool result = false;
    errCode = resultSet->IsEnded(result);
    EXPECT_NE(E_OK, errCode);

    errCode = resultSet->IsStarted(result);
    EXPECT_NE(E_OK, errCode);

    errCode = resultSet->IsAtFirstRow(result);
    EXPECT_NE(E_OK, errCode);

    errCode = resultSet->IsAtLastRow(result);
    EXPECT_NE(E_OK, errCode);

    ValueObject value;
    errCode = resultSet->Get(1, value);
    EXPECT_NE(E_OK, errCode);

    size_t size = 0;
    errCode = resultSet->GetSize(1, size);
    EXPECT_NE(E_OK, errCode);

    errCode = resultSet->Close();
    EXPECT_NE(E_OK, errCode);
}