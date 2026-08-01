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

#include "result_set_proxy.h"
#include "rdb_errno.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace NativeRdb {

class ResultSetProxyAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

/**
 * @tc.name: ResultSetProxy001
 * @tc.desc: Abnormal testcase of distributed ResultSetProxy, if resultSet is Empty
 * @tc.type: FUNC
 */
HWTEST_F(ResultSetProxyAdapterTest, Abnormal_ResultSetProxy001, TestSize.Level1)
{
    int errCode = 0;
    auto resultSet = std::make_shared<OHOS::NativeRdb::ResultSetProxy>(nullptr);
    ColumnType columnType;
    errCode = resultSet->GetColumnType(1, columnType);
    EXPECT_NE(E_OK, errCode);

    std::string columnName;
    errCode = resultSet->GetColumnName(1, columnName);
    EXPECT_NE(E_OK, errCode);

    std::vector<uint8_t> blob;
    errCode = resultSet->GetBlob(1, blob);
    EXPECT_NE(E_OK, errCode);

    std::string getStringValue;
    errCode = resultSet->GetString(1, getStringValue);
    EXPECT_NE(E_OK, errCode);

    int getIntValue;
    errCode = resultSet->GetInt(1, getIntValue);
    EXPECT_NE(E_OK, errCode);

    int64_t getLongValue;
    errCode = resultSet->GetLong(1, getLongValue);
    EXPECT_NE(E_OK, errCode);

    double getDoubleValue;
    errCode = resultSet->GetDouble(1, getDoubleValue);
    EXPECT_NE(E_OK, errCode);

    bool isNull;
    errCode = resultSet->IsColumnNull(1, isNull);
    EXPECT_NE(E_OK, errCode);
}

} // namespace NativeRdb
} // namespace OHOS