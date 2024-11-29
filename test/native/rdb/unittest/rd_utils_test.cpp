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

#include "rd_utils.h"

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <climits>
#include <string>

#include "grd_type_export.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace Test {
class RdUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) {};
    void TearDown(void) {};
};

void RdUtilsTest::SetUpTestCase(void)
{
}

void RdUtilsTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: RdUtils_Test_001
 * @tc.desc: Normal testCase of sqlite_utils for IsSpecial, if sqlType is special
 * @tc.type: FUNC
 */
HWTEST_F(RdUtilsTest, RdUtils_Test_001, TestSize.Level1)
{
    EXPECT_EQ(RdUtils::TransferGrdErrno(1), 1);
    EXPECT_EQ(RdUtils::TransferGrdErrno(0), E_OK);
    EXPECT_EQ(RdUtils::TransferGrdErrno(-9999), E_ERROR);
}

HWTEST_F(RdUtilsTest, RdUtils_Test_002, TestSize.Level1)
{
    EXPECT_EQ(RdUtils::TransferGrdTypeToColType(GRD_DB_DATATYPE_INTEGER), ColumnType::TYPE_INTEGER);
    EXPECT_EQ(RdUtils::TransferGrdTypeToColType(GRD_DB_DATATYPE_FLOAT), ColumnType::TYPE_FLOAT);
    EXPECT_EQ(RdUtils::TransferGrdTypeToColType(GRD_DB_DATATYPE_TEXT), ColumnType::TYPE_STRING);
    EXPECT_EQ(RdUtils::TransferGrdTypeToColType(GRD_DB_DATATYPE_BLOB), ColumnType::TYPE_BLOB);
    EXPECT_EQ(RdUtils::TransferGrdTypeToColType(GRD_DB_DATATYPE_FLOATVECTOR), ColumnType::TYPE_FLOAT32_ARRAY);
    EXPECT_EQ(RdUtils::TransferGrdTypeToColType(GRD_DB_DATATYPE_NULL), ColumnType::TYPE_NULL);
}
} // namespace Test
