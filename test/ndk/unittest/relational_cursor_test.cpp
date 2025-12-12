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
#include "relational_cursor.h"

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#include "accesstoken_kit.h"
#include "common.h"
#include "oh_data_value.h"
#include "oh_rdb_types.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"
#include "token_setproc.h"


using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::RdbNdk;

class RelationalCursorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RelationalCursorTest::SetUpTestCase(void)
{
}

void RelationalCursorTest::TearDownTestCase(void)
{
}

void RelationalCursorTest::SetUp(void)
{
}

void RelationalCursorTest::TearDown(void)
{
}

/**
 * @tc.name: GetAssetsCount_test_001
 * @tc.desc: Test the GetAssetsCount function. In the scenario where resultSet_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(RelationalCursorTest, GetAssetsCount_test_001, TestSize.Level1)
{
    RelationalCursor cursor(nullptr);
    const int columnIndex = 0;
    int count = 0 int ret = cursor.GetAssetsCount(columnIndex, &count);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    ret = cursor.GetAssetsCount(columnIndex, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}