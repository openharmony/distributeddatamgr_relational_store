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
 
#include "gtest/gtest.h"
#include "serializable.h"
 
#include "common.h"
#include "knowledge_schema_helper.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
 
using Json = OHOS::Serializable::JSONWrapper;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb;
 
class OpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override
    {
        return E_OK;
    }
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};
 
class KnowledgeSchemaHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
 
    static const std::string rdbStorePath;
    static std::shared_ptr<RdbStore> store;
};
const std::string DB_NAME = "test.db";
const std::string KnowledgeSchemaHelperTest::rdbStorePath = RDB_TEST_PATH + DB_NAME;
std::shared_ptr<KnowledgeSchemaHelper> helper_ = nullptr;
 
void KnowledgeSchemaHelperTest::SetUpTestCase(void)
{
    helper_ = std::make_shared<KnowledgeSchemaHelper>();
    RdbHelper::DeleteRdbStore(rdbStorePath);
}
 
void KnowledgeSchemaHelperTest::TearDownTestCase(void)
{
    helper_ = nullptr;
    RdbHelper::DeleteRdbStore(rdbStorePath);
}
 
void KnowledgeSchemaHelperTest::SetUp(void)
{}
 
void KnowledgeSchemaHelperTest::TearDown(void)
{}
 
/**
 * @tc.name: KnowledgeSchemaHelperTest001
 * @tc.desc: test marshall schema
 * @tc.type: FUNC
 */
HWTEST_F(KnowledgeSchemaHelperTest, KnowledgeSchemaHelperTest001, TestSize.Level0)
{
    std::string dbNameNotExist = "xxxxxx.db";
    std::pair<int, RdbKnowledgeSchema> ret = helper_->GetRdbKnowledgeSchema(dbNameNotExist);
    ASSERT_EQ(ret.first, E_ERROR);
}
