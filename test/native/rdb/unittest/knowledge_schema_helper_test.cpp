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
#include "nlohmann/json.hpp"

#include "common.h"
#include "knowledge_schema.h"
#include "knowledge_schema_helper.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using Json = nlohmann::json;
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

void GenerateKnowledgeSchema(OHOS::DistributedRdb::RdbKnowledgeSchema &schema)
{
    RdbKnowledgeField knowledgeField = {};
    knowledgeField.columnName = "colName";
    knowledgeField.type = {"TEXT"};
    knowledgeField.description = "description";

    RdbKnowledgeTable knowledgeTable = {};
    knowledgeTable.referenceFields = {"id"};
    knowledgeTable.knowledgeFields = {knowledgeField};

    schema.version = 1;
    schema.dbName = DB_NAME;
    schema.tables = {knowledgeTable};
}

const std::string SCHEMA_STR = R"({
    "knowledgeSource": [
    {
        "version": 1,
        "dbName": "test.db",
        "tables": [
        {
            "tableName": "test",
            "referenceFields": ["id"],
            "knowledgeFields": [
            {
                "columnName": "subject",
                "type": ["Text"]
            },
            {
                "columnName": "content",
                "type": ["Text"]
            },
            {
                "columnName": "image_text",
                "type": ["Text"]
            },
            {
                "columnName": "attachment_names",
                "type": ["Text"]
            },
            {
                "columnName": "send_time",
                "type": ["Scalar"],
                "description": "send_time"
            },
            {
                "columnName": "receivers",
                "type": ["Scalar"],
                "description": "receivers"
            },
            {
                "columnName": "sender",
                "type": ["Scalar"],
                "description": "sender"
            },
            {
               "columnName": "inline_files",
               "type": ["Json"],
               "parser": [
                   {
                       "type": "File",
                       "path": "$[*].localPath"
                   }
               ]
            },
            {
               "columnName": "attachments",
               "type": ["Json"],
               "parser": [
                   {
                       "type": "File",
                       "path": "$[*].localPath"
                   }
               ]
            }]
        }]
    }]})";

/**
 * @tc.name: KnowledgeSchemaHelperTest001
 * @tc.desc: test unmarshall schema
 * @tc.type: FUNC
 */
HWTEST_F(KnowledgeSchemaHelperTest, KnowledgeSchemaHelperTest001, TestSize.Level0)
{
    KnowledgeSource source;
    bool ret = OHOS::Serializable::Unmarshall(SCHEMA_STR, source);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KnowledgeSchemaHelperTest002
 * @tc.desc: test unmarshall with invalid schema
 * @tc.type: FUNC
 */
HWTEST_F(KnowledgeSchemaHelperTest, KnowledgeSchemaHelperTest002, TestSize.Level0)
{
    RdbKnowledgeSchema schema = {};
    RdbStoreConfig config(rdbStorePath);
    helper_->Init(config, schema);

    KnowledgeSource source;
    std::string jsonStr = R"({"wrong": []})";
    bool ret = helper_->ParseRdbKnowledgeSchema(jsonStr, DB_NAME, schema);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KnowledgeSchemaHelperTest003
 * @tc.desc: test marshall schema
 * @tc.type: FUNC
 */
HWTEST_F(KnowledgeSchemaHelperTest, KnowledgeSchemaHelperTest003, TestSize.Level0)
{
    KnowledgeSource source;
    RdbKnowledgeSchema schema = {};
    bool ret = helper_->ParseRdbKnowledgeSchema(SCHEMA_STR, DB_NAME, schema);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KnowledgeSchemaHelperTest004
 * @tc.desc: test parse schema with db name inval
 * @tc.type: FUNC
 */
HWTEST_F(KnowledgeSchemaHelperTest, KnowledgeSchemaHelperTest004, TestSize.Level0)
{
    KnowledgeSource source;
    RdbKnowledgeSchema schema = {};
    std::string dbName = "not_exist.db";
    bool ret = helper_->ParseRdbKnowledgeSchema(SCHEMA_STR, dbName, schema);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KnowledgeSchemaHelperTest005
 * @tc.desc: test unmarshall schema
 * @tc.type: FUNC
 */
HWTEST_F(KnowledgeSchemaHelperTest, KnowledgeSchemaHelperTest005, TestSize.Level0)
{
    KnowledgeSource source;
    RdbKnowledgeSchema schema = {};
    bool ret = OHOS::Serializable::Unmarshall(SCHEMA_STR, source);
    ASSERT_TRUE(ret);

    std::string schemaStr = OHOS::Serializable::Marshall(source);
    ASSERT_TRUE(schemaStr.size() > 0);
}

/**
 * @tc.name: KnowledgeSchemaHelperTest006
 * @tc.desc: test unmarshall json path
 * @tc.type: FUNC
 */
HWTEST_F(KnowledgeSchemaHelperTest, KnowledgeSchemaHelperTest006, TestSize.Level0)
{
    KnowledgeSource source;
    RdbKnowledgeSchema schema = {};
    bool ret = helper_->ParseRdbKnowledgeSchema(SCHEMA_STR, DB_NAME, schema);
    ASSERT_TRUE(ret);

    ASSERT_FALSE(schema.tables.empty());
    RdbKnowledgeTable table = schema.tables.front();
    for (const auto &field : table.knowledgeFields) {
        if (field.parser.empty()) {
            continue;
        }
        for (const auto &parser : field.parser) {
            EXPECT_EQ(parser.type, "File");
            EXPECT_EQ(parser.path, "$[*].localPath");
        }
    }
}