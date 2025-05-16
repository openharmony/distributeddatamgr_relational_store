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

const std::string INVALID_SCHEMA_STR_1 = R"({
	"knowledgeSource": [{
		"version": 0,
		"dbName": "test.db",
		"tables": []
	}]
})";

const std::string INVALID_SCHEMA_STR_2 = R"({
	"knowledgeSource": [{
		"version": 2147483648,
		"dbName": "test.db",
		"tables": []
	}]
})";

const std::string INVALID_SCHEMA_STR_3 = R"({
	"knowledgeSource": [{
		"version": 1,
		"dbName": "",
		"tables": []
	}]
})";

const std::string INVALID_SCHEMA_STR_4 = R"({
	"knowledgeSource": [{
		"version": 1,
		"dbName": "tese,db",
		"tables": []
	}]
})";

const std::string INVALID_SCHEMA_STR_5 = R"({
	"knowledgeSource": [{
		"version": 1,
		"dbName": "test.db",
		"tables": [{
			"tableName": "",
			"referenceFields": ["id"],
            "knowledgeFields": [
            {
                "columnName": "subject",
                "type": ["Text"]
            }]
		}]
	}]
})";

const std::string INVALID_SCHEMA_STR_6 = R"({
	"knowledgeSource": [{
		"version": 1,
		"dbName": "test.db",
		"tables": [{
			"tableName": "invalid-table-name",
			"referenceFields": ["id"],
            "knowledgeFields": [
            {
                "columnName": "subject",
                "type": ["Text"]
            }]
		}]
	}]
})";

const std::string INVALID_SCHEMA_STR_7 = R"({
	"knowledgeSource": [{
		"version": 1,
		"dbName": "test.db",
		"tables": [{
			"tableName": "test",
			"referenceFields": ["id2", "id2"],
            "knowledgeFields": [
            {
                "columnName": "subject",
                "type": ["Text"]
            }]
		}]
	}]
})";

const std::string INVALID_SCHEMA_STR_8 = R"({
	"knowledgeSource": [{
		"version": 1,
		"dbName": "test.db",
		"tables": [{
			"tableName": "test",
			"referenceFields": ["'id2'"],
            "knowledgeFields": [
            {
                "columnName": "subject",
                "type": ["Text"]
            }]
		}]
	}]
})";

const std::string INVALID_SCHEMA_STR_9 = R"({
	"knowledgeSource": [{
		"version": 1,
		"dbName": "test.db",
		"tables": [{
			"tableName": "test",
			"referenceFields": ["id"],
            "knowledgeFields": [
            {
                "columnName": "",
                "type": ["Text"]
            }]
		}]
	}]
})";

const std::string INVALID_SCHEMA_STR_10 = R"({
	"knowledgeSource": [{
		"version": 1,
		"dbName": "test.db",
		"tables": [{
			"tableName": "test",
			"referenceFields": ["id"],
            "knowledgeFields": [
            {
                "columnName": "%subject",
                "type": ["Text"]
            }]
		}]
	}]
})";

const std::string INVALID_SCHEMA_STR_11 = R"({
	"knowledgeSource": [{
		"version": 1,
		"dbName": "test.db",
		"tables": [{
			"tableName": "test",
			"referenceFields": ["id"],
            "knowledgeFields": [
            {
                "columnName": "subject",
                "type": [""]
            }]
		}]
	}]
})";

const std::string INVALID_SCHEMA_STR_12 = R"({
	"knowledgeSource": [{
		"version": 1,
		"dbName": "test.db",
		"tables": [{
			"tableName": "test",
			"referenceFields": ["id"],
            "knowledgeFields": [
            {
                "columnName": "subject",
                "type": ["Text", "File"]
            }]
		}]
	}]
})";

const std::string INVALID_SCHEMA_STR_13 = R"({
	"knowledgeSource": [{
		"version": 1,
		"dbName": "test.db",
		"tables": [{
			"tableName": "test",
			"referenceFields": ["id"],
            "knowledgeFields": [
            {
                "columnName": "subject",
                "type": ["ScalarScalarScalarScalarScalarScalarScalarScalarScalarScalarScalarScalarScalarScalarScalar"]
            }]
		}]
	}]
})";

const std::string INVALID_SCHEMA_STR_14 = R"({
	"knowledgeSource": [{
		"version": 1,
		"dbName": "test.db",
		"tables": [{
			"tableName": "test",
			"referenceFields": ["id"],
            "knowledgeFields": [
            {
                "columnName": "subject",
                "type": ["Scalar"],
                "description": ""
            }]
		}]
	}]
})";

const std::string INVALID_SCHEMA_STR_15 = R"({
	"knowledgeSource": [{
		"version": 1,
		"dbName": "test.db",
		"tables": [{
			"tableName": "test",
			"referenceFields": ["id"],
            "knowledgeFields": [
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
                "columnName": "inline_files",
                "type": ["Json"],
                "parser": [
                {
                    "type": "File",
                    "path": "$[*].localPath"
                }
                ]
            }]
		}]
	}]
})";

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

/**
 * @tc.name: KnowledgeSchemaHelperTest007
 * @tc.desc: test unmarshall schema with no db name
 * @tc.type: FUNC
 */
HWTEST_F(KnowledgeSchemaHelperTest, KnowledgeSchemaHelperTest007, TestSize.Level0)
{
    RdbKnowledgeSchema schema = {};
    const std::string missingDbName = R"({
        "knowledgeSource": [{
            "version": 1,
            "tables": [{
                "tableName": "test",
                "referenceFields": ["id"],
                "knowledgeFields": [
                {
                    "columnName": "subject",
                    "type": ["Text"]
                }]
            }]
        }]})";
    bool ret = helper_->ParseRdbKnowledgeSchema(missingDbName, DB_NAME, schema);
    ASSERT_TRUE(ret);
    ASSERT_EQ(schema.dbName, DB_NAME);
}

/**
 * @tc.name: KnowledgeInvalidSchemaTest001
 * @tc.desc: test invalid version
 * @tc.type: FUNC
 */
HWTEST_F(KnowledgeSchemaHelperTest, KnowledgeInvalidSchemaTest001, TestSize.Level0)
{
    RdbKnowledgeSchema schema1 = {};
    bool ret1 = helper_->ParseRdbKnowledgeSchema(INVALID_SCHEMA_STR_1, DB_NAME, schema1);
    EXPECT_FALSE(ret1);
    RdbKnowledgeSchema schema2 = {};
    bool ret2 = helper_->ParseRdbKnowledgeSchema(INVALID_SCHEMA_STR_2, DB_NAME, schema2);
    EXPECT_FALSE(ret2);
}

/**
 * @tc.name: KnowledgeInvalidSchemaTest002
 * @tc.desc: test invalid db name
 * @tc.type: FUNC
 */
HWTEST_F(KnowledgeSchemaHelperTest, KnowledgeInvalidSchemaTest002, TestSize.Level0)
{
    RdbKnowledgeSchema schema1 = {};
    bool ret1 = helper_->ParseRdbKnowledgeSchema(INVALID_SCHEMA_STR_3, DB_NAME, schema1);
    EXPECT_FALSE(ret1);
    RdbKnowledgeSchema schema2 = {};
    bool ret2 = helper_->ParseRdbKnowledgeSchema(INVALID_SCHEMA_STR_4, DB_NAME, schema2);
    EXPECT_FALSE(ret2);
}

/**
 * @tc.name: KnowledgeInvalidSchemaTest003
 * @tc.desc: test invalid table name
 * @tc.type: FUNC
 */
HWTEST_F(KnowledgeSchemaHelperTest, KnowledgeInvalidSchemaTest003, TestSize.Level0)
{
    RdbKnowledgeSchema schema1 = {};
    bool ret1 = helper_->ParseRdbKnowledgeSchema(INVALID_SCHEMA_STR_5, DB_NAME, schema1);
    EXPECT_FALSE(ret1);
    RdbKnowledgeSchema schema2 = {};
    bool ret2 = helper_->ParseRdbKnowledgeSchema(INVALID_SCHEMA_STR_6, DB_NAME, schema2);
    EXPECT_FALSE(ret2);
}

/**
 * @tc.name: KnowledgeInvalidSchemaTest004
 * @tc.desc: test invalid reference field
 * @tc.type: FUNC
 */
HWTEST_F(KnowledgeSchemaHelperTest, KnowledgeInvalidSchemaTest004, TestSize.Level0)
{
    RdbKnowledgeSchema schema1 = {};
    bool ret1 = helper_->ParseRdbKnowledgeSchema(INVALID_SCHEMA_STR_7, DB_NAME, schema1);
    EXPECT_FALSE(ret1);
    RdbKnowledgeSchema schema2 = {};
    bool ret2 = helper_->ParseRdbKnowledgeSchema(INVALID_SCHEMA_STR_8, DB_NAME, schema2);
    EXPECT_FALSE(ret2);
}

/**
 * @tc.name: KnowledgeInvalidSchemaTest005
 * @tc.desc: test invalid column field
 * @tc.type: FUNC
 */
HWTEST_F(KnowledgeSchemaHelperTest, KnowledgeInvalidSchemaTest005, TestSize.Level0)
{
    RdbKnowledgeSchema schema1 = {};
    bool ret1 = helper_->ParseRdbKnowledgeSchema(INVALID_SCHEMA_STR_9, DB_NAME, schema1);
    EXPECT_FALSE(ret1);
    RdbKnowledgeSchema schema2 = {};
    bool ret2 = helper_->ParseRdbKnowledgeSchema(INVALID_SCHEMA_STR_10, DB_NAME, schema2);
    EXPECT_FALSE(ret2);
}

/**
 * @tc.name: KnowledgeInvalidSchemaTest006
 * @tc.desc: test invalid column type
 * @tc.type: FUNC
 */
HWTEST_F(KnowledgeSchemaHelperTest, KnowledgeInvalidSchemaTest006, TestSize.Level0)
{
    RdbKnowledgeSchema schema1 = {};
    bool ret1 = helper_->ParseRdbKnowledgeSchema(INVALID_SCHEMA_STR_11, DB_NAME, schema1);
    EXPECT_FALSE(ret1);
    RdbKnowledgeSchema schema2 = {};
    bool ret2 = helper_->ParseRdbKnowledgeSchema(INVALID_SCHEMA_STR_12, DB_NAME, schema2);
    EXPECT_FALSE(ret2);
    RdbKnowledgeSchema schema3 = {};
    bool ret3 = helper_->ParseRdbKnowledgeSchema(INVALID_SCHEMA_STR_13, DB_NAME, schema3);
    EXPECT_FALSE(ret3);
}

/**
 * @tc.name: KnowledgeInvalidSchemaTest007
 * @tc.desc: test invalid column description
 * @tc.type: FUNC
 */
HWTEST_F(KnowledgeSchemaHelperTest, KnowledgeInvalidSchemaTest007, TestSize.Level0)
{
    RdbKnowledgeSchema schema = {};
    bool ret = helper_->ParseRdbKnowledgeSchema(INVALID_SCHEMA_STR_14, DB_NAME, schema);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KnowledgeInvalidSchemaTest009
 * @tc.desc: test invalid column description, duplicate column name
 * @tc.type: FUNC
 */
HWTEST_F(KnowledgeSchemaHelperTest, KnowledgeInvalidSchemaTest008, TestSize.Level0)
{
    RdbKnowledgeSchema schema = {};
    bool ret = helper_->ParseRdbKnowledgeSchema(INVALID_SCHEMA_STR_15, DB_NAME, schema);
    EXPECT_FALSE(ret);
}
