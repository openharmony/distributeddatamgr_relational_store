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

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <variant>

#include "gdb_errors.h"
#include "gdb_helper.h"
#include "gdb_store.h"
#include "grd_adapter_manager.h"

using namespace testing::ext;
using namespace OHOS::DistributedDataAip;

constexpr int32_t VERTEX_PROP = 3;
constexpr int32_t EDGE_PROP = 2;

typedef struct {
    std::string name;
    std::string gender;
    std::string embedding;
} PersonParam;

typedef struct {
    std::string title;
    std::string description;
    std::string embedding;
} EventParam;

typedef struct {
    PersonParam person;
    EventParam event;
    std::string description;
    std::string embedding;
} ParticipateParam;

class GdbFloatVectorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    void CreateGraph(const std::string &gql, int32_t errCode);
    std::string GenerateInsertPersonGql(const PersonParam &param);
    std::string GenerateDeletePersonGql(const PersonParam &param);
    std::string GenerateUpdatePersonGql(const PersonParam &param);
    std::string GenerateQueryPersonGql(const PersonParam &param);
    void CheckPerson(std::shared_ptr<Result> result, const PersonParam &param);

    std::string GenerateInsertEventGql(const EventParam &param);
    std::string GenerateDeleteEventGql(const EventParam &param);
    std::string GenerateUpdateEventGql(const EventParam &param);
    std::string GenerateQueryEventGql(const EventParam &param);
    void CheckEvent(std::shared_ptr<Result> result, const EventParam &param);

    std::string GenerateInsertParticipateGql(const ParticipateParam &param);
    std::string GenerateDeleteParticipateGql(const ParticipateParam &param);
    std::string GenerateUpdateParticipateGql(const ParticipateParam &param);
    std::string GenerateQueryParticipateGql(const ParticipateParam &param);
    void CheckParticipate(std::shared_ptr<Result> result, const ParticipateParam &param);

    void CheckFloatVector(std::shared_ptr<Result> result, const std::string &paramEmbedding, const std::string &key);

    static const std::string databaseName;
    static const std::string databasePath;
    static std::shared_ptr<DBStore> store_;
    static const std::string createGraphGql;
};

std::shared_ptr<DBStore> GdbFloatVectorTest::store_;
const std::string GdbFloatVectorTest::databaseName = "test_float_vector_db";
const std::string GdbFloatVectorTest::databasePath = "/data";
const std::string GdbFloatVectorTest::createGraphGql = "CREATE GRAPH testGraph { "
    "(person:Person {name STRING, gender STRING, embedding FLOATVECTOR(4)}),"
    "(event:Event {title STRING, description STRING, embedding FLOATVECTOR(4)}),"
    "(person) -[:Participate{description STRING, embedding FLOATVECTOR(4)}]-> (event)"
    "};";

void GdbFloatVectorTest::SetUpTestCase()
{
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
    }
    int errCode = E_OK;
    auto config = StoreConfig(databaseName, databasePath);
    GDBHelper::DeleteDBStore(config);

    GdbFloatVectorTest::store_ = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(GdbFloatVectorTest::store_, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void GdbFloatVectorTest::TearDownTestCase()
{
    GDBHelper::DeleteDBStore(StoreConfig(databaseName, databasePath));
    store_ = nullptr;
}

void GdbFloatVectorTest::SetUp()
{
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
    }
}

void GdbFloatVectorTest::TearDown()
{
    if (store_ != nullptr) {
        auto result = store_->ExecuteGql("DROP GRAPH IF EXISTS testGraph");
    }
}

void GdbFloatVectorTest::CreateGraph(const std::string &gql, int32_t errCode)
{
    ASSERT_NE(store_, nullptr);
    auto result = store_->ExecuteGql(gql);
    EXPECT_EQ(result.first, errCode);
}

std::string GdbFloatVectorTest::GenerateInsertPersonGql(const PersonParam &param)
{
    std::string gql = "INSERT (:Person {name: '" + param.name +
        "', gender: '" + param.gender + "', embedding: '[" + param.embedding + "]'});";
    return gql;
}

std::string GdbFloatVectorTest::GenerateDeletePersonGql(const PersonParam &param)
{
    std::string gql = "MATCH (p:Person {name: '" + param.name + "'}) DETACH DELETE p;";
    return gql;
}

std::string GdbFloatVectorTest::GenerateUpdatePersonGql(const PersonParam &param)
{
    std::string gql = "MATCH (p:Person) WHERE p.name='" + param.name + "' SET p.embedding='[" + param.embedding + "]';";
    return gql;
}

std::string GdbFloatVectorTest::GenerateQueryPersonGql(const PersonParam &param)
{
    std::string gql = "MATCH (person:Person {name: '" + param.name + "'}) RETURN person.embedding;";
    return gql;
}

void GdbFloatVectorTest::CheckPerson(std::shared_ptr<Result> result, const PersonParam &param)
{
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetAllData().size(), 1);
    GraphValue person = result->GetAllData()[0]["person"];

    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Vertex>>(person));
    auto personVertex = std::get<std::shared_ptr<Vertex>>(person);
    EXPECT_EQ(personVertex->GetLabel(), "Person");
    ASSERT_EQ(personVertex->GetProperties().size(), VERTEX_PROP);

    auto name = personVertex->GetProperties().find("name");
    ASSERT_NE(name, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(name->second));
    EXPECT_EQ(std::get<std::string>(name->second), param.name);

    auto gender = personVertex->GetProperties().find("gender");
    ASSERT_NE(gender, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(gender->second));
    EXPECT_EQ(std::get<std::string>(gender->second), param.gender);

    auto embedding = personVertex->GetProperties().find("embedding");
    ASSERT_NE(embedding, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(embedding->second));
    EXPECT_EQ(std::get<std::string>(embedding->second), param.embedding);
}

std::string GdbFloatVectorTest::GenerateInsertEventGql(const EventParam &param)
{
    std::string gql = "INSERT (:Event {title: '" + param.title +
        "', description: '" + param.description + "', embedding: '[" + param.embedding + "]'});";
    return gql;
}

std::string GdbFloatVectorTest::GenerateDeleteEventGql(const EventParam &param)
{
    std::string gql = "MATCH (e:Event {title: '" + param.title + "'}) DETACH DELETE e;";
    return gql;
}

std::string GdbFloatVectorTest::GenerateUpdateEventGql(const EventParam &param)
{
    std::string gql = "MATCH (e:Event) WHERE e.title='" + param.title +
        "' SET e.embedding='[" + param.embedding + "]';";
    return gql;
}

std::string GdbFloatVectorTest::GenerateQueryEventGql(const EventParam &param)
{
    std::string gql = "MATCH (event:Event {title: '" + param.title + "'}) RETURN event.embedding;";
    return gql;
}

void GdbFloatVectorTest::CheckEvent(std::shared_ptr<Result> result, const EventParam &param)
{
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetAllData().size(), 1);
    GraphValue event = result->GetAllData()[0]["event"];

    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Vertex>>(event));
    auto eventVertex = std::get<std::shared_ptr<Vertex>>(event);
    EXPECT_EQ(eventVertex->GetLabel(), "Event");
    ASSERT_EQ(eventVertex->GetProperties().size(), VERTEX_PROP);

    auto title = eventVertex->GetProperties().find("title");
    ASSERT_NE(title, eventVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(title->second));
    EXPECT_EQ(std::get<std::string>(title->second), param.title);

    auto description = eventVertex->GetProperties().find("description");
    ASSERT_NE(description, eventVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(description->second));
    EXPECT_EQ(std::get<std::string>(description->second), param.description);

    auto embedding = eventVertex->GetProperties().find("embedding");
    ASSERT_NE(embedding, eventVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(embedding->second));
    EXPECT_EQ(std::get<std::string>(embedding->second), param.embedding);
}

std::string GdbFloatVectorTest::GenerateInsertParticipateGql(const ParticipateParam &param)
{
    std::string gql = "MATCH (p:Person {name: '" + param.person.name +
        "'}), (e:Event {title: '" + param.event.title +
        "'}) INSERT (p)-[r:Participate {description: '" + param.description +
        "', embedding: '[" + param.embedding + "]'}]->(e);";
    return gql;
}

std::string GdbFloatVectorTest::GenerateDeleteParticipateGql(const ParticipateParam &param)
{
    std::string gql = "MATCH (p:Person {name: '" + param.person.name +
        "'})-[r:Participate]->(e:Event {title: '" + param.event.title + "'}) DETACH DELETE r;";
    return gql;
}

std::string GdbFloatVectorTest::GenerateUpdateParticipateGql(const ParticipateParam &param)
{
    std::string gql = "MATCH (p:Person {name: '" + param.person.name +
        "'})-[r:Participate]->(e:Event {title: '" + param.event.title +
        "'}) SET r.embedding='[" + param.embedding + "]';";
    return gql;
}

std::string GdbFloatVectorTest::GenerateQueryParticipateGql(const ParticipateParam &param)
{
    std::string gql = "MATCH (p:Person {name: '" + param.person.name +
        "'})-[relation:Participate]->(e:Event {title: '" + param.event.title + "'}) RETURN relation.embedding;";
    return gql;
}

void GdbFloatVectorTest::CheckParticipate(std::shared_ptr<Result> result, const ParticipateParam &param)
{
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetAllData().size(), 1);
    GraphValue relation = result->GetAllData()[0]["relation"];

    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Edge>>(relation));
    auto relationEdge = std::get<std::shared_ptr<Edge>>(relation);
    EXPECT_EQ(relationEdge->GetLabel(), "Participate");
    ASSERT_EQ(relationEdge->GetProperties().size(), EDGE_PROP);

    auto description = relationEdge->GetProperties().find("description");
    ASSERT_NE(description, relationEdge->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(description->second));
    EXPECT_EQ(std::get<std::string>(description->second), param.description);

    auto embedding = relationEdge->GetProperties().find("embedding");
    ASSERT_NE(embedding, relationEdge->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(embedding->second));
    EXPECT_EQ(std::get<std::string>(embedding->second), param.embedding);
}

void GdbFloatVectorTest::CheckFloatVector(std::shared_ptr<Result> result, const std::string &paramEmbedding,
    const std::string &key)
{
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetAllData().size(), 1);
    ASSERT_NE(result->GetAllData()[0].find(key), result->GetAllData()[0].end());
    ASSERT_TRUE(std::holds_alternative<std::vector<float>>(result->GetAllData()[0][key]));
    std::vector<float> floatVector = std::get<std::vector<float>>(result->GetAllData()[0][key]);

    std::string embedding = paramEmbedding;
    std::vector<float> splitEmbedding;
    while (!embedding.empty()) {
        auto splitPos = embedding.find(",");
        if (splitPos == std::string::npos) {
            std::string subEmbedding = embedding;
            splitEmbedding.push_back(atof(subEmbedding.c_str()));
            break;
        }
        std::string subEmbedding = embedding.substr(0, splitPos);
        splitEmbedding.push_back(atof(subEmbedding.c_str()));
        embedding = embedding.substr(splitPos + 1);
    }

    ASSERT_EQ(splitEmbedding.size(), floatVector.size());
    auto floatCnt = floatVector.size();
    for (auto i = 0; i < floatCnt; i++) {
        EXPECT_EQ(splitEmbedding[i], floatVector[i]);
    }
}

/**
 * @tc.name: GdbFloatVectorTest001
 * @tc.desc: Normal case: Create a graph where some of the properties of vertexes and edges are FLOATVECTOR.
 * @tc.type: FUNC
 */
HWTEST_F(GdbFloatVectorTest, GdbFloatVectorTest001, TestSize.Level1)
{
    CreateGraph(GdbFloatVectorTest::createGraphGql, E_OK);
}

/**
 * @tc.name: GdbFloatVectorTest002
 * @tc.desc: Abnormal case: The dimension does not meet the constraint [1, 1024].
 * @tc.type: FUNC
 */
HWTEST_F(GdbFloatVectorTest, GdbFloatVectorTest002, TestSize.Level1)
{
    std::string gql = "CREATE GRAPH testGraph { "
        "(person:Person {name STRING, gender STRING, embedding FLOATVECTOR(0)}),"
        "(event:Event {title STRING, description STRING, embedding FLOATVECTOR(0)}),"
        "(person) -[:Participate{description STRING, embedding FLOATVECTOR(0)}]-> (event)"
        "};";
    CreateGraph(gql, E_GRD_SEMANTIC_ERROR);

    gql = "CREATE GRAPH testGraph { "
        "(person:Person {name STRING, gender STRING, embedding FLOATVECTOR(1025)}),"
        "(event:Event {title STRING, description STRING, embedding FLOATVECTOR(1025)}),"
        "(person) -[:Participate{description STRING, embedding FLOATVECTOR(1025)}]-> (event)"
        "};";
    CreateGraph(gql, E_GRD_SEMANTIC_ERROR);
}

/**
 * @tc.name: GdbFloatVectorTest003
 * @tc.desc: Abnormal case: Type misspelled, FLOATVECTOR -> VECTOR.
 * @tc.type: FUNC
 */
HWTEST_F(GdbFloatVectorTest, GdbFloatVectorTest003, TestSize.Level1)
{
    std::string gql = "CREATE GRAPH testGraph { "
        "(person:Person {name STRING, gender STRING, embedding VECTOR(4)}),"
        "(event:Event {title STRING, description STRING, embedding VECTOR(4)}),"
        "(person) -[:Participate{description STRING, embedding VECTOR(4)}]-> (event)"
        "};";
    CreateGraph(gql, E_GRD_SYNTAX_ERROR);
}

/**
 * @tc.name: GdbFloatVectorTest004
 * @tc.desc: Normal case: The FLOATVECTOR properties support NOT NULL.
 * @tc.type: FUNC
 */
HWTEST_F(GdbFloatVectorTest, GdbFloatVectorTest004, TestSize.Level1)
{
    std::string gql = "CREATE GRAPH testGraph { "
        "(person:Person {name STRING, gender STRING, embedding FLOATVECTOR(4) NOT NULL}),"
        "(event:Event {title STRING, description STRING, embedding FLOATVECTOR(4) NOT NULL}),"
        "(person) -[:Participate{description STRING, embedding FLOATVECTOR(4)}]-> (event)"
        "};";
    CreateGraph(gql, E_OK);
}

/**
 * @tc.name: GdbFloatVectorTest005
 * @tc.desc: Normal case: The FLOATVECTOR properties do not support DEFAULT.
 * @tc.type: FUNC
 */
HWTEST_F(GdbFloatVectorTest, GdbFloatVectorTest005, TestSize.Level1)
{
    std::string gql = "CREATE GRAPH testGraph { "
        "(person:Person {name STRING, gender STRING, embedding FLOATVECTOR(4) DEFAULT}),"
        "(event:Event {title STRING, description STRING, embedding FLOATVECTOR(4) DEFAULT}),"
        "(person) -[:Participate{description STRING, embedding FLOATVECTOR(4)}]-> (event)"
        "};";
    CreateGraph(gql, E_GRD_SYNTAX_ERROR);
}

/**
 * @tc.name: GdbFloatVectorTest006
 * @tc.desc: Normal case: The FLOATVECTOR properties do not support UNIQUE.
 * @tc.type: FUNC
 */
HWTEST_F(GdbFloatVectorTest, GdbFloatVectorTest006, TestSize.Level1)
{
    std::string gql = "CREATE GRAPH testGraph { "
        "(person:Person {name STRING, gender STRING, embedding FLOATVECTOR(4) UNIQUE}),"
        "(event:Event {title STRING, description STRING, embedding FLOATVECTOR(4) UNIQUE}),"
        "(person) -[:Participate{description STRING, embedding FLOATVECTOR(4)}]-> (event)"
        "};";
    CreateGraph(gql, E_GRD_SYNTAX_ERROR);
}

/**
 * @tc.name: GdbFloatVectorTest007_1
 * @tc.desc: Normal case: Insert, delete, update, and query vertexes that contain FLOATVECTOR properties.
 * @tc.type: FUNC
 */
HWTEST_F(GdbFloatVectorTest, GdbFloatVectorTest007_1, TestSize.Level1)
{
    CreateGraph(GdbFloatVectorTest::createGraphGql, E_OK);
    PersonParam person = { "name_1", "male", "0.1,0.1,0.1,0.1" };
    std::string gql = GenerateInsertPersonGql(person);
    auto [errCode, result] = store_->ExecuteGql(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryPersonGql(person);
    std::tie(errCode, result) = store_->QueryGql(gql);
    EXPECT_EQ(errCode, E_OK);
    CheckFloatVector(result, person.embedding, "person.embedding");

    PersonParam updatedPerson = { "name_1", "male", "0.1,0.2,0.3,0.4" };
    gql = GenerateUpdatePersonGql(updatedPerson);
    std::tie(errCode, result) = store_->ExecuteGql(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryPersonGql(updatedPerson);
    std::tie(errCode, result) = store_->QueryGql(gql);
    EXPECT_EQ(errCode, E_OK);
    CheckFloatVector(result, updatedPerson.embedding, "person.embedding");

    gql = GenerateDeletePersonGql(updatedPerson);
    std::tie(errCode, result) = store_->ExecuteGql(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryPersonGql(updatedPerson);
    std::tie(errCode, result) = store_->QueryGql(gql);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetAllData().size(), 0);
}

/**
 * @tc.name: GdbFloatVectorTest007_2
 * @tc.desc: Normal case: Insert, delete, update, and query vertexes that contain FLOATVECTOR properties.
 * @tc.type: FUNC
 */
HWTEST_F(GdbFloatVectorTest, GdbFloatVectorTest007_2, TestSize.Level1)
{
    CreateGraph(GdbFloatVectorTest::createGraphGql, E_OK);
    EventParam event = { "title_1", "This is a event which title is 1", "0.1,0.1,0.1,0.1" };
    std::string gql = GenerateInsertEventGql(event);
    auto [errCode, result] = store_->ExecuteGql(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryEventGql(event);
    std::tie(errCode, result) = store_->QueryGql(gql);
    EXPECT_EQ(errCode, E_OK);
    CheckFloatVector(result, event.embedding, "event.embedding");

    EventParam updatedEvent = { "title_1", "This is a event which title is 1", "0.1,0.2,0.3,0.4" };
    gql = GenerateUpdateEventGql(updatedEvent);
    std::tie(errCode, result) = store_->ExecuteGql(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryEventGql(updatedEvent);
    std::tie(errCode, result) = store_->QueryGql(gql);
    EXPECT_EQ(errCode, E_OK);
    CheckFloatVector(result, updatedEvent.embedding, "event.embedding");

    gql = GenerateDeleteEventGql(updatedEvent);
    std::tie(errCode, result) = store_->ExecuteGql(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryEventGql(updatedEvent);
    std::tie(errCode, result) = store_->QueryGql(gql);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetAllData().size(), 0);
}

/**
 * @tc.name: GdbFloatVectorTest008
 * @tc.desc: Normal case: Insert, delete, update, and query edges that contain FLOATVECTOR properties.
 * @tc.type: FUNC
 */
HWTEST_F(GdbFloatVectorTest, GdbFloatVectorTest008, TestSize.Level1)
{
    CreateGraph(GdbFloatVectorTest::createGraphGql, E_OK);
    PersonParam person = { "name_1", "male", "0.1,0.1,0.1,0.1" };
    std::string gql = GenerateInsertPersonGql(person);
    auto [errCode, result] = store_->ExecuteGql(gql);
    EXPECT_EQ(errCode, E_OK);

    EventParam event = { "title_1", "This is a event which title is 1", "0.1,0.1,0.1,0.1" };
    gql = GenerateInsertEventGql(event);
    std::tie(errCode, result) = store_->ExecuteGql(gql);
    EXPECT_EQ(errCode, E_OK);

    ParticipateParam relation = { person, event, "name_1 participate title_1", "0.1,0.1,0.1,0.1" };
    gql = GenerateInsertParticipateGql(relation);
    std::tie(errCode, result) = store_->ExecuteGql(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryParticipateGql(relation);
    std::tie(errCode, result) = store_->QueryGql(gql);
    EXPECT_EQ(errCode, E_OK);
    CheckFloatVector(result, relation.embedding, "relation.embedding");

    ParticipateParam updatedRelation = { person, event, "name_1 participate title_1", "0.1,0.2,0.3,0.4" };
    gql = GenerateUpdateParticipateGql(updatedRelation);
    std::tie(errCode, result) = store_->ExecuteGql(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryParticipateGql(updatedRelation);
    std::tie(errCode, result) = store_->QueryGql(gql);
    EXPECT_EQ(errCode, E_OK);
    CheckFloatVector(result, updatedRelation.embedding, "relation.embedding");

    gql = GenerateDeleteParticipateGql(updatedRelation);
    std::tie(errCode, result) = store_->ExecuteGql(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryParticipateGql(updatedRelation);
    std::tie(errCode, result) = store_->QueryGql(gql);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetAllData().size(), 0);
}

/**
 * @tc.name: GdbFloatVectorTest009_1
 * @tc.desc: Normal case: Insert, delete, update, and query vertexes that contain FLOATVECTOR properties by transaction.
 * @tc.type: FUNC
 */
HWTEST_F(GdbFloatVectorTest, GdbFloatVectorTest009_1, TestSize.Level1)
{
    CreateGraph(GdbFloatVectorTest::createGraphGql, E_OK);
    auto [err, trans] = store_->CreateTransaction();
    EXPECT_EQ(err, E_OK);
    ASSERT_NE(trans, nullptr);

    PersonParam person = { "name_1", "male", "0.1,0.1,0.1,0.1" };
    std::string gql = GenerateInsertPersonGql(person);
    auto [errCode, result] = trans->Execute(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryPersonGql(person);
    std::tie(errCode, result) = trans->Query(gql);
    EXPECT_EQ(errCode, E_OK);
    CheckFloatVector(result, person.embedding, "person.embedding");

    PersonParam updatedPerson = { "name_1", "male", "0.1,0.2,0.3,0.4" };
    gql = GenerateUpdatePersonGql(updatedPerson);
    std::tie(errCode, result) = trans->Execute(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryPersonGql(updatedPerson);
    std::tie(errCode, result) = trans->Query(gql);
    EXPECT_EQ(errCode, E_OK);
    CheckFloatVector(result, updatedPerson.embedding, "person.embedding");

    gql = GenerateDeletePersonGql(updatedPerson);
    std::tie(errCode, result) = trans->Execute(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryPersonGql(updatedPerson);
    std::tie(errCode, result) = trans->Query(gql);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetAllData().size(), 0);
}

/**
 * @tc.name: GdbFloatVectorTest009_2
 * @tc.desc: Normal case: Insert, delete, update, and query vertexes that contain FLOATVECTOR properties by transaction.
 * @tc.type: FUNC
 */
HWTEST_F(GdbFloatVectorTest, GdbFloatVectorTest009_2, TestSize.Level1)
{
    CreateGraph(GdbFloatVectorTest::createGraphGql, E_OK);
    auto [err, trans] = store_->CreateTransaction();
    EXPECT_EQ(err, E_OK);
    ASSERT_NE(trans, nullptr);

    EventParam event = { "title_1", "This is a event which title is 1", "0.1,0.1,0.1,0.1" };
    std::string gql = GenerateInsertEventGql(event);
    auto [errCode, result] = trans->Execute(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryEventGql(event);
    std::tie(errCode, result) = trans->Query(gql);
    EXPECT_EQ(errCode, E_OK);
    CheckFloatVector(result, event.embedding, "event.embedding");

    EventParam updatedEvent = { "title_1", "This is a event which title is 1", "0.1,0.2,0.3,0.4" };
    gql = GenerateUpdateEventGql(updatedEvent);
    std::tie(errCode, result) = trans->Execute(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryEventGql(updatedEvent);
    std::tie(errCode, result) = trans->Query(gql);
    EXPECT_EQ(errCode, E_OK);
    CheckFloatVector(result, updatedEvent.embedding, "event.embedding");

    gql = GenerateDeleteEventGql(updatedEvent);
    std::tie(errCode, result) = trans->Execute(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryEventGql(updatedEvent);
    std::tie(errCode, result) = trans->Query(gql);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetAllData().size(), 0);
}

/**
 * @tc.name: GdbFloatVectorTest010
 * @tc.desc: Normal case: Insert, delete, update, and query edges that contain FLOATVECTOR properties by transaction.
 * @tc.type: FUNC
 */
HWTEST_F(GdbFloatVectorTest, GdbFloatVectorTest010, TestSize.Level1)
{
    CreateGraph(GdbFloatVectorTest::createGraphGql, E_OK);
    auto [err, trans] = store_->CreateTransaction();
    EXPECT_EQ(err, E_OK);
    ASSERT_NE(trans, nullptr);

    PersonParam person = { "name_1", "male", "0.1,0.1,0.1,0.1" };
    std::string gql = GenerateInsertPersonGql(person);
    auto [errCode, result] = trans->Execute(gql);
    EXPECT_EQ(errCode, E_OK);

    EventParam event = { "title_1", "This is a event which title is 1", "0.1,0.1,0.1,0.1" };
    gql = GenerateInsertEventGql(event);
    std::tie(errCode, result) = trans->Execute(gql);
    EXPECT_EQ(errCode, E_OK);

    ParticipateParam relation = { person, event, "name_1 participate title_1", "0.1,0.1,0.1,0.1" };
    gql = GenerateInsertParticipateGql(relation);
    std::tie(errCode, result) = trans->Execute(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryParticipateGql(relation);
    std::tie(errCode, result) = trans->Query(gql);
    EXPECT_EQ(errCode, E_OK);
    CheckFloatVector(result, relation.embedding, "relation.embedding");

    ParticipateParam updatedRelation = { person, event, "name_1 participate title_1", "0.1,0.2,0.3,0.4" };
    gql = GenerateUpdateParticipateGql(updatedRelation);
    std::tie(errCode, result) = trans->Execute(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryParticipateGql(updatedRelation);
    std::tie(errCode, result) = trans->Query(gql);
    EXPECT_EQ(errCode, E_OK);
    CheckFloatVector(result, updatedRelation.embedding, "relation.embedding");

    gql = GenerateDeleteParticipateGql(updatedRelation);
    std::tie(errCode, result) = trans->Execute(gql);
    EXPECT_EQ(errCode, E_OK);

    gql = GenerateQueryParticipateGql(updatedRelation);
    std::tie(errCode, result) = trans->Query(gql);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetAllData().size(), 0);
}