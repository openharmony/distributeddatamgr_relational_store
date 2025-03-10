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
class GdbQueryTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void InsertCompany(const std::string &name, const int32_t &founded);
    void MatchAndVerifyCompany(const std::string &name, const int32_t &founded);
    void VerifyCompanyInfo(const GraphValue &company, const std::string &name, const int32_t &founded);

    static const std::string databaseName;
    static const std::string databasePath;
    static std::shared_ptr<DBStore> store_;
    static const std::string createGraphGql;
    static const std::string createGraphGql2;
    static const std::shared_ptr<StoreConfig> databaseConfig;
};
std::shared_ptr<DBStore> GdbQueryTest::store_;
const std::string GdbQueryTest::databaseName = "test_gdb";
const std::string GdbQueryTest::databasePath = "/data";
const std::string GdbQueryTest::createGraphGql = "CREATE GRAPH companyGraph { "
                                                    "(company:Company {name STRING, founded INT}), "
                                                    "(department:Department {name STRING}), "
                                                    "(employee:Employee {name STRING, position STRING}), "
                                                    "(project:Project {name STRING, budget INT}), "
                                                    "(company) -[:HAS_DEPARTMENT]-> (department), "
                                                    "(department) -[:HAS_EMPLOYEE]-> (employee), "
                                                    "(employee) -[:WORKS_ON]-> (project), "
                                                    "(department) -[:HAS_PROJECT]-> (project) "
                                                    "};";
const std::string GdbQueryTest::createGraphGql2 = "CREATE GRAPH companyGraph2 {"
                                                     "(company:Company {name STRING, founded INT}) };";
void GdbQueryTest::SetUpTestCase()
{
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
    }
    int errCode = E_OK;
    auto config = StoreConfig(databaseName, databasePath);
    GDBHelper::DeleteDBStore(config);

    GdbQueryTest::store_ = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(GdbQueryTest::store_, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void GdbQueryTest::TearDownTestCase()
{
    GDBHelper::DeleteDBStore(StoreConfig(databaseName, databasePath));
    store_ = nullptr;
}

void GdbQueryTest::SetUp()
{
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
    }
    auto result = store_->ExecuteGql(createGraphGql);
    EXPECT_EQ(result.first, E_OK);
}

void GdbQueryTest::TearDown()
{
    if (store_ != nullptr) {
        auto result = store_->ExecuteGql("DROP GRAPH companyGraph");
    }
}

HWTEST_F(GdbQueryTest, GdbStore_Test_CreateHaveRowId, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    auto createGql = "CREATE GRAPH companyGraph3 {"
                     "(company:Company {rowid INT, name STRING, founded INT}) };";
    auto result = store_->ExecuteGql(createGql);
    EXPECT_EQ(result.first, E_GRD_OVER_LIMIT);
}

/**
 * @tc.name: GdbStore_Test_CreateLimitDb
 * @tc.desc: Too many graphs can be created for only one graph in a library. Failed to create too many graphs.
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_Test_CreateLimitDb, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    // Too many graphs can be created for only one graph in a library. Failed to create too many graphs.
    auto result = store_->ExecuteGql(createGraphGql2);
    EXPECT_EQ(result.first, E_GRD_OVER_LIMIT);
}

/**
 * @tc.name: GdbStore_QuertTest_001
 * @tc.desc: To test the function of querying an employee.
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_001, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    // Insert Employee
    const std::string insertEmployeeQuery = "INSERT (:Employee {name: 'John Doe11', position: 'Software Engineer'});";
    auto result = store_->ExecuteGql(insertEmployeeQuery);
    EXPECT_EQ(result.first, E_OK);

    // Verifying the Employee Vertex
    result = store_->QueryGql("MATCH (e:Employee {name: 'John Doe11'}) RETURN e;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 1);

    GraphValue employee = result.second->GetAllData()[0]["e"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Vertex>>(employee));
    auto employeeVertex = std::get<std::shared_ptr<Vertex>>(employee);
    EXPECT_EQ(employeeVertex->GetLabel(), "Employee");

    auto name = employeeVertex->GetProperties().find("name");
    ASSERT_NE(name, employeeVertex->GetProperties().end());
    EXPECT_EQ(std::get<std::string>(name->second), "John Doe11");

    auto position = employeeVertex->GetProperties().find("position");
    ASSERT_NE(position, employeeVertex->GetProperties().end());
    EXPECT_EQ(std::get<std::string>(position->second), "Software Engineer");
}

/**
 * @tc.name: GdbStore_QuertTest_002
 * @tc.desc: To test the function of querying an Employee and Project and Relation.
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_002, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    // insert Employee
    auto result = store_->ExecuteGql("INSERT (:Employee {name: 'John Doe', position: 'Software Engineer'});");
    EXPECT_EQ(result.first, E_OK);
    // insert Project
    result = store_->ExecuteGql("INSERT (:Project {name: 'Project Alpha'});");
    EXPECT_EQ(result.first, E_OK);

    // Associating an Employee with a Project, WORKS_ON
    const std::string insertRelationQuery =
        "MATCH (e:Employee {name: 'John Doe'}), (p:Project {name: 'Project Alpha'}) "
        "INSERT (e)-[:WORKS_ON]->(p);";
    result = store_->ExecuteGql(insertRelationQuery);
    EXPECT_EQ(result.first, E_OK);

    // Querying and Verifying the Relationship Existence
    result = store_->QueryGql("MATCH (e:Employee {name: 'John Doe'})-[r:WORKS_ON]->"
                              "(p:Project {name: 'Project Alpha'}) RETURN e, r, p;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);

    // Verifying the Employee Vertex
    GraphValue employee = result.second->GetAllData()[0]["e"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Vertex>>(employee));
    auto employeeVertex = std::get<std::shared_ptr<Vertex>>(employee);
    EXPECT_EQ(employeeVertex->GetLabel(), "Employee");

    // Verifying Project Vertex
    GraphValue project = result.second->GetAllData()[0]["p"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Vertex>>(project));
    auto projectVertex = std::get<std::shared_ptr<Vertex>>(project);
    EXPECT_EQ(projectVertex->GetLabel(), "Project");

    // Validate Relationships
    GraphValue relation = result.second->GetAllData()[0]["r"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Edge>>(relation));
    auto relationship = std::get<std::shared_ptr<Edge>>(relation);
    EXPECT_EQ(relationship->GetSourceId(), "1");
    EXPECT_EQ(relationship->GetTargetId(), "2");
}

/**
 * @tc.name: MatchAndVerifyCompany
 * @tc.desc: Match And Verify that company information meets expectations
 * @tc.type: FUNC
 */
void GdbQueryTest::MatchAndVerifyCompany(const std::string &name, const int32_t &founded)
{
    ASSERT_NE(store_, nullptr);
    auto gql = "MATCH (company:Company {name: '" + name + "'}) RETURN company;";
    auto result = store_->QueryGql(gql);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, name, founded);
}

/**
 * @tc.name: VerifyCompanyInfo
 * @tc.desc: Verify that company information meets expectations
 * @tc.type: FUNC
 */
void GdbQueryTest::VerifyCompanyInfo(const GraphValue &company, const std::string &name, const int32_t &founded)
{
    auto expectSize = 2;
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Vertex>>(company));
    auto companyVertex = std::get<std::shared_ptr<Vertex>>(company);
    EXPECT_EQ(companyVertex->GetLabel(), "Company");
    ASSERT_EQ(companyVertex->GetProperties().size(), expectSize);

    auto nameDb = companyVertex->GetProperties().find("name");
    ASSERT_NE(nameDb, companyVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(nameDb->second));
    EXPECT_EQ(std::get<std::string>(nameDb->second), name);

    auto foundedDb = companyVertex->GetProperties().find("founded");
    ASSERT_NE(foundedDb, companyVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<int64_t>(foundedDb->second));
    EXPECT_EQ(std::get<int64_t>(foundedDb->second), founded);
}

/**
 * @tc.name: InsertCompany
 * @tc.desc: Insert Company Information
 * @tc.type: FUNC
 */
void GdbQueryTest::InsertCompany(const std::string &name, const int32_t &founded)
{
    ASSERT_NE(store_, nullptr);
    auto result =
        store_->ExecuteGql("INSERT (:Company {name: '" + name + "', founded: " + std::to_string(founded) + "});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyCompany(name, founded);
}

/**
 * @tc.name: GdbStore_QuertTest_WhereInMatch
 * @tc.desc: Verify the where condition in match.
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_WhereInMatch, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    InsertCompany("myCompany", 1991);
    InsertCompany("myCompany2", 2001);
    InsertCompany("myCompany3", 2011);
    // where condition in match.
    auto result = store_->QueryGql("MATCH (company:Company where company.founded > 2000) RETURN company;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 2);
    GraphValue company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, "myCompany2", 2001);

    GraphValue company1 = result.second->GetAllData()[1]["company"];
    VerifyCompanyInfo(company1, "myCompany3", 2011);
}

/**
 * @tc.name: GdbStore_QuertTest_WhereOutsideMatch
 * @tc.desc: Validate where condition outside match
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_WhereOutsideMatch, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    InsertCompany("myCompany", 1991);
    InsertCompany("myCompany2", 2001);
    InsertCompany("myCompany3", 2011);
    // where condition outside match
    auto result = store_->QueryGql("MATCH (company:Company) where company.founded != 2001 RETURN company;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 2);
    GraphValue company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, "myCompany", 1991);

    GraphValue company1 = result.second->GetAllData()[1]["company"];
    VerifyCompanyInfo(company1, "myCompany3", 2011);
}

/**
 * @tc.name: GdbStore_QuertTest_WhereAppendAnd
 * @tc.desc: Verify that the where condition is appended to the AND statement outside the match condition.
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_WhereAppendAnd, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    InsertCompany("myCompany", 1991);
    InsertCompany("myCompany2", 2001);
    InsertCompany("myCompany3", 2011);
    // Verify that the where condition is appended to the AND statement outside the match condition.
    auto result = store_->QueryGql("MATCH (company:Company) "
                                   "where company.founded != 2001 and company.name <> 'myCompany3' RETURN company;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, "myCompany", 1991);
}

/**
 * @tc.name: GdbStore_QuertTest_WhereOutsideAndInsideMatch
 * @tc.desc: Validate where conditions outside and inside match
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_WhereOutsideAndInsideMatch, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    InsertCompany("myCompany", 1991);
    InsertCompany("myCompany2", 2001);
    InsertCompany("myCompany3", 2011);
    // Validate where conditions outside and inside match
    auto result = store_->QueryGql("MATCH (company:Company where company.founded != 2001 ) "
                                   " where company.name <> 'myCompany3' RETURN company;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, "myCompany", 1991);
}

/**
 * @tc.name: GdbStore_QuertTest_WhereStartAnd
 * @tc.desc: The validation condition is outside and inside match, but outside it starts with and, not where.
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_WhereStartAnd, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    InsertCompany("myCompany", 1991);
    InsertCompany("myCompany2", 2001);
    InsertCompany("myCompany3", 2011);
    // The validation condition is outside and inside match, but outside it starts with and, not where.
    auto result = store_->QueryGql("MATCH (company:Company where company.founded != 2001 ) "
                                   " AND company.name <> 'myCompany3' RETURN company;");
    ASSERT_EQ(result.first, E_GRD_SYNTAX_ERROR);
    EXPECT_EQ(result.second->GetAllData().size(), 0);
}

/**
 * @tc.name: GdbStore_QuertTest_WhereByMatch
 * @tc.desc: Use {} to transfer query conditions in match.
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_WhereByMatch, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    InsertCompany("myCompany", 1991);
    InsertCompany("myCompany2", 2001);
    InsertCompany("myCompany3", 2011);
    // The validation condition is outside and inside match, but outside it starts with and, not where.
    auto result = store_->QueryGql("MATCH (company:Company {founded: 2001} ) "
                                   " where company.name = 'myCompany2' RETURN company;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, "myCompany2", 2001);
}

/**
 * @tc.name: GdbStore_QuertTest_WhereOperators
 * @tc.desc: Verify that operators are supported in the where condition.
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_WhereOperators, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    InsertCompany("myCompany", 1991);
    InsertCompany("myCompany2", 2001);
    InsertCompany("myCompany3", 2011);
    auto result = store_->QueryGql("MATCH (company:Company) "
                                   "where company.founded >= 2000+1 and company.founded < 2012 -1 RETURN company;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, "myCompany2", 2001);

    result = store_->QueryGql("MATCH (company:Company) "
                              "where company.founded > 2 * 1000 +1 and company.founded < 2 * 1000 +12 RETURN company;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, "myCompany3", 2011);
}

/**
 * @tc.name: GdbStore_QuertTest_PostLike
 * @tc.desc: Verify that the matching starts with a fixed character and ends with any number of other characters.
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_PostLike, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    InsertCompany("myCompany", 1991);
    InsertCompany("myCompany2", 2001);
    InsertCompany("aimyCompany", 2011);
    auto result = store_->QueryGql("MATCH (company:Company) "
                                   "where company.name like 'myCompany%' RETURN company;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 2);
    GraphValue company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, "myCompany", 1991);

    company = result.second->GetAllData()[1]["company"];
    VerifyCompanyInfo(company, "myCompany2", 2001);
}

/**
 * @tc.name: GdbStore_QuertTest_WhereLike
 * @tc.desc: Matches contain specific characters.
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_Like, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    InsertCompany("myCompany", 1991);
    InsertCompany("myCompany2", 2001);
    InsertCompany("aimyCompany", 2011);
    auto result = store_->QueryGql("MATCH (company:Company) "
                                   "where company.name like '%myCompany%' RETURN company;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 3);
    GraphValue company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, "myCompany", 1991);

    company = result.second->GetAllData()[1]["company"];
    VerifyCompanyInfo(company, "myCompany2", 2001);

    company = result.second->GetAllData()[2]["company"];
    VerifyCompanyInfo(company, "aimyCompany", 2011);
}

/**
 * @tc.name: GdbStore_QuertTest_BeferLike
 * @tc.desc: Matches any number of other characters before the end of a fixed character.
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_BeferLike, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    InsertCompany("myCompany", 1991);
    InsertCompany("myCompany2", 2001);
    InsertCompany("aimyCompany", 2011);
    auto result = store_->QueryGql("MATCH (company:Company) "
                                   "where company.name like '%myCompany' RETURN company;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 2);
    GraphValue company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, "myCompany", 1991);

    company = result.second->GetAllData()[1]["company"];
    VerifyCompanyInfo(company, "aimyCompany", 2011);
}

/**
 * @tc.name: GdbStore_QuertTest_MatchesCharacter
 * @tc.desc: Matches a character
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_MatchesCharacter, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    InsertCompany("myCompany", 1991);
    InsertCompany("amyCompany", 2001);
    InsertCompany("amyCompanya", 2002);
    InsertCompany("abmyCompanyab", 2003);
    InsertCompany("abmyCompany", 2004);
    auto result = store_->QueryGql("MATCH (company:Company) "
                                   "where company.name like '_myCompany' RETURN company;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, "amyCompany", 2001);
}

/**
 * @tc.name: GdbStore_QuertTest_MatchesCharacter02
 * @tc.desc: Matches a character
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_MatchesCharacter02, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    InsertCompany("myCompany", 1991);
    InsertCompany("amyCompany", 2001);
    InsertCompany("amyCompanya", 2002);
    InsertCompany("abmyCompanyab", 2003);
    InsertCompany("abmyCompany", 2004);
    auto result = store_->QueryGql("MATCH (company:Company) "
                                   "where company.name like '_myCompany_' RETURN company;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, "amyCompanya", 2002);
}

/**
 * @tc.name: GdbStore_QuertTest_MatchesCharacter03
 * @tc.desc: Matches a character
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_MatchesCharacter03, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    InsertCompany("myCompany", 1991);
    InsertCompany("myCompanya", 2001);
    InsertCompany("myCompanyab", 2002);
    InsertCompany("amyCompanya", 2003);
    auto result = store_->QueryGql("MATCH (company:Company) "
                                   "where company.name like 'myCompany_' RETURN company;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, "myCompanya", 2001);
}

/**
 * @tc.name: GdbStore_QuertTest_In
 * @tc.desc: Match conditions in
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_In, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    InsertCompany("myCompany", 1991);
    InsertCompany("myCompany1", 2001);
    InsertCompany("myCompany2", 2002);
    auto result = store_->QueryGql("MATCH (company:Company) "
                                   "where company.founded in (2001, 2002, 9999) RETURN company;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 2);
    GraphValue company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, "myCompany1", 2001);

    company = result.second->GetAllData()[1]["company"];
    VerifyCompanyInfo(company, "myCompany2", 2002);
}

/**
 * @tc.name: GdbStore_QuertTest_In01
 * @tc.desc: Match conditions in
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_NotIn, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    InsertCompany("myCompany", 1991);
    InsertCompany("myCompany1", 2001);
    InsertCompany("myCompany2", 2002);
    auto result = store_->QueryGql("MATCH (company:Company) "
                                   "where company.founded not in (2001, 9999) RETURN company;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 2);
    GraphValue company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, "myCompany", 1991);

    company = result.second->GetAllData()[1]["company"];
    VerifyCompanyInfo(company, "myCompany2", 2002);
}

/**
 * @tc.name: GdbStore_QuertTest_IsNull
 * @tc.desc: Match conditions in
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_IsNull, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    auto result = store_->ExecuteGql("INSERT (:Employee {name: 'zhangsan', position: 'Software'});");
    EXPECT_EQ(result.first, E_OK);
    result = store_->ExecuteGql("INSERT (:Employee {name: 'zhangsan1', position: 'Software1'});");
    EXPECT_EQ(result.first, E_OK);
    // 寮簊chema涓嬪叾浠栨湭濉瓧娈典负null
    result = store_->ExecuteGql("MATCH (e:Employee {name: 'zhangsan'}) SET e = {position: 'SoftwareNew'};");
    EXPECT_EQ(result.first, E_OK);
    result = store_->QueryGql("MATCH (e:Employee) "
                              "where e.name IS NULL RETURN e;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue company = result.second->GetAllData()[0]["e"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Vertex>>(company));
    auto companyVertex = std::get<std::shared_ptr<Vertex>>(company);
    EXPECT_EQ(companyVertex->GetLabel(), "Employee");
    ASSERT_EQ(companyVertex->GetProperties().size(), 1);

    auto nameDb = companyVertex->GetProperties().find("name");
    EXPECT_EQ(nameDb, companyVertex->GetProperties().end());

    auto foundedDb = companyVertex->GetProperties().find("position");
    ASSERT_NE(foundedDb, companyVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(foundedDb->second));
    EXPECT_EQ(std::get<std::string>(foundedDb->second), "SoftwareNew");
}

/**
 * @tc.name: GdbStore_QuertTest_IsNotNull
 * @tc.desc: Match conditions in
 * @tc.type: FUNC
 */
HWTEST_F(GdbQueryTest, GdbStore_QuertTest_IsNotNull, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    auto result = store_->ExecuteGql("INSERT (:Company {founded: 1991});");
    EXPECT_EQ(result.first, E_OK);
    InsertCompany("myCompany1", 2001);
    InsertCompany("myCompany2", 2002);
    result = store_->QueryGql("MATCH (company:Company) "
                              "where company.name IS NOT NULL RETURN company;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 2);
    GraphValue company = result.second->GetAllData()[0]["company"];
    VerifyCompanyInfo(company, "myCompany1", 2001);

    company = result.second->GetAllData()[1]["company"];
    VerifyCompanyInfo(company, "myCompany2", 2002);
}