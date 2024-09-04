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
#define LOG_TAG "SerializableTest"
#include "serializable.h"

#include <type_traits>

#include "gtest/gtest.h"
#include "logger.h"

using namespace testing::ext;
namespace OHOS::Test {
class SerializableTest : public testing::Test {
public:
    struct Normal final : public Serializable {
    public:
        std::string name = "Test";
        int32_t count = 0;
        uint32_t status = 1;
        int64_t value = 2;
        bool isClear = false;
        std::vector<std::string> cols{ "123", "345", "789" };
        std::vector<std::vector<int32_t>> colRow{ { 123, 345, 789 }, { 123, 345, 789 } };

        bool Marshal(json &node) const override
        {
            SetValue(node[GET_NAME(name)], name);
            SetValue(node[GET_NAME(count)], count);
            SetValue(node[GET_NAME(status)], status);
            SetValue(node[GET_NAME(value)], value);
            SetValue(node[GET_NAME(isClear)], isClear);
            SetValue(node[GET_NAME(cols)], cols);
            SetValue(node[GET_NAME(colRow)], colRow);
            return true;
        }
        bool Unmarshal(const json &node) override
        {
            GetValue(node, GET_NAME(name), name);
            GetValue(node, GET_NAME(count), count);
            GetValue(node, GET_NAME(status), status);
            GetValue(node, GET_NAME(value), value);
            GetValue(node, GET_NAME(isClear), isClear);
            GetValue(node, GET_NAME(cols), cols);
            GetValue(node, GET_NAME(colRow), colRow);
            return true;
        }
        bool operator==(const Normal &ref) const
        {
            return name == ref.name && count == ref.count && status == ref.status && value == ref.value &&
                   isClear == ref.isClear && cols == ref.cols;
        }
    };

    struct NormalEx final : public Serializable {
    public:
        std::vector<Normal> normals{ Normal(), Normal() };
        Normal normal;
        int32_t count = 123;
        std::string name = "wdt";
        bool Marshal(json &node) const override
        {
            SetValue(node[GET_NAME(normals)], normals);
            SetValue(node[GET_NAME(normal)], normal);
            SetValue(node[GET_NAME(count)], count);
            SetValue(node[GET_NAME(name)], name);
            return true;
        }
        bool Unmarshal(const json &node) override
        {
            GetValue(node, GET_NAME(normals), normals);
            GetValue(node, GET_NAME(normal), normal);
            GetValue(node, GET_NAME(count), count);
            GetValue(node, GET_NAME(name), name);
            return true;
        }
        bool operator==(const NormalEx &normalEx) const
        {
            return normals == normalEx.normals && count == normalEx.count && name == normalEx.name;
        }
    };
    static void SetUpTestCase(void)
    {
    }
    static void TearDownTestCase(void)
    {
    }
    void SetUp()
    {
        Test::SetUp();
    }
    void TearDown()
    {
        Test::TearDown();
    }

    template<typename T>
    static inline bool EqualPtr(const T *src, const T *target)
    {
        return (((src) == (target)) || ((src) != nullptr && (target) != nullptr && *(src) == *(target)));
    }
};

/**
* @tc.name: SerializableSuiteGetVal
* @tc.desc: Get Value.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SerializableTest, GetNormalVal, TestSize.Level2)
{
    Normal normal;
    normal.name = "normal";
    normal.count = -1;
    normal.status = 12;
    normal.value = -56;
    normal.isClear = true;
    normal.cols = { "adfasdfas" };
    auto jstr = to_string(normal.Marshall());
    Normal normal1;
    normal1.Unmarshall(jstr);
    ASSERT_TRUE(normal == normal1) << normal1.name;
}

/**
* @tc.name: Delete Serializable
* @tc.desc: can delete child class, but not delete parent class point.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SerializableTest, DeleteSerializable, TestSize.Level2)
{
    ASSERT_FALSE(std::is_destructible<Serializable>::value);
    ASSERT_TRUE(std::is_destructible<NormalEx>::value);
}

/**
* @tc.name: SerializableSuiteGetMutilVal
* @tc.desc: mutil value case.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SerializableTest, GetMutilVal, TestSize.Level2)
{
    NormalEx normalEx;
    normalEx.normals = { Normal() };
    normalEx.name = "normalEx";
    auto jstr = to_string(normalEx.Marshall());
    NormalEx normal1;
    normal1.Unmarshall(jstr);
    ASSERT_TRUE(normalEx == normal1) << normal1.name;
}

/**
* @tc.name: IsJson
* @tc.desc: is json.
* @tc.type: FUNC
*/
HWTEST_F(SerializableTest, IsJson, TestSize.Level1)
{
    std::string str = "test";
    std::string jsonStr = "\"test\"";
    ASSERT_FALSE(Serializable::IsJson(str));
    ASSERT_TRUE(Serializable::IsJson(jsonStr));
}

/**
* @tc.name: ToJson_01
* @tc.desc: to json.
* @tc.type: FUNC
*/
HWTEST_F(SerializableTest, ToJson_01, TestSize.Level1)
{
    std::string jsonStr = "{\"key\":\"value\"}";
    Serializable::json result = Serializable::ToJson(jsonStr);
    ASSERT_FALSE(result.is_discarded());
}

/**
* @tc.name: ToJson_02
* @tc.desc: to json.
* @tc.type: FUNC
*/
HWTEST_F(SerializableTest, ToJson_02, TestSize.Level1)
{
    std::string jsonStr = "invalid_json";
    Serializable::json result = Serializable::ToJson(jsonStr);
    ASSERT_FALSE(result.is_discarded());
}

/**
* @tc.name: ToJson_03
* @tc.desc: to json.
* @tc.type: FUNC
*/
HWTEST_F(SerializableTest, ToJson_03, TestSize.Level1)
{
    std::string jsonStr = "";
    Serializable::json result = Serializable::ToJson(jsonStr);
    ASSERT_TRUE(result.empty());
}

/**
* @tc.name: ToJson_04
* @tc.desc: to json.
* @tc.type: FUNC
*/
HWTEST_F(SerializableTest, ToJson_04, TestSize.Level1)
{
    std::string jsonStr = "{invalid_json}";
    Serializable::json result = Serializable::ToJson(jsonStr);
    ASSERT_FALSE(result.is_discarded());
}
} // namespace OHOS::Test