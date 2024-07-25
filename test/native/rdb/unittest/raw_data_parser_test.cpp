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
#define LOG_TAG "RdbBigIntTest"
#include "raw_data_parser.h"

#include <gtest/gtest.h>

#include "value_object.h"
using namespace testing::ext;
using namespace OHOS::NativeRdb;
namespace Test {
class RawDataParserTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void RawDataParserTest::SetUpTestCase(void)
{
}

void RawDataParserTest::TearDownTestCase(void)
{
}

void RawDataParserTest::SetUp(void)
{
}

void RawDataParserTest::TearDown(void)
{
}

/**
 * @tc.name: BigInt_Parser
 * @tc.desc: test insert bigint to rdb store
 * @tc.type: FUNC
 */
HWTEST_F(RawDataParserTest, BigInt_Parser, TestSize.Level1)
{
    std::vector<uint64_t> u64Val(2 + rand() % 100, 0);
    for (int i = 0; i < u64Val.size(); ++i) {
        uint64_t high = uint64_t(rand());
        uint64_t low = uint64_t(rand());
        u64Val[i] = (high << 32) | low;
    }
    BigInteger value1 = BigInteger(0, std::vector<uint64_t>(u64Val));
    auto rawData = RawDataParser::PackageRawData(value1);
    for (size_t i = 0; i < sizeof(uintptr_t); ++i) {
        std::vector<uint8_t> noAlign(rawData.size() + i, 0);
        noAlign.insert(noAlign.begin() + i, rawData.begin(), rawData.end());
        BigInteger parsedValue1;
        RawDataParser::ParserRawData(noAlign.data() + i, noAlign.size() - i, parsedValue1);
        ASSERT_TRUE(value1 == parsedValue1);
    }
}
/**
 * @tc.name: Float32_Parser
 * @tc.desc: test insert bigint to rdb store
 * @tc.type: FUNC
 */
HWTEST_F(RawDataParserTest, Float32_Parser, TestSize.Level1)
{
    std::vector<float> floats(15, 9.65);
    auto rawData = RawDataParser::PackageRawData(floats);
    for (size_t i = 0; i < sizeof(uintptr_t); ++i) {
        std::vector<uint8_t> noAlign(rawData.size() + i, 0);
        noAlign.insert(noAlign.begin() + i, rawData.begin(), rawData.end());
        std::vector<float> parsedFloats;
        RawDataParser::ParserRawData(noAlign.data() + i, noAlign.size() - i, parsedFloats);
        ASSERT_TRUE(floats.size() == parsedFloats.size());
    }
}
/**
 * @tc.name: Asset_Parser
 * @tc.desc: test insert bigint to rdb store
 * @tc.type: FUNC
 */
HWTEST_F(RawDataParserTest, Asset_Parser, TestSize.Level1)
{
    ValueObject::Asset asset;
    asset.id = "100";
    asset.name = "IMG_1690.png";
    asset.uri = "file://data/args/header/IMG_1690.png";
    asset.createTime = "2024-07-05 20:37.982158265 +8:00";
    asset.modifyTime = "2024-07-05 20:37.982158265 +8:00";
    asset.size = "4194304";
    asset.hash = "2024-07-05 20:37.982158265 +8:00_4194304";
    asset.path = "photos/header/IMG_1690.png";
    auto rawData = RawDataParser::PackageRawData(asset);
    for (size_t i = 0; i < sizeof(uintptr_t); ++i) {
        std::vector<uint8_t> noAlign(rawData.size() + i, 0);
        noAlign.insert(noAlign.begin() + i, rawData.begin(), rawData.end());
        ValueObject::Asset parsedAsset;
        RawDataParser::ParserRawData(noAlign.data() + i, noAlign.size() - i, parsedAsset);
        ASSERT_TRUE(parsedAsset.id == asset.id);
        ASSERT_TRUE(parsedAsset.name == asset.name);
        ASSERT_TRUE(parsedAsset.uri == asset.uri);
        ASSERT_TRUE(parsedAsset.createTime == asset.createTime);
        ASSERT_TRUE(parsedAsset.modifyTime == asset.modifyTime);
        ASSERT_TRUE(parsedAsset.size == asset.size);
        ASSERT_TRUE(parsedAsset.hash == asset.hash);
        ASSERT_TRUE(parsedAsset.path == asset.path);
    }
}
/**
 * @tc.name: Assets_Parser
 * @tc.desc: test insert bigint to rdb store
 * @tc.type: FUNC
 */
HWTEST_F(RawDataParserTest, Assets_Parser, TestSize.Level1)
{
    ValueObject::Assets assets(1);
    assets[0].id = "100";
    assets[0].name = "IMG_1690.png";
    assets[0].uri = "file://data/args/header/IMG_1690.png";
    assets[0].createTime = "2024-07-05 20:37.982158265 +8:00";
    assets[0].modifyTime = "2024-07-05 20:37.982158265 +8:00";
    assets[0].size = "4194304";
    assets[0].hash = "2024-07-05 20:37.982158265 +8:00_4194304";
    assets[0].path = "photos/header/IMG_1690.png";
    auto rawData = RawDataParser::PackageRawData(assets);
    for (size_t i = 0; i < sizeof(uintptr_t); ++i) {
        std::vector<uint8_t> noAlign(rawData.size() + i, 0);
        noAlign.insert(noAlign.begin() + i, rawData.begin(), rawData.end());
        ValueObject::Assets parsedAssets;
        RawDataParser::ParserRawData(noAlign.data() + i, noAlign.size() - i, parsedAssets);
        ASSERT_TRUE(parsedAssets[0].id == assets[0].id);
        ASSERT_TRUE(parsedAssets[0].name == assets[0].name);
        ASSERT_TRUE(parsedAssets[0].uri == assets[0].uri);
        ASSERT_TRUE(parsedAssets[0].createTime == assets[0].createTime);
        ASSERT_TRUE(parsedAssets[0].modifyTime == assets[0].modifyTime);
        ASSERT_TRUE(parsedAssets[0].size == assets[0].size);
        ASSERT_TRUE(parsedAssets[0].hash == assets[0].hash);
        ASSERT_TRUE(parsedAssets[0].path == assets[0].path);
    }
}
} // namespace Test
