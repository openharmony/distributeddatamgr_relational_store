/*
* Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "cache_block.h"

#include <gtest/gtest.h>

#include <map>
#include <string>

#include "common.h"
#include "raw_data_parser.h"
#include "rdb_errno.h"
#include "value_object.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::AppDataFwk;
using Asset = ValueObject::Asset;
using Assets = ValueObject::Assets;

class CacheBlockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static constexpr int MAX_COUNT = 10;
};

void CacheBlockTest::SetUpTestCase(void)
{
}

void CacheBlockTest::TearDownTestCase(void)
{
}

void CacheBlockTest::SetUp()
{
}

void CacheBlockTest::TearDown()
{
}

/**
 * @tc.name: AllocRow001
 * @tc.desc: AllocRow test
 * @tc.type: FUNC
 */
HWTEST_F(CacheBlockTest, AllocRow001, TestSize.Level2)
{
    CacheBlock block(MAX_COUNT, {"name", "age"});
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.SetColumnNum(0));
    EXPECT_FALSE(block.isFull_);
    for (size_t i = 0; i < MAX_COUNT; ++i) {
        EXPECT_EQ(CacheBlock::BLOCK_OK, block.AllocRow());
    }
    EXPECT_EQ(MAX_COUNT, block.rows_.size());
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.AllocRow());
    EXPECT_EQ(MAX_COUNT, block.rows_.size());
    EXPECT_TRUE(block.isFull_);
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.Clear());
}

/**
 * @tc.name: FreeLastRow001
 * @tc.desc: FreeLastRow test
 * @tc.type: FUNC
 */
HWTEST_F(CacheBlockTest, FreeLastRow001, TestSize.Level2)
{
    CacheBlock block(MAX_COUNT, {"name", "age"});
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.AllocRow());
    EXPECT_FALSE(block.rows_.empty());
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.FreeLastRow());
    EXPECT_TRUE(block.rows_.empty());
}

/**
 * @tc.name: PutBlob001
 * @tc.desc: PutBlob test
 * @tc.type: FUNC
 */
HWTEST_F(CacheBlockTest, PutBlob001, TestSize.Level2)
{
    CacheBlock block(MAX_COUNT, {"name", "age"});
    block.isFull_ = true;
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutBlob(0, 0, nullptr, 0));
    block.isFull_ = false;
    block.AllocRow();
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutBlob(1, 0, nullptr, 0));
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutBlob(0, 2, nullptr, 0));
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutBlob(0, 0, nullptr, 0));
    std::vector<uint8_t> blob = { 1, 2, 3 };
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutBlob(0, 0, blob.data(), blob.size()));
    ValueObject object;
    block.rows_[0].GetObject("name", object);
    EXPECT_EQ(ValueObjectType::TYPE_BLOB, object.GetType());
    EXPECT_EQ(ValueObject(blob), object);
}

/**
 * @tc.name: PutString001
 * @tc.desc: PutString test
 * @tc.type: FUNC
 */
HWTEST_F(CacheBlockTest, PutString001, TestSize.Level2)
{
    CacheBlock block(MAX_COUNT, {"name", "age"});
    block.isFull_ = true;
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutString(0, 0, nullptr, 0));
    block.isFull_ = false;
    block.AllocRow();
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutString(1, 0, nullptr, 0));
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutString(0, 2, nullptr, 0));
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutString(0, 0, nullptr, 0));
    const char * value = "test";
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutString(0, 0, value, 5));
    ValueObject object;
    block.rows_[0].GetObject("name", object);
    EXPECT_EQ(ValueObjectType::TYPE_STRING, object.GetType());
    EXPECT_EQ(ValueObject("test"), object);
    CacheBlock block1(MAX_COUNT, {"name", "age"});
    block1.AllocRow();
    EXPECT_EQ(CacheBlock::BLOCK_OK, block1.PutString(0, 0, value, 0));
    block1.rows_[0].GetObject("name", object);
    EXPECT_EQ(ValueObjectType::TYPE_STRING, object.GetType());
    EXPECT_EQ(ValueObject(""), object);
}

/**
 * @tc.name: PutAsset001
 * @tc.desc: PutAsset test
 * @tc.type: FUNC
 */
HWTEST_F(CacheBlockTest, PutAsset001, TestSize.Level2)
{
    CacheBlock block(MAX_COUNT, {"name", "age"});
    block.isFull_ = true;
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutAsset(0, 0, nullptr, 0));
    block.isFull_ = false;
    block.AllocRow();
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutAsset(1, 0, nullptr, 0));
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutAsset(0, 2, nullptr, 0));
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutAsset(0, 0, nullptr, 0));
    Asset asset;
    asset.name = "asset";
    std::vector<uint8_t> data = RawDataParser::PackageRawData(asset);
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutAsset(0, 0, data.data(), data.size()));
    ValueObject object;
    block.rows_[0].GetObject("name", object);
    EXPECT_EQ(ValueObjectType::TYPE_ASSET, object.GetType());
    EXPECT_EQ(ValueObject(asset), object);
    std::vector<uint8_t> wrongData(2, 1);
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutAsset(0, 0, wrongData.data(), wrongData.size()));
    EXPECT_TRUE(block.HasException());
}

/**
 * @tc.name: PutAssets001
 * @tc.desc: PutAssets test
 * @tc.type: FUNC
 */
HWTEST_F(CacheBlockTest, PutAssets001, TestSize.Level2)
{
    CacheBlock block(MAX_COUNT, {"name", "age"});
    block.isFull_ = true;
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutAssets(0, 0, nullptr, 0));
    block.isFull_ = false;
    block.AllocRow();
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutAssets(1, 0, nullptr, 0));
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutAssets(0, 2, nullptr, 0));
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutAssets(0, 0, nullptr, 0));
    Asset asset;
    asset.name = "asset";
    Assets assets = {asset};
    std::vector<uint8_t> data = RawDataParser::PackageRawData(assets);
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutAssets(0, 0, data.data(), data.size()));
    ValueObject object;
    block.rows_[0].GetObject("name", object);
    EXPECT_EQ(ValueObjectType::TYPE_ASSETS, object.GetType());
    EXPECT_EQ(ValueObject(assets), object);
    std::vector<uint8_t> wrongData(2, 1);
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutAssets(0, 0, wrongData.data(), wrongData.size()));
    EXPECT_TRUE(block.HasException());
}

/**
 * @tc.name: PutFloats001
 * @tc.desc: PutFloats test
 * @tc.type: FUNC
 */
HWTEST_F(CacheBlockTest, PutFloats001, TestSize.Level2)
{
    CacheBlock block(MAX_COUNT, {"name", "age"});
    block.isFull_ = true;
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutFloats(0, 0, nullptr, 0));
    block.isFull_ = false;
    block.AllocRow();
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutFloats(1, 0, nullptr, 0));
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutFloats(0, 2, nullptr, 0));
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutFloats(0, 0, nullptr, 0));
    ValueObject::FloatVector flots= {1, 2, 3};
    std::vector<uint8_t> data = RawDataParser::PackageRawData(flots);
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutFloats(0, 0, data.data(), data.size()));
    ValueObject object;
    block.rows_[0].GetObject("name", object);
    EXPECT_EQ(ValueObjectType::TYPE_VECS, object.GetType());
    EXPECT_EQ(ValueObject(flots), object);
    std::vector<uint8_t> wrongData(2, 1);
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutFloats(0, 0, wrongData.data(), wrongData.size()));
    EXPECT_TRUE(block.HasException());
}

/**
 * @tc.name: PutBigInt001
 * @tc.desc: PutBigInt test
 * @tc.type: FUNC
 */
HWTEST_F(CacheBlockTest, PutBigInt001, TestSize.Level2)
{
    CacheBlock block(MAX_COUNT, {"name", "age"});
    block.isFull_ = true;
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutBigInt(0, 0, nullptr, 0));
    block.isFull_ = false;
    block.AllocRow();
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutBigInt(1, 0, nullptr, 0));
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutBigInt(0, 2, nullptr, 0));
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutBigInt(0, 0, nullptr, 0));
    ValueObject::BigInt bigint(1);
    std::vector<uint8_t> data = RawDataParser::PackageRawData(bigint);
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutBigInt(0, 0, data.data(), data.size()));
    ValueObject object;
    block.rows_[0].GetObject("name", object);
    EXPECT_EQ(ValueObjectType::TYPE_BIGINT, object.GetType());
    EXPECT_EQ(ValueObject(bigint), object);
    std::vector<uint8_t> wrongData(2, 1);
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutBigInt(0, 0, wrongData.data(), wrongData.size()));
    EXPECT_TRUE(block.HasException());
}

/**
 * @tc.name: PutLong001
 * @tc.desc: PutLong test
 * @tc.type: FUNC
 */
HWTEST_F(CacheBlockTest, PutLong001, TestSize.Level2)
{
    CacheBlock block(MAX_COUNT, {"name", "age"});
    block.isFull_ = true;
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutLong(0, 0, 0));
    block.isFull_ = false;
    block.AllocRow();
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutLong(1, 0, 0));
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutLong(0, 2, 0));
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutLong(0, 0, 1));
    ValueObject object;
    block.rows_[0].GetObject("name", object);
    EXPECT_EQ(ValueObjectType::TYPE_INT, object.GetType());
    EXPECT_EQ(ValueObject(int64_t(1)), object);
}

/**
 * @tc.name: PutDouble001
 * @tc.desc: PutDouble test
 * @tc.type: FUNC
 */
HWTEST_F(CacheBlockTest, PutDouble001, TestSize.Level2)
{
    CacheBlock block(MAX_COUNT, {"name", "age"});
    block.isFull_ = true;
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutDouble(0, 0, 0));
    block.isFull_ = false;
    block.AllocRow();
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutDouble(1, 0, 0));
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutDouble(0, 2, 0));
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutDouble(0, 0, 1.2));
    ValueObject object;
    block.rows_[0].GetObject("name", object);
    EXPECT_EQ(ValueObjectType::TYPE_DOUBLE, object.GetType());
    EXPECT_EQ(ValueObject(1.2), object);
}

/**
 * @tc.name: PutNull001
 * @tc.desc: PutNull test
 * @tc.type: FUNC
 */
HWTEST_F(CacheBlockTest, PutNull001, TestSize.Level2)
{
    CacheBlock block(MAX_COUNT, {"name", "age"});
    block.isFull_ = true;
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutNull(0, 0));
    block.isFull_ = false;
    block.AllocRow();
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutNull(1, 0));
    EXPECT_EQ(CacheBlock::BLOCK_BAD_VALUE, block.PutNull(0, 2));
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutNull(0, 0));
    ValueObject object;
    block.rows_[0].GetObject("name", object);
    EXPECT_EQ(ValueObjectType::TYPE_NULL, object.GetType());
}

/**
 * @tc.name: StealRows001
 * @tc.desc: StealRows test
 * @tc.type: FUNC
 */
HWTEST_F(CacheBlockTest, StealRows001, TestSize.Level2)
{
    CacheBlock block(MAX_COUNT, {"name", "age"});
    block.AllocRow();
    EXPECT_EQ(CacheBlock::BLOCK_OK, block.PutLong(0, 0, 1));
    auto res = block.StealRows();
    EXPECT_TRUE(block.rows_.empty());
    EXPECT_EQ(res.size(), 1);
    ValueObject object;
    res[0].GetObject("name", object);
    EXPECT_EQ(ValueObjectType::TYPE_INT, object.GetType());
    EXPECT_EQ(ValueObject(int64_t(1)), object);
}