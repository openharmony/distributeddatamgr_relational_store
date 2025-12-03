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
#define LOG_TAG "CacheDataBlock"
#include "cache_data_block.h"

#include <string>
#include <vector>

#include "logger.h"
#include "raw_data_parser.h"
namespace OHOS {
using namespace NativeRdb;
using namespace Rdb;
namespace AppDataFwk {
CacheDataBlock::CacheDataBlock(int32_t maxCount, int32_t colCount)
    : colCount_(colCount), maxCount_(maxCount)
{
}

CacheDataBlock::~CacheDataBlock()
{
}

int CacheDataBlock::CacheDataBlock::Clear()
{
    return BLOCK_OK;
}

int CacheDataBlock::SetColumnNum(uint32_t numColumns)
{
    return BLOCK_OK;
}

int CacheDataBlock::AllocRow()
{
    if (rows_.size() >= static_cast<size_t>(maxCount_)) {
        isFull_ = true;
        return BLOCK_OK;
    }
    rows_.resize(rows_.size() + 1);
    return BLOCK_OK;
}

int CacheDataBlock::FreeLastRow()
{
    if (!rows_.empty()) {
        rows_.pop_back();
    }
    return BLOCK_OK;
}

int CacheDataBlock::PutBlob(uint32_t row, uint32_t column, const void *value, size_t size)
{
    if (isFull_) {
        return BLOCK_OK;
    }

    if (row >= rows_.size() || column >= static_cast<uint32_t>(colCount_) || value == nullptr) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheDataBlock"
                  " which has %{public}zu rows, %{public}d columns.", row, column, rows_.size(), colCount_);
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    const uint8_t *ptr = static_cast<const uint8_t *>(value);
    rows_[row].emplace_back(std::vector<uint8_t>(ptr, ptr + size));
    return BLOCK_OK;
}

int CacheDataBlock::PutString(uint32_t row, uint32_t column, const char *value, size_t size)
{
    if (isFull_) {
        return BLOCK_OK;
    }
    if (row >= rows_.size() || column >= static_cast<uint32_t>(colCount_) || value == nullptr) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheDataBlock"
                  " which has %{public}zu rows, %{public}d columns.", row, column, rows_.size(), colCount_);
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    if (size < 1) {
        rows_[row].emplace_back("");
        return BLOCK_OK;
    }
    rows_[row].emplace_back(value);
    return BLOCK_OK;
}

int CacheDataBlock::PutAsset(uint32_t row, uint32_t column, const void *value, size_t size)
{
    if (isFull_) {
        return BLOCK_OK;
    }
    if (row >= rows_.size() || column >= static_cast<uint32_t>(colCount_) || value == nullptr) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheDataBlock"
                  " which has %{public}zu rows, %{public}d columns.", row, column, rows_.size(), colCount_);
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    ValueObject::Asset asset;
    auto dataLen = RawDataParser::ParserRawData(static_cast<const uint8_t *>(value), size, asset);
    if (dataLen == 0) {
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    rows_[row].emplace_back(std::move(asset));
    return BLOCK_OK;
}

int CacheDataBlock::PutAssets(uint32_t row, uint32_t column, const void *value, size_t size)
{
    if (isFull_) {
        return BLOCK_OK;
    }
    if (row >= rows_.size() || column >= static_cast<uint32_t>(colCount_) || value == nullptr) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheDataBlock"
                  " which has %{public}zu rows, %{public}d columns.", row, column, rows_.size(), colCount_);
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    ValueObject::Assets assets;
    auto dataLen = RawDataParser::ParserRawData(static_cast<const uint8_t *>(value), size, assets);
    if (dataLen == 0) {
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    rows_[row].emplace_back(std::move(assets));
    return BLOCK_OK;
}

int CacheDataBlock::PutFloats(uint32_t row, uint32_t column, const void *value, size_t size)
{
    if (isFull_) {
        return BLOCK_OK;
    }
    if (row >= rows_.size() || column >= static_cast<uint32_t>(colCount_) || value == nullptr) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheDataBlock"
                  " which has %{public}zu rows, %{public}d columns.", row, column, rows_.size(), colCount_);
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    std::vector<float> floats;
    auto dataLen = RawDataParser::ParserRawData(static_cast<const uint8_t *>(value), size, floats);
    if (dataLen == 0) {
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    rows_[row].emplace_back(std::move(floats));
    return BLOCK_OK;
}

int CacheDataBlock::PutBigInt(uint32_t row, uint32_t column, const void *value, size_t size)
{
    if (isFull_) {
        return BLOCK_OK;
    }
    if (row >= rows_.size() || column >= static_cast<uint32_t>(colCount_) || value == nullptr) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheDataBlock"
                  " which has %{public}zu rows, %{public}d columns.", row, column, rows_.size(), colCount_);
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    ValueObject::BigInt bigint;
    auto dataLen = RawDataParser::ParserRawData(static_cast<const uint8_t *>(value), size, bigint);
    if (dataLen == 0) {
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    rows_[row].emplace_back(std::move(bigint));
    return BLOCK_OK;
}

int CacheDataBlock::PutLong(uint32_t row, uint32_t column, int64_t value)
{
    if (isFull_) {
        return BLOCK_OK;
    }
    if (row >= rows_.size() || column >= static_cast<uint32_t>(colCount_)) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheDataBlock"
                  " which has %{public}zu rows, %{public}d columns.", row, column, rows_.size(), colCount_);
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    rows_[row].emplace_back(value);
    return BLOCK_OK;
}

int CacheDataBlock::PutDouble(uint32_t row, uint32_t column, double value)
{
    if (isFull_) {
        return BLOCK_OK;
    }
    if (row >= rows_.size() || column >= static_cast<uint32_t>(colCount_)) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheDataBlock"
                  " which has %{public}zu rows, %{public}d columns.", row, column, rows_.size(), colCount_);
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    rows_[row].emplace_back(value);
    return BLOCK_OK;
}

int CacheDataBlock::PutNull(uint32_t row, uint32_t column)
{
    if (isFull_) {
        return BLOCK_OK;
    }
    if (row >= rows_.size() || column >= static_cast<uint32_t>(colCount_)) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheDataBlock"
                  " which has %{public}zu rows, %{public}d columns.", row, column, rows_.size(), colCount_);
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    rows_[row].emplace_back(ValueObject());
    return BLOCK_OK;
}

bool CacheDataBlock::HasException()
{
    return hasException_;
}

std::vector<std::vector<NativeRdb::ValueObject>> CacheDataBlock::StealRows()
{
    return std::move(rows_);
}
} // namespace AppDataFwk
} // namespace OHOS
