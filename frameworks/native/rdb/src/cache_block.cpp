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
#define LOG_TAG "CacheBlock"
#include "cache_block.h"

#include <string>
#include <vector>

#include "logger.h"
#include "raw_data_parser.h"
#include "values_bucket.h"
namespace OHOS {
using namespace NativeRdb;
using namespace Rdb;
namespace AppDataFwk {

CacheBlock::CacheBlock(int32_t maxCount, const std::vector<std::string> &columns)
    : columns_(columns), maxCount_(maxCount)
{
}
CacheBlock::~CacheBlock()
{
    rows_.clear();
}

int CacheBlock::CacheBlock::Clear()
{
    rows_.clear();
    return BLOCK_OK;
}

int CacheBlock::SetColumnNum(uint32_t numColumns)
{
    return BLOCK_OK;
}

int CacheBlock::AllocRow()
{
    if (rows_.size() >= static_cast<size_t>(maxCount_)) {
        isFull_ = true;
        return BLOCK_OK;
    }
    rows_.push_back(ValuesBucket());
    return BLOCK_OK;
}

int CacheBlock::FreeLastRow()
{
    if (!rows_.empty()) {
        rows_.pop_back();
    }
    return BLOCK_OK;
}

int CacheBlock::PutBlob(uint32_t row, uint32_t column, const void *value, size_t size)
{
    if (isFull_) {
        return BLOCK_OK;
    }

    if (row >= rows_.size() || column >= columns_.size() || value == nullptr) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheBlock"
                  " which has %{public}zu rows, %{public}zu columns.",
            row, column, rows_.size(), columns_.size());
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    const uint8_t *ptr = static_cast<const uint8_t *>(value);
    rows_[row].Put(columns_[column], std::vector<uint8_t>(ptr, ptr + size));
    return BLOCK_OK;
}

int CacheBlock::PutString(uint32_t row, uint32_t column, const char *value, size_t size)
{
    if (isFull_) {
        return BLOCK_OK;
    }
    if (row >= rows_.size() || column >= columns_.size() || value == nullptr) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheBlock"
                  " which has %{public}zu rows, %{public}zu columns.",
            row, column, rows_.size(), columns_.size());
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    if (size < 1) {
        rows_[row].PutString(columns_[column], "");
        return BLOCK_OK;
    }
    rows_[row].Put(columns_[column], value);
    return BLOCK_OK;
}

int CacheBlock::PutAsset(uint32_t row, uint32_t column, const void *value, size_t size)
{
    if (isFull_) {
        return BLOCK_OK;
    }
    if (row >= rows_.size() || column >= columns_.size() || value == nullptr) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheBlock"
                  " which has %{public}zu rows, %{public}zu columns.",
            row, column, rows_.size(), columns_.size());
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    ValueObject::Asset asset;
    auto dataLen = RawDataParser::ParserRawData(static_cast<const uint8_t *>(value), size, asset);
    if (dataLen == 0) {
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    rows_[row].Put(columns_[column], std::move(asset));
    return BLOCK_OK;
}

int CacheBlock::PutAssets(uint32_t row, uint32_t column, const void *value, size_t size)
{
    if (isFull_) {
        return BLOCK_OK;
    }
    if (row >= rows_.size() || column >= columns_.size() || value == nullptr) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheBlock"
                  " which has %{public}zu rows, %{public}zu columns.",
            row, column, rows_.size(), columns_.size());
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    ValueObject::Assets assets;
    auto dataLen = RawDataParser::ParserRawData(static_cast<const uint8_t *>(value), size, assets);
    if (dataLen == 0) {
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    rows_[row].Put(columns_[column], std::move(assets));
    return BLOCK_OK;
}

int CacheBlock::PutFloats(uint32_t row, uint32_t column, const void *value, size_t size)
{
    if (isFull_) {
        return BLOCK_OK;
    }
    if (row >= rows_.size() || column >= columns_.size() || value == nullptr) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheBlock"
                  " which has %{public}zu rows, %{public}zu columns.",
            row, column, rows_.size(), columns_.size());
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    std::vector<float> floats;
    auto dataLen = RawDataParser::ParserRawData(static_cast<const uint8_t *>(value), size, floats);
    if (dataLen == 0) {
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    rows_[row].Put(columns_[column], std::move(floats));
    return BLOCK_OK;
}

int CacheBlock::PutBigInt(uint32_t row, uint32_t column, const void *value, size_t size)
{
    if (isFull_) {
        return BLOCK_OK;
    }
    if (row >= rows_.size() || column >= columns_.size() || value == nullptr) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheBlock"
                  " which has %{public}zu rows, %{public}zu columns.",
            row, column, rows_.size(), columns_.size());
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    ValueObject::BigInt bigint;
    auto dataLen = RawDataParser::ParserRawData(static_cast<const uint8_t *>(value), size, bigint);
    if (dataLen == 0) {
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    rows_[row].Put(columns_[column], std::move(bigint));
    return BLOCK_OK;
}

int CacheBlock::PutLong(uint32_t row, uint32_t column, int64_t value)
{
    if (isFull_) {
        return BLOCK_OK;
    }
    if (row >= rows_.size() || column >= columns_.size()) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheBlock"
                  " which has %{public}zu rows, %{public}zu columns.",
            row, column, rows_.size(), columns_.size());
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    rows_[row].PutLong(columns_[column], value);
    return BLOCK_OK;
}

int CacheBlock::PutDouble(uint32_t row, uint32_t column, double value)
{
    if (isFull_) {
        return BLOCK_OK;
    }
    if (row >= rows_.size() || column >= columns_.size()) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheBlock"
                  " which has %{public}zu rows, %{public}zu columns.",
            row, column, rows_.size(), columns_.size());
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    rows_[row].PutDouble(columns_[column], value);
    return BLOCK_OK;
}

int CacheBlock::PutNull(uint32_t row, uint32_t column)
{
    if (isFull_) {
        return BLOCK_OK;
    }
    if (row >= rows_.size() || column >= columns_.size()) {
        LOG_ERROR("Failed to put row %{public}" PRIu32 ", column %{public}" PRIu32 " to a CacheBlock"
                  " which has %{public}zu rows, %{public}zu columns.",
            row, column, rows_.size(), columns_.size());
        hasException_ = true;
        return BLOCK_BAD_VALUE;
    }
    rows_[row].PutNull(columns_[column]);
    return BLOCK_OK;
}

bool CacheBlock::HasException()
{
    return hasException_;
}

std::vector<NativeRdb::ValuesBucket> CacheBlock::StealRows()
{
    return std::move(rows_);
}
} // namespace AppDataFwk
} // namespace OHOS
