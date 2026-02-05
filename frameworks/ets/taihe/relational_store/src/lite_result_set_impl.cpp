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

#define LOG_TAG "LiteResultSetImpl"
#include "lite_result_set_impl.h"
#include "ohos.data.relationalStore.impl.h"
#include "ohos.data.relationalStore.proj.hpp"

namespace OHOS {
namespace RdbTaihe {

LiteResultSetImpl::LiteResultSetImpl()
{
}

LiteResultSetImpl::LiteResultSetImpl(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet)
{
    nativeResultSet_ = resultSet;
    proxy_ = std::make_shared<LiteResultSetProxy>(resultSet);
    SetResource(resultSet);
}

intptr_t LiteResultSetImpl::GetProxy()
{
    return reinterpret_cast<intptr_t>(proxy_.get());
}

array<ohos::data::relationalStore::ValuesBucket> LiteResultSetImpl::GetRowsSync(int32_t maxCount,
    optional_view<int32_t> position)
{
    auto resultSet = GetResource();
    if (maxCount <= 0) {
        LOG_ERROR("invalid maxCount");
        ThrowInnerError(OHOS::NativeRdb::E_INVALID_ARGS_NEW);
        return {};
    }
    int positionNative = INIT_POSITION;
    if (position.has_value()) {
        if (position.value() < 0) {
            LOG_ERROR("invalid position");
            ThrowInnerError(OHOS::NativeRdb::E_INVALID_ARGS_NEW);
            return {};
        }
        positionNative = position.value();
    }
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    std::vector<OHOS::NativeRdb::RowEntity> rowEntities;

    if (resultSet != nullptr) {
        std::tie(errCode, rowEntities) = ani_rdbutils::GetRows(*resultSet, maxCount, positionNative);
    }
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode);
        return {};
    }
    std::vector<ohos::data::relationalStore::ValuesBucket> valuesBuckets;
    for (size_t  i = 0; i < rowEntities.size(); ++i) {
        map<string, ValueType> aniMap;
        const std::map<std::string, OHOS::NativeRdb::ValueObject> &rowMap = rowEntities[i].Get();
        for (auto const &[key, value] : rowMap) {
            aniMap.emplace(string(key), ani_rdbutils::ValueObjectToAni(value));
        }
        OHOS::NativeRdb::ValuesBucket bucket = ani_rdbutils::MapValuesToNative(aniMap);
        valuesBuckets.push_back(ani_rdbutils::ValuesBucketToAni(bucket));
    }

    return array<ohos::data::relationalStore::ValuesBucket>(valuesBuckets);
}

int32_t LiteResultSetImpl::GetColumnIndex(string_view columnName)
{
    int32_t result = -1;
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GetColumnIndex(std::string(columnName), result);
    }
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode);
    }
    return result;
}

uintptr_t LiteResultSetImpl::GetColumnTypeSync(ohos::data::relationalStore::ColumnIdentifier const& columnIdentifier)
{
    auto resultSet = GetResource();
    OHOS::DistributedRdb::ColumnType columnType = OHOS::DistributedRdb::ColumnType::TYPE_NULL;
    ASSERT_RETURN_THROW_ERROR(resultSet != nullptr,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), 0);
    int32_t columnIndex = 0;
    int errCode = OHOS::NativeRdb::E_OK;
    if (columnIdentifier.holds_columnIndex()) {
        columnIndex = columnIdentifier.get_columnIndex_ref();
        ASSERT_RETURN_THROW_ERROR(columnIndex >= 0,
            std::make_shared<ParamError>("Invalid columnIndex"), 0);
    } else {
        std::string columnName(columnIdentifier.get_columnName_ref());
        ASSERT_RETURN_THROW_ERROR(!columnName.empty(),
            std::make_shared<ParamError>("columnName", "a non empty string."), 0);
        errCode = resultSet->GetColumnIndex(columnName, columnIndex);
    }
    if (errCode == OHOS::NativeRdb::E_OK) {
        errCode = resultSet->GetColumnType(columnIndex, columnType);
    }
    if (errCode == NativeRdb::E_INVALID_ARGS) {
        errCode = E_PARAM_ERROR;
    }
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode);
        return 0;
    }
    return ani_rdbutils::ColumnTypeToTaihe(columnType);
}

string LiteResultSetImpl::GetColumnName(int32_t columnIndex)
{
    std::string result;
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GetColumnName(columnIndex, result);
    }
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode);
    }
    return string(result);
}

bool LiteResultSetImpl::GoToNextRow()
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GoToNextRow();
    }
    if (errCode != OHOS::NativeRdb::E_ROW_OUT_RANGE && errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode);
    }
    return errCode == OHOS::NativeRdb::E_OK;
}

array<uint8_t> LiteResultSetImpl::GetBlob(int32_t columnIndex)
{
    std::vector<uint8_t> result;
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GetBlob(columnIndex, result);
    }
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode);
    }
    return array<uint8_t>(::taihe::copy_data_t{}, result.data(), result.size());
}

string LiteResultSetImpl::GetString(int32_t columnIndex)
{
    std::string result = "";
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GetString(columnIndex, result);
    }
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode);
    }
    return string(result);
}

int64_t LiteResultSetImpl::GetLong(int32_t columnIndex)
{
    int64_t result = 0;
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GetLong(columnIndex, result);
    }
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode);
    }
    return result;
}

double LiteResultSetImpl::GetDouble(int32_t columnIndex)
{
    double result = 0.0;
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GetDouble(columnIndex, result);
    }
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode);
    }
    return result;
}

ohos::data::relationalStore::Asset LiteResultSetImpl::GetAsset(int32_t columnIndex)
{
    OHOS::NativeRdb::AssetValue result;
    ohos::data::relationalStore::Asset aniret = {};
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GetAsset(columnIndex, result);
    }
    if (errCode == OHOS::NativeRdb::E_NULL_OBJECT) {
        return aniret;
    } else if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode);
    }
    return ani_rdbutils::AssetToAni(result);
}

array<ohos::data::relationalStore::Asset> LiteResultSetImpl::GetAssets(int32_t columnIndex)
{
    std::vector<OHOS::NativeRdb::AssetValue> result;
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GetAssets(columnIndex, result);
    }
    if (errCode == OHOS::NativeRdb::E_NULL_OBJECT) {
        return {};
    } else if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode);
        return {};
    }
    std::vector<ohos::data::relationalStore::Asset> resultTemp;
    std::transform(result.begin(), result.end(), std::back_inserter(resultTemp),
        [](const OHOS::NativeRdb::AssetValue &asset) { return ani_rdbutils::AssetToAni(asset); });
    return array<ohos::data::relationalStore::Asset>(::taihe::copy_data_t{}, resultTemp.data(), resultTemp.size());
}

ValueType LiteResultSetImpl::GetValue(int32_t columnIndex)
{
    OHOS::NativeRdb::ValueObject object;
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->Get(columnIndex, object);
    }
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode);
    }
    return ani_rdbutils::ValueObjectToAni(object);
}

array<float> LiteResultSetImpl::GetFloat32Array(int32_t columnIndex)
{
    std::vector<float> result = {};
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GetFloat32Array(columnIndex, result);
    }
    if (errCode == OHOS::NativeRdb::E_NULL_OBJECT) {
        return {};
    } else if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode);
        return {};
    }
    return array<float>(::taihe::copy_data_t{}, result.data(), result.size());
}

ohos::data::relationalStore::ValuesBucket LiteResultSetImpl::GetRow()
{
    OHOS::NativeRdb::RowEntity rowEntity;
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GetRow(rowEntity);
    }
    map<string, ValueType> aniMap;
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode);
        return ani_rdbutils::ValuesBucketToAni(ani_rdbutils::MapValuesToNative(aniMap));
    }
    const std::map<std::string, OHOS::NativeRdb::ValueObject> &rowMap = rowEntity.Get();
    for (auto const &[key, value] : rowMap) {
        aniMap.emplace(string(key), ani_rdbutils::ValueObjectToAni(value));
    }
    return ani_rdbutils::ValuesBucketToAni(ani_rdbutils::MapValuesToNative(aniMap));
}

bool LiteResultSetImpl::IsColumnNull(int32_t columnIndex)
{
    bool result = false;
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->IsColumnNull(columnIndex, result);
    }
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode);
    }
    return result;
}

void LiteResultSetImpl::Close()
{
    ResetResource();
    nativeResultSet_ = nullptr;
    proxy_ = nullptr;
}

array<string> LiteResultSetImpl::GetColumnNames()
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    std::vector<std::string> colNames;
    if (nativeResultSet_ != nullptr) {
        std::tie(errCode, colNames) = nativeResultSet_->GetWholeColumnNames();
    }
    ASSERT_RETURN_THROW_ERROR(errCode == OHOS::NativeRdb::E_OK,
        std::make_shared<OHOS::RelationalStoreJsKit::InnerErrorExt>(errCode), {});
    return array<string>(::taihe::copy_data_t{}, colNames.data(), colNames.size());
}

array<ohos::data::relationalStore::ValueType> LiteResultSetImpl::GetCurrentRowData()
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    std::vector<OHOS::NativeRdb::ValueObject> rowData;
    if (nativeResultSet_ != nullptr) {
        std::tie(errCode, rowData) = nativeResultSet_->GetRowData();
    }
    ASSERT_RETURN_THROW_ERROR(errCode == OHOS::NativeRdb::E_OK,
        std::make_shared<OHOS::RelationalStoreJsKit::InnerErrorExt>(errCode), {});
    std::vector<ValueType> rowDataTemp;
    std::transform(rowData.begin(), rowData.end(), std::back_inserter(rowDataTemp),
        [](const OHOS::NativeRdb::ValueObject &object) { return ani_rdbutils::ValueObjectToAni(object); });
    return array<ValueType>(::taihe::copy_data_t{}, rowDataTemp.data(), rowDataTemp.size());
}

array<array<ValueType>> LiteResultSetImpl::GetRowsDataSync(int32_t maxCount, optional_view<int32_t> position)
{
    auto resultSet = GetResource();
    ASSERT_RETURN_THROW_ERROR(maxCount > 0,
        std::make_shared<InnerErrorExt>(OHOS::NativeRdb::E_INVALID_ARGS_NEW, "Invalid maxCount"), {});
    int32_t nativePosition = INIT_POSITION;
    if (position.has_value()) {
        nativePosition = position.value();
        ASSERT_RETURN_THROW_ERROR(nativePosition >= 0,
            std::make_shared<InnerErrorExt>(OHOS::NativeRdb::E_INVALID_ARGS_NEW, "position is invalid."), {});
    }

    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    std::vector<std::vector<ValueObject>> rowsData;
    if (resultSet != nullptr) {
        std::tie(errCode, rowsData) = resultSet->GetRowsData(maxCount, nativePosition);
    }
    ASSERT_RETURN_THROW_ERROR(errCode == OHOS::NativeRdb::E_OK,
        std::make_shared<OHOS::RelationalStoreJsKit::InnerErrorExt>(errCode), {});

    std::vector<std::vector<ValueType>> rowsDataTemp;
    rowsDataTemp.reserve(rowsData.size());
    for (const auto &rowData : rowsData) {
        std::vector<ValueType> rowDataTemp;
        std::transform(rowData.begin(), rowData.end(), std::back_inserter(rowDataTemp),
            [](const ValueObject &object) { return ani_rdbutils::ValueObjectToAni(object); });
        rowsDataTemp.push_back(std::move(rowDataTemp));
    }

    return array<array<ValueType>>(::taihe::copy_data_t{}, rowsDataTemp.data(), rowsDataTemp.size());
}
}
}