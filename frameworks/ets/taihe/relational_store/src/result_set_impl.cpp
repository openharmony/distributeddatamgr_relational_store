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

#include "result_set_impl.h"

#include "napi_rdb_error.h"
#include "ohos.data.relationalStore.impl.h"
#include "ohos.data.relationalStore.proj.hpp"
#include "rdb_errno.h"

namespace OHOS {
namespace RdbTaihe {

ResultSetImpl::ResultSetImpl()
{
}

ResultSetImpl::ResultSetImpl(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet)
{
    nativeResultSet_ = resultSet;
    proxy_ = std::make_shared<ResultSetProxy>(resultSet);
    SetResource(resultSet);
}

int64_t ResultSetImpl::GetProxy()
{
    return reinterpret_cast<int64_t>(proxy_.get());
}

array<string> ResultSetImpl::GetAllColumnNames()
{
    std::vector<std::string> colNames;
    if (nativeResultSet_ != nullptr) {
        nativeResultSet_->GetAllColumnNames(colNames);
    }
    return array<string>(::taihe::copy_data_t{}, colNames.data(), colNames.size());
}

array<string> ResultSetImpl::GetColumnNames()
{
    auto resultSet = GetResource();
    ASSERT_RETURN_THROW_ERROR(
        resultSet != nullptr, std::make_shared<InnerErrorExt>(OHOS::NativeRdb::E_ALREADY_CLOSED), {});
    auto [errCode, colNames] = resultSet->GetWholeColumnNames();
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode, resultSet->GetLastErrorMsg());
        return {};
    }
    return array<string>(::taihe::copy_data_t{}, colNames.data(), colNames.size());
}

int32_t ResultSetImpl::GetColumnCount()
{
    int32_t count = 0;
    if (nativeResultSet_ != nullptr) {
        nativeResultSet_->GetColumnCount(count);
    }
    return count;
}

int32_t ResultSetImpl::GetRowCount()
{
    if (nativeResultSet_ == nullptr) {
        return -1;
    }
    int32_t rowCount = 0;
    nativeResultSet_->GetRowCount(rowCount);
    return rowCount;
}

int32_t ResultSetImpl::GetRowIndex()
{
    int32_t rowIndex = -1;
    if (nativeResultSet_ != nullptr) {
        nativeResultSet_->GetRowIndex(rowIndex);
    }
    return rowIndex;
}

bool ResultSetImpl::GetIsAtFirstRow()
{
    bool isAtFirstRow = false;
    if (nativeResultSet_ != nullptr) {
        nativeResultSet_->IsAtFirstRow(isAtFirstRow);
    }
    return isAtFirstRow;
}

bool ResultSetImpl::GetIsAtLastRow()
{
    bool isAtLastRow = false;
    if (nativeResultSet_ != nullptr) {
        nativeResultSet_->IsAtLastRow(isAtLastRow);
    }
    return isAtLastRow;
}

bool ResultSetImpl::GetIsEnded()
{
    bool isEnded = true;
    if (nativeResultSet_ != nullptr) {
        nativeResultSet_->IsEnded(isEnded);
    }
    return isEnded;
}

bool ResultSetImpl::GetIsStarted()
{
    bool isStarted = false;
    if (nativeResultSet_ != nullptr) {
        nativeResultSet_->IsStarted(isStarted);
    }
    return isStarted;
}

bool ResultSetImpl::GetIsClosed()
{
    return nativeResultSet_ == nullptr;
}

int32_t ResultSetImpl::GetColumnIndex(string_view columnName)
{
    int32_t result = -1;
    int errCode = OHOS::NativeRdb::E_OK;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GetColumnIndex(std::string(columnName), result);
    }
    return result;
}

string ResultSetImpl::GetColumnName(int32_t columnIndex)
{
    std::string result;
    int errCode = OHOS::NativeRdb::E_OK;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GetColumnName(columnIndex, result);
    }
    return string(result);
}

uintptr_t ResultSetImpl::GetColumnTypeSync(ohos::data::relationalStore::ColumnIdentifier const &columnIdentifier)
{
    auto resultSet = GetResource();
    OHOS::DistributedRdb::ColumnType columnType = OHOS::DistributedRdb::ColumnType::TYPE_NULL;
    ASSERT_RETURN_THROW_ERROR(resultSet != nullptr, std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), 0);
    int32_t columnIndex = 0;
    int errCode = OHOS::NativeRdb::E_OK;
    if (columnIdentifier.holds_columnIndex()) {
        columnIndex = columnIdentifier.get_columnIndex_ref();
        ASSERT_RETURN_THROW_ERROR(columnIndex >= 0, std::make_shared<ParamError>("Invalid columnIndex"), 0);
    } else {
        std::string columnName(columnIdentifier.get_columnName_ref());
        ASSERT_RETURN_THROW_ERROR(
            !columnName.empty(), std::make_shared<ParamError>("columnName", "a non empty string."), 0);
        errCode = resultSet->GetColumnIndex(columnName, columnIndex);
    }
    if (errCode == OHOS::NativeRdb::E_OK) {
        errCode = resultSet->GetColumnType(columnIndex, columnType);
    }
    if (errCode == NativeRdb::E_INVALID_ARGS) {
        errCode = E_PARAM_ERROR;
    }
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode, resultSet->GetLastErrorMsg());
        return 0;
    }
    return ani_rdbutils::ColumnTypeToTaihe(columnType);
}

bool ResultSetImpl::GoTo(int32_t offset)
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GoTo(offset);
    }
    return errCode == OHOS::NativeRdb::E_OK;
}

bool ResultSetImpl::GoToRow(int32_t position)
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GoToRow(position);
    }
    return errCode == OHOS::NativeRdb::E_OK;
}

bool ResultSetImpl::GoToFirstRow()
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GoToFirstRow();
    }
    return errCode == OHOS::NativeRdb::E_OK;
}

bool ResultSetImpl::GoToLastRow()
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GoToLastRow();
    }
    return errCode == OHOS::NativeRdb::E_OK;
}

bool ResultSetImpl::GoToNextRow()
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GoToNextRow();
    }
    return errCode == OHOS::NativeRdb::E_OK;
}

bool ResultSetImpl::GoToPreviousRow()
{
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (nativeResultSet_ != nullptr) {
        errCode = nativeResultSet_->GoToPreviousRow();
    }
    return errCode == OHOS::NativeRdb::E_OK;
}

array<uint8_t> ResultSetImpl::GetBlob(int32_t columnIndex)
{
    auto resultSet = GetResource();
    ASSERT_RETURN_THROW_ERROR(
        resultSet != nullptr, std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), {});
    std::vector<uint8_t> result;
    int errCode = resultSet->GetBlob(columnIndex, result);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode, resultSet->GetLastErrorMsg());
    }
    return array<uint8_t>(::taihe::copy_data_t{}, result.data(), result.size());
}

string ResultSetImpl::GetString(int32_t columnIndex)
{
    auto resultSet = GetResource();
    std::string result;
    ASSERT_RETURN_THROW_ERROR(
        resultSet != nullptr, std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), result);
    int errCode = resultSet->GetString(columnIndex, result);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode, resultSet->GetLastErrorMsg());
    }
    return string(result);
}

int64_t ResultSetImpl::GetLong(int32_t columnIndex)
{
    auto resultSet = GetResource();
    int64_t result = 0;
    ASSERT_RETURN_THROW_ERROR(
        resultSet != nullptr, std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), result);
    int errCode = resultSet->GetLong(columnIndex, result);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode, resultSet->GetLastErrorMsg());
    }
    return result;
}

double ResultSetImpl::GetDouble(int32_t columnIndex)
{
    double result = 0.0;
    auto resultSet = GetResource();
    ASSERT_RETURN_THROW_ERROR(
        resultSet != nullptr, std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), result);
    int errCode = resultSet->GetDouble(columnIndex, result);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode, resultSet->GetLastErrorMsg());
    }
    return result;
}

ohos::data::relationalStore::Asset ResultSetImpl::GetAsset(int32_t columnIndex)
{
    auto resultSet = GetResource();
    OHOS::NativeRdb::AssetValue result;
    ohos::data::relationalStore::Asset aniret = {};
    ASSERT_RETURN_THROW_ERROR(
        resultSet != nullptr, std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), aniret);
    int errCode = resultSet->GetAsset(columnIndex, result);
    if (errCode == OHOS::NativeRdb::E_NULL_OBJECT) {
        return aniret;
    } else if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode, resultSet->GetLastErrorMsg());
    }
    return ani_rdbutils::AssetToAni(result);
}

array<ohos::data::relationalStore::Asset> ResultSetImpl::GetAssets(int32_t columnIndex)
{
    auto resultSet = GetResource();
    std::vector<OHOS::NativeRdb::AssetValue> result;
    ASSERT_RETURN_THROW_ERROR(
        resultSet != nullptr, std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), {});
    int errCode = resultSet->GetAssets(columnIndex, result);
    if (errCode == OHOS::NativeRdb::E_NULL_OBJECT) {
        return {};
    } else if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode, resultSet->GetLastErrorMsg());
        return {};
    }
    std::vector<ohos::data::relationalStore::Asset> resultTemp;
    std::transform(result.begin(), result.end(), std::back_inserter(resultTemp),
        [](const OHOS::NativeRdb::AssetValue &asset) { return ani_rdbutils::AssetToAni(asset); });
    return array<ohos::data::relationalStore::Asset>(::taihe::copy_data_t{}, resultTemp.data(), resultTemp.size());
}

ValueType ResultSetImpl::GetValue(int32_t columnIndex)
{
    auto resultSet = GetResource();
    OHOS::NativeRdb::ValueObject object;
    ASSERT_RETURN_THROW_ERROR(resultSet != nullptr, std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED),
        ani_rdbutils::ValueObjectToAni(object));
    int errCode = resultSet->Get(columnIndex, object);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode, resultSet->GetLastErrorMsg());
    }
    return ani_rdbutils::ValueObjectToAni(object);
}

array<float> ResultSetImpl::GetFloat32Array(int32_t columnIndex)
{
    auto resultSet = GetResource();
    std::vector<float> result = {};
    ASSERT_RETURN_THROW_ERROR(
        resultSet != nullptr, std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), {});
    int errCode = resultSet->GetFloat32Array(columnIndex, result);
    if (errCode == OHOS::NativeRdb::E_NULL_OBJECT) {
        return {};
    } else if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode, resultSet->GetLastErrorMsg());
        return {};
    }
    return array<float>(::taihe::copy_data_t{}, result.data(), result.size());
}

map<string, ValueType> ResultSetImpl::GetRow()
{
    auto resultSet = GetResource();
    OHOS::NativeRdb::RowEntity rowEntity;
    map<string, ValueType> aniMap;
    ASSERT_RETURN_THROW_ERROR(
        resultSet != nullptr, std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), aniMap);
    int errCode = resultSet->GetRow(rowEntity);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode, resultSet->GetLastErrorMsg());
        return aniMap;
    }
    const std::map<std::string, OHOS::NativeRdb::ValueObject> &rowMap = rowEntity.Get();
    for (auto const &[key, value] : rowMap) {
        aniMap.emplace(string(key), ani_rdbutils::ValueObjectToAni(value));
    }
    return aniMap;
}

taihe::array<ohos::data::relationalStore::ValuesBucket> ResultSetImpl::GetRowsSync(
    int32_t maxCount, taihe::optional_view<int32_t> position)
{
    auto resultSet = GetResource();
    if (maxCount < 0) {
        ThrowParamError("Invalid maxCount");
        return {};
    }
    int positionNative = INIT_POSITION;
    if (position.has_value()) {
        if (position.value() < 0) {
            ThrowParamError("invalid position");
            return {};
        }
        positionNative = position.value();
    }
    ASSERT_RETURN_THROW_ERROR(
        resultSet != nullptr, std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), {});
    auto [errCode, rowEntities] = ani_rdbutils::GetRows(*resultSet, maxCount, positionNative);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode, resultSet->GetLastErrorMsg());
        return {};
    }
    std::vector<ohos::data::relationalStore::ValuesBucket> res;
    for (size_t i = 0; i < rowEntities.size(); ++i) {
        OHOS::NativeRdb::ValuesBucket bucket(rowEntities[i].Get());
        res.push_back(ani_rdbutils::ValuesBucketToAni(bucket));
    }

    return taihe::array<ohos::data::relationalStore::ValuesBucket>(res);
}

array<ohos::data::relationalStore::ValueType> ResultSetImpl::GetCurrentRowData()
{
    auto resultSet = GetResource();
    ASSERT_RETURN_THROW_ERROR(
        resultSet != nullptr, std::make_shared<InnerErrorExt>(OHOS::NativeRdb::E_ALREADY_CLOSED), {});
    auto [errCode, rowData] = resultSet->GetRowData();
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode, resultSet->GetLastErrorMsg());
        return {};
    }
    std::vector<ValueType> rowDataTemp;
    std::transform(rowData.begin(), rowData.end(), std::back_inserter(rowDataTemp),
        [](const OHOS::NativeRdb::ValueObject &object) { return ani_rdbutils::ValueObjectToAni(object); });
    return array<ValueType>(::taihe::copy_data_t{}, rowDataTemp.data(), rowDataTemp.size());
}

array<array<ValueType>> ResultSetImpl::GetRowsDataSync(int32_t maxCount, optional_view<int32_t> position)
{
    auto resultSet = GetResource();
    if (maxCount <= 0) {
        ThrowInnerError(OHOS::NativeRdb::E_INVALID_ARGS_NEW);
        return {};
    }
    int32_t nativePosition = INIT_POSITION;
    if (position.has_value()) {
        nativePosition = position.value();
        if (nativePosition < 0) {
            ThrowInnerError(OHOS::NativeRdb::E_INVALID_ARGS_NEW);
            return {};
        }
    }
    ASSERT_RETURN_THROW_ERROR(
        resultSet != nullptr, std::make_shared<InnerErrorExt>(OHOS::NativeRdb::E_ALREADY_CLOSED), {});
    auto [errCode, rowsData] = resultSet->GetRowsData(maxCount, nativePosition);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerErrorExt(errCode, resultSet->GetLastErrorMsg());
        return {};
    }
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

bool ResultSetImpl::IsColumnNull(int32_t columnIndex)
{
    auto resultSet = GetResource();
    bool result = false;
    ASSERT_RETURN_THROW_ERROR(
        resultSet != nullptr, std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), result);
    int errCode = resultSet->IsColumnNull(columnIndex, result);
    if (errCode != OHOS::NativeRdb::E_OK) {
        ThrowInnerError(errCode, resultSet->GetLastErrorMsg());
    }
    return result;
}

void ResultSetImpl::Close()
{
    ResetResource();
    nativeResultSet_ = nullptr;
    proxy_ = nullptr;
}
} // namespace RdbTaihe
} // namespace OHOS