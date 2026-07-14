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
    proxy_ = std::make_shared<ResultSetProxy>(resultSet);
    SetResource(resultSet);
}

int64_t ResultSetImpl::GetProxy()
{
    return reinterpret_cast<int64_t>(proxy_.get());
}

array<string> ResultSetImpl::GetAllColumnNames()
{
    auto resultSet = GetResource();
    std::vector<std::string> colNames;
    if (resultSet != nullptr) {
        resultSet->GetAllColumnNames(colNames);
    }
    return array<string>(::taihe::copy_data_t{}, colNames.data(), colNames.size());
}

array<string> ResultSetImpl::GetColumnNames()
{
    auto resultSet = GetResource();
    ASSERT_THROW_INNER_ERROR_EXT(resultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "", {});
    auto [errCode, colNames] = resultSet->GetWholeColumnNames();
    CHECK_ERRCODE_THROW_INNER_ERROR_EXT(errCode, resultSet->GetLastErrorMsg(),
        array<string>(::taihe::copy_data_t{}, colNames.data(), colNames.size()));
    return array<string>(::taihe::copy_data_t{}, colNames.data(), colNames.size());
}

int32_t ResultSetImpl::GetColumnCount()
{
    auto resultSet = GetResource();
    int32_t count = 0;
    if (resultSet != nullptr) {
        resultSet->GetColumnCount(count);
    }
    return count;
}

int32_t ResultSetImpl::GetRowCount()
{
    auto resultSet = GetResource();
    if (resultSet == nullptr) {
        return -1;
    }
    int32_t rowCount = 0;
    resultSet->GetRowCount(rowCount);
    return rowCount;
}

int32_t ResultSetImpl::GetRowIndex()
{
    auto resultSet = GetResource();
    int32_t rowIndex = -1;
    if (resultSet != nullptr) {
        resultSet->GetRowIndex(rowIndex);
    }
    return rowIndex;
}

bool ResultSetImpl::GetIsAtFirstRow()
{
    auto resultSet = GetResource();
    bool isAtFirstRow = false;
    if (resultSet != nullptr) {
        resultSet->IsAtFirstRow(isAtFirstRow);
    }
    return isAtFirstRow;
}

bool ResultSetImpl::GetIsAtLastRow()
{
    auto resultSet = GetResource();
    bool isAtLastRow = false;
    if (resultSet != nullptr) {
        resultSet->IsAtLastRow(isAtLastRow);
    }
    return isAtLastRow;
}

bool ResultSetImpl::GetIsEnded()
{
    auto resultSet = GetResource();
    bool isEnded = true;
    if (resultSet != nullptr) {
        resultSet->IsEnded(isEnded);
    }
    return isEnded;
}

bool ResultSetImpl::GetIsStarted()
{
    auto resultSet = GetResource();
    bool isStarted = false;
    if (resultSet != nullptr) {
        resultSet->IsStarted(isStarted);
    }
    return isStarted;
}

bool ResultSetImpl::GetIsClosed()
{
    return GetResource() == nullptr;
}

int32_t ResultSetImpl::GetColumnIndex(string_view columnName)
{
    auto resultSet = GetResource();
    int32_t result = -1;
    int errCode = OHOS::NativeRdb::E_OK;
    if (resultSet != nullptr) {
        errCode = resultSet->GetColumnIndex(std::string(columnName), result);
    }
    return result;
}

string ResultSetImpl::GetColumnName(int32_t columnIndex)
{
    auto resultSet = GetResource();
    std::string result;
    int errCode = OHOS::NativeRdb::E_OK;
    if (resultSet != nullptr) {
        errCode = resultSet->GetColumnName(columnIndex, result);
    }
    return string(result);
}

uintptr_t ResultSetImpl::GetColumnTypeSync(ohos::data::relationalStore::ColumnIdentifier const &columnIdentifier)
{
    auto resultSet = GetResource();
    OHOS::DistributedRdb::ColumnType columnType = OHOS::DistributedRdb::ColumnType::TYPE_NULL;
    ASSERT_THROW_INNER_ERROR_EXT(resultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "", 0);
    int32_t columnIndex = 0;
    int errCode = OHOS::NativeRdb::E_OK;
    if (columnIdentifier.holds_columnIndex()) {
        columnIndex = columnIdentifier.get_columnIndex_ref();
        ASSERT_THROW_PARAM_ERROR(columnIndex >= 0, "Invalid columnIndex", "", 0);
    } else {
        std::string columnName(columnIdentifier.get_columnName_ref());
        ASSERT_THROW_PARAM_ERROR(!columnName.empty(), "columnName", "a non empty string.", 0);
        errCode = resultSet->GetColumnIndex(columnName, columnIndex);
    }
    if (errCode == OHOS::NativeRdb::E_OK) {
        errCode = resultSet->GetColumnType(columnIndex, columnType);
    }
    if (errCode == NativeRdb::E_INVALID_ARGS) {
        errCode = E_PARAM_ERROR;
    }
    CHECK_ERRCODE_THROW_INNER_ERROR(errCode, resultSet->GetLastErrorMsg(), 0);
    return ani_rdbutils::ColumnTypeToTaihe(columnType);
}

bool ResultSetImpl::GoTo(int32_t offset)
{
    auto resultSet = GetResource();
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GoTo(offset);
    }
    return errCode == OHOS::NativeRdb::E_OK;
}

bool ResultSetImpl::GoToRow(int32_t position)
{
    auto resultSet = GetResource();
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GoToRow(position);
    }
    return errCode == OHOS::NativeRdb::E_OK;
}

bool ResultSetImpl::GoToFirstRow()
{
    auto resultSet = GetResource();
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GoToFirstRow();
    }
    return errCode == OHOS::NativeRdb::E_OK;
}

bool ResultSetImpl::GoToLastRow()
{
    auto resultSet = GetResource();
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GoToLastRow();
    }
    return errCode == OHOS::NativeRdb::E_OK;
}

bool ResultSetImpl::GoToNextRow()
{
    auto resultSet = GetResource();
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GoToNextRow();
    }
    return errCode == OHOS::NativeRdb::E_OK;
}

bool ResultSetImpl::GoToPreviousRow()
{
    auto resultSet = GetResource();
    int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GoToPreviousRow();
    }
    return errCode == OHOS::NativeRdb::E_OK;
}

array<uint8_t> ResultSetImpl::GetBlob(int32_t columnIndex)
{
    auto resultSet = GetResource();
    ASSERT_THROW_INNER_ERROR(resultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "", {});
    std::vector<uint8_t> result;
    int errCode = resultSet->GetBlob(columnIndex, result);
    CHECK_ERRCODE_THROW_INNER_ERROR(
        errCode, resultSet->GetLastErrorMsg(), array<uint8_t>(::taihe::copy_data_t{}, result.data(), result.size()));
    return array<uint8_t>(::taihe::copy_data_t{}, result.data(), result.size());
}

string ResultSetImpl::GetString(int32_t columnIndex)
{
    auto resultSet = GetResource();
    std::string result;
    ASSERT_THROW_INNER_ERROR(resultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "", result);
    int errCode = resultSet->GetString(columnIndex, result);
    CHECK_ERRCODE_THROW_INNER_ERROR(errCode, resultSet->GetLastErrorMsg(), string(result));
    return string(result);
}

int64_t ResultSetImpl::GetLong(int32_t columnIndex)
{
    auto resultSet = GetResource();
    int64_t result = 0;
    ASSERT_THROW_INNER_ERROR(resultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "", result);
    int errCode = resultSet->GetLong(columnIndex, result);
    CHECK_ERRCODE_THROW_INNER_ERROR(errCode, resultSet->GetLastErrorMsg(), result);
    return result;
}

double ResultSetImpl::GetDouble(int32_t columnIndex)
{
    double result = 0.0;
    auto resultSet = GetResource();
    ASSERT_THROW_INNER_ERROR(resultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "", result);
    int errCode = resultSet->GetDouble(columnIndex, result);
    CHECK_ERRCODE_THROW_INNER_ERROR(errCode, resultSet->GetLastErrorMsg(), result);
    return result;
}

ohos::data::relationalStore::Asset ResultSetImpl::GetAsset(int32_t columnIndex)
{
    auto resultSet = GetResource();
    OHOS::NativeRdb::AssetValue result;
    ohos::data::relationalStore::Asset aniret = {};
    ASSERT_THROW_INNER_ERROR(resultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "", aniret);
    int errCode = resultSet->GetAsset(columnIndex, result);
    if (errCode == OHOS::NativeRdb::E_NULL_OBJECT) {
        return aniret;
    } else
        CHECK_ERRCODE_THROW_INNER_ERROR(errCode, resultSet->GetLastErrorMsg(), aniret);
    return ani_rdbutils::AssetToAni(result);
}

array<ohos::data::relationalStore::Asset> ResultSetImpl::GetAssets(int32_t columnIndex)
{
    auto resultSet = GetResource();
    std::vector<OHOS::NativeRdb::AssetValue> result;
    ASSERT_THROW_INNER_ERROR(resultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "", {});
    int errCode = resultSet->GetAssets(columnIndex, result);
    if (errCode == OHOS::NativeRdb::E_NULL_OBJECT) {
        return {};
    } else
        CHECK_ERRCODE_THROW_INNER_ERROR(errCode, resultSet->GetLastErrorMsg(), {});
    std::vector<ohos::data::relationalStore::Asset> resultTemp;
    std::transform(result.begin(), result.end(), std::back_inserter(resultTemp),
        [](const OHOS::NativeRdb::AssetValue &asset) { return ani_rdbutils::AssetToAni(asset); });
    return array<ohos::data::relationalStore::Asset>(::taihe::copy_data_t{}, resultTemp.data(), resultTemp.size());
}

ValueType ResultSetImpl::GetValue(int32_t columnIndex)
{
    auto resultSet = GetResource();
    OHOS::NativeRdb::ValueObject object;
    ASSERT_THROW_INNER_ERROR(
        resultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "", ani_rdbutils::ValueObjectToAni(object));
    int errCode = resultSet->Get(columnIndex, object);
    CHECK_ERRCODE_THROW_INNER_ERROR(errCode, resultSet->GetLastErrorMsg(), ani_rdbutils::ValueObjectToAni(object));
    return ani_rdbutils::ValueObjectToAni(object);
}

array<float> ResultSetImpl::GetFloat32Array(int32_t columnIndex)
{
    auto resultSet = GetResource();
    std::vector<float> result = {};
    ASSERT_THROW_INNER_ERROR(resultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "", {});
    int errCode = resultSet->GetFloat32Array(columnIndex, result);
    if (errCode == OHOS::NativeRdb::E_NULL_OBJECT) {
        return {};
    } else
        CHECK_ERRCODE_THROW_INNER_ERROR(errCode, resultSet->GetLastErrorMsg(), {});
    return array<float>(::taihe::copy_data_t{}, result.data(), result.size());
}

map<string, ValueType> ResultSetImpl::GetRow()
{
    auto resultSet = GetResource();
    OHOS::NativeRdb::RowEntity rowEntity;
    map<string, ValueType> aniMap;
    ASSERT_THROW_INNER_ERROR(resultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "", aniMap);
    int errCode = resultSet->GetRow(rowEntity);
    CHECK_ERRCODE_THROW_INNER_ERROR(errCode, resultSet->GetLastErrorMsg(), aniMap);
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
    ASSERT_THROW_PARAM_ERROR(maxCount >= 0, "Invalid maxCount", "", {});
    int positionNative = INIT_POSITION;
    if (position.has_value()) {
        ASSERT_THROW_PARAM_ERROR(position.value() >= 0, "invalid position", "", {});
        positionNative = position.value();
    }
    ASSERT_THROW_INNER_ERROR(resultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "", {});
    auto [errCode, rowEntities] = ani_rdbutils::GetRows(*resultSet, maxCount, positionNative);
    CHECK_ERRCODE_THROW_INNER_ERROR(errCode, resultSet->GetLastErrorMsg(), {});
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
    ASSERT_THROW_INNER_ERROR(resultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "", {});
    auto [errCode, rowData] = resultSet->GetRowData();
    CHECK_ERRCODE_THROW_INNER_ERROR_EXT(errCode, resultSet->GetLastErrorMsg(), {});
    std::vector<ValueType> rowDataTemp;
    std::transform(rowData.begin(), rowData.end(), std::back_inserter(rowDataTemp),
        [](const OHOS::NativeRdb::ValueObject &object) { return ani_rdbutils::ValueObjectToAni(object); });
    return array<ValueType>(::taihe::copy_data_t{}, rowDataTemp.data(), rowDataTemp.size());
}

array<array<ValueType>> ResultSetImpl::GetRowsDataSync(int32_t maxCount, optional_view<int32_t> position)
{
    auto resultSet = GetResource();
    ASSERT_THROW_INNER_ERROR(maxCount > 0, OHOS::NativeRdb::E_INVALID_ARGS_NEW, "", {});
    int32_t nativePosition = INIT_POSITION;
    if (position.has_value()) {
        nativePosition = position.value();
        ASSERT_THROW_INNER_ERROR(nativePosition >= 0, OHOS::NativeRdb::E_INVALID_ARGS_NEW, "", {});
    }
    ASSERT_THROW_INNER_ERROR_EXT(resultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "", {});
    auto [errCode, rowsData] = resultSet->GetRowsData(maxCount, nativePosition);
    CHECK_ERRCODE_THROW_INNER_ERROR_EXT(errCode, resultSet->GetLastErrorMsg(), {});
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
    ASSERT_THROW_INNER_ERROR(resultSet != nullptr, OHOS::NativeRdb::E_ALREADY_CLOSED, "", result);
    int errCode = resultSet->IsColumnNull(columnIndex, result);
    CHECK_ERRCODE_THROW_INNER_ERROR(errCode, resultSet->GetLastErrorMsg(), result);
    return result;
}

void ResultSetImpl::Close()
{
    ResetResource();
    proxy_ = nullptr;
}
} // namespace RdbTaihe
} // namespace OHOS