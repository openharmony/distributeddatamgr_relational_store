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
#define LOG_TAG "AniRelationalStoreImpl"
#include "ohos.data.relationalStore.proj.hpp"
#include "ohos.data.relationalStore.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include "ani_utils.h"
#include "ani_rdb_utils.h"
#include "logger.h"
#include "abs_rdb_predicates.h"
#include "datashare_abs_predicates.h"
#include "napi_rdb_js_utils.h"
#include "rdb_store_config.h"
#include "rdb_open_callback.h"
#include "rdb_result_set_bridge.h"
#include "rdb_sql_utils.h"
#include "rdb_helper.h"
#include "rdb_predicates.h"
#include "rdb_utils.h"
#include "rdb_types.h"

using namespace taihe;
using namespace ohos::data::relationalStore;

namespace {
using namespace OHOS::Rdb;

static constexpr int ERR_NULL = -1;

void ThrowInnerError(int errcode)
{
    LOG_ERROR("ThrowInnerError, errcode = %{public}d", errcode);
    auto innErr = std::make_shared<OHOS::RelationalStoreJsKit::InnerError>(errcode);
    if (innErr != nullptr) {
        taihe::set_business_error(innErr->GetCode(), innErr->GetMessage());
    }
}

void ThrowParamError(const char* message)
{
    if (message == nullptr) {
        return;
    }
    auto paraErr = std::make_shared<OHOS::RelationalStoreJsKit::ParamError>(message);
    if (paraErr != nullptr) {
        taihe::set_business_error(paraErr->GetCode(), paraErr->GetMessage());
    }
}

class ResultSetImpl {
public:
    ResultSetImpl()
    {
    }
    explicit ResultSetImpl(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet)
    {
        nativeResultSet_ = resultSet;
    }

    array<string> GetColumnNames()
    {
        std::vector<std::string> colNames;
        if (nativeResultSet_ != nullptr) {
            nativeResultSet_->GetAllColumnNames(colNames);
        }
        return array<string>(::taihe::copy_data_t{}, colNames.data(), colNames.size());
    }

    int32_t GetColumnCount()
    {
        int32_t count = 0;
        if (nativeResultSet_ != nullptr) {
            nativeResultSet_->GetColumnCount(count);
        }
        return count;
    }

    int32_t GetRowCount()
    {
        if (nativeResultSet_ == nullptr) {
            return -1;
        }
        int32_t rowCount = 0;
        nativeResultSet_->GetRowCount(rowCount);
        return rowCount;
    }

    int32_t GetRowIndex()
    {
        int32_t rowIndex = -1;
        if (nativeResultSet_ != nullptr) {
            nativeResultSet_->GetRowIndex(rowIndex);
        }
        return rowIndex;
    }

    bool GetIsAtFirstRow()
    {
        bool isAtFirstRow = false;
        if (nativeResultSet_ != nullptr) {
            nativeResultSet_->IsAtFirstRow(isAtFirstRow);
        }
        return isAtFirstRow;
    }

    bool GetIsAtLastRow()
    {
        bool isAtLastRow = false;
        if (nativeResultSet_ != nullptr) {
            nativeResultSet_->IsAtLastRow(isAtLastRow);
        }
        return isAtLastRow;
    }

    bool GetIsEnded()
    {
        bool isEnded = true;
        if (nativeResultSet_ != nullptr) {
            nativeResultSet_->IsEnded(isEnded);
        }
        return isEnded;
    }

    bool GetIsStarted()
    {
        bool isStarted = false;
        if (nativeResultSet_ != nullptr) {
            nativeResultSet_->IsStarted(isStarted);
        }
        return isStarted;
    }

    bool GetIsClosed()
    {
        return nativeResultSet_ == nullptr;
    }

    int32_t GetColumnIndex(string_view columnName)
    {
        int32_t result = -1;
        int errCode = OHOS::NativeRdb::E_OK;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->GetColumnIndex(std::string(columnName), result);
        }
        if (errCode != OHOS::NativeRdb::E_INVALID_ARGS && errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
        return result;
    }

    string GetColumnName(int32_t columnIndex)
    {
        std::string result;
        int errCode = OHOS::NativeRdb::E_OK;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->GetColumnName(columnIndex, result);
        }
        if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
        return string(result);
    }

    bool GoTo(int32_t offset)
    {
        int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->GoTo(offset);
        }
        if (errCode != OHOS::NativeRdb::E_ROW_OUT_RANGE && errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
        return errCode == OHOS::NativeRdb::E_OK;
    }

    bool GoToRow(int32_t position)
    {
        int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->GoToRow(position);
        }
        if (errCode != OHOS::NativeRdb::E_ROW_OUT_RANGE && errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
        return errCode == OHOS::NativeRdb::E_OK;
    }

    bool GoToFirstRow()
    {
        int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->GoToFirstRow();
        }
        if (errCode != OHOS::NativeRdb::E_ROW_OUT_RANGE && errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
        return errCode == OHOS::NativeRdb::E_OK;
    }

    bool GoToLastRow()
    {
        int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->GoToLastRow();
        }
        if (errCode != OHOS::NativeRdb::E_ROW_OUT_RANGE && errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
        return errCode == OHOS::NativeRdb::E_OK;
    }

    bool GoToNextRow()
    {
        int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->GoToNextRow();
        }
        if (errCode != OHOS::NativeRdb::E_ROW_OUT_RANGE && errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
        return errCode == OHOS::NativeRdb::E_OK;
    }

    bool GoToPreviousRow()
    {
        int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->GoToPreviousRow();
        }
        if (errCode != OHOS::NativeRdb::E_ROW_OUT_RANGE && errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
        return errCode == OHOS::NativeRdb::E_OK;
    }

    array<uint8_t> GetBlob(int32_t columnIndex)
    {
        std::vector<uint8_t> result;
        int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->GetBlob(columnIndex, result);
        }
        if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
        return array<uint8_t>(::taihe::copy_data_t{}, result.data(), result.size());
    }

    string GetString(int32_t columnIndex)
    {
        std::string result;
        int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->GetString(columnIndex, result);
        }
        if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
        return string(result);
    }

    int64_t GetLong(int32_t columnIndex)
    {
        int64_t result = 0;
        int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->GetLong(columnIndex, result);
        }
        if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
        return result;
    }

    double GetDouble(int32_t columnIndex)
    {
        double result = 0.0;
        int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->GetDouble(columnIndex, result);
        }
        if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
        return result;
    }

    ohos::data::relationalStore::Asset GetAsset(int32_t columnIndex)
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
            ThrowInnerError(errCode);
        }
        return ani_rdbutils::AssetToAni(result);
    }

    array<ohos::data::relationalStore::Asset> GetAssets(int32_t columnIndex)
    {
        std::vector<OHOS::NativeRdb::AssetValue> result;
        int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->GetAssets(columnIndex, result);
        }
        if (errCode == OHOS::NativeRdb::E_NULL_OBJECT || result.size() == 0) {
            return {};
        } else if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
            return {};
        }
        ohos::data::relationalStore::Asset aniempty = {};
        std::vector<ohos::data::relationalStore::Asset> resultTemp(result.size(), aniempty);
        std::transform(result.begin(), result.end(), resultTemp.begin(), [](OHOS::NativeRdb::AssetValue c) {
            ohos::data::relationalStore::Asset anitemp = ani_rdbutils::AssetToAni(c);
            return anitemp;
        });
        return array<ohos::data::relationalStore::Asset>(::taihe::copy_data_t{}, resultTemp.data(), resultTemp.size());
    }

    ValueType GetValue(int32_t columnIndex)
    {
        OHOS::NativeRdb::ValueObject object;
        int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->Get(columnIndex, object);
        }
        if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
        ValueType aniresult = ani_rdbutils::ValueObjectToAni(object);
        return aniresult;
    }

    array<float> GetFloat32Array(int32_t columnIndex)
    {
        std::vector<float> result = {};
        int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->GetFloat32Array(columnIndex, result);
        }
        if (errCode == OHOS::NativeRdb::E_NULL_OBJECT) {
            return {};
        } else if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
            return {};
        }
        return array<float>(::taihe::copy_data_t{}, result.data(), result.size());
    }

    map<string, ValueType> GetRow()
    {
        OHOS::NativeRdb::RowEntity rowEntity;
        int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->GetRow(rowEntity);
        }
        map<string, ValueType> aniMap;
        if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
            return aniMap;
        }
        std::map<std::string, OHOS::NativeRdb::ValueObject> rowMap = rowEntity.Get();
        for (auto it = rowMap.begin(); it != rowMap.end(); ++it) {
            auto const &[key, value] = *it;
            ValueType aniTemp = ani_rdbutils::ValueObjectToAni(value);
            aniMap.emplace(string(key), aniTemp);
        }
        return aniMap;
    }

    bool IsColumnNull(int32_t columnIndex)
    {
        bool result = false;
        int errCode = OHOS::NativeRdb::E_ALREADY_CLOSED;
        if (nativeResultSet_ != nullptr) {
            errCode = nativeResultSet_->IsColumnNull(columnIndex, result);
        }
        if (errCode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errCode);
        }
        return result;
    }

    void Close()
    {
        nativeResultSet_ = nullptr;
    }

protected:
    std::shared_ptr<OHOS::NativeRdb::ResultSet> nativeResultSet_;
};

class RdbPredicatesImpl {
public:
    RdbPredicatesImpl()
    {
    }

    explicit RdbPredicatesImpl(std::string name)
    {
        nativeRdbPredicates_ = std::make_shared<OHOS::NativeRdb::RdbPredicates>(name);
    }

    int64_t GetSpecificImplPtr()
    {
        return reinterpret_cast<int64_t>(this);
    }

    RdbPredicates InDevices(weak::RdbPredicates thiz, array_view<string> devices)
    {
        std::vector<std::string> fields(devices.begin(), devices.end());
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->InDevices(fields);
        }
        return thiz;
    }

    RdbPredicates InAllDevices(weak::RdbPredicates thiz)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->InAllDevices();
        }
        return thiz;
    }

    RdbPredicates EqualTo(weak::RdbPredicates thiz, string_view field, ValueType const &value)
    {
        OHOS::NativeRdb::ValueObject valueObj = ani_rdbutils::ValueTypeToNative(value);
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->EqualTo(std::string(field), valueObj);
        }
        return thiz;
    }

    RdbPredicates NotEqualTo(weak::RdbPredicates thiz, string_view field, ValueType const &value)
    {
        OHOS::NativeRdb::ValueObject valueObj = ani_rdbutils::ValueTypeToNative(value);
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->NotEqualTo(std::string(field), valueObj);
        }
        return thiz;
    }

    RdbPredicates BeginWrap(weak::RdbPredicates thiz)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->BeginWrap();
        }
        return thiz;
    }

    RdbPredicates EndWrap(weak::RdbPredicates thiz)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->EndWrap();
        }
        return thiz;
    }

    RdbPredicates Or(weak::RdbPredicates thiz)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->Or();
        }
        return thiz;
    }

    RdbPredicates And(weak::RdbPredicates thiz)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->And();
        }
        return thiz;
    }

    RdbPredicates Contains(weak::RdbPredicates thiz, string_view field, string_view value)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->Contains(std::string(field), std::string(value));
        }
        return thiz;
    }

    RdbPredicates BeginsWith(weak::RdbPredicates thiz, string_view field, string_view value)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->BeginsWith(std::string(field), std::string(value));
        }
        return thiz;
    }

    RdbPredicates EndsWith(weak::RdbPredicates thiz, string_view field, string_view value)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->EndsWith(std::string(field), std::string(value));
        }
        return thiz;
    }

    RdbPredicates IsNull(weak::RdbPredicates thiz, string_view field)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->IsNull(std::string(field));
        }
        return thiz;
    }

    RdbPredicates IsNotNull(weak::RdbPredicates thiz, string_view field)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->IsNotNull(std::string(field));
        }
        return thiz;
    }

    RdbPredicates Like(weak::RdbPredicates thiz, string_view field, string_view value)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->Like(std::string(field), std::string(value));
        }
        return thiz;
    }

    RdbPredicates Glob(weak::RdbPredicates thiz, string_view field, string_view value)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->Glob(std::string(field), std::string(value));
        }
        return thiz;
    }

    RdbPredicates Between(weak::RdbPredicates thiz, string_view field, ValueType const &low,
        ValueType const &high)
    {
        OHOS::NativeRdb::ValueObject lowValueObj = ani_rdbutils::ValueTypeToNative(low);
        OHOS::NativeRdb::ValueObject highValueObj = ani_rdbutils::ValueTypeToNative(high);
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->Between(std::string(field), lowValueObj, highValueObj);
        }
        return thiz;
    }

    RdbPredicates NotBetween(weak::RdbPredicates thiz, string_view field, ValueType const &low,
        ValueType const &high)
    {
        OHOS::NativeRdb::ValueObject lowValueObj = ani_rdbutils::ValueTypeToNative(low);
        OHOS::NativeRdb::ValueObject highValueObj = ani_rdbutils::ValueTypeToNative(high);
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->NotBetween(std::string(field), lowValueObj, highValueObj);
        }
        return thiz;
    }

    RdbPredicates GreaterThan(weak::RdbPredicates thiz, string_view field, ValueType const &value)
    {
        OHOS::NativeRdb::ValueObject valueObj = ani_rdbutils::ValueTypeToNative(value);
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->GreaterThan(std::string(field), valueObj);
        }
        return thiz;
    }

    RdbPredicates LessThan(weak::RdbPredicates thiz, string_view field, ValueType const &value)
    {
        OHOS::NativeRdb::ValueObject valueObj = ani_rdbutils::ValueTypeToNative(value);
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->LessThan(std::string(field), valueObj);
        }
        return thiz;
    }

    RdbPredicates GreaterThanOrEqualTo(weak::RdbPredicates thiz, string_view field, ValueType const &value)
    {
        OHOS::NativeRdb::ValueObject valueObj = ani_rdbutils::ValueTypeToNative(value);
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->GreaterThanOrEqualTo(std::string(field), valueObj);
        }
        return thiz;
    }

    RdbPredicates LessThanOrEqualTo(weak::RdbPredicates thiz, string_view field, ValueType const &value)
    {
        OHOS::NativeRdb::ValueObject valueObj = ani_rdbutils::ValueTypeToNative(value);
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->LessThanOrEqualTo(std::string(field), valueObj);
        }
        return thiz;
    }

    RdbPredicates OrderByAsc(weak::RdbPredicates thiz, string_view field)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->OrderByAsc(std::string(field));
        }
        return thiz;
    }

    RdbPredicates OrderByDesc(weak::RdbPredicates thiz, string_view field)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->OrderByDesc(std::string(field));
        }
        return thiz;
    }

    RdbPredicates Distinct(weak::RdbPredicates thiz)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->Distinct();
        }
        return thiz;
    }

    RdbPredicates LimitAs(weak::RdbPredicates thiz, int32_t value)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->Limit(value);
        }
        return thiz;
    }

    RdbPredicates OffsetAs(weak::RdbPredicates thiz, int32_t rowOffset)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->Offset(rowOffset);
        }
        return thiz;
    }

    RdbPredicates GroupBy(weak::RdbPredicates thiz, array_view<string> fields)
    {
        std::vector<std::string> para(fields.begin(), fields.end());
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->GroupBy(para);
        }
        return thiz;
    }

    RdbPredicates IndexedBy(weak::RdbPredicates thiz, string_view field)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->IndexedBy(std::string(field));
        }
        return thiz;
    }

    RdbPredicates InValues(weak::RdbPredicates thiz, string_view field, array_view<ValueType> value)
    {
        std::vector<OHOS::NativeRdb::ValueObject> para(value.size());
        std::transform(value.begin(), value.end(), para.begin(), [](ValueType c) {
            OHOS::NativeRdb::ValueObject obj = ani_rdbutils::ValueTypeToNative(c);
            return obj;
        });
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->In(std::string(field), para);
        }
        return thiz;
    }

    RdbPredicates NotInValues(weak::RdbPredicates thiz, string_view field, array_view<ValueType> value)
    {
        std::vector<OHOS::NativeRdb::ValueObject> para(value.size());
        std::transform(value.begin(), value.end(), para.begin(), [](ValueType c) {
            OHOS::NativeRdb::ValueObject obj = ani_rdbutils::ValueTypeToNative(c);
            return obj;
        });
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->NotIn(std::string(field), para);
        }
        return thiz;
    }

    RdbPredicates NotContains(weak::RdbPredicates thiz, string_view field, string_view value)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->NotContains(std::string(field), std::string(value));
        }
        return thiz;
    }

    RdbPredicates NotLike(weak::RdbPredicates thiz, string_view field, string_view value)
    {
        if (nativeRdbPredicates_ != nullptr) {
            nativeRdbPredicates_->NotLike(std::string(field), std::string(value));
        }
        return thiz;
    }

    std::shared_ptr<OHOS::NativeRdb::RdbPredicates> GetNativePtr()
    {
        return nativeRdbPredicates_;
    }

private:
    std::shared_ptr<OHOS::NativeRdb::RdbPredicates> nativeRdbPredicates_;
};

class TransactionImpl {
public:
    TransactionImpl()
    {
    }
    explicit TransactionImpl(std::shared_ptr<OHOS::NativeRdb::Transaction> transaction)
    {
        nativeTransaction_ = transaction;
    }

    void CommitSync()
    {
        if (nativeTransaction_ == nullptr) {
            LOG_ERROR("nativeTransaction_ is nullptr");
            return;
        }
        nativeTransaction_->Commit();
    }

    void RollbackSync()
    {
        if (nativeTransaction_ == nullptr) {
            LOG_ERROR("nativeTransaction_ is nullptr");
            return;
        }
        nativeTransaction_->Rollback();
    }

    int64_t InsertSync(string_view table, map_view<::taihe::string, ValueType> values,
        optional_view<ConflictResolution> conflict)
    {
        if (nativeTransaction_ == nullptr) {
            LOG_ERROR("nativeTransaction_ is nullptr");
            return ERR_NULL;
        }
        ConflictResolution conflictres = ConflictResolution::key_t::ON_CONFLICT_NONE;
        if (conflict.has_value()) {
            conflictres = conflict.value().get_key();
        }
        OHOS::NativeRdb::ValuesBucket bucket = ani_rdbutils::MapValuesToNative(values);
        auto nativeConflictValue = (OHOS::NativeRdb::ConflictResolution)conflictres.get_key();
        auto [errcode, output] = nativeTransaction_->Insert(
            std::string(table), bucket, nativeConflictValue);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
            return 0;
        }
        return output;
    }

    int64_t BatchInsertSync(string_view table, array_view<map<string, ValueType>> values)
    {
        if (nativeTransaction_ == nullptr) {
            LOG_ERROR("nativeTransaction_ is nullptr");
            return ERR_NULL;
        }
        OHOS::NativeRdb::ValuesBuckets buckets = ani_rdbutils::BucketValuesToNative(values);
        if (ani_rdbutils::HasDuplicateAssets(buckets)) {
            ThrowParamError("Duplicate assets are not allowed");
            return ERR_NULL;
        }
        auto [errcode, output] = nativeTransaction_->BatchInsert(std::string(table), buckets);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
            return 0;
        }
        return output;
    }

    int64_t UpdateSync(map_view<string, ValueType> values, weak::RdbPredicates predicates,
        optional_view<ConflictResolution> conflict)
    {
        if (nativeTransaction_ == nullptr) {
            LOG_ERROR("nativeTransaction_ is nullptr");
            return ERR_NULL;
        }
        ConflictResolution conflictres = ConflictResolution::key_t::ON_CONFLICT_NONE;
        if (conflict.has_value()) {
            conflictres = conflict.value().get_key();
        }
        RdbPredicatesImpl* impl = reinterpret_cast<RdbPredicatesImpl*>(predicates->GetSpecificImplPtr());
        std::shared_ptr<OHOS::NativeRdb::RdbPredicates> rdbPredicateNative = impl->GetNativePtr();
        if (rdbPredicateNative == nullptr) {
            LOG_ERROR("rdbPredicateNative is nullptr");
            return ERR_NULL;
        }
        OHOS::NativeRdb::ValuesBucket bucket = ani_rdbutils::MapValuesToNative(values);
        auto nativeConflictValue = (OHOS::NativeRdb::ConflictResolution)conflictres.get_key();
        auto [errcode, rows] = nativeTransaction_->Update(
            bucket, *rdbPredicateNative, nativeConflictValue);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
            return 0;
        }
        return rows;
    }

    int64_t DeleteSync(weak::RdbPredicates predicates)
    {
        if (nativeTransaction_ == nullptr) {
            LOG_ERROR("nativeTransaction_ is nullptr");
            return ERR_NULL;
        }
        RdbPredicatesImpl* impl = reinterpret_cast<RdbPredicatesImpl*>(predicates->GetSpecificImplPtr());
        std::shared_ptr<OHOS::NativeRdb::RdbPredicates> rdbPredicateNative = impl->GetNativePtr();
        if (rdbPredicateNative == nullptr) {
            LOG_ERROR("rdbPredicateNative is nullptr");
            return ERR_NULL;
        }
        auto [errcode, rows] = nativeTransaction_->Delete(*rdbPredicateNative);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
            return 0;
        }
        return rows;
    }

    ResultSet QuerySync(weak::RdbPredicates predicates, optional_view<array<string>> columns)
    {
        if (nativeTransaction_ == nullptr) {
            LOG_ERROR("nativeTransaction_ is nullptr");
            return make_holder<ResultSetImpl, ResultSet>();
        }
        std::vector<std::string> stdcolumns;
        if (columns.has_value()) {
            stdcolumns = std::vector<std::string>(columns.value().begin(), columns.value().end());
        }
        RdbPredicatesImpl* impl = reinterpret_cast<RdbPredicatesImpl*>(predicates->GetSpecificImplPtr());
        std::shared_ptr<OHOS::NativeRdb::RdbPredicates> rdbPredicateNative = impl->GetNativePtr();
        if (rdbPredicateNative == nullptr) {
            LOG_ERROR("rdbPredicateNative is nullptr");
            return make_holder<ResultSetImpl, ResultSet>();
        }
        auto nativeResultSet = nativeTransaction_->QueryByStep(*rdbPredicateNative, stdcolumns);
        return make_holder<ResultSetImpl, ResultSet>(nativeResultSet);
    }

    ResultSet QuerySqlSync(string_view sql, optional_view<array<ValueType>> args)
    {
        if (nativeTransaction_ == nullptr) {
            LOG_ERROR("nativeTransaction_ is nullptr");
            return make_holder<ResultSetImpl, ResultSet>();
        }
        std::vector<OHOS::NativeRdb::ValueObject> para;
        if (args.has_value()) {
            para.resize(args.value().size());
            std::transform(args.value().begin(), args.value().end(), para.begin(), [](ValueType c) {
                OHOS::NativeRdb::ValueObject obj = ani_rdbutils::ValueTypeToNative(c);
                return obj;
            });
        }
        auto nativeResultSet = nativeTransaction_->QueryByStep(std::string(sql), para);
        return make_holder<ResultSetImpl, ResultSet>(nativeResultSet);
    }

    ValueType ExecuteSync(string_view sql, optional_view<array<ValueType>> args)
    {
        ValueType aniValue = ::ohos::data::relationalStore::ValueType::make_EMPTY();
        if (nativeTransaction_ == nullptr) {
            LOG_ERROR("nativeTransaction_ is nullptr");
            return aniValue;
        }
        std::vector<OHOS::NativeRdb::ValueObject> para;
        if (args.has_value()) {
            para.resize(args.value().size());
            std::transform(args.value().begin(), args.value().end(), para.begin(), [](ValueType c) {
                OHOS::NativeRdb::ValueObject obj = ani_rdbutils::ValueTypeToNative(c);
                return obj;
            });
        }
        auto [errcode, nativeValue] = nativeTransaction_->Execute(std::string(sql), para);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
            return aniValue;
        }
        return ani_rdbutils::ValueObjectToAni(nativeValue);
    }

protected:
    std::shared_ptr<OHOS::NativeRdb::Transaction> nativeTransaction_ = nullptr;
};

class DefaultOpenCallback : public OHOS::NativeRdb::RdbOpenCallback {
public:
    int OnCreate(OHOS::NativeRdb::RdbStore &rdbStore) override
    {
        return OHOS::NativeRdb::E_OK;
    }
    int OnUpgrade(OHOS::NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override
    {
        return OHOS::NativeRdb::E_OK;
    }
};

class RdbStoreImpl {
public:
    RdbStoreImpl()
    {
    }

    explicit RdbStoreImpl(ani_object context, StoreConfig const &config)
    {
        ani_env *env = get_env();
        OHOS::AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig = ani_rdbutils::AniGetRdbConfig(config);
        auto configRet = ani_rdbutils::AniGetRdbStoreConfig(env, context, rdbConfig);
        DefaultOpenCallback callback;
        int errCode = OHOS::AppDataMgrJsKit::JSUtils::OK;
        if (!configRet.first) {
            LOG_ERROR("AniGetRdbStoreConfig failed, use default config");
            std::string dir = "/data/storage/el2/database/rdb";
            std::string path = dir + "/" + std::string(config.name);
            OHOS::NativeRdb::RdbStoreConfig storeConfig(path.c_str());
            OHOS::NativeRdb::RdbSqlUtils::CreateDirectory(dir);
            nativeRdbStore_ = OHOS::NativeRdb::RdbHelper::GetRdbStore(storeConfig, -1, callback, errCode);
        } else {
            nativeRdbStore_ = OHOS::NativeRdb::RdbHelper::GetRdbStore(configRet.second, -1, callback, errCode);
        }
        if (errCode != OHOS::AppDataMgrJsKit::JSUtils::OK) {
            ThrowInnerError(errCode);
            nativeRdbStore_ = nullptr;
            LOG_ERROR("GetRdbStore failed");
            return;
        }
        LOG_INFO("GetRdbStore success");
    }

    int32_t GetVersion()
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return ERR_NULL;
        }
        int32_t version = 0;
        int errcode = nativeRdbStore_->GetVersion(version);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
        }
        return version;
    }

    void SetVersion(int32_t veriosn)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return;
        }
        int errcode = nativeRdbStore_->SetVersion(veriosn);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
        }
    }

    RebuildType GetRebuilt()
    {
        OHOS::NativeRdb::RebuiltType rebuilt = OHOS::NativeRdb::RebuiltType::NONE;
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return (RebuildType::key_t)rebuilt;
        }
        int errcode = nativeRdbStore_->GetRebuilt(rebuilt);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
        }
        return (RebuildType::key_t)rebuilt;
    }

    void SetRebuilt(RebuildType type)
    {
        TH_THROW(std::runtime_error, "setRebuilt not implemented");
    }

    int64_t InsertWithConflict(string_view table, map_view<string, ValueType> values, ConflictResolution conflict)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return ERR_NULL;
        }

        int64_t int64Output = 0;
        OHOS::NativeRdb::ValuesBucket bucket = ani_rdbutils::MapValuesToNative(values);
        if (ani_rdbutils::HasDuplicateAssets(bucket)) {
            ThrowParamError("Duplicate assets are not allowed");
            return ERR_NULL;
        }

        int errcode = nativeRdbStore_->InsertWithConflictResolution(
            int64Output, std::string(table), bucket, (OHOS::NativeRdb::ConflictResolution)conflict.get_key());
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
            return 0;
        }
        return int64Output;
    }

    int64_t InsertWithValue(string_view table, map_view<string, ValueType> values)
    {
        return InsertWithConflict(table, values, ConflictResolution::key_t::ON_CONFLICT_NONE);
    }

    int64_t InsertSync(string_view table, map_view<string, ValueType> values,
        optional_view<ConflictResolution> conflict)
    {
        ConflictResolution conflictres = ConflictResolution::key_t::ON_CONFLICT_NONE;
        if (conflict.has_value()) {
            conflictres = conflict.value().get_key();
        }
        return InsertWithConflict(table, values, conflictres);
    }

    int64_t BatchInsertSync(string_view table, array_view<map<string, ValueType>> values)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return ERR_NULL;
        }
        OHOS::NativeRdb::ValuesBuckets buckets = ani_rdbutils::BucketValuesToNative(values);
        if (ani_rdbutils::HasDuplicateAssets(buckets)) {
            ThrowParamError("Duplicate assets are not allowed");
            return ERR_NULL;
        }
        auto [errcode, output] = nativeRdbStore_->BatchInsert(std::string(table), buckets);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
            return 0;
        }
        return output;
    }

    int64_t UpdateWithPredicate(map_view<string, ValueType> values, weak::RdbPredicates predicates)
    {
        optional<ConflictResolution> emptyConflict;
        return UpdateSync(values, predicates, emptyConflict);
    }

    int64_t UpdateSync(map_view<string, ValueType> values, weak::RdbPredicates predicates,
        optional_view<ConflictResolution> conflict)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return ERR_NULL;
        }
        ConflictResolution conflictres = ConflictResolution::key_t::ON_CONFLICT_NONE;
        if (conflict.has_value()) {
            conflictres = conflict.value().get_key();
        }
        RdbPredicatesImpl* impl = reinterpret_cast<RdbPredicatesImpl*>(predicates->GetSpecificImplPtr());
        std::shared_ptr<OHOS::NativeRdb::RdbPredicates> rdbPredicateNative = impl->GetNativePtr();
        if (rdbPredicateNative == nullptr) {
            LOG_ERROR("rdbPredicateNative is nullptr");
            return ERR_NULL;
        }
        OHOS::NativeRdb::ValuesBucket bucket = ani_rdbutils::MapValuesToNative(values);
        auto nativeConflictValue = (OHOS::NativeRdb::ConflictResolution)conflictres.get_key();
        int output = 0;
        int errcode = nativeRdbStore_->UpdateWithConflictResolution(output, rdbPredicateNative->GetTableName(), bucket,
            rdbPredicateNative->GetWhereClause(), rdbPredicateNative->GetBindArgs(),
            nativeConflictValue);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
            return 0;
        }
        return output;
    }

    int64_t UpdateDataShareSync(::taihe::string_view table, ::ohos::data::relationalStore::ValuesBucket const &values,
        uintptr_t predicates)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return ERR_NULL;
        }
        ani_env *env = get_env();
        ani_object object = reinterpret_cast<ani_object>(predicates);
        OHOS::DataShare::DataShareAbsPredicates *holder =
            ani_utils::AniObjectUtils::Unwrap<OHOS::DataShare::DataShareAbsPredicates>(env, object);
        if (holder == nullptr) {
            LOG_ERROR("UpdateDataShareSync, holder is nullptr");
            return 0;
        }
        auto rdbPredicates = OHOS::RdbDataShareAdapter::RdbUtils::ToPredicates(*holder, std::string(table));
        OHOS::NativeRdb::ValuesBucket bucket = ani_rdbutils::MapValuesToNative(values.get_VALUESBUCKET_ref());

        int output = 0;
        int errcode = nativeRdbStore_->UpdateWithConflictResolution(output, rdbPredicates.GetTableName(), bucket,
            rdbPredicates.GetWhereClause(), rdbPredicates.GetBindArgs(),
            OHOS::NativeRdb::ConflictResolution::ON_CONFLICT_NONE);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
            return 0;
        }
        return output;
    }

    int64_t DeleteSync(weak::RdbPredicates predicates)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return ERR_NULL;
        }
        RdbPredicatesImpl* impl = reinterpret_cast<RdbPredicatesImpl*>(predicates->GetSpecificImplPtr());
        std::shared_ptr<OHOS::NativeRdb::RdbPredicates> rdbPredicateNative = impl->GetNativePtr();
        if (rdbPredicateNative == nullptr) {
            LOG_ERROR("rdbPredicateNative is nullptr");
            return ERR_NULL;
        }
        int output = 0;
        int errcode = nativeRdbStore_->Delete(output, *rdbPredicateNative);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
            return 0;
        }
        return output;
    }

    int64_t DeleteDataShareSync(::taihe::string_view table, uintptr_t predicates)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return ERR_NULL;
        }
        ani_env *env = get_env();
        ani_object object = reinterpret_cast<ani_object>(predicates);
        OHOS::DataShare::DataShareAbsPredicates *holder =
            ani_utils::AniObjectUtils::Unwrap<OHOS::DataShare::DataShareAbsPredicates>(env, object);
        if (holder == nullptr) {
            LOG_ERROR("DeleteDataShareSync, holder is nullptr");
            return 0;
        }
        auto rdbPredicates = OHOS::RdbDataShareAdapter::RdbUtils::ToPredicates(*holder, std::string(table));
        int output = 0;
        int errcode = nativeRdbStore_->Delete(output, rdbPredicates);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
            return 0;
        }
        return output;
    }

    ResultSet QueryWithPredicate(weak::RdbPredicates predicates)
    {
        optional_view<array<string>> empty;
        return QuerySync(predicates, empty);
    }

    ResultSet QueryWithColumn(weak::RdbPredicates predicates, array_view<string> columns)
    {
        return QuerySync(predicates, optional<array<string>>::make(columns));
    }

    ResultSet QueryWithOptionalColumn(weak::RdbPredicates predicates, optional_view<array<string>> columns)
    {
        return QuerySync(predicates, columns);
    }

    ResultSet QuerySync(weak::RdbPredicates predicates, optional_view<array<string>> columns)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return make_holder<ResultSetImpl, ResultSet>();
        }
        std::vector<std::string> stdcolumns;
        if (columns.has_value()) {
            stdcolumns = std::vector<std::string>(columns.value().begin(), columns.value().end());
        }
        RdbPredicatesImpl* impl = reinterpret_cast<RdbPredicatesImpl*>(predicates->GetSpecificImplPtr());
        std::shared_ptr<OHOS::NativeRdb::RdbPredicates> rdbPredicateNative = impl->GetNativePtr();
        if (rdbPredicateNative == nullptr) {
            LOG_ERROR("rdbPredicateNative is nullptr");
            return make_holder<ResultSetImpl, ResultSet>();
        }
        auto nativeResultSet = nativeRdbStore_->Query(*rdbPredicateNative, stdcolumns);
        return make_holder<ResultSetImpl, ResultSet>(nativeResultSet);
    }

    ResultSet QueryDataShareSync(::taihe::string_view table, uintptr_t predicates)
    {
        optional_view<array<::taihe::string>> empty;
        return QueryDataShareWithColumnSync(table, predicates, empty);
    }

    ResultSet QueryDataShareWithColumnSync(string_view table, uintptr_t predicates,
        optional_view<array<::taihe::string>> columns)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return taihe::make_holder<ResultSetImpl, ResultSet>();
        }
        ani_env *env = get_env();
        ani_object object = reinterpret_cast<ani_object>(predicates);
        OHOS::DataShare::DataShareAbsPredicates *holder =
            ani_utils::AniObjectUtils::Unwrap<OHOS::DataShare::DataShareAbsPredicates>(env, object);
        if (holder == nullptr) {
            LOG_ERROR("QueryDataShareSync, holder is nullptr");
            return taihe::make_holder<ResultSetImpl, ResultSet>();
        }
        std::vector<std::string> stdcolumns;
        if (columns.has_value()) {
            stdcolumns = std::vector<std::string>(columns.value().begin(), columns.value().end());
        }
        auto rdbPredicates = OHOS::RdbDataShareAdapter::RdbUtils::ToPredicates(*holder, std::string(table));
        auto nativeResultSet = nativeRdbStore_->Query(rdbPredicates, stdcolumns);
        return taihe::make_holder<ResultSetImpl, ResultSet>(nativeResultSet);
    }

    ResultSet QuerySqlWithSql(string_view sql)
    {
        optional_view<array<ValueType>> empty;
        return QuerySqlSync(sql, empty);
    }

    ResultSet QuerySqlWithArgs(string_view sql, array_view<ValueType> bindArgs)
    {
        return QuerySqlSync(sql, optional<array<ValueType>>::make(bindArgs));
    }

    ResultSet QuerySqlSync(string_view sql, optional_view<array<ValueType>> bindArgs)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return taihe::make_holder<ResultSetImpl, ResultSet>();
        }
        std::vector<OHOS::NativeRdb::ValueObject> para;
        if (bindArgs.has_value()) {
            para.resize(bindArgs.value().size());
            std::transform(bindArgs.value().begin(), bindArgs.value().end(), para.begin(), [](ValueType c) {
                OHOS::NativeRdb::ValueObject obj = ani_rdbutils::ValueTypeToNative(c);
                return obj;
            });
        }
        std::shared_ptr<OHOS::NativeRdb::ResultSet> nativeResultSet = nullptr;
        if (nativeRdbStore_->GetDbType() == OHOS::NativeRdb::DB_VECTOR) {
            nativeResultSet = nativeRdbStore_->QueryByStep(std::string(sql), para);
        } else {
#if defined(CROSS_PLATFORM)
            nativeResultSet = nativeRdbStore_->QueryByStep(std::string(sql), para);
#else
            nativeResultSet = nativeRdbStore_->QuerySql(std::string(sql), para);
#endif
        }
        return make_holder<ResultSetImpl, ResultSet>(nativeResultSet);
    }

    map<PRIKeyType, uintptr_t> GetModifyTimeSync(string_view table, string_view columnName,
        array_view<PRIKeyType> primaryKeys)
    {
        TH_THROW(std::runtime_error, "getModifyTimeSync not implemented");
    }

    void CleanDirtyDataWithCursor(string_view table, uint64_t cursor)
    {
        TH_THROW(std::runtime_error, "cleanDirtyDataWithCursor not implemented");
    }

    void CleanDirtyDataWithTable(string_view table)
    {
        TH_THROW(std::runtime_error, "cleanDirtyDataWithTable not implemented");
    }

    void CleanDirtyDataWithOptionCursor(string_view table, optional_view<uint64_t> cursor)
    {
        TH_THROW(std::runtime_error, "cleanDirtyDataWithOptionCursor not implemented");
    }

    ResultSet QuerySharingResourceWithOptionColumn(weak::RdbPredicates predicates,
        optional_view<array<string>> columns)
    {
        return make_holder<ResultSetImpl, ResultSet>();
    }

    ResultSet QuerySharingResourceWithPredicate(weak::RdbPredicates predicates)
    {
        return make_holder<ResultSetImpl, ResultSet>();
    }

    ResultSet QuerySharingResourceWithColumn(weak::RdbPredicates predicates, array_view<string> columns)
    {
        return make_holder<ResultSetImpl, ResultSet>();
    }

    void ExecuteSqlWithSql(string_view sql)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return;
        }
        int errcode = nativeRdbStore_->ExecuteSql(std::string(sql));
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
        }
    }

    void ExecuteSqlWithArgs(string_view sql, array_view<ValueType> bindArgs)
    {
        ExecuteSqlWithOptionArgs(sql, optional<array<ValueType>>::make(bindArgs));
    }

    void ExecuteSqlWithOptionArgs(string_view sql, optional_view<array<ValueType>> bindArgs)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return;
        }
        if (!bindArgs.has_value()) {
            int errcode = nativeRdbStore_->ExecuteSql(std::string(sql));
            if (errcode != OHOS::NativeRdb::E_OK) {
                ThrowInnerError(errcode);
            }
            return;
        }
        array<ValueType> const &value = bindArgs.value();
        std::vector<OHOS::NativeRdb::ValueObject> para(value.size());
        std::transform(value.begin(), value.end(), para.begin(), [](ValueType c) {
            OHOS::NativeRdb::ValueObject obj = ani_rdbutils::ValueTypeToNative(c);
            return obj;
        });
        if (ani_rdbutils::HasDuplicateAssets(para)) {
            ThrowParamError("Duplicate assets are not allowed");
            return;
        }
        int errcode = nativeRdbStore_->ExecuteSql(std::string(sql), para);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
        }
    }

    ValueType ExecuteWithOptionArgs(string_view sql, optional_view<array<ValueType>> args)
    {
        ValueType aniValue = ::ohos::data::relationalStore::ValueType::make_EMPTY();
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return aniValue;
        }
        return ExecuteWithTxId(sql, 0, args);
    }

    ValueType ExecuteWithTxId(string_view sql, int64_t txId, optional_view<array<ValueType>> args)
    {
        ValueType aniValue = ::ohos::data::relationalStore::ValueType::make_EMPTY();
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return aniValue;
        }
        std::vector<OHOS::NativeRdb::ValueObject> nativeValues;
        if (args.has_value()) {
            array_view<ValueType> const &arrayView = args.value();
            nativeValues = ani_rdbutils::ArrayValuesToNative(arrayView);
        }
        if (ani_rdbutils::HasDuplicateAssets(nativeValues)) {
            ThrowParamError("Duplicate assets are not allowed");
            return aniValue;
        }
        auto [errcode, sqlExeOutput] = nativeRdbStore_->Execute(std::string(sql), nativeValues, txId);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
            return aniValue;
        }
        return ani_rdbutils::ValueObjectToAni(sqlExeOutput);
    }

    ValueType ExecuteSync(string_view sql, optional_view<array<ValueType>> args)
    {
        return ExecuteWithTxId(sql, 0, args);
    }

    void BeginTransaction()
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return;
        }
        int errcode = nativeRdbStore_->BeginTransaction();
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
        }
    }

    int64_t BeginTransSync()
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return ERR_NULL;
        }
        auto [errcode, rxid] = nativeRdbStore_->BeginTrans();
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
            return 0;
        }
        return rxid;
    }

    void Commit()
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return;
        }
        int errcode = nativeRdbStore_->Commit();
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
        }
    }

    void CommitWithTxId(int64_t txId)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return;
        }
        int errcode = nativeRdbStore_->Commit(txId);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
        }
    }

    void RollBack()
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return;
        }
        int errcode = nativeRdbStore_->RollBack();
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
        }
    }

    void RollbackSync(int64_t txId)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return;
        }
        int errcode = nativeRdbStore_->RollBack(txId);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
        }
    }

    void BackupSync(string_view destName)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return;
        }
        int errcode = nativeRdbStore_->Backup(std::string(destName));
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
        }
    }

    void RestoreWithSrcName(string_view srcName)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return;
        }
        int errcode = nativeRdbStore_->Restore(std::string(srcName));
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
        }
    }

    void RestoreWithVoid()
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return;
        }
        int errcode = nativeRdbStore_->Restore("");
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
        }
    }

    void SetDistributedTablesWithTables(array_view<string> tables)
    {
        TH_THROW(std::runtime_error, "setDistributedTablesWithTables not implemented");
    }

    void SetDistributedTablesWithType(array_view<string> tables, DistributedType type)
    {
        TH_THROW(std::runtime_error, "setDistributedTablesWithType not implemented");
    }

    void SetDistributedTablesWithConfig(array_view<string> tables, DistributedType type,
        DistributedConfig const &config)
    {
        TH_THROW(std::runtime_error, "setDistributedTablesWithConfig not implemented");
    }

    void SetDistributedTablesWithOptionConfig(array_view<string> tables, optional_view<DistributedType> type,
        optional_view<DistributedConfig> config)
    {
        TH_THROW(std::runtime_error, "setDistributedTablesWithOptionConfig not implemented");
    }

    string ObtainDistributedTableNameSync(string_view device, string_view table)
    {
        TH_THROW(std::runtime_error, "obtainDistributedTableNameSync not implemented");
    }

    array<map<string, int32_t>> SyncSync(SyncMode mode, weak::RdbPredicates predicates)
    {
        TH_THROW(std::runtime_error, "syncSync not implemented");
    }

    void CloudSyncWithProgress(SyncMode mode, callback_view<void(ProgressDetails const&)> progress)
    {
        TH_THROW(std::runtime_error, "cloudSyncWithProgress not implemented");
    }

    void CloudSyncWithTable(SyncMode mode, array_view<string> tables,
        callback_view<void(ProgressDetails const&)> progress)
    {
        TH_THROW(std::runtime_error, "cloudSyncWithTable not implemented");
    }

    void CloudSyncWithPredicates(SyncMode mode, weak::RdbPredicates predicates,
        callback_view<void(ProgressDetails const&)> progress)
    {
        TH_THROW(std::runtime_error, "cloudSyncWithPredicates not implemented");
    }

    ResultSet RemoteQuerySync(string_view device, string_view table, weak::RdbPredicates predicates,
        array_view<string> columns)
    {
        return make_holder<ResultSetImpl, ResultSet>();
    }

    void OnDataChange(SubscribeType type, callback_view<void(array_view<string>)> f, uintptr_t opq)
    {
        TH_THROW(std::runtime_error, "onDataChange not implemented");
    }

    void OffDataChange(SubscribeType type, optional_view<uintptr_t> opq)
    {
        TH_THROW(std::runtime_error, "offDataChange not implemented");
    }

    void OnAutoSyncProgress(SubscribeType type, callback_view<void(array_view<ProgressDetails>)> f, uintptr_t opq)
    {
        TH_THROW(std::runtime_error, "onAutoSyncProgress not implemented");
    }

    void OffAutoSyncProgress(SubscribeType type, optional_view<uintptr_t> opq)
    {
        TH_THROW(std::runtime_error, "offAutoSyncProgress not implemented");
    }

    void OnStatistics(callback_view<void(array_view<SqlExecutionInfo>)> f, uintptr_t opq)
    {
        TH_THROW(std::runtime_error, "onStatistics not implemented");
    }

    void OffStatistics(optional_view<uintptr_t> opq)
    {
        TH_THROW(std::runtime_error, "offStatistics not implemented");
    }

    void OnCommon(bool interProcess, callback_view<void()> f, uintptr_t opq)
    {
        TH_THROW(std::runtime_error, "onCommon not implemented");
    }

    void OffCommon(bool interProcess, optional_view<uintptr_t> opq)
    {
        TH_THROW(std::runtime_error, "offCommon not implemented");
    }

    void Emit(string_view event)
    {
        TH_THROW(std::runtime_error, "emit not implemented");
    }

    void CloseSync()
    {
        LOG_INFO("closeSync");
        if (nativeRdbStore_ == nullptr) {
            LOG_ERROR("nativeRdbStore_ is nullptr");
            return;
        }
        nativeRdbStore_ = nullptr;
    }

    int32_t AttachWithWaitTime(string_view fullPath, string_view attachName, int64_t waitTime)
    {
        TH_THROW(std::runtime_error, "attachWithWaitTime not implemented");
    }

    int32_t AttachWithContext(uintptr_t context, StoreConfig const &config,
        string_view attachName, optional_view<int64_t> waitTime)
    {
        TH_THROW(std::runtime_error, "attachWithContext not implemented");
    }

    int32_t DetachSync(string_view attachName, optional_view<int64_t> waitTime)
    {
        TH_THROW(std::runtime_error, "detachSync not implemented");
    }

    void LockRowSync(weak::RdbPredicates predicates)
    {
        TH_THROW(std::runtime_error, "lockRowSync not implemented");
    }

    void UnlockRowSync(weak::RdbPredicates predicates)
    {
        TH_THROW(std::runtime_error, "unlockRowSync not implemented");
    }

    ResultSet QueryLockedRowSync(weak::RdbPredicates predicates, optional_view<array<string>> columns)
    {
        return make_holder<ResultSetImpl, ResultSet>();
    }

    uint32_t LockCloudContainerSync()
    {
        TH_THROW(std::runtime_error, "lockCloudContainerSync not implemented");
    }

    void UnlockCloudContainerSync()
    {
        TH_THROW(std::runtime_error, "unlockCloudContainerSync not implemented");
    }

    Transaction CreateTransactionSync(optional_view<::ohos::data::relationalStore::TransactionOptions> options)
    {
        if (nativeRdbStore_ == nullptr) {
            ThrowInnerError(OHOS::NativeRdb::E_ALREADY_CLOSED);
            return make_holder<TransactionImpl, Transaction>();
        }
        int32_t transactionType = 0;
        if (options.has_value()) {
            auto optType = options.value();
            if (optType.transactionType.has_value()) {
                transactionType = (int)(optType.transactionType.value());
            }
        }
        auto [errcode, transaction] = nativeRdbStore_->CreateTransaction(transactionType);
        if (errcode != OHOS::NativeRdb::E_OK) {
            ThrowInnerError(errcode);
            return make_holder<TransactionImpl, Transaction>();
        }
        return make_holder<TransactionImpl, Transaction>(transaction);
    }

private:
    std::shared_ptr<OHOS::NativeRdb::RdbStore> nativeRdbStore_;
};

RdbPredicates CreateRdbPredicates(string_view name)
{
    return make_holder<RdbPredicatesImpl, RdbPredicates>(std::string(name));
}

RdbStore GetRdbStoreSync(uintptr_t context, StoreConfig const &config)
{
    return make_holder<RdbStoreImpl, RdbStore>(reinterpret_cast<ani_object>(context), config);
}

void DeleteRdbStoreWithName(uintptr_t context, string_view name)
{
    ani_env *env = get_env();
    OHOS::AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig;
    rdbConfig.name = std::string(name);
    auto configRet = ani_rdbutils::AniGetRdbStoreConfig(env, reinterpret_cast<ani_object>(context), rdbConfig);
    if (!configRet.first) {
        LOG_INFO("AniGetRdbStoreConfig failed");
        return;
    }
    OHOS::NativeRdb::RdbStoreConfig storeConfig = configRet.second;

    storeConfig.SetDBType(OHOS::NativeRdb::DBType::DB_SQLITE);
    int errCodeSqlite = OHOS::NativeRdb::RdbHelper::DeleteRdbStore(
        storeConfig, OHOS::AppDataMgrJsKit::JSUtils::GetHapVersion() >= 20);
    storeConfig.SetDBType(OHOS::NativeRdb::DBType::DB_VECTOR);
    int errCodeVector = OHOS::NativeRdb::RdbHelper::DeleteRdbStore(
        storeConfig, OHOS::AppDataMgrJsKit::JSUtils::GetHapVersion() >= 20);
    LOG_INFO("deleteRdbStoreWithName sqlite %{public}d, vector %{public}d", errCodeSqlite, errCodeVector);
}

void DeleteRdbStoreWithConfig(uintptr_t context, StoreConfig const &config)
{
    ani_env *env = get_env();
    OHOS::AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig = ani_rdbutils::AniGetRdbConfig(config);
    auto configRet = ani_rdbutils::AniGetRdbStoreConfig(env, reinterpret_cast<ani_object>(context), rdbConfig);
    if (!configRet.first) {
        LOG_INFO("AniGetRdbStoreConfig failed");
        return;
    }
    OHOS::NativeRdb::RdbStoreConfig storeConfig = configRet.second;

    int errcode = OHOS::NativeRdb::RdbHelper::DeleteRdbStore(
        storeConfig, OHOS::AppDataMgrJsKit::JSUtils::GetHapVersion() >= 20);
    LOG_INFO("deleteRdbStoreWithConfig errcode %{public}d", errcode);
}

}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateRdbPredicates(CreateRdbPredicates);
TH_EXPORT_CPP_API_GetRdbStoreSync(GetRdbStoreSync);
TH_EXPORT_CPP_API_DeleteRdbStoreWithName(DeleteRdbStoreWithName);
TH_EXPORT_CPP_API_DeleteRdbStoreWithConfig(DeleteRdbStoreWithConfig);
// NOLINTEND
