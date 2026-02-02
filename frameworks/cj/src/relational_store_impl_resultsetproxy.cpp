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

#include "relational_store_impl_resultsetproxy.h"
#include "relational_store_utils.h"
#include "napi_rdb_error.h"
#include "value_object.h"
#include "native_log.h"
#include "js_utils.h"
#include "rdb_errno.h"

namespace OHOS {
namespace Relational {
static const int E_OK = 0;

ResultSetImpl::ResultSetImpl(std::shared_ptr<NativeRdb::ResultSet> resultSet)
{
    resultSetValue = resultSet;
}

OHOS::FFI::RuntimeType* ResultSetImpl::GetClassType()
{
    static OHOS::FFI::RuntimeType runtimeType = OHOS::FFI::RuntimeType::Create<OHOS::FFI::FFIData>("ResultSetImpl");
    return &runtimeType;
}

CArrStr ResultSetImpl::GetAllColumnNames()
{
    std::vector<std::string> colNames;
    int errCode = resultSetValue->GetAllColumnNames(colNames);
    if (errCode != RelationalStoreJsKit::OK) {
        LOGE("GetAllColumnNames failed code: %{public}d", errCode);
        return CArrStr{nullptr, 0};
    }
    if (colNames.size() == 0) {
        return CArrStr{nullptr, 0};
    }
    char** result = static_cast<char**>(malloc(colNames.size() * sizeof(char*)));
    if (result == nullptr) {
        return CArrStr{nullptr, -1};
    }
    for (size_t i = 0; i < colNames.size(); i++) {
        result[i] = MallocCString(colNames[i]);
        if (result[i] == nullptr) {
            for (size_t j = 0; j < i; j++) {
                free(result[j]);
            }
            free(result);
            return CArrStr{nullptr, -1};
        }
    }
    return CArrStr{result, int64_t(colNames.size())};
}

int32_t ResultSetImpl::GetColumnCount()
{
    int32_t count = 0;
    int errCode = resultSetValue->GetColumnCount(count);
    if (errCode != RelationalStoreJsKit::OK) {
        LOGE("GetColumnCount failed code:%{public}d", errCode);
    }
    return count;
}

int32_t ResultSetImpl::GetRowCount()
{
    int32_t result;
    int errCode = resultSetValue->GetRowCount(result);
    if (errCode != RelationalStoreJsKit::OK) {
        LOGE("GetRowCount failed code:%{public}d", errCode);
    }
    return result;
}

int32_t ResultSetImpl::GetRowIndex()
{
    int32_t result;
    int errCode = resultSetValue->GetRowIndex(result);
    if (errCode != RelationalStoreJsKit::OK) {
        LOGE("GetRowIndex failed code:%{public}d", errCode);
    }
    return result;
}

bool ResultSetImpl::IsAtFirstRow()
{
    bool result = false;
    int errCode = resultSetValue->IsAtFirstRow(result);
    if (errCode != RelationalStoreJsKit::OK) {
        LOGE("IsAtFirstRow failed code:%{public}d", errCode);
    }
    return result;
}

bool ResultSetImpl::IsAtLastRow()
{
    bool result = false;
    int errCode = resultSetValue->IsAtLastRow(result);
    if (errCode != RelationalStoreJsKit::OK) {
        LOGE("IsAtLastRow failed code:%{public}d", errCode);
    }
    return result;
}

bool ResultSetImpl::IsEnded()
{
    bool result = false;
    int errCode = resultSetValue->IsEnded(result);
    if (errCode != RelationalStoreJsKit::OK) {
        LOGE("IsEnded failed code:%{public}d", errCode);
        result = true;
    }
    return result;
}

bool ResultSetImpl::IsStarted()
{
    bool result = false;
    int errCode = resultSetValue->IsStarted(result);
    if (errCode != RelationalStoreJsKit::OK) {
        LOGE("IsBegin failed code:%{public}d", errCode);
    }
    return result;
}

bool ResultSetImpl::IsClosed()
{
    return resultSetValue->IsClosed();
}

double ResultSetImpl::GetDouble(int32_t columnIndex, int32_t* rtnCode)
{
    double result = 0.0;
    *rtnCode = resultSetValue->GetDouble(columnIndex, result);
    return result;
}

bool ResultSetImpl::GoToRow(int32_t position, int32_t* rtnCode)
{
    *rtnCode = resultSetValue->GoToRow(position);
    return *rtnCode == RelationalStoreJsKit::OK;
}

bool ResultSetImpl::GoToPreviousRow(int32_t* rtnCode)
{
    *rtnCode = resultSetValue->GoToPreviousRow();
    return *rtnCode == RelationalStoreJsKit::OK;
}

bool ResultSetImpl::GoToLastRow(int32_t* rtnCode)
{
    *rtnCode = resultSetValue->GoToLastRow();
    return *rtnCode == RelationalStoreJsKit::OK;
}

char* ResultSetImpl::GetColumnName(int32_t columnIndex, int32_t* rtnCode)
{
    std::string result;
    *rtnCode = resultSetValue->GetColumnName(columnIndex, result);
    if (*rtnCode != RelationalStoreJsKit::OK) {
        LOGE("IsAtLastRow failed code:%{public}d", *rtnCode);
    }
    return MallocCString(result);
}

bool ResultSetImpl::IsColumnNull(int32_t columnIndex, int32_t* rtnCode)
{
    bool result;
    *rtnCode = resultSetValue->IsColumnNull(columnIndex, result);
    return result;
}

Asset ResultSetImpl::GetAsset(int32_t columnIndex, int32_t* rtnCode)
{
    NativeRdb::ValueObject::Asset asset;
    *rtnCode = resultSetValue->GetAsset(columnIndex, asset);
    if (*rtnCode != RelationalStoreJsKit::OK) {
        return Asset{nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, 0};
    }
    Asset result = {
        .name= MallocCString(asset.name),
        .uri= MallocCString(asset.uri),
        .path= MallocCString(asset.path),
        .createTime= MallocCString(asset.createTime),
        .modifyTime= MallocCString(asset.modifyTime),
        .size= MallocCString(asset.size),
        .status= (int32_t)asset.status
    };
    return result;
}

int32_t ResultSetImpl::Close()
{
    return resultSetValue->Close();
}

int32_t ResultSetImpl::GetColumnIndex(char* columnName, int32_t* rtnCode)
{
    int32_t result = -1;
    *rtnCode = resultSetValue->GetColumnIndex(columnName, result);
    // If the API version is less than 13, directly return.
    if (AppDataMgrJsKit::JSUtils::GetHapVersion() < 13 || (*rtnCode == NativeRdb::E_INVALID_ARGS)) {
        *rtnCode = E_OK;
    }
    return result;
}

char* ResultSetImpl::GetString(int32_t columnIndex, int32_t* rtnCode)
{
    std::string result;
    *rtnCode = resultSetValue->GetString(columnIndex, result);
    return MallocCString(result);
}

bool ResultSetImpl::GoToFirstRow(int32_t* rtnCode)
{
    *rtnCode = resultSetValue->GoToFirstRow();
    return *rtnCode == RelationalStoreJsKit::OK;
}

int64_t ResultSetImpl::GetLong(int32_t columnIndex, int32_t* rtnCode)
{
    int64_t result;
    *rtnCode = resultSetValue->GetLong(columnIndex, result);
    return result;
}

bool ResultSetImpl::GoToNextRow(int32_t* rtnCode)
{
    *rtnCode = resultSetValue->GoToNextRow();
    return *rtnCode == RelationalStoreJsKit::OK;
}

CArrUI8 ResultSetImpl::GetBlob(int32_t columnIndex, int32_t* rtnCode)
{
    std::vector<uint8_t> vec;
    *rtnCode = resultSetValue->GetBlob(columnIndex, vec);
    if (*rtnCode != RelationalStoreJsKit::OK || vec.size() == 0) {
        return CArrUI8{nullptr, 0};
    }
    uint8_t* result = static_cast<uint8_t*>(malloc(vec.size() * sizeof(uint8_t)));
    if (result == nullptr) {
        return CArrUI8{nullptr, -1};
    }
    for (size_t i = 0; i < vec.size(); i++) {
        result[i] = vec[i];
    }
    return CArrUI8{result, int64_t(vec.size())};
}

bool ResultSetImpl::GoTo(int32_t offset, int32_t* rtnCode)
{
    *rtnCode = resultSetValue->GoTo(offset);
    return *rtnCode == RelationalStoreJsKit::OK;
}

Assets ResultSetImpl::GetAssets(int32_t columnIndex, int32_t* rtnCode)
{
    std::vector<NativeRdb::ValueObject::Asset> assets;
    *rtnCode = resultSetValue->GetAssets(columnIndex, assets);
    if (*rtnCode != RelationalStoreJsKit::OK || assets.size() == 0) {
        return Assets{nullptr, 0};
    }
    Asset* result = static_cast<Asset*>(malloc(assets.size() * sizeof(Asset)));
    if (result == nullptr) {
        return Assets{nullptr, -1};
    }
    for (size_t i = 0; i < assets.size(); i++) {
        result[i] = Asset {
            .name= MallocCString(assets[i].name),
            .uri= MallocCString(assets[i].uri),
            .path= MallocCString(assets[i].path),
            .createTime= MallocCString(assets[i].createTime),
            .modifyTime= MallocCString(assets[i].modifyTime),
            .size= MallocCString(assets[i].size),
            .status= (int32_t)assets[i].status
        };
    }
    return Assets{.head = result, .size = (int64_t)(assets.size())};
}

ValuesBucket ResultSetImpl::GetRow(int32_t* rtnCode)
{
    NativeRdb::RowEntity rowEntity;
    *rtnCode = resultSetValue->GetRow(rowEntity);
    if (*rtnCode != E_OK) {
        return ValuesBucket{nullptr, nullptr, 0};
    }
    const std::map<std::string, NativeRdb::ValueObject> map = rowEntity.Get();
    size_t size = map.size();
    if (size == 0) {
        return ValuesBucket{nullptr, nullptr, 0};
    }
    ValuesBucket result = ValuesBucket {
        .key = static_cast<char**>(malloc(sizeof(char*) * size)),
        .value = static_cast<ValueType*>(malloc(sizeof(ValueType) * size)),
        .size = size
    };
    if (result.key == nullptr || result.value == nullptr) {
        free(result.key);
        free(result.value);
        return ValuesBucket{nullptr, nullptr, -1};
    }
    int64_t i = 0;
    for (auto &t : map) {
        result.key[i] = MallocCString(t.first);
        result.value[i] = ValueObjectToValueType(t.second);
        i++;
    }
    return result;
}

ValuesBucketEx ResultSetImpl::GetRowEx(int32_t* rtnCode)
{
    NativeRdb::RowEntity rowEntity;
    *rtnCode = resultSetValue->GetRow(rowEntity);
    if (*rtnCode != E_OK) {
        return ValuesBucketEx{nullptr, nullptr, 0};
    }
    const std::map<std::string, NativeRdb::ValueObject> map = rowEntity.Get();
    size_t size = map.size();
    if (size == 0) {
        return ValuesBucketEx{nullptr, nullptr, 0};
    }
    ValuesBucketEx result = ValuesBucketEx {
        .key = static_cast<char**>(malloc(sizeof(char*) * size)),
        .value = static_cast<ValueTypeEx*>(malloc(sizeof(ValueTypeEx) * size)),
        .size = size
    };
    if (result.key == nullptr || result.value == nullptr) {
        free(result.key);
        free(result.value);
        return ValuesBucketEx{nullptr, nullptr, ERROR_VALUE};
    }
    int64_t i = 0;
    for (auto &t : map) {
        result.key[i] = MallocCString(t.first);
        result.value[i] = ValueObjectToValueTypeEx(t.second);
        i++;
    }
    return result;
}

ValueTypeEx ResultSetImpl::GetValue(int32_t columnIndex, int32_t* rtnCode)
{
    NativeRdb::ValueObject object;
    *rtnCode = NativeRdb::E_ALREADY_CLOSED;
    if (resultSetValue != nullptr) {
        *rtnCode = resultSetValue->Get(columnIndex, object);
    }
    if (*rtnCode != E_OK) {
        return ValueTypeEx{ 0 };
    }
    return ValueObjectToValueTypeEx(object);
}
}
}