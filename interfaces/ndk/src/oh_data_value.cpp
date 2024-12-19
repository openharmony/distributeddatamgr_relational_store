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
#define LOG_TAG "DataValue"

#include "oh_data_value.h"
#include "oh_data_define.h"
#include "relational_store_error_code.h"
#include "relational_asset.h"
#include "logger.h"

using namespace OHOS::RdbNdk;
using namespace OHOS::NativeRdb;

constexpr int32_t TO_OH_TYPE[] = {
    OH_ColumnType::TYPE_NULL,
    OH_ColumnType::TYPE_INT64,
    OH_ColumnType::TYPE_REAL,
    OH_ColumnType::TYPE_TEXT,
    OH_ColumnType::TYPE_INT64,
    OH_ColumnType::TYPE_BLOB,
    OH_ColumnType::TYPE_ASSET,
    OH_ColumnType::TYPE_ASSETS,
    OH_ColumnType::TYPE_FLOAT_VECTOR,
    OH_ColumnType::TYPE_UNLIMITED_INT,
};

static constexpr int32_t TO_OH_TYPE_SIZE = sizeof(TO_OH_TYPE) / sizeof(TO_OH_TYPE[0]);

static int CheckValueType(const OH_Data_Value *value, int32_t type)
{
    if (value == nullptr || !value->IsValid()) {
        return RDB_E_INVALID_ARGS;
    }
    int32_t valueType = value->value_.GetType();
    if (valueType == ValueObject::TYPE_NULL && type == ValueObject::TYPE_NULL) {
        return RDB_OK;
    }
    if (valueType == ValueObject::TYPE_NULL) {
        LOG_ERROR("type mismatch, value type is null, get type=%{public}d", type);
        return RDB_E_DATA_TYPE_NULL;
    }
    if (valueType != type) {
        LOG_ERROR("type mismatch, value type=%{public}d, get type=%{public}d", valueType, type);
        return RDB_E_TYPE_MISMATCH;
    }
    return RDB_OK;
}

OH_Data_Value *OH_Value_Create()
{
    OH_Data_Value *value = new (std::nothrow) OH_Data_Value;
    if (value == nullptr) {
        return nullptr;
    }
    return value;
}

int OH_Value_Destroy(OH_Data_Value *value)
{
    if (value == nullptr || !value->IsValid()) {
        return RDB_E_INVALID_ARGS;
    }
    delete value;
    return RDB_OK;
}

int OH_Value_PutNull(OH_Data_Value *value)
{
    if (value == nullptr || !value->IsValid()) {
        return RDB_E_INVALID_ARGS;
    }
    value->value_.value = ValueObject::Nil{};
    return RDB_OK;
}

int OH_Value_PutInt(OH_Data_Value *value, int64_t val)
{
    if (value == nullptr || !value->IsValid()) {
        return RDB_E_INVALID_ARGS;
    }
    value->value_.value = val;
    return RDB_OK;
}

int OH_Value_PutReal(OH_Data_Value *value, double val)
{
    if (value == nullptr || !value->IsValid()) {
        return RDB_E_INVALID_ARGS;
    }
    value->value_.value = val;
    return RDB_OK;
}

int OH_Value_PutText(OH_Data_Value *value, const char *val)
{
    if (value == nullptr || !value->IsValid()) {
        return RDB_E_INVALID_ARGS;
    }
    value->value_.value = std::string(val);
    return RDB_OK;
}

int OH_Value_PutBlob(OH_Data_Value *value, const unsigned char *val, size_t length)
{
    if (value == nullptr || !value->IsValid() || val == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    value->value_.value = std::vector<uint8_t>{ val, val + length };
    return RDB_OK;
}

int OH_Value_PutAsset(OH_Data_Value *value, const Data_Asset *val)
{
    if (value == nullptr || !value->IsValid() || val == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    value->value_.value = val->asset_;
    return RDB_OK;
}

int OH_Value_PutAssets(OH_Data_Value *value, const Data_Asset * const * val, size_t length)
{
    if (value == nullptr || !value->IsValid() || val == nullptr || length == 0) {
        return RDB_E_INVALID_ARGS;
    }
    ValueObject::Assets assets;
    for (size_t i = 0; i < length; i++) {
        if (val[i] != nullptr) {
            assets.push_back(val[i]->asset_);
        }
    }
    value->value_.value = assets;
    return RDB_OK;
}

int OH_Value_PutFloatVector(OH_Data_Value *value, const float *val, size_t length)
{
    if (value == nullptr || !value->IsValid() || val == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    std::vector<float> valVec = std::vector<float>{ val, val + length };
    value->value_.value = valVec;
    return RDB_OK;
}

int OH_Value_PutUnlimitedInt(OH_Data_Value *value, int sign, const uint64_t *trueForm, size_t length)
{
    if (value == nullptr || !value->IsValid() || (sign != 0 && sign != 1) || trueForm == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    ValueObject::BigInt bigNumber(sign, {trueForm, trueForm + length});
    value->value_.value = bigNumber;
    return RDB_OK;
}

int OH_Value_GetType(OH_Data_Value *value, OH_ColumnType *type)
{
    if (value == nullptr || !value->IsValid() || type == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    auto valueType = value->value_.GetType();
    if (valueType < TO_OH_TYPE_SIZE) {
        *type = static_cast<OH_ColumnType>(TO_OH_TYPE[valueType]);
        return RDB_OK;
    }
    return RDB_E_INVALID_ARGS;
}

int OH_Value_IsNull(OH_Data_Value *value, bool *val)
{
    if (value == nullptr || !value->IsValid() || val == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    *val = (value->value_.GetType() == ValueObject::TYPE_NULL);
    return RDB_OK;
}

int OH_Value_GetInt(OH_Data_Value *value, int64_t *val)
{
    if (val == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    int checkRet = CheckValueType(value, ValueObject::TYPE_INT);
    if (checkRet != RDB_OK) {
        return checkRet;
    }
    *val = value->value_;
    return RDB_OK;
}

int OH_Value_GetReal(OH_Data_Value *value, double *val)
{
    if (val == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    int checkRet = CheckValueType(value, ValueObject::TYPE_DOUBLE);
    if (checkRet != RDB_OK) {
        return checkRet;
    }
    *val = value->value_;
    return RDB_OK;
}

int OH_Value_GetText(OH_Data_Value *value, const char **val)
{
    if (val == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    int checkRet = CheckValueType(value, ValueObject::TYPE_STRING);
    if (checkRet != RDB_OK) {
        return checkRet;
    }
    auto actualValue = std::get_if<std::string>(&value->value_.value);
    if (actualValue == nullptr) {
        return RDB_E_TYPE_MISMATCH;
    }
    *val = actualValue->c_str();
    return RDB_OK;
}

int OH_Value_GetBlob(OH_Data_Value *value, const uint8_t **val, size_t *length)
{
    if (val == nullptr || length == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    int checkRet = CheckValueType(value, ValueObject::TYPE_BLOB);
    if (checkRet != RDB_OK) {
        return checkRet;
    }
    auto actualValue = std::get_if<std::vector<uint8_t>>(&value->value_.value);
    if (actualValue == nullptr) {
        return RDB_E_TYPE_MISMATCH;
    }
    *val = actualValue->data();
    *length = actualValue->size();
    return RDB_OK;
}

int OH_Value_GetAsset(OH_Data_Value *value, Data_Asset *val)
{
    if (val == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    int checkRet = CheckValueType(value, ValueObject::TYPE_ASSET);
    if (checkRet != RDB_OK) {
        return checkRet;
    }
    val->asset_ = std::get<ValueObject::Asset>(value->value_.value);
    return RDB_OK;
}

int OH_Value_GetAssetsCount(OH_Data_Value *value, size_t *size)
{
    if (size == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    int checkRet = CheckValueType(value, ValueObject::TYPE_ASSETS);
    if (checkRet != RDB_OK) {
        return checkRet;
    }
    *size = std::get<ValueObject::Assets>(value->value_.value).size();
    return RDB_OK;
}

int OH_Value_GetAssets(OH_Data_Value *value, Data_Asset **val, size_t inLen, size_t *outLen)
{
    if (val == nullptr || outLen == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    int checkRet = CheckValueType(value, ValueObject::TYPE_ASSETS);
    if (checkRet != RDB_OK) {
        return checkRet;
    }
    for (size_t i = 0; i < inLen; i++) {
        if (val[i] == nullptr || val[i]->cid != DATA_ASSET_V0) {
            return RDB_E_INVALID_ARGS;
        }
    }

    auto asserts = std::get<ValueObject::Assets>(value->value_.value);
    *outLen = 0;
    for (size_t i = 0; i < inLen && i < asserts.size(); i++) {
        if (val[i] != nullptr) {
            val[i]->asset_ = asserts[i];
            (*outLen)++;
        }
    }
    return RDB_OK;
}

int OH_Value_GetFloatVectorCount(OH_Data_Value *value, size_t *length)
{
    if (length == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    int checkRet = CheckValueType(value, ValueObject::TYPE_VECS);
    if (checkRet != RDB_OK) {
        return checkRet;
    }
    *length = std::get<ValueObject::FloatVector>(value->value_.value).size();
    return RDB_OK;
}

int OH_Value_GetFloatVector(OH_Data_Value *value, float *val, size_t inLen, size_t *outLen)
{
    if (val == nullptr || inLen == 0 || outLen == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    int checkRet = CheckValueType(value, ValueObject::TYPE_VECS);
    if (checkRet != RDB_OK) {
        return checkRet;
    }
    auto floatVec = std::get<ValueObject::FloatVector>(value->value_.value);
    *outLen = 0;
    for (size_t i = 0; i < floatVec.size() && i < inLen; i++) {
        val[i] = floatVec[i];
        (*outLen)++;
    }
    return RDB_OK;
}

int OH_Value_GetUnlimitedIntBand(OH_Data_Value *value, size_t *length)
{
    if (length == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    int checkRet = CheckValueType(value, ValueObject::TYPE_BIGINT);
    if (checkRet != RDB_OK) {
        return checkRet;
    }
    *length = std::get<ValueObject::BigInt>(value->value_.value).Size();
    return RDB_OK;
}

int OH_Value_GetUnlimitedInt(OH_Data_Value *value, int *sign, uint64_t *trueForm, size_t inLen, size_t *outLen)
{
    if (sign == nullptr || trueForm == nullptr || inLen == 0 || outLen == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    int checkRet = CheckValueType(value, ValueObject::TYPE_BIGINT);
    if (checkRet != RDB_OK) {
        return checkRet;
    }
    auto bigInt = std::get<ValueObject::BigInt>(value->value_.value);
    if (inLen < bigInt.Size()) {
        return RDB_E_INVALID_ARGS;
    }
    auto numVec = bigInt.Value();
    *outLen = 0;
    for (size_t i = 0; i < numVec.size(); i++) {
        trueForm[i] = numVec[i];
        (*outLen)++;
    }
    *sign = bigInt.Sign();
    return RDB_OK;
}

bool OH_Data_Value::IsValid() const
{
    return id == OH_VALUE_ID;
}