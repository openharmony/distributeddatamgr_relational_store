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
#define LOG_TAG "DataValues"

#include "oh_data_values.h"
#include "oh_data_define.h"
#include "relational_store_error_code.h"
#include "logger.h"

using namespace OHOS::RdbNdk;

static bool IsValidValues(const OH_Data_Values *values)
{
    if (values == nullptr) {
        LOG_ERROR("values is null.");
        return false;
    }
    bool ret = values->IsValid();
    if (!ret) {
        LOG_ERROR("invalid data values object.");
    }
    return ret;
}

static bool IsValidValuesElement(OH_Data_Values *values, int index)
{
    if (!IsValidValues(values) || index < 0 || static_cast<size_t>(index) >= values->values_.size()) {
        return false;
    }
    return true;
}

OH_Data_Values *OH_Values_Create(void)
{
    OH_Data_Values *values = new (std::nothrow) OH_Data_Values;
    return values;
}

int OH_Values_Destroy(OH_Data_Values *values)
{
    if (!IsValidValues(values)) {
        return RDB_E_INVALID_ARGS;
    }
    delete values;
    return RDB_OK;
}

int OH_Values_Put(OH_Data_Values *values, const OH_Data_Value *val)
{
    if (!IsValidValues(values) || (val == nullptr) || !val->IsValid()) {
        return RDB_E_INVALID_ARGS;
    }
    values->values_.push_back(*val);
    return RDB_OK;
}

int OH_Values_PutNull(OH_Data_Values *values)
{
    if (!IsValidValues(values)) {
        return RDB_E_INVALID_ARGS;
    }
    OH_Data_Value nullValue;
    int ret = OH_Value_PutNull(&nullValue);
    if (ret != RDB_OK) {
        return ret;
    }
    values->values_.push_back(nullValue);
    return RDB_OK;
}

int OH_Values_PutInt(OH_Data_Values *values, int64_t val)
{
    if (!IsValidValues(values)) {
        return RDB_E_INVALID_ARGS;
    }
    OH_Data_Value intValue;
    int ret = OH_Value_PutInt(&intValue, val);
    if (ret != RDB_OK) {
        return ret;
    }
    values->values_.push_back(intValue);
    return RDB_OK;
}

int OH_Values_PutReal(OH_Data_Values *values, double val)
{
    if (!IsValidValues(values)) {
        return RDB_E_INVALID_ARGS;
    }
    OH_Data_Value realValue;
    int ret = OH_Value_PutReal(&realValue, val);
    if (ret != RDB_OK) {
        return ret;
    }
    values->values_.push_back(realValue);
    return RDB_OK;
}

int OH_Values_PutText(OH_Data_Values *values, const char *val)
{
    if (!IsValidValues(values)) {
        return RDB_E_INVALID_ARGS;
    }
    OH_Data_Value textValue;
    int ret = OH_Value_PutText(&textValue, val);
    if (ret != RDB_OK) {
        return ret;
    }
    values->values_.push_back(textValue);
    return RDB_OK;
}

int OH_Values_PutBlob(OH_Data_Values *values, const unsigned char *val, size_t length)
{
    if (!IsValidValues(values)) {
        return RDB_E_INVALID_ARGS;
    }
    OH_Data_Value blobValue;
    int ret = OH_Value_PutBlob(&blobValue, val, length);
    if (ret != RDB_OK) {
        return ret;
    }
    values->values_.push_back(blobValue);
    return RDB_OK;
}

int OH_Values_PutAsset(OH_Data_Values *values, const Data_Asset *val)
{
    if (!IsValidValues(values)) {
        return RDB_E_INVALID_ARGS;
    }
    OH_Data_Value assetValue;
    int ret = OH_Value_PutAsset(&assetValue, val);
    if (ret != RDB_OK) {
        return ret;
    }
    values->values_.push_back(assetValue);
    return RDB_OK;
}

int OH_Values_PutAssets(OH_Data_Values *values, const Data_Asset * const * val, size_t length)
{
    if (!IsValidValues(values)) {
        return RDB_E_INVALID_ARGS;
    }
    OH_Data_Value assetsValue;
    int ret = OH_Value_PutAssets(&assetsValue, val, length);
    if (ret != RDB_OK) {
        return ret;
    }
    values->values_.push_back(assetsValue);
    return RDB_OK;
}

int OH_Values_PutFloatVector(OH_Data_Values *values, const float *val, size_t length)
{
    if (!IsValidValues(values)) {
        return RDB_E_INVALID_ARGS;
    }
    OH_Data_Value floatVectorValue;
    int ret = OH_Value_PutFloatVector(&floatVectorValue, val, length);
    if (ret != RDB_OK) {
        return ret;
    }
    values->values_.push_back(floatVectorValue);
    return RDB_OK;
}

int OH_Values_PutUnlimitedInt(OH_Data_Values *values, int sign, const uint64_t *trueForm, size_t length)
{
    if (!IsValidValues(values)) {
        return RDB_E_INVALID_ARGS;
    }
    OH_Data_Value unlimitedIntValue;
    int ret = OH_Value_PutUnlimitedInt(&unlimitedIntValue, sign, trueForm, length);
    if (ret != RDB_OK) {
        return ret;
    }
    values->values_.push_back(unlimitedIntValue);
    return RDB_OK;
}

int OH_Values_Count(OH_Data_Values *values, size_t *count)
{
    if (!IsValidValues(values) || count == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    *count = values->values_.size();
    return RDB_OK;
}

int OH_Values_GetType(OH_Data_Values *values, int index, OH_ColumnType *type)
{
    if (!IsValidValuesElement(values, index)) {
        return RDB_E_INVALID_ARGS;
    }
    return OH_Value_GetType(&values->values_[index], type);
}

int OH_Values_Get(OH_Data_Values *values, int index, OH_Data_Value **val)
{
    if (!IsValidValuesElement(values, index) || val == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    *val = &values->values_[index];
    return RDB_OK;
}

int OH_Values_IsNull(OH_Data_Values *values, int index, bool *val)
{
    if (!IsValidValuesElement(values, index)) {
        return RDB_E_INVALID_ARGS;
    }
    return OH_Value_IsNull(&values->values_[index], val);
}

int OH_Values_GetInt(OH_Data_Values *values, int index, int64_t *val)
{
    if (!IsValidValuesElement(values, index)) {
        return RDB_E_INVALID_ARGS;
    }
    return OH_Value_GetInt(&values->values_[index], val);
}

int OH_Values_GetReal(OH_Data_Values *values, int index, double *val)
{
    if (!IsValidValuesElement(values, index)) {
        return RDB_E_INVALID_ARGS;
    }
    return OH_Value_GetReal(&values->values_[index], val);
}

int OH_Values_GetText(OH_Data_Values *values, int index, const char **val)
{
    if (!IsValidValuesElement(values, index)) {
        return RDB_E_INVALID_ARGS;
    }
    return OH_Value_GetText(&values->values_[index], val);
}

int OH_Values_GetBlob(OH_Data_Values *values, int index, const uint8_t **val, size_t *length)
{
    if (!IsValidValuesElement(values, index)) {
        return RDB_E_INVALID_ARGS;
    }
    return OH_Value_GetBlob(&values->values_[index], val, length);
}

int OH_Values_GetAsset(OH_Data_Values *values, int index, Data_Asset *val)
{
    if (!IsValidValuesElement(values, index)) {
        return RDB_E_INVALID_ARGS;
    }
    return OH_Value_GetAsset(&values->values_[index], val);
}

int OH_Values_GetAssetsCount(OH_Data_Values *values, int index, size_t *length)
{
    if (!IsValidValuesElement(values, index)) {
        return RDB_E_INVALID_ARGS;
    }
    return OH_Value_GetAssetsCount(&values->values_[index], length);
}

int OH_Values_GetAssets(OH_Data_Values *values, int index, Data_Asset **val, size_t inLen, size_t *outLen)
{
    if (!IsValidValuesElement(values, index)) {
        return RDB_E_INVALID_ARGS;
    }
    return OH_Value_GetAssets(&values->values_[index], val, inLen, outLen);
}

int OH_Values_GetFloatVectorCount(OH_Data_Values *values, int index, size_t *length)
{
    if (!IsValidValuesElement(values, index)) {
        return RDB_E_INVALID_ARGS;
    }
    return OH_Value_GetFloatVectorCount(&values->values_[index], length);
}

int OH_Values_GetFloatVector(OH_Data_Values *values, int index, float *val, size_t inLen, size_t *outLen)
{
    if (!IsValidValuesElement(values, index)) {
        return RDB_E_INVALID_ARGS;
    }
    return OH_Value_GetFloatVector(&values->values_[index], val, inLen, outLen);
}

int OH_Values_GetUnlimitedIntBand(OH_Data_Values *values, int index, size_t *length)
{
    if (!IsValidValuesElement(values, index)) {
        return RDB_E_INVALID_ARGS;
    }
    return OH_Value_GetUnlimitedIntBand(&values->values_[index], length);
}

int OH_Values_GetUnlimitedInt(OH_Data_Values *values, int index, int *sign, uint64_t *trueForm, size_t inLen,
    size_t *outLen)
{
    if (!IsValidValuesElement(values, index)) {
        return RDB_E_INVALID_ARGS;
    }
    return OH_Value_GetUnlimitedInt(&values->values_[index], sign, trueForm, inLen, outLen);
}

bool OH_Data_Values::IsValid() const
{
    return id == OH_VALUES_ID;
}