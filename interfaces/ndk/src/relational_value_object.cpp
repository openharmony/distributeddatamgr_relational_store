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

#include "oh_value_object.h"
#include "relational_value_object_impl.h"
#include "relational_error_code.h"
#include "logger.h"

using OHOS::RdbNdk::RDB_NDK_LABEL;

int Rdb_ValueObject_PutInt64(OH_VObject *valueObject, int64_t *value, uint32_t count)
{
    if (valueObject == nullptr || value == nullptr || valueObject->id != OHOS::RdbNdk::RDB_VOBJECT_CID) {
        LOG_ERROR("Parameters set error:valueObject is NULL ? %{public}d, value is NULL ? %{public}d",
            (valueObject == nullptr), (value == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }

    auto vObject = static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject);
    vObject->getValue().clear();
    if (count == 1) {
        vObject->getValue().push_back(std::to_string(*value));
    } else {
        for (uint32_t i = 0; i < count; i++) {
            vObject->getValue().push_back(std::to_string(value[i]));
        }
    };
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int Rdb_ValueObject_PutDouble(OH_VObject *valueObject, double *value, uint32_t count)
{
    if (valueObject == nullptr || value == nullptr || valueObject->id != OHOS::RdbNdk::RDB_VOBJECT_CID) {
        LOG_ERROR("Parameters set error:valueObject is NULL ? %{public}d, value is NULL ? %{public}d",
            (valueObject == nullptr), (value == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }

    auto vObject = static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject);
    vObject->getValue().clear();
    if (count == 1) {
        vObject->getValue().push_back(std::to_string(*value));
    } else {
        for (uint32_t i = 0; i < count; i++) {
            vObject->getValue().push_back(std::to_string(value[i]));
        }
    }
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int Rdb_ValueObject_PutText(OH_VObject *valueObject, const char *value)
{
    if (valueObject == nullptr || value == nullptr || valueObject->id != OHOS::RdbNdk::RDB_VOBJECT_CID) {
        LOG_ERROR("Parameters set error:valueObject is NULL ? %{public}d, value is NULL ? %{public}d",
            (valueObject == nullptr), (value == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }

    std::string textValue(value);
    auto vObject = static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject);
    vObject->getValue().clear();
    vObject->getValue().push_back(textValue);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int Rdb_ValueObject_PutTexts(OH_VObject *valueObject, const char **value, uint32_t count)
{
    if (valueObject == nullptr || value == nullptr || valueObject->id != OHOS::RdbNdk::RDB_VOBJECT_CID) {
        LOG_ERROR("Parameters set error:valueObject is NULL ? %{public}d, value is NULL ? %{public}d",
            (valueObject == nullptr), (value == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }

    auto vObject = static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject);
    vObject->getValue().clear();
    for (uint32_t i = 0; i < count; i++) {
        std::string textValue(value[i]);
        vObject->getValue().push_back(textValue);
    }
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int Rdb_DestroyValueObject(OH_VObject *valueObject)
{
    if (valueObject == nullptr || valueObject->id != OHOS::RdbNdk::RDB_VOBJECT_CID) {
        LOG_ERROR("Parameters set error:valueObject is NULL ? %{public}d", (valueObject == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    delete static_cast<OHOS::RdbNdk::ValueObjectImpl *>(valueObject);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

OHOS::RdbNdk::ValueObjectImpl::ValueObjectImpl()
{
    id = RDB_VOBJECT_CID;
    putInt64 = Rdb_ValueObject_PutInt64;
    putDouble = Rdb_ValueObject_PutDouble;
    putText = Rdb_ValueObject_PutText;
    putTexts = Rdb_ValueObject_PutTexts;
    destroyValueObject = Rdb_DestroyValueObject;
}

std::vector<std::string> &OHOS::RdbNdk::ValueObjectImpl::getValue()
{
    return value;
}