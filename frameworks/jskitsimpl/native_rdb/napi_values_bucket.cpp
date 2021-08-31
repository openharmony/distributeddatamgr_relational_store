/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "napi_values_bucket.h"

#include "js_utils.h"
#include "value_object.h"

namespace OHOS {
namespace RdbJsKit {
napi_value ValuesBucketProxy::Convert2JSValue(napi_env env)
{
    napi_value ret;
    NAPI_CALL(env, napi_create_object(env, &ret));
    std::map<std::string, NativeRdb::ValueObject> valuesMap;
    valuesBucket_.GetAll(valuesMap);
    std::map<std::string, NativeRdb::ValueObject>::iterator it;
    for (it = valuesMap.begin(); it != valuesMap.end(); it++) {
        std::string key = it->first;
        auto valueObject = it->second;
        napi_value value = nullptr;
        switch (valueObject.GetType()) {
            case NativeRdb::ValueObjectType::TYPE_NULL: {
                value = nullptr;
            } break;
            case NativeRdb::ValueObjectType::TYPE_INT: {
                int64_t intVal = 0;
                valueObject.GetLong(intVal);
                value = JsKit::JSUtils::Convert2JSValue(env, intVal);
            } break;
            case NativeRdb::ValueObjectType::TYPE_DOUBLE: {
                double doubleVal = 0L;
                valueObject.GetDouble(doubleVal);
                value = JsKit::JSUtils::Convert2JSValue(env, doubleVal);
            } break;
            case NativeRdb::ValueObjectType::TYPE_BLOB: {
                std::vector<uint8_t> blobVal;
                valueObject.GetBlob(blobVal);
                value = JsKit::JSUtils::Convert2JSValue(env, blobVal);
            } break;
            case NativeRdb::ValueObjectType::TYPE_BOOL: {
                bool boolVal = false;
                valueObject.GetBool(boolVal);
                value = JsKit::JSUtils::Convert2JSValue(env, boolVal);
            } break;
            default: {
                std::string strVal = "";
                valueObject.GetString(strVal);
                value = JsKit::JSUtils::Convert2JSValue(env, strVal);
            } break;
        }
        NAPI_CALL(env, napi_set_named_property(env, ret, key.c_str(), value));
    }

    return ret;
}
} // namespace RdbJsKit
} // namespace OHOS