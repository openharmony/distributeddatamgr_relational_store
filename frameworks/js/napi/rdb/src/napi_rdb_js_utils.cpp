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
#define LOG_TAG "NapiRdbJsUtils"
#include "napi_rdb_js_utils.h"

#include "logger.h"
#include "result_set.h"

namespace OHOS::AppDataMgrJsKit {
namespace JSUtils {
using namespace OHOS::Rdb;
using namespace NativeRdb;

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, Asset &output)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, jsValue, &type);
    if (status != napi_ok || type != napi_object) {
        LOG_DEBUG("napi_typeof failed status = %{public}d type = %{public}d", status, type);
        return napi_invalid_arg;
    }

    NAPI_CALL_BASE(env, GetNamedProperty(env, jsValue, "version", output.version), napi_invalid_arg);
    NAPI_CALL_BASE(env, GetNamedProperty(env, jsValue, "name", output.name), napi_invalid_arg);
    NAPI_CALL_BASE(env, GetNamedProperty(env, jsValue, "uri", output.uri), napi_invalid_arg);
    NAPI_CALL_BASE(env, GetNamedProperty(env, jsValue, "createTime", output.createTime), napi_invalid_arg);
    NAPI_CALL_BASE(env, GetNamedProperty(env, jsValue, "modifyTime", output.modifyTime), napi_invalid_arg);
    NAPI_CALL_BASE(env, GetNamedProperty(env, jsValue, "size", output.size), napi_invalid_arg);
    NAPI_CALL_BASE(env, GetNamedProperty(env, jsValue, "hash", output.hash), napi_invalid_arg);
    return napi_ok;
}

template<>
napi_value Convert2JSValue(napi_env env, const Asset &value)
{
    napi_value object = nullptr;
    NAPI_CALL_BASE(env, napi_create_object(env, &object), object);
    NAPI_CALL_BASE(env, SetNamedProperty(env, object, "version", value.version), object);
    NAPI_CALL_BASE(env, SetNamedProperty(env, object, "name", value.name), object);
    NAPI_CALL_BASE(env, SetNamedProperty(env, object, "uri", value.uri), object);
    NAPI_CALL_BASE(env, SetNamedProperty(env, object, "createTime", value.createTime), object);
    NAPI_CALL_BASE(env, SetNamedProperty(env, object, "modifyTime", value.modifyTime), object);
    NAPI_CALL_BASE(env, SetNamedProperty(env, object, "size", value.size), object);
    NAPI_CALL_BASE(env, SetNamedProperty(env, object, "hash", value.hash), object);
    return object;
}

template<>
napi_value Convert2JSValue(napi_env env, const RowEntity &rowEntity)
{
    napi_value ret = nullptr;
    NAPI_CALL(env, napi_create_object(env, &ret));
    auto &values = rowEntity.Get();
    for (auto const &[key, object] : values) {
        napi_value value = JSUtils::Convert2JSValue(env, object.value);
        NAPI_CALL(env, napi_set_named_property(env, ret, key.c_str(), value));
    }
    return ret;
}

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, ValueObject &valueObject)
{
    auto status = Convert2Value(env, jsValue, valueObject.value);
    if (status != napi_ok) {
        return napi_invalid_arg;
    }
    return napi_ok;
}

template<>
napi_value Convert2JSValue(napi_env env, const BigInt& value)
{
    napi_value val = nullptr;
    napi_status status = napi_create_bigint_words(env, value.Sign(), value.Size(), value.TrueForm(), &val);
    if (status != napi_ok) {
        return nullptr;
    }
    return val;
}

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, BigInt& value)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, jsValue, &type);
    if (status != napi_ok || type != napi_bigint) {
        return napi_invalid_arg;
    }
    int sign = 0;
    size_t count = 0;
    status = napi_get_value_bigint_words(env, jsValue, nullptr, &count, nullptr);
    if (status != napi_ok) {
        return napi_bigint_expected;
    }
    std::vector<uint64_t> words(count, 0);
    status = napi_get_value_bigint_words(env, jsValue, &sign, &count, words.data());
    if (status != napi_ok) {
        return napi_bigint_expected;
    }
    value = BigInteger(sign, std::move(words));
    return napi_ok;
}
}; // namespace JSUtils
} // namespace OHOS::AppDataMgrJsKit