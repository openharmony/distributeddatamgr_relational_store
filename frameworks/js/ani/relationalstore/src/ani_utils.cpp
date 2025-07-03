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

#define LOG_TAG "AniUtils"
#include "ani_utils.h"
#include "asset_value.h"
#include "big_integer.h"
#include "values_bucket.h"
#include "logger.h"

using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;


template<>
bool UnionAccessor::IsInstanceOfType<bool>()
{
    return IsInstanceOf("std.core.Boolean");
}

template<>
bool UnionAccessor::IsInstanceOfType<int>()
{
    return IsInstanceOf("std.core.Int");
}

template<>
bool UnionAccessor::IsInstanceOfType<double>()
{
    return IsInstanceOf("std.core.Double");
}

template<>
bool UnionAccessor::IsInstanceOfType<std::string>()
{
    return IsInstanceOf("std.core.String");
}

template<>
bool UnionAccessor::TryConvertArray<ani_ref>(std::vector<ani_ref> &value)
{
    ani_double length;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        LOG_ERROR("Object_GetPropertyByName_Double length failed");
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref ref;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "i:C{std.core.Object}", &ref, (ani_int)i)) {
            LOG_ERROR("Object_GetPropertyByName_Ref failed");
            return false;
        }
        value.push_back(ref);
    }
    LOG_DEBUG("convert ref array ok.");
    return true;
}

template<>
bool UnionAccessor::TryConvertArray<bool>(std::vector<bool> &value)
{
    ani_double length;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        LOG_ERROR("Object_GetPropertyByName_Double length failed");
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref ref;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "i:C{std.core.Object}", &ref, (ani_int)i)) {
            LOG_ERROR("Object_GetPropertyByName_Ref failed");
            return false;
        }
        ani_boolean val;
        if (ANI_OK != env_->Object_CallMethodByName_Boolean(static_cast<ani_object>(ref), "unboxed", nullptr, &val)) {
            LOG_ERROR("Object_CallMethodByName_Boolean unbox failed");
            return false;
        }
        value.push_back(static_cast<bool>(val));
    }
    LOG_DEBUG("convert bool array ok.");
    return true;
}

template<>
bool UnionAccessor::TryConvertArray<int>(std::vector<int> &value)
{
    ani_double length;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        LOG_ERROR("Object_GetPropertyByName_Double length failed");
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref ref;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "i:C{std.core.Object}", &ref, (ani_int)i)) {
            LOG_ERROR("Object_GetPropertyByName_Ref failed");
            return false;
        }
        ani_int intValue;
        if (ANI_OK != env_->Object_CallMethodByName_Int(static_cast<ani_object>(ref), "unboxed", nullptr, &intValue)) {
            LOG_ERROR("Object_CallMethodByName_Int unbox failed");
            return false;
        }
        value.push_back(static_cast<int>(intValue));
    }
    LOG_DEBUG("convert int array ok.");
    return true;
}

template<>
bool UnionAccessor::TryConvertArray<double>(std::vector<double> &value)
{
    ani_double length;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        LOG_ERROR("Object_GetPropertyByName_Double length failed");
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref ref;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "i:C{std.core.Object}", &ref, (ani_int)i)) {
            LOG_ERROR("Object_GetPropertyByName_Ref failed");
            return false;
        }
        ani_double val;
        if (ANI_OK != env_->Object_CallMethodByName_Double(static_cast<ani_object>(ref), "unboxed", nullptr, &val)) {
            LOG_ERROR("Object_CallMethodByName_Double unbox failed");
            return false;
        }
        value.push_back(static_cast<double>(val));
    }
    LOG_DEBUG("convert double array ok.");
    return true;
}

template<>
bool UnionAccessor::TryConvertArray<uint8_t>(std::vector<uint8_t> &value)
{
    ani_ref buffer;
    if (ANI_OK != env_->Object_GetFieldByName_Ref(obj_, "buffer", &buffer)) {
        LOG_ERROR("Object_GetFieldByName_Ref failed");
        return false;
    }
    void* data;
    size_t size;
    if (ANI_OK != env_->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &data, &size)) {
        LOG_ERROR("ArrayBuffer_GetInfo failed");
        return false;
    }
    for (size_t i = 0; i < size; i++) {
        value.push_back(static_cast<uint8_t*>(data)[i]);
    }
    LOG_DEBUG("convert uint8 array ok.");
    return true;
}

template<>
bool UnionAccessor::TryConvertArray<float>(std::vector<float> &value)
{
    ani_ref buffer;
    if (ANI_OK != env_->Object_GetFieldByName_Ref(obj_, "buffer", &buffer)) {
        LOG_ERROR("Object_GetFieldByName_Ref failed");
        return false;
    }
    void* data;
    size_t size;
    if (ANI_OK != env_->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &data, &size)) {
        LOG_ERROR("ArrayBuffer_GetInfo failed");
        return false;
    }
    auto count = size / sizeof(float);
    for (size_t i = 0; i < count; i++) {
        value.push_back(static_cast<uint8_t*>(data)[i]);
    }
    LOG_DEBUG("convert float array ok.");
    return true;
}

template<>
bool UnionAccessor::TryConvertArray<std::string>(std::vector<std::string> &value)
{
    ani_double length;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        LOG_ERROR("Object_GetPropertyByName_Double length failed");
        return false;
    }

    for (int i = 0; i < int(length); i++) {
        ani_ref ref;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "i:C{std.core.Object}", &ref, (ani_int)i)) {
            LOG_ERROR("Object_CallMethodByName_Ref failed");
            return false;
        }
        value.push_back(AniStringUtils::ToStd(env_, static_cast<ani_string>(ref)));
    }
    LOG_DEBUG("convert string array ok.");
    return true;
}

template<>
bool UnionAccessor::TryConvert<int>(int &value)
{
    if (!IsInstanceOfType<int>()) {
        return false;
    }

    ani_int aniValue;
    auto ret = env_->Object_CallMethodByName_Int(obj_, "unboxed", nullptr, &aniValue);
    if (ret != ANI_OK) {
        return false;
    }
    value = static_cast<int>(aniValue);
    LOG_DEBUG("convert int ok.");
    return true;
}

template<>
bool UnionAccessor::TryConvert<std::monostate>(std::monostate &value)
{
    ani_boolean isNull = false;
    auto status = env_->Reference_IsNull(static_cast<ani_ref>(obj_), &isNull);
    if (ANI_OK == status) {
        if (isNull) {
            value = std::monostate();
            LOG_DEBUG("convert null ok.");
            return true;
        }
    }
    return false;
}

template<>
bool UnionAccessor::TryConvert<int64_t>(int64_t &value)
{
    return false;
}

template<>
bool UnionAccessor::TryConvert<double>(double &value)
{
    if (!IsInstanceOfType<double>()) {
        return false;
    }

    ani_double aniValue;
    auto ret = env_->Object_CallMethodByName_Double(obj_, "unboxed", nullptr, &aniValue);
    if (ret != ANI_OK) {
        return false;
    }
    value = static_cast<double>(aniValue);
    LOG_DEBUG("convert double ok.");
    return true;
}

template<>
bool UnionAccessor::TryConvert<std::string>(std::string &value)
{
    if (!IsInstanceOfType<std::string>()) {
        return false;
    }

    value = AniStringUtils::ToStd(env_, static_cast<ani_string>(obj_));
    LOG_DEBUG("convert string ok.");
    return true;
}

template<>
bool UnionAccessor::TryConvert<bool>(bool &value)
{
    if (!IsInstanceOfType<bool>()) {
        return false;
    }

    ani_boolean aniValue;
    auto ret = env_->Object_CallMethodByName_Boolean(obj_, "unboxed", nullptr, &aniValue);
    if (ret != ANI_OK) {
        return false;
    }
    value = static_cast<bool>(aniValue);
    LOG_DEBUG("convert bool ok.");
    return true;
}

template<>
bool UnionAccessor::TryConvert<std::vector<uint8_t>>(std::vector<uint8_t> &value)
{
    if (!IsInstanceOf("Lescompat/Uint8Array;")) {
        return false;
    }
    return TryConvertArray(value);
}

bool UnionAccessor::GetObjectRefPropertyByName(std::string clsName, const char *name, ani_ref &val)
{
    ani_class cls;
    env_->FindClass(clsName.c_str(), &cls);
    ani_method getter;
    if (ANI_OK != env_->Class_FindGetter(cls, name,  &getter)) {
        LOG_ERROR("GetObjectRefPropertyByName Class_FindGetter failed");
        return false;
    }
    ani_ref ref;
    if (ANI_OK != env_->Object_CallMethod_Ref(obj_, getter, &ref)) {
        LOG_ERROR("GetObjectRefPropertyByName Object_CallMethod_Ref failed");
        return false;
    }
    val = ref;
    return true;
}

bool UnionAccessor::GetObjectStringPropertyByName(std::string clsName, const char *name, std::string &val)
{
    ani_ref ref;
    auto isOk = GetObjectRefPropertyByName(clsName, name, ref);
    if (!isOk) {
        LOG_ERROR("GetObjectRefPropertyByName failed");
        return false;
    }
    val = AniStringUtils::ToStd(env_, static_cast<ani_string>(ref));
    return true;
}

bool UnionAccessor::GetObjectEnumValuePropertyByName(
    std::string clsName, const char *name, ani_int &val, bool optional)
{
    ani_ref ref;
    auto isOk = GetObjectRefPropertyByName(clsName, name, ref);
    if (!isOk) {
        LOG_ERROR("GetObjectRefPropertyByName failed");
        return false;
    }
    if (optional) {
        ani_boolean isUndefined;
        auto err = env_->Reference_IsUndefined(ref, &isUndefined);
        if (err != ANI_OK) {
            LOG_ERROR("Reference_IsUndefined fail.");
            return false;
        }
        if (isUndefined) {
            LOG_DEBUG("Optional enum item undefined.");
            return true;
        }
    }
    ani_int enumValue;
    auto status = env_->EnumItem_GetValue_Int(static_cast<ani_enum_item>(ref), &enumValue);
    if (status != ANI_OK) {
        LOG_ERROR("EnumItem_GetValue_Int failed");
        return false;
    }
    val = enumValue;
    return true;
}

template<>
bool UnionAccessor::TryConvert<AssetValue>(AssetValue &value)
{
    std::string clsName = "@ohos.data.relationalStore.relationalStore.Asset";
    if (!IsInstanceOf(clsName)) {
        return false;
    }
    auto isOk = GetObjectStringPropertyByName(clsName, "name", value.name);
    if (!isOk) {
        return false;
    }
    isOk = GetObjectStringPropertyByName(clsName, "uri", value.uri);
    if (!isOk) {
        return false;
    }
    isOk = GetObjectStringPropertyByName(clsName, "path", value.path);
    if (!isOk) {
        return false;
    }
    isOk = GetObjectStringPropertyByName(clsName, "createTime", value.createTime);
    if (!isOk) {
        return false;
    }
    isOk = GetObjectStringPropertyByName(clsName, "modifyTime", value.modifyTime);
    if (!isOk) {
        return false;
    }
    isOk = GetObjectStringPropertyByName(clsName, "size", value.size);
    if (!isOk) {
        return false;
    }
    ani_int enumVal = 0;
    isOk = GetObjectEnumValuePropertyByName(clsName, "status", enumVal, true);
    if (!isOk) {
        return false;
    }
    value.status = static_cast<AssetValue::Status>(enumVal);
    if (value.status != AssetValue::STATUS_DELETE) {
        value.status = AssetValue::STATUS_UNKNOWN;
    }
    value.hash = value.modifyTime + "_" + value.size;
    LOG_DEBUG("convert asset ok.");
    return true;
}

template<>
bool UnionAccessor::TryConvert<std::vector<AssetValue>>(std::vector<AssetValue> &value)
{
    std::string clsName = "A{C{@ohos.data.relationalStore.relationalStore.Asset}}";
    if (!IsInstanceOf(clsName)) {
        return false;
    }
    ani_size arrayLength;
    auto status = env_->Array_GetLength(static_cast<ani_array>(obj_), &arrayLength);
    if (status != ANI_OK) {
        LOG_ERROR("Array_GetLength failed");
        return false;
    }
    for (int i = 0; i < int(arrayLength); i++) {
        ani_ref result;
        status = env_->Array_Get_Ref(static_cast<ani_array_ref>(obj_), i, &result);
        if (status != ANI_OK) {
            LOG_ERROR("Array_Get_Ref failed");
            return false;
        }
        ani_object asset = static_cast<ani_object>(result);
        UnionAccessor sub(env_, asset);
        AssetValue val;
        auto isOk = sub.TryConvert(val);
        if (!isOk) {
            return false;
        }
        value.push_back(val);
    }
    LOG_DEBUG("convert assets ok.");
    return true;
}

template<>
bool UnionAccessor::TryConvert<std::vector<float>>(std::vector<float> &value)
{
    if (!IsInstanceOf("escompat.Float32Array")) {
        return false;
    }
    return TryConvertArray(value);
}

template<>
bool UnionAccessor::TryConvert<BigInteger>(BigInteger &value)
{
    std::string clsName = "escompat.BigInt";
    ani_class cls;
    auto status = env_->FindClass(clsName.c_str(), &cls);
    if (status != ANI_OK) {
        LOG_ERROR("FindClass failed");
        return false;
    }

    ani_boolean ret;
    env_->Object_InstanceOf(obj_, cls, &ret);
    if (!ret) {
        return false;
    }

    ani_method getLongMethod;
    if (ANI_OK != env_->Class_FindMethod(cls, "getLong", ":l", &getLongMethod)) {
        LOG_ERROR("Class_FindMethod failed");
        return false;
    }

    ani_long longNum;
    if (ANI_OK != env_->Object_CallMethod_Long(obj_, getLongMethod, &longNum)) {
        LOG_ERROR("Object_CallMethod_Long failed");
        return false;
    }
    value = BigInteger(longNum);
    LOG_DEBUG("convert bigint ok.");
    return true;
}

template<>
bool UnionAccessor::TryConvert<std::vector<ani_ref>>(std::vector<ani_ref> &value)
{
    if (!IsInstanceOf("escompat.Array")) {
        return false;
    }
    return TryConvertArray(value);
}

ani_ref UnionAccessor::AniIteratorNext(ani_ref interator, bool &isSuccess)
{
    ani_ref next;
    ani_boolean done;
    if (ANI_OK != env_->Object_CallMethodByName_Ref(static_cast<ani_object>(interator), "next", nullptr, &next)) {
        LOG_ERROR("Failed to get next key");
        isSuccess = false;
        return nullptr;
    }

    if (ANI_OK != env_->Object_GetFieldByName_Boolean(static_cast<ani_object>(next), "done", &done)) {
        LOG_ERROR("Failed to check iterator done");
        isSuccess = false;
        return nullptr;
    }
    if (done) {
        return nullptr;
    }
    return next;
}

template<>
bool UnionAccessor::TryConvert<ValuesBucket>(ValuesBucket &value)
{
    if (!IsInstanceOf("escompat.Record")) {
        return false;
    }
    ani_ref keys;
    auto status = env_->Object_CallMethodByName_Ref(obj_, "keys", ":C{escompat.IterableIterator}", &keys);
    if (status != ANI_OK) {
        LOG_ERROR("Object_CallMethodByName_Ref failed");
    }
    bool success = true;
    ani_ref next = AniIteratorNext(keys, success);
    while (next) {
        ani_ref key_value;
        if (ANI_OK != env_->Object_GetFieldByName_Ref(static_cast<ani_object>(next), "value", &key_value)) {
            LOG_ERROR("Failed to get key value");
            success = false;
            break;
        }

        ani_ref valueObj;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", nullptr, &valueObj, key_value)) {
            LOG_ERROR("Failed to get value for key");
            success = false;
            break;
        }
        ani_object recordValue = static_cast<ani_object>(valueObj);
        UnionAccessor sub(env_, recordValue);
        ValueObject val;
        success = sub.TryConvertVariant(val.value);
        if (success) {
            value.Put(AniStringUtils::ToStd(env_, static_cast<ani_string>(key_value)), val);
        } else {
            LOG_ERROR("Failed to convert AssetValue");
            break;
        }
        next = AniIteratorNext(keys, success);
    }
    return success;
}

template<>
std::optional<double> OptionalAccessor::Convert<double>()
{
    if (IsUndefined()) {
        return std::nullopt;
    }

    ani_double aniValue;
    auto ret = env_->Object_CallMethodByName_Double(obj_, "doubleValue", nullptr, &aniValue);
    if (ret != ANI_OK) {
        return std::nullopt;
    }
    auto value = static_cast<double>(aniValue);
    return value;
}

template<>
std::optional<std::string> OptionalAccessor::Convert<std::string>()
{
    if (IsUndefined()) {
        return std::nullopt;
    }

    ani_size strSize;
    env_->String_GetUTF8Size(static_cast<ani_string>(obj_), &strSize);

    std::vector<char> buffer(strSize + 1);
    char* utf8_buffer = buffer.data();

    ani_size bytes_written = 0;
    env_->String_GetUTF8(static_cast<ani_string>(obj_), utf8_buffer, strSize + 1, &bytes_written);

    utf8_buffer[bytes_written] = '\0';
    std::string content = std::string(utf8_buffer);
    return content;
}

static void CleanNativePtr(ani_env *env, ani_object object)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return;
    }
    ani_long ptr = 0;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "targetPtr", &ptr)) {
        LOG_ERROR("Can not get targetPtr.");
        return;
    }
    delete reinterpret_cast<NativeObject *>(ptr);
}

ani_status CleanerInit(ani_env *env)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return ANI_ERROR;
    }

    ani_class cls;
    const char *className = "@ohos.data.relationalStore.relationalStore.Cleaner;";
    if (ANI_OK != env->FindClass(className, &cls)) {
        LOG_ERROR("Not found '%{public}s", className);
        return ANI_ERROR;
    }

    std::array methods = {
        ani_native_function {"clean", nullptr, reinterpret_cast<void *>(CleanNativePtr)},
    };
    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        LOG_ERROR("Cannot bind native methods to '%{public}s", className);
        return ANI_ERROR;
    }
    return ANI_OK;
}
