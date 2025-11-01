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

#include <ani_signature_builder.h>

#include "asset_value.h"
#include "big_integer.h"
#include "logger.h"
#include "securec.h"
#include "values_bucket.h"
using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;
using namespace arkts::ani_signature;

namespace ani_utils {
inline ani_status HandlePropertyError(
    ani_status status, const char *property, ErrorHandling handling, const char *type_name)
{
    return PropertyErrorHandler::HandleError(status, property, handling, type_name);
}

ani_status AniGetProperty(
    ani_env *env, ani_object ani_obj, const char *property, std::string &result, ErrorHandling handling)
{
    ani_object property_obj;
    ani_status status = AniGetPropertyImpl<ani_object, ani_ref>(
        env, ani_obj, property, property_obj, handling, &ani_env::Object_GetPropertyByName_Ref);
    if (status != ANI_OK) {
        return status;
    }
    result = AniStringUtils::ToStd(env, reinterpret_cast<ani_string>(property_obj));
    return status;
}

ani_status GetEnumValueInt(
    ani_env *env, ani_object ani_obj, const char *property, int32_t &result, ErrorHandling handling)
{
    ani_object property_obj;
    ani_status status = AniGetPropertyImpl<ani_object, ani_ref>(
        env, ani_obj, property, property_obj, handling, &ani_env::Object_GetPropertyByName_Ref);
    if (status != ANI_OK) {
        return status;
    }
    status = env->EnumItem_GetValue_Int(static_cast<ani_enum_item>(property_obj), &result);
    if (status != ANI_OK) {
        return HandlePropertyError(status, property, handling, GetTypeName<ani_enum_item>());
    }
    return ANI_OK;
}
ani_status AniGetProperty(ani_env *env, ani_object ani_obj, const char *property, bool &result, ErrorHandling handling)
{
    return AniGetPropertyImpl<bool, ani_boolean>(
        env, ani_obj, property, result, handling, &ani_env::Object_GetPropertyByName_Boolean);
}

ani_status AniGetProperty(
    ani_env *env, ani_object ani_obj, const char *property, int32_t &result, ErrorHandling handling)
{
    return AniGetPropertyImpl<int32_t, ani_int>(
        env, ani_obj, property, result, handling, &ani_env::Object_GetPropertyByName_Int);
}

ani_status AniGetProperty(
    ani_env *env, ani_object ani_obj, const char *property, uint32_t &result, ErrorHandling handling)
{
    return AniGetPropertyImpl<uint32_t, ani_int>(
        env, ani_obj, property, result, handling, &ani_env::Object_GetPropertyByName_Int);
}

ani_status AniGetProperty(
    ani_env *env, ani_object ani_obj, const char *property, ani_object &result, ErrorHandling handling)
{
    return AniGetPropertyImpl<ani_object, ani_ref>(
        env, ani_obj, property, result, handling, &ani_env::Object_GetPropertyByName_Ref);
}

ani_status PropertyErrorHandler::HandleError(
    ani_status status, const char *property, ErrorHandling handling, const char *type_name)
{
    switch (status) {
        case ANI_OK:
            return ANI_OK;
        case ANI_NOT_FOUND:
            return PropertyErrorHandler::HandleNotFound(property, handling, type_name);
        default:
            return PropertyErrorHandler::HandleSystemError(status, property, type_name);
    }
}

ani_status PropertyErrorHandler::HandleNotFound(const char *property, ErrorHandling handling, const char *type_name)
{
    if (handling == ErrorHandling::OPTIONAL) {
        return ANI_OK;
    } else {
        LOG_ERROR("Required %{public}s property '%{public}s' not found", type_name, property);
        return ANI_NOT_FOUND;
    }
}

ani_status PropertyErrorHandler::HandleSystemError(ani_status status, const char *property, const char *type_name)
{
    LOG_ERROR("System error getting %{public}s property '%{public}s': %{public}d", type_name, property, status);
    return status;
}

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
    ani_double length = 0;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        LOG_ERROR("Object_GetPropertyByName_Double length failed");
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref ref;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "i:Y", &ref, (ani_int)i)) {
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
    ani_double length = 0;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        LOG_ERROR("Object_GetPropertyByName_Double length failed");
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref ref;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "i:Y", &ref, (ani_int)i)) {
            LOG_ERROR("Object_GetPropertyByName_Ref failed");
            return false;
        }
        ani_boolean val = false;
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
    ani_double length = 0;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        LOG_ERROR("Object_GetPropertyByName_Double length failed");
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref ref;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "i:Y", &ref, (ani_int)i)) {
            LOG_ERROR("Object_GetPropertyByName_Ref failed");
            return false;
        }
        ani_int intValue = 0;
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
    ani_double length = 0;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        LOG_ERROR("Object_GetPropertyByName_Double length failed");
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref ref;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "i:Y", &ref, (ani_int)i)) {
            LOG_ERROR("Object_GetPropertyByName_Ref failed");
            return false;
        }
        ani_double val = 0;
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
    void *data = nullptr;
    size_t size = 0;
    if (ANI_OK != env_->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &data, &size)) {
        LOG_ERROR("ArrayBuffer_GetInfo failed");
        return false;
    }
    const size_t old_size = value.size();
    value.resize(old_size + size);
    errno_t result = memcpy_s(value.data() + old_size, size, data, size);
    if (result != 0) {
        LOG_ERROR("memcpy_s failed with error: %{public}d", result);
        return false;
    }
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
    void *data = nullptr;
    size_t size = 0;
    if (ANI_OK != env_->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &data, &size)) {
        LOG_ERROR("ArrayBuffer_GetInfo failed");
        return false;
    }
    if (data == nullptr) {
        LOG_ERROR("ArrayBuffer data is null");
        return false;
    }
    if (size == 0) {
        LOG_DEBUG("ArrayBuffer is empty");
        return true;
    }
    if (size % sizeof(float) != 0) {
        LOG_ERROR("ArrayBuffer size %{public}zu is not multiple of float size %{public}zu", size, sizeof(float));
        return false;
    }
    value = (data != nullptr
                 ? std::vector<float>(static_cast<float *>(data), static_cast<float *>(data) + size / sizeof(float))
                 : std::vector<float>());
    return true;
}

template<>
bool UnionAccessor::TryConvertArray<std::string>(std::vector<std::string> &value)
{
    ani_double length = 0;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        LOG_ERROR("Object_GetPropertyByName_Double length failed");
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref ref;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "i:Y", &ref, (ani_int)i)) {
            LOG_ERROR("Object_CallMethodByName_Ref failed");
            return false;
        }
        value.push_back(AniStringUtils::ToStd(env_, static_cast<ani_string>(ref)));
    }
    return true;
}

template<>
bool UnionAccessor::TryConvert<int>(int &value)
{
    if (!IsInstanceOfType<int>()) {
        return false;
    }
    ani_int aniValue = 0;
    auto ret = env_->Object_CallMethodByName_Int(obj_, "unboxed", nullptr, &aniValue);
    if (ret != ANI_OK) {
        return false;
    }
    value = static_cast<int>(aniValue);
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
    ani_double aniValue = 0;
    auto ret = env_->Object_CallMethodByName_Double(obj_, "unboxed", nullptr, &aniValue);
    if (ret != ANI_OK) {
        return false;
    }
    value = static_cast<double>(aniValue);
    return true;
}

template<>
bool UnionAccessor::TryConvert<std::string>(std::string &value)
{
    if (!IsInstanceOfType<std::string>()) {
        return false;
    }
    value = AniStringUtils::ToStd(env_, static_cast<ani_string>(obj_));
    return true;
}

template<>
bool UnionAccessor::TryConvert<bool>(bool &value)
{
    if (!IsInstanceOfType<bool>()) {
        return false;
    }
    ani_boolean aniValue = false;
    auto ret = env_->Object_CallMethodByName_Boolean(obj_, "unboxed", nullptr, &aniValue);
    if (ret != ANI_OK) {
        return false;
    }
    value = static_cast<bool>(aniValue);
    return true;
}

template<>
bool UnionAccessor::TryConvert<std::vector<uint8_t>>(std::vector<uint8_t> &value)
{
    if (!IsInstanceOf("escompat.Uint8Array")) {
        return false;
    }
    return TryConvertArray(value);
}

bool UnionAccessor::GetObjectRefPropertyByName(const std::string &clsName, const char *name, ani_ref &val)
{
    ani_class cls;
    ani_status status = env_->FindClass(clsName.c_str(), &cls);
    if (status != ANI_OK) {
        LOG_ERROR("FindClass failed, status=%{public}d", status);
        return false;
    }
    std::string methodName(name);
    ani_method getter;
    status = env_->Class_FindMethod(cls, Builder::BuildGetterName(methodName).c_str(), nullptr, &getter);
    if (status != ANI_OK) {
        LOG_ERROR("GetObjectRefPropertyByName Class_FindMethod failed, status=%{public}d", status);
        return false;
    }
    ani_ref ref;
    status = env_->Object_CallMethod_Ref(obj_, getter, &ref);
    if (status != ANI_OK) {
        LOG_ERROR("GetObjectRefPropertyByName Object_CallMethod_Ref failed, status=%{public}d", status);
        return false;
    }
    val = ref;
    return true;
}

bool UnionAccessor::GetObjectStringPropertyByName(const std::string &clsName, const char *name, std::string &val)
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

bool UnionAccessor::GetObjectEnumValuePropertyByName(const std::string &clsName, const char *name, ani_int &val)
{
    ani_ref ref;
    auto isOk = GetObjectRefPropertyByName(clsName, name, ref);
    if (!isOk) {
        LOG_ERROR("GetObjectRefPropertyByName failed");
        return false;
    }
    ani_int enumValue = 0;
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
    isOk = GetObjectEnumValuePropertyByName(clsName, "status", enumVal);
    if (!isOk) {
        return false;
    }
    value.status = static_cast<AssetValue::Status>(enumVal);
    return true;
}

template<>
bool UnionAccessor::TryConvert<std::vector<AssetValue>>(std::vector<AssetValue> &value)
{
    std::string clsName = "A{C{@ohos.data.relationalStore.relationalStore.Asset}}";
    if (!IsInstanceOf(clsName)) {
        return false;
    }
    ani_size arrayLength = 0;
    auto status = env_->Array_GetLength(static_cast<ani_array>(obj_), &arrayLength);
    if (status != ANI_OK) {
        LOG_ERROR("Array_GetLength failed");
        return false;
    }
    for (ani_size i = 0; i < arrayLength; i++) {
        ani_ref result;
        status = env_->Array_Get(static_cast<ani_array>(obj_), i, &result);
        if (status != ANI_OK) {
            LOG_ERROR("Array_Get failed");
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
    std::string clsName = "std.core.BigInt";
    ani_class cls;
    auto status = env_->FindClass(clsName.c_str(), &cls);
    if (status != ANI_OK) {
        LOG_ERROR("FindClass failed, status=%{public}d", status);
        return false;
    }
    ani_boolean ret = false;
    env_->Object_InstanceOf(obj_, cls, &ret);
    if (!ret) {
        return false;
    }
    ani_method getLongMethod;
    if (ANI_OK != env_->Class_FindMethod(cls, "getLong", ":l", &getLongMethod)) {
        LOG_ERROR("Class_FindMethod failed");
        return false;
    }
    ani_long longNum = 0;
    if (ANI_OK != env_->Object_CallMethod_Long(obj_, getLongMethod, &longNum)) {
        LOG_ERROR("Object_CallMethod_Long failed");
        return false;
    }
    value = BigInteger(longNum);
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
    auto status = env_->Object_CallMethodByName_Ref(obj_, "keys", ":ableIterator", &keys);
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
    ani_double aniValue = 0;
    auto ret = env_->Object_CallMethodByName_Double(obj_, "unboxed", nullptr, &aniValue);
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
    ani_size strSize = 0;
    env_->String_GetUTF8Size(static_cast<ani_string>(obj_), &strSize);
    std::vector<char> buffer(strSize + 1);
    char *utf8_buffer = buffer.data();
    ani_size bytes_written = 0;
    env_->String_GetUTF8(static_cast<ani_string>(obj_), utf8_buffer, strSize + 1, &bytes_written);
    utf8_buffer[bytes_written] = '\0';
    std::string content = std::string(utf8_buffer);
    return content;
}

std::string AniStringUtils::ToStd(ani_env *env, ani_string ani_str)
{
    if (env == nullptr || ani_str == nullptr) {
        LOG_ERROR("[ANI] Invalid parameters");
        return std::string();
    }
    ani_size strSize = 0;
    auto status = env->String_GetUTF8Size(ani_str, &strSize);
    if (ANI_OK != status) {
        LOG_ERROR("[ANI] String_GetUTF8Size failed errcode:%{public}d", status);
        return std::string();
    }
    if (strSize == 0) {
        return std::string();
    }
    std::string result(strSize + 1, '\0');
    status = env->String_GetUTF8(ani_str, result.data(), result.size(), &strSize);
    if (ANI_OK != status) {
        LOG_ERROR("[ANI] String_GetUTF8Size failed errcode:%{public}d", status);
        return std::string();
    }
    result.resize(strSize);
    return result;
}

ani_string AniStringUtils::ToAni(ani_env *env, const std::string &str)
{
    ani_string aniStr = nullptr;
    if (ANI_OK != env->String_NewUTF8(str.data(), str.size(), &aniStr)) {
        LOG_ERROR("[ANI] Unsupported ANI_VERSION_1");
        return nullptr;
    }
    return aniStr;
}

} //namespace ani_utils
