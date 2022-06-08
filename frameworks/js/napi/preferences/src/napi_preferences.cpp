/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "napi_preferences.h"

#include <linux/limits.h>

#include <cerrno>
#include <cmath>
#include <limits>

#include "js_logger.h"
#include "napi_async_proxy.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_value.h"
#include "securec.h"

using namespace OHOS::NativePreferences;
using namespace OHOS::AppDataMgrJsKit;

namespace OHOS {
namespace PreferencesJsKit {
#define MAX_KEY_LENGTH Preferences::MAX_KEY_LENGTH
#define MAX_VALUE_LENGTH Preferences::MAX_VALUE_LENGTH

struct PreferencesAysncContext : NapiAsyncProxy<PreferencesAysncContext>::AysncContext {
    std::string key;
    PreferencesValue defValue = PreferencesValue((int)0);
    std::map<std::string, PreferencesValue> allElements;
    bool hasKey;
};

static __thread napi_ref constructor_;

PreferencesProxy::PreferencesProxy(std::shared_ptr<OHOS::NativePreferences::Preferences> &value)
    : value_(value), env_(nullptr), wrapper_(nullptr)
{
}

PreferencesProxy::~PreferencesProxy()
{
    napi_delete_reference(env_, wrapper_);
}

void PreferencesProxy::Destructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    PreferencesProxy *obj = static_cast<PreferencesProxy *>(nativeObject);
    delete obj;
}

void PreferencesProxy::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("put", SetValue),
        DECLARE_NAPI_FUNCTION("get", GetValue),
        DECLARE_NAPI_FUNCTION("getAll", GetAll),
        DECLARE_NAPI_FUNCTION("delete", Delete),
        DECLARE_NAPI_FUNCTION("clear", Clear),
        DECLARE_NAPI_FUNCTION("has", HasKey),
        DECLARE_NAPI_FUNCTION("flush", Flush),
        DECLARE_NAPI_FUNCTION("on", RegisterObserver),
        DECLARE_NAPI_FUNCTION("off", UnRegisterObserver),
    };
    napi_value cons = nullptr;
    napi_define_class(env, "Storage", NAPI_AUTO_LENGTH, New, nullptr,
        sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors, &cons);

    napi_create_reference(env, cons, 1, &constructor_);
}

napi_status PreferencesProxy::NewInstance(napi_env env, napi_value arg, napi_value *instance)
{
    napi_status status;

    const int argc = 1;
    napi_value argv[argc] = { arg };

    napi_value cons;
    status = napi_get_reference_value(env, constructor_, &cons);
    if (status != napi_ok) {
        return status;
    }

    status = napi_new_instance(env, cons, argc, argv, instance);
    if (status != napi_ok) {
        return status;
    }

    return napi_ok;
}

napi_value PreferencesProxy::New(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_value thiz = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thiz, nullptr));
    if (thiz == nullptr) {
        LOG_WARN("get this failed");
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[0], &valueType));
    NAPI_ASSERT(env, valueType == napi_string, "input type not string");
    char *path = new char[PATH_MAX];
    size_t pathLen = 0;
    napi_status status = napi_get_value_string_utf8(env, args[0], path, PATH_MAX, &pathLen);
    if (status != napi_ok) {
        LOG_ERROR("get path failed. ");
        delete[] path;
        return nullptr;
    }
    // get native object
    int errCode = 0;
    std::shared_ptr<OHOS::NativePreferences::Preferences> preference =
        OHOS::NativePreferences::PreferencesHelper::GetPreferences(path, errCode);
    delete[] path;
    NAPI_ASSERT(env, preference != nullptr, "failed to call native");
    PreferencesProxy *obj = new PreferencesProxy(preference);
    obj->env_ = env;
    NAPI_CALL(env, napi_wrap(env, thiz, obj, PreferencesProxy::Destructor,
                       nullptr, // finalize_hint
                       &obj->wrapper_));
    return thiz;
}

template<typename T> bool CheckNumberType(double input)
{
    if (input > (std::numeric_limits<T>::max)() || input < (std::numeric_limits<T>::min)()) {
        return false;
    }
    return true;
}

bool IsFloat(double input)
{
    return abs(input - floor(input)) >= 0; // DBL_EPSILON;
}

void ParseKey(const napi_env &env, const napi_value &arg, PreferencesAysncContext *asyncContext)
{
    // get input key
    char key[MAX_KEY_LENGTH] = { 0 };
    size_t keySize = 0;
    napi_get_value_string_utf8(env, arg, key, MAX_KEY_LENGTH, &keySize);
    asyncContext->key = key;
}

int32_t ParseDoubleElement(
    const napi_env &env, const napi_value &arg, PreferencesAysncContext *asyncContext, size_t arrLen)
{
    std::vector<double> doubleArray;
    napi_value doubleElement;
    for (size_t i = 0; i < arrLen; i++) {
        napi_status status = napi_get_element(env, arg, i, &doubleElement);
        if (status != napi_ok) {
            LOG_ERROR("ParseObjectElement get doubleElement failed, status = %{public}d", status);
            return E_ERROR;
        }
        double number = 0.0;
        status = napi_get_value_double(env, doubleElement, &number);
        if (status != napi_ok) {
            LOG_ERROR("ParseObjectElement get doubleElement failed, status = %{public}d", status);
            return E_ERROR;
        }
        doubleArray.push_back(number);
    }
    PreferencesValue value((std::vector<double>)doubleArray);
    asyncContext->defValue = value;
    return E_OK;
}

int32_t ParseBoolElement(
    const napi_env &env, const napi_value &arg, PreferencesAysncContext *asyncContext, size_t arrLen)
{
    std::vector<bool> boolArray;
    napi_value boolElement;
    for (int32_t i = 0; i < arrLen; i++) {
        napi_status status = napi_get_element(env, arg, i, &boolElement);
        if (status != napi_ok) {
            LOG_ERROR("ParseObjectElement get boolElement failed, status = %{public}d", status);
            return E_ERROR;
        }
        bool bValue = false;
        napi_get_value_bool(env, boolElement, &bValue);
        if (status != napi_ok) {
            LOG_ERROR("ParseObjectElement get boolElement failed, status = %{public}d", status);
            return E_ERROR;
        }
        boolArray.push_back(bValue);
    }
    PreferencesValue value((std::vector<bool>)boolArray);
    asyncContext->defValue = value;
    return E_OK;
}

int32_t ParseStringElement(
    const napi_env &env, const napi_value &arg, PreferencesAysncContext *asyncContext, size_t arrLen)
{
    std::vector<std::string> stringArray;
    napi_value stringElement = nullptr;
    for (int32_t i = 0; i < arrLen; i++) {
        napi_status status = napi_get_element(env, arg, i, &stringElement);
        if (status != napi_ok) {
            LOG_ERROR("ParseObjectElement get stringElement failed, status = %{public}d", status);
            return E_ERROR;
        }
        char *str = new char[MAX_VALUE_LENGTH];
        size_t valueSize = 0;
        napi_get_value_string_utf8(env, stringElement, str, MAX_VALUE_LENGTH, &valueSize);
        if (status != napi_ok) {
            LOG_ERROR("ParseObjectElement get stringElement failed, status = %{public}d", status);
            return E_ERROR;
        }
        stringArray.push_back((std::string)str);
    }
    PreferencesValue value((std::vector<std::string>)stringArray);
    asyncContext->defValue = value;
    return E_OK;
}

int32_t ParseObjectElement(napi_valuetype valueType, const napi_env &env, const napi_value &arg,
    PreferencesAysncContext *asyncContext, size_t arrLen)
{
    if (valueType == napi_number) {
        return ParseDoubleElement(env, arg, asyncContext, arrLen);
    } else if (valueType == napi_boolean) {
        return ParseBoolElement(env, arg, asyncContext, arrLen);
    } else if (valueType == napi_string) {
        return ParseStringElement(env, arg, asyncContext, arrLen);
    } else {
        LOG_ERROR("ParseObjectElement unexpected valueType");
        return E_ERROR;
    }
}

int32_t ParseDefObject(const napi_env &env, const napi_value &arg, PreferencesAysncContext *asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    uint32_t arrLen = 0;
    napi_status status = napi_get_array_length(env, arg, &arrLen);
    if (status != napi_ok) {
        LOG_ERROR("ParseDefObject get array failed, status = %{public}d", status);
        return E_ERROR;
    }
    napi_value flag = nullptr;
    status = napi_get_element(env, arg, 0, &flag);
    if (status != napi_ok) {
        LOG_ERROR("ParseDefObject get array element failed, status = %{public}d", status);
        return E_ERROR;
    }
    status = napi_typeof(env, flag, &valueType);
    if (status != napi_ok) {
        LOG_ERROR("ParseDefObject get array element type failed, status = %{public}d", status);
        return E_ERROR;
    }
    if (ParseObjectElement(valueType, env, arg, asyncContext, arrLen) != E_OK) {
        LOG_ERROR("ParseDefObject parse array element failed, status = %{public}d", status);
        return E_ERROR;
    }
    return E_OK;
}

void ParseDefValue(const napi_env &env, const napi_value &arg, PreferencesAysncContext *asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, arg, &valueType);
    if (valueType == napi_number) {
        double number = 0.0;
        napi_get_value_double(env, arg, &number);
        PreferencesValue value((double)number);
        asyncContext->defValue = value;
    } else if (valueType == napi_string) {
        char *str = new char[MAX_VALUE_LENGTH];
        size_t valueSize = 0;
        napi_get_value_string_utf8(env, arg, str, MAX_VALUE_LENGTH, &valueSize);
        PreferencesValue value((std::string)(str));
        asyncContext->defValue = value;
        delete[] str;
    } else if (valueType == napi_boolean) {
        bool bValue = false;
        napi_get_value_bool(env, arg, &bValue);
        PreferencesValue value((bool)(bValue));
        asyncContext->defValue = value;
    } else if (valueType == napi_object) {
        if (ParseDefObject(env, arg, asyncContext) != E_OK) {
            LOG_ERROR("ParseDefValue::ParseDefObject failed");
        }
    } else {
        LOG_ERROR("Wrong second parameter type");
    }
}

int32_t GetAllArr(
    const std::string &key, const PreferencesValue &value, PreferencesAysncContext *asyncContext, napi_value &output)
{
    napi_value jsArr = nullptr;
    if (value.IsDoubleArray()) {
        std::vector<double> arrays = (std::vector<double>)value;
        size_t arrLen = arrays.size();
        napi_create_array_with_length(asyncContext->env, arrLen, &jsArr);
        for (size_t i = 0; i < arrLen; i++) {
            napi_value val = nullptr;
            napi_create_double(asyncContext->env, arrays[i], &val);
            napi_set_element(asyncContext->env, jsArr, i, val);
        }
        if (napi_set_named_property(asyncContext->env, output, key.c_str(), jsArr) != napi_ok) {
            LOG_ERROR("PreferencesProxy::GetAll set property doubleArr failed");
            return ERR;
        }
    } else if (value.IsStringArray()) {
        std::vector<std::string> arrays = (std::vector<std::string>)value;
        size_t arrLen = arrays.size();
        napi_create_array_with_length(asyncContext->env, arrLen, &jsArr);
        for (size_t i = 0; i < arrLen; i++) {
            napi_value val = nullptr;
            napi_create_string_utf8(asyncContext->env, arrays[i].c_str(), arrays[i].size(), &val);
            napi_set_element(asyncContext->env, jsArr, i, val);
        }
        if (napi_set_named_property(asyncContext->env, output, key.c_str(), jsArr) != napi_ok) {
            LOG_ERROR("PreferencesProxy::GetAll set property stringArr failed");
            return ERR;
        }
    } else if (value.IsBoolArray()) {
        std::vector<bool> arrays = (std::vector<bool>)value;
        size_t arrLen = arrays.size();
        napi_create_array_with_length(asyncContext->env, arrLen, &jsArr);
        for (size_t i = 0; i < arrLen; i++) {
            napi_value val = nullptr;
            napi_get_boolean(asyncContext->env, arrays[i], &val);
            napi_set_element(asyncContext->env, jsArr, i, val);
        }
        if (napi_set_named_property(asyncContext->env, output, key.c_str(), jsArr) != napi_ok) {
            LOG_ERROR("PreferencesProxy::GetAll set property boolArr failed");
            return ERR;
        }
    }
    return OK;
}

int32_t GetAllExecute(PreferencesAysncContext *asyncContext, napi_value &output)
{
    if (napi_create_object(asyncContext->env, &output) != napi_ok) {
        LOG_ERROR("PreferencesProxy::GetAll creat object failed");
        return ERR;
    }
    napi_value jsVal = nullptr;
    for (const auto &[key, value] : asyncContext->allElements) {
        if (value.IsBool()) {
            if (napi_get_boolean(asyncContext->env, value, &jsVal) != napi_ok) {
                LOG_ERROR("PreferencesProxy::GetAll get property bool failed");
                return ERR;
            }
            if (napi_set_named_property(asyncContext->env, output, key.c_str(), jsVal) != napi_ok) {
                LOG_ERROR("PreferencesProxy::GetAll set property bool failed");
                return ERR;
            }
        } else if (value.IsDouble()) {
            if (napi_create_double(asyncContext->env, value, &jsVal) != napi_ok) {
                LOG_ERROR("PreferencesProxy::GetAll get property double failed");
                return ERR;
            }
            if (napi_set_named_property(asyncContext->env, output, key.c_str(), jsVal) != napi_ok) {
                LOG_ERROR("PreferencesProxy::GetAll set property double failed");
                return ERR;
            }
        } else if (value.IsString()) {
            std::string tempStr = (std::string)value;
            if (napi_create_string_utf8(asyncContext->env, tempStr.c_str(), tempStr.size(), &jsVal) != napi_ok) {
                LOG_ERROR("PreferencesProxy::GetAll get property string failed");
                return ERR;
            }
            if (napi_set_named_property(asyncContext->env, output, key.c_str(), jsVal) != napi_ok) {
                LOG_ERROR("PreferencesProxy::GetAll set property string failed");
                return ERR;
            }
        } else {
            int errCode = GetAllArr(key, value, asyncContext, output);
            if (errCode != OK) {
                LOG_ERROR("PreferencesProxy::GetAll set property array failed");
                return ERR;
            }
        }
    }
    return OK;
}

napi_value PreferencesProxy::GetAll(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<PreferencesAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<PreferencesAysncContext>::InputParser> parsers;
    proxy.ParseInputs(parsers);
    return proxy.DoAsyncWork(
        "GetAll",
        [](PreferencesAysncContext *asyncContext) {
            PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(asyncContext->boundObj);
            asyncContext->allElements = obj->value_->GetAll();
            return OK;
        },
        GetAllExecute);
}

void GetArrayValue(PreferencesAysncContext *asyncContext, napi_value &output)
{
    if (asyncContext->defValue.IsDoubleArray()) {
        std::vector<double> arrays = (std::vector<double>)asyncContext->defValue;
        size_t arrLen = arrays.size();
        napi_create_array_with_length(asyncContext->env, arrLen, &output);
        for (size_t i = 0; i < arrLen; i++) {
            napi_value value = nullptr;
            napi_create_double(asyncContext->env, arrays[i], &value);
            napi_set_element(asyncContext->env, output, i, value);
        }
    } else if (asyncContext->defValue.IsStringArray()) {
        std::vector<std::string> arrays = (std::vector<std::string>)asyncContext->defValue;
        size_t arrLen = arrays.size();
        napi_create_array_with_length(asyncContext->env, arrLen, &output);
        for (size_t i = 0; i < arrLen; i++) {
            napi_value value = nullptr;
            napi_create_string_utf8(asyncContext->env, arrays[i].c_str(), arrays[i].size(), &value);
            napi_set_element(asyncContext->env, output, i, value);
        }
    } else if (asyncContext->defValue.IsBoolArray()) {
        std::vector<bool> arrays = (std::vector<bool>)asyncContext->defValue;
        size_t arrLen = arrays.size();
        napi_create_array_with_length(asyncContext->env, arrLen, &output);
        for (size_t i = 0; i < arrLen; i++) {
            napi_value value = nullptr;
            napi_get_boolean(asyncContext->env, arrays[i], &value);
            napi_set_element(asyncContext->env, output, i, value);
        }
    }
}

napi_value PreferencesProxy::GetValue(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<PreferencesAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<PreferencesAysncContext>::InputParser> parsers;
    parsers.push_back(ParseKey);
    parsers.push_back(ParseDefValue);
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "GetValue",
        [](PreferencesAysncContext *asyncContext) {
            int errCode = OK;
            PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(asyncContext->boundObj);
            asyncContext->defValue = obj->value_->Get(asyncContext->key, asyncContext->defValue);
            return errCode;
        },
        [](PreferencesAysncContext *asyncContext, napi_value &output) {
            int errCode = OK;
            if (asyncContext->defValue.IsBool()) {
                napi_get_boolean(asyncContext->env, (bool)asyncContext->defValue, &output);
            } else if (asyncContext->defValue.IsString()) {
                std::string tempStr = (std::string)asyncContext->defValue;
                napi_create_string_utf8(asyncContext->env, tempStr.c_str(), tempStr.size(), &output);
            } else if (asyncContext->defValue.IsDouble()) {
                napi_create_double(asyncContext->env, (double)asyncContext->defValue, &output);
            } else if (asyncContext->defValue.IsDoubleArray() || asyncContext->defValue.IsStringArray()
                       || asyncContext->defValue.IsBoolArray()) {
                GetArrayValue(asyncContext, output);
            } else {
                errCode = ERR;
            }

            return errCode;
        });
}

napi_value PreferencesProxy::SetValue(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<PreferencesAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<PreferencesAysncContext>::InputParser> parsers;
    parsers.push_back(ParseKey);
    parsers.push_back(ParseDefValue);
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "SetValue",
        [](PreferencesAysncContext *asyncContext) {
            int errCode = ERR;
            PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(asyncContext->boundObj);
            errCode = obj->value_->Put(asyncContext->key, asyncContext->defValue);
            return errCode;
        },
        [](PreferencesAysncContext *asyncContext, napi_value &output) {
            napi_status status = napi_get_undefined(asyncContext->env, &output);
            return (status == napi_ok) ? OK : ERR;
        });
}

napi_value PreferencesProxy::Delete(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<PreferencesAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<PreferencesAysncContext>::InputParser> parsers;
    parsers.push_back(ParseKey);
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "Delete",
        [](PreferencesAysncContext *asyncContext) {
            PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(asyncContext->boundObj);
            int errCode = obj->value_->Delete(asyncContext->key);

            return errCode;
        },
        [](PreferencesAysncContext *asyncContext, napi_value &output) {
            napi_status status = napi_get_undefined(asyncContext->env, &output);
            return (status == napi_ok) ? OK : ERR;
        });
}

napi_value PreferencesProxy::HasKey(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<PreferencesAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<PreferencesAysncContext>::InputParser> parsers;
    parsers.push_back(ParseKey);
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "HasKey",
        [](PreferencesAysncContext *asyncContext) {
            PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(asyncContext->boundObj);
            asyncContext->hasKey = obj->value_->HasKey(asyncContext->key);

            return OK;
        },
        [](PreferencesAysncContext *asyncContext, napi_value &output) {
            napi_status status = napi_get_boolean(asyncContext->env, asyncContext->hasKey, &output);
            return (status == napi_ok) ? OK : ERR;
        });
}

napi_value PreferencesProxy::Flush(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<PreferencesAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<PreferencesAysncContext>::InputParser> parsers;
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "Flush",
        [](PreferencesAysncContext *asyncContext) {
            PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(asyncContext->boundObj);
            return obj->value_->FlushSync();
        },
        [](PreferencesAysncContext *asyncContext, napi_value &output) {
            napi_status status = napi_get_undefined(asyncContext->env, &output);
            return (status == napi_ok) ? OK : ERR;
        });
}

napi_value PreferencesProxy::Clear(napi_env env, napi_callback_info info)
{
    NapiAsyncProxy<PreferencesAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxy<PreferencesAysncContext>::InputParser> parsers;
    proxy.ParseInputs(parsers);

    return proxy.DoAsyncWork(
        "Clear",
        [](PreferencesAysncContext *asyncContext) {
            PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(asyncContext->boundObj);
            return obj->value_->Clear();
        },
        [](PreferencesAysncContext *asyncContext, napi_value &output) {
            napi_status status = napi_get_undefined(asyncContext->env, &output);
            return (status == napi_ok) ? OK : ERR;
        });
}

napi_value PreferencesProxy::RegisterObserver(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    size_t argc = 2;
    napi_value args[2] = { 0 };

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thiz, nullptr));
    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, args[0], &type));
    NAPI_ASSERT(env, type == napi_string, "key not string type");

    NAPI_CALL(env, napi_typeof(env, args[1], &type));
    NAPI_ASSERT(env, type == napi_function, "observer not function type");

    PreferencesProxy *obj = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thiz, reinterpret_cast<void **>(&obj)));

    // reference save
    obj->observer_ = std::make_shared<PreferencesObserverImpl>(env, args[1]);
    obj->value_->RegisterObserver(obj->observer_);
    LOG_DEBUG("RegisterObserver end");

    return nullptr;
}

napi_value PreferencesProxy::UnRegisterObserver(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    size_t argc = 2;
    napi_value args[2] = { 0 };

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thiz, nullptr));
    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, args[0], &type));
    NAPI_ASSERT(env, type == napi_string, "key not string type");

    NAPI_CALL(env, napi_typeof(env, args[1], &type));
    NAPI_ASSERT(env, type == napi_function, "observer not function type");

    PreferencesProxy *obj = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thiz, reinterpret_cast<void **>(&obj)));
    obj->value_->UnRegisterObserver(obj->observer_);
    obj->observer_.reset();
    obj->observer_ = nullptr;
    LOG_DEBUG("UnRegisterObserver end");
    return nullptr;
}

PreferencesObserverImpl::PreferencesObserverImpl(napi_env env, napi_value callback) : observerRef(nullptr)
{
    this->env_ = env;
    napi_create_reference(env_, callback, 1, &observerRef);
}

PreferencesObserverImpl::~PreferencesObserverImpl()
{
    napi_delete_reference(env_, observerRef);
}

void PreferencesObserverImpl::OnChange(Preferences &preferences, const std::string &key)
{
    LOG_DEBUG("OnChange key:%{public}s", key.c_str());
    napi_value callback = nullptr;
    napi_value global = nullptr;
    napi_value result = nullptr;
    napi_value args[1] = { 0 };

    napi_create_string_utf8(env_, key.c_str(), key.size(), &args[0]);
    napi_get_reference_value(env_, observerRef, &callback);
    napi_get_global(env_, &global);

    napi_call_function(env_, global, callback, 1, args, &result);
    LOG_DEBUG("OnChange key end");
}
} // namespace PreferencesJsKit
} // namespace OHOS
