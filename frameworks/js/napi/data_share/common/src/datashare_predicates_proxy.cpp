/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "datashare_predicates_proxy.h"

#include "datashare_log.h"
#include "datashare_js_utils.h"
#include "napi_datashare_async_proxy.h"

namespace OHOS {
namespace DataShare {
static __thread napi_ref constructor_ = nullptr;

void DataSharePredicatesProxy::Init(napi_env env, napi_value exports)
{
    LOG_INFO("Init DataSharePredicatesProxy");
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("equalTo", EqualTo),
        DECLARE_NAPI_FUNCTION("notEqualTo", NotEqualTo),
        DECLARE_NAPI_FUNCTION("beginWrap", BeginWrap),
        DECLARE_NAPI_FUNCTION("endWrap", EndWrap),
        DECLARE_NAPI_FUNCTION("or", Or),
        DECLARE_NAPI_FUNCTION("and", And),
        DECLARE_NAPI_FUNCTION("contains", Contains),
        DECLARE_NAPI_FUNCTION("beginsWith", BeginsWith),
        DECLARE_NAPI_FUNCTION("endsWith", EndsWith),
        DECLARE_NAPI_FUNCTION("isNull", IsNull),
        DECLARE_NAPI_FUNCTION("isNotNull", IsNotNull),
        DECLARE_NAPI_FUNCTION("like", Like),
        DECLARE_NAPI_FUNCTION("unlike", Unlike),
        DECLARE_NAPI_FUNCTION("glob", Glob),
        DECLARE_NAPI_FUNCTION("between", Between),
        DECLARE_NAPI_FUNCTION("notBetween", NotBetween),
        DECLARE_NAPI_FUNCTION("greaterThan", GreaterThan),
        DECLARE_NAPI_FUNCTION("lessThan", LessThan),
        DECLARE_NAPI_FUNCTION("greaterThanOrEqualTo", GreaterThanOrEqualTo),
        DECLARE_NAPI_FUNCTION("lessThanOrEqualTo", LessThanOrEqualTo),
        DECLARE_NAPI_FUNCTION("orderByAsc", OrderByAsc),
        DECLARE_NAPI_FUNCTION("orderByDesc", OrderByDesc),
        DECLARE_NAPI_FUNCTION("distinct", Distinct),
        DECLARE_NAPI_FUNCTION("limit", Limit),
        DECLARE_NAPI_FUNCTION("groupBy", GroupBy),
        DECLARE_NAPI_FUNCTION("indexedBy", IndexedBy),
        DECLARE_NAPI_FUNCTION("in", In),
        DECLARE_NAPI_FUNCTION("notIn", NotIn),
        DECLARE_NAPI_FUNCTION("prefixKey", PrefixKey),
        DECLARE_NAPI_FUNCTION("inKeys", InKeys),
    };

    napi_value cons;
    NAPI_CALL_RETURN_VOID(env, napi_define_class(env, "DataSharePredicates", NAPI_AUTO_LENGTH, New, nullptr,
                                   sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors, &cons));

    NAPI_CALL_RETURN_VOID(env, napi_create_reference(env, cons, 1, &constructor_));

    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, exports, "DataSharePredicates", cons));
    LOG_DEBUG("Init DataSharePredicatesProxy end");
}

napi_value DataSharePredicatesProxy::New(napi_env env, napi_callback_info info)
{
    napi_value new_target;
    NAPI_CALL(env, napi_get_new_target(env, info, &new_target));
    bool is_constructor = (new_target != nullptr);

    napi_value thiz;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr));

    if (is_constructor) {
        auto *proxy = new DataSharePredicatesProxy();
        proxy->env_ = env;
        NAPI_CALL(env, napi_wrap(env, thiz, proxy, DataSharePredicatesProxy::Destructor, nullptr, &proxy->wrapper_));
        LOG_INFO("DataSharePredicatesProxy::New constructor ref:%{public}p", proxy->wrapper_);
        return thiz;
    }

    napi_value cons;
    NAPI_CALL(env, napi_get_reference_value(env, constructor_, &cons));

    napi_value output;
    NAPI_CALL(env, napi_new_instance(env, cons, 0, nullptr, &output));

    return output;
}

napi_value DataSharePredicatesProxy::NewInstance(
    napi_env env, std::shared_ptr<DataSharePredicates> value)
{
    napi_value cons;
    napi_status status = napi_get_reference_value(env, constructor_, &cons);
    if (status != napi_ok) {
        LOG_ERROR("DataSharePredicatesProxy get constructor failed! napi_status:%{public}d!", status);
        return nullptr;
    }

    napi_value instance = nullptr;
    status = napi_new_instance(env, cons, 0, nullptr, &instance);
    if (status != napi_ok) {
        LOG_ERROR("DataSharePredicatesProxy napi_new_instance failed! napi_status:%{public}d!", status);
        return nullptr;
    }

    DataSharePredicatesProxy *proxy = nullptr;
    status = napi_unwrap(env, instance, reinterpret_cast<void **>(&proxy));
    if (status != napi_ok) {
        LOG_ERROR("DataSharePredicatesProxy native instance is nullptr! napi_status:%{public}d!", status);
        return instance;
    }
    proxy->predicates_ = std::move(value);
    return instance;
}

std::shared_ptr<DataSharePredicates> DataSharePredicatesProxy::GetNativePredicates(
    const napi_env &env, const napi_value &arg)
{
    LOG_DEBUG("GetNativePredicates on called.");
    if (arg == nullptr) {
        LOG_ERROR("DataSharePredicatesProxy arg is null.");
        return nullptr;
    }
    DataSharePredicatesProxy *proxy = nullptr;
    napi_unwrap(env, arg, reinterpret_cast<void **>(&proxy));
    return proxy->predicates_;
}

void DataSharePredicatesProxy::Destructor(napi_env env, void *nativeObject, void *)
{
    DataSharePredicatesProxy *proxy = static_cast<DataSharePredicatesProxy *>(nativeObject);
    delete proxy;
}

DataSharePredicatesProxy::~DataSharePredicatesProxy()
{
    napi_delete_reference(env_, wrapper_);
}

DataSharePredicatesProxy::DataSharePredicatesProxy()
    : predicates_(new DataSharePredicates()), env_(nullptr), wrapper_(nullptr)
{
}

std::shared_ptr<DataSharePredicates> DataSharePredicatesProxy::GetNativePredicates(
    napi_env env, napi_callback_info info)
{
    DataSharePredicatesProxy *predicatesProxy = nullptr;
    napi_value thiz;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    napi_unwrap(env, thiz, reinterpret_cast<void **>(&predicatesProxy));
    return predicatesProxy->predicates_;
}

napi_value DataSharePredicatesProxy::EqualTo(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::EqualTo on called.");
    napi_value thiz;
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::EqualTo Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, args[1], &valueType);
    if (status != napi_ok) {
        LOG_ERROR("napi_typeof status : %{public}d", status);
        return thiz;
    }
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    switch (valueType) {
        case napi_number: {
            double value;
            napi_get_value_double(env, args[1], &value);
            nativePredicates->EqualTo(field, value);
            break;
        }
        case napi_boolean: {
            bool value = false;
            napi_get_value_bool(env, args[1], &value);
            nativePredicates->EqualTo(field, value);
            break;
        }
        case napi_string: {
            std::string value = DataShareJSUtils::Convert2String(env, args[1], DataShareJSUtils::DEFAULT_BUF_SIZE);
            nativePredicates->EqualTo(field, value);
            break;
        }
        default:
            break;
    }
    return thiz;
}

napi_value DataSharePredicatesProxy::NotEqualTo(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::NotEqualTo on called.");
    napi_value thiz;
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::NotEqualTo Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, args[1], &valueType);
    if (status != napi_ok) {
        LOG_ERROR("napi_typeof status : %{public}d", status);
        return thiz;
    }
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    switch (valueType) {
        case napi_number: {
            double value;
            napi_get_value_double(env, args[1], &value);
            nativePredicates->NotEqualTo(field, value);
            break;
        }
        case napi_boolean: {
            bool value = false;
            napi_get_value_bool(env, args[1], &value);
            nativePredicates->NotEqualTo(field, value);
            break;
        }
        case napi_string: {
            std::string value = DataShareJSUtils::Convert2String(env, args[1], DataShareJSUtils::DEFAULT_BUF_SIZE);
            nativePredicates->NotEqualTo(field, value);
            break;
        }
        default:
            break;
    }
    return thiz;
}

napi_value DataSharePredicatesProxy::BeginWrap(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::BeginWrap on called.");
    napi_value thiz;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->BeginWrap();
    return thiz;
}

napi_value DataSharePredicatesProxy::EndWrap(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::EndWrap on called.");
    napi_value thiz;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->EndWrap();
    return thiz;
}

napi_value DataSharePredicatesProxy::Or(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::Or on called.");
    napi_value thiz;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->Or();
    return thiz;
}

napi_value DataSharePredicatesProxy::And(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::And on called.");
    napi_value thiz;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->And();
    return thiz;
}

napi_value DataSharePredicatesProxy::Contains(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::Contains on called.");
    napi_value thiz;
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::Contains Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::string value = DataShareJSUtils::ConvertAny2String(env, args[1]);

    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->Contains(field, value);
    return thiz;
}

napi_value DataSharePredicatesProxy::BeginsWith(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::BeginsWith on called.");
    napi_value thiz;
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::BeginsWith Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::string value = DataShareJSUtils::ConvertAny2String(env, args[1]);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->BeginsWith(field, value);
    return thiz;
}

napi_value DataSharePredicatesProxy::EndsWith(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::EndsWith on called.");
    napi_value thiz;
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::EndsWith Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::string value = DataShareJSUtils::ConvertAny2String(env, args[1]);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->EndsWith(field, value);
    return thiz;
}

napi_value DataSharePredicatesProxy::IsNull(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::IsNull on called.");
    napi_value thiz;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::IsNull Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->IsNull(field);
    return thiz;
}

napi_value DataSharePredicatesProxy::IsNotNull(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::IsNotNull on called.");
    napi_value thiz;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::IsNotNull Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->IsNotNull(field);
    return thiz;
}

napi_value DataSharePredicatesProxy::Like(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::Like on called.");
    napi_value thiz;
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::Like Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::string value = DataShareJSUtils::ConvertAny2String(env, args[1]);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->Like(field, value);
    return thiz;
}

napi_value DataSharePredicatesProxy::Unlike(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::Unlike on called.");
    napi_value thiz;
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::Unlike Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::string value = DataShareJSUtils::ConvertAny2String(env, args[1]);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->Unlike(field, value);
    return thiz;
}

napi_value DataSharePredicatesProxy::Glob(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::Glob on called.");
    napi_value thiz;
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::Glob Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::string value = DataShareJSUtils::ConvertAny2String(env, args[1]);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->Glob(field, value);
    return thiz;
}

napi_value DataSharePredicatesProxy::Between(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::Between on called.");
    napi_value thiz;
    size_t argc = 3;
    napi_value args[3] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::Between Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::string low = DataShareJSUtils::ConvertAny2String(env, args[1]);
    std::string high = DataShareJSUtils::ConvertAny2String(env, args[2]);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->Between(field, low, high);
    return thiz;
}

napi_value DataSharePredicatesProxy::NotBetween(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::NotBetween on called.");
    napi_value thiz;
    size_t argc = 3;
    napi_value args[3] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::NotBetween Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::string low = DataShareJSUtils::ConvertAny2String(env, args[1]);
    std::string high = DataShareJSUtils::ConvertAny2String(env, args[2]);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->NotBetween(field, low, high);
    return thiz;
}

napi_value DataSharePredicatesProxy::GreaterThan(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::GreaterThan on called.");
    napi_value thiz;
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::GreaterThan Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, args[1], &valueType);
    if (status != napi_ok) {
        LOG_ERROR("napi_typeof status : %{public}d", status);
        return thiz;
    }
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    switch (valueType) {
        case napi_number: {
            double value;
            napi_get_value_double(env, args[1], &value);
            nativePredicates->GreaterThan(field, value);
            break;
        }
        case napi_string: {
            std::string value = DataShareJSUtils::Convert2String(env, args[1], DataShareJSUtils::DEFAULT_BUF_SIZE);
            nativePredicates->GreaterThan(field, value);
            break;
        }
        default:
            break;
    }
    return thiz;
}

napi_value DataSharePredicatesProxy::LessThan(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::LessThan on called.");
    napi_value thiz;
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::LessThan Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, args[1], &valueType);
    if (status != napi_ok) {
        LOG_ERROR("napi_typeof status : %{public}d", status);
        return thiz;
    }
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    switch (valueType) {
        case napi_number: {
            double value;
            napi_get_value_double(env, args[1], &value);
            nativePredicates->LessThan(field, value);
            break;
        }
        case napi_string: {
            std::string value = DataShareJSUtils::Convert2String(env, args[1], DataShareJSUtils::DEFAULT_BUF_SIZE);
            nativePredicates->LessThan(field, value);
            break;
        }
        default:
            break;
    }
    return thiz;
}

napi_value DataSharePredicatesProxy::GreaterThanOrEqualTo(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::GreaterThanOrEqualTo on called.");
    napi_value thiz;
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::GreaterThanOrEqualTo Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, args[1], &valueType);
    if (status != napi_ok) {
        LOG_ERROR("napi_typeof status : %{public}d", status);
        return thiz;
    }
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    switch (valueType) {
        case napi_number: {
            double value;
            napi_get_value_double(env, args[1], &value);
            nativePredicates->GreaterThanOrEqualTo(field, value);
            break;
        }
        case napi_string: {
            std::string value = DataShareJSUtils::Convert2String(env, args[1], DataShareJSUtils::DEFAULT_BUF_SIZE);
            nativePredicates->GreaterThanOrEqualTo(field, value);
            break;
        }
        default:
            break;
    }
    return thiz;
}

napi_value DataSharePredicatesProxy::LessThanOrEqualTo(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::LessThanOrEqualTo on called.");
    napi_value thiz;
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::LessThanOrEqualTo Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, args[1], &valueType);
    if (status != napi_ok) {
        LOG_ERROR("napi_typeof status : %{public}d", status);
        return thiz;
    }
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    switch (valueType) {
        case napi_number: {
            double value;
            napi_get_value_double(env, args[1], &value);
            nativePredicates->LessThanOrEqualTo(field, value);
            break;
        }
        case napi_string: {
            std::string value = DataShareJSUtils::Convert2String(env, args[1], DataShareJSUtils::DEFAULT_BUF_SIZE);
            nativePredicates->LessThanOrEqualTo(field, value);
            break;
        }
        default:
            break;
    }
    return thiz;
}

napi_value DataSharePredicatesProxy::OrderByAsc(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::OrderByAsc on called.");
    napi_value thiz;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::OrderByAsc Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->OrderByAsc(field);
    return thiz;
}

napi_value DataSharePredicatesProxy::OrderByDesc(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::OrderByDesc on called.");
    napi_value thiz;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::OrderByDesc Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->OrderByDesc(field);
    return thiz;
}

napi_value DataSharePredicatesProxy::Distinct(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::Distinct on called.");
    napi_value thiz;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->Distinct();
    return thiz;
}

napi_value DataSharePredicatesProxy::Limit(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::Limit on called.");
    napi_value thiz;
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::Limit Invalid argvs!");
    int number = 0;
    napi_status status = napi_get_value_int32(env, args[0], &number);
    LOG_INFO("number, napi_get_value_int32 : %{public}d", status);
    int offset = 0;
    status = napi_get_value_int32(env, args[1], &offset);
    LOG_INFO("offset, napi_get_value_int32 : %{public}d", status);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->Limit(number, offset);
    return thiz;
}

napi_value DataSharePredicatesProxy::GroupBy(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::GroupBy on called.");
    napi_value thiz;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::GroupBy Invalid argvs!");
    std::vector<std::string> fields = DataShareJSUtils::Convert2StrVector(env,
        args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->GroupBy(fields);
    return thiz;
}

napi_value DataSharePredicatesProxy::IndexedBy(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::IndexedBy on called.");
    napi_value thiz;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::IndexedBy Invalid argvs!");
    std::string indexName = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->IndexedBy(indexName);
    return thiz;
}

napi_value DataSharePredicatesProxy::In(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::In on called.");
    napi_value thiz;
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::In Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::vector<std::string> values = DataShareJSUtils::Convert2StrVector(env,
        args[1], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->In(field, values);
    return thiz;
}

napi_value DataSharePredicatesProxy::NotIn(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::NotIn on called.");
    napi_value thiz;
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::NotIn Invalid argvs!");
    std::string field = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::vector<std::string> values = DataShareJSUtils::Convert2StrVector(env,
        args[1], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->NotIn(field, values);
    return thiz;
}

std::shared_ptr<DataSharePredicates> DataSharePredicatesProxy::GetPredicates() const
{
    return this->predicates_;
}

napi_value DataSharePredicatesProxy::PrefixKey(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::PrefixKey on called.");
    napi_value thiz;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::PrefixKey Invalid argvs!");
    std::string prefix = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->KeyPrefix(prefix);
    return thiz;
}

napi_value DataSharePredicatesProxy::InKeys(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::InKeys on called.");
    napi_value thiz;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::InKeys Invalid argvs!");
    std::vector<std::string> keys = DataShareJSUtils::Convert2StrVector(env,
        args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    std::shared_ptr<DataSharePredicates> nativePredicates = GetNativePredicates(env, info);
    if (nativePredicates == nullptr) {
        LOG_ERROR("GetNativePredicates failed.");
        return thiz;
    }
    nativePredicates->InKeys(keys);
    return thiz;
}

napi_value GetNapiObject(napi_env env, DataSharePredicates *predicates)
{
    return DataSharePredicatesProxy::NewInstance(
        env, std::shared_ptr<DataSharePredicates>(predicates));
}

DataSharePredicates *GetNativePredicatesObject(const napi_env &env, const napi_value &arg)
{
    auto predicates = DataSharePredicatesProxy::GetNativePredicates(env, arg);
    return predicates.get();
}
} // namespace DataShare
} // namespace OHOS
