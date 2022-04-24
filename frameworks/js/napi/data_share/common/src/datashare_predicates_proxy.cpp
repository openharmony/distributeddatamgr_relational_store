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
        // DECLARE_NAPI_FUNCTION("limitAs", Limit),
        DECLARE_NAPI_FUNCTION("limit", Limit),
        DECLARE_NAPI_FUNCTION("offsetAs", Offset),
        DECLARE_NAPI_FUNCTION("groupBy", GroupBy),
        DECLARE_NAPI_FUNCTION("indexedBy", IndexedBy),
        DECLARE_NAPI_FUNCTION("in", In),
        DECLARE_NAPI_FUNCTION("notIn", NotIn),
        DECLARE_NAPI_FUNCTION("prefixKey", PrefixKey),
        DECLARE_NAPI_FUNCTION("setSuggestIndex", SetSuggestIndex),
        DECLARE_NAPI_FUNCTION("inAllDevices", InAllDevices),
        DECLARE_NAPI_FUNCTION("inDevices", InDevices),
        //DECLARE_NAPI_FUNCTION("reset", Reset),
        // DECLARE_NAPI_FUNCTION("clear", Clear),
        // DECLARE_NAPI_FUNCTION("isRawSelection", IsRawSelection),
        // DECLARE_NAPI_GETTER_SETTER("whereClause", GetWhereClause, SetWhereClause),
        // DECLARE_NAPI_GETTER_SETTER("whereArgs", GetWhereArgs, SetWhereArgs),
        //DECLARE_NAPI_GETTER_SETTER("order", GetOrder, SetOrder),
        //DECLARE_NAPI_GETTER("limit", GetLimit),
        //DECLARE_NAPI_GETTER("offset", GetOffset),
        //DECLARE_NAPI_GETTER("isDistinct", IsDistinct),
        //DECLARE_NAPI_GETTER("group", GetGroup),
        //DECLARE_NAPI_GETTER("index", GetIndex),
        //DECLARE_NAPI_GETTER("isNeedAnd", IsNeedAnd),
        //DECLARE_NAPI_GETTER("getJudgeSource", GetJudgeSource),
        //DECLARE_NAPI_GETTER("isSorted", IsSorted),
        
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
    napi_typeof(env, args[1], &valueType);
    // std::string value = DataShareJSUtils::ConvertAny2String(env, args[1]);
    switch (valueType) {
        case napi_number: {
            double value;
            napi_get_value_double(env, args[1], &value);
            GetNativePredicates(env, info)->EqualTo(field, value);
        }
        case napi_boolean: {
            bool value = false;
            napi_get_value_bool(env, args[1], &value);
            GetNativePredicates(env, info)->EqualTo(field, value);
        }
        case napi_string: {
            std::string value = DataShareJSUtils::Convert2String(env, args[1], DataShareJSUtils::DEFAULT_BUF_SIZE);
            GetNativePredicates(env, info)->EqualTo(field, value);
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
    napi_typeof(env, args[1], &valueType);
    switch (valueType) {
        case napi_number: {
            double value;
            napi_get_value_double(env, args[1], &value);
            GetNativePredicates(env, info)->NotEqualTo(field, value);
        }
        case napi_boolean: {
            bool value = false;
            napi_get_value_bool(env, args[1], &value);
            GetNativePredicates(env, info)->NotEqualTo(field, value);
        }
        case napi_string: {
            std::string value = DataShareJSUtils::Convert2String(env, args[1], DataShareJSUtils::DEFAULT_BUF_SIZE);
            GetNativePredicates(env, info)->NotEqualTo(field, value);
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
    GetNativePredicates(env, info)->BeginWrap();
    return thiz;
}

napi_value DataSharePredicatesProxy::EndWrap(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::EndWrap on called.");
    napi_value thiz;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    GetNativePredicates(env, info)->EndWrap();
    return thiz;
}

napi_value DataSharePredicatesProxy::Or(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::Or on called.");
    napi_value thiz;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    GetNativePredicates(env, info)->Or();
    return thiz;
}

napi_value DataSharePredicatesProxy::And(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::And on called.");
    napi_value thiz;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    GetNativePredicates(env, info)->And();
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

    GetNativePredicates(env, info)->Contains(field, value);
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
    GetNativePredicates(env, info)->BeginsWith(field, value);
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
    GetNativePredicates(env, info)->EndsWith(field, value);
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
    GetNativePredicates(env, info)->IsNull(field);
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
    GetNativePredicates(env, info)->IsNotNull(field);
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
    GetNativePredicates(env, info)->Like(field, value);
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
    GetNativePredicates(env, info)->Unlike(field, value);
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
    GetNativePredicates(env, info)->Glob(field, value);
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
    GetNativePredicates(env, info)->Between(field, low, high);
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
    GetNativePredicates(env, info)->NotBetween(field, low, high);
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
    napi_typeof(env, args[1], &valueType);
    switch (valueType) {
        case napi_number: {
            double value;
            napi_get_value_double(env, args[1], &value);
            GetNativePredicates(env, info)->GreaterThan(field, value);
        }
        case napi_string: {
            std::string value = DataShareJSUtils::Convert2String(env, args[1], DataShareJSUtils::DEFAULT_BUF_SIZE);
            GetNativePredicates(env, info)->GreaterThan(field, value);
        }
        default:
            break;
    }
    // std::string value = DataShareJSUtils::ConvertAny2String(env, args[1]);
    // GetNativePredicates(env, info)->GreaterThan(field, value);
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
    napi_typeof(env, args[1], &valueType);
    switch (valueType) {
        case napi_number: {
            double value;
            napi_get_value_double(env, args[1], &value);
            GetNativePredicates(env, info)->LessThan(field, value);
        }
        case napi_string: {
            std::string value = DataShareJSUtils::Convert2String(env, args[1], DataShareJSUtils::DEFAULT_BUF_SIZE);
            GetNativePredicates(env, info)->LessThan(field, value);
        }
        default:
            break;
    }
    // std::string value = DataShareJSUtils::ConvertAny2String(env, args[1]);
    // GetNativePredicates(env, info)->LessThan(field, value);
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
    napi_typeof(env, args[1], &valueType);
    switch (valueType) {
        case napi_number: {
            double value;
            napi_get_value_double(env, args[1], &value);
            GetNativePredicates(env, info)->GreaterThanOrEqualTo(field, value);
        }
        case napi_string: {
            std::string value = DataShareJSUtils::Convert2String(env, args[1], DataShareJSUtils::DEFAULT_BUF_SIZE);
            GetNativePredicates(env, info)->GreaterThanOrEqualTo(field, value);
        }
        default:
            break;
    }
    // std::string value = DataShareJSUtils::ConvertAny2String(env, args[1]);
    // GetNativePredicates(env, info)->GreaterThanOrEqualTo(field, value);
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
    napi_typeof(env, args[1], &valueType);
    switch (valueType) {
        case napi_number: {
            double value;
            napi_get_value_double(env, args[1], &value);
            GetNativePredicates(env, info)->LessThanOrEqualTo(field, value);
        }
        case napi_string: {
            std::string value = DataShareJSUtils::Convert2String(env, args[1], DataShareJSUtils::DEFAULT_BUF_SIZE);
            GetNativePredicates(env, info)->LessThanOrEqualTo(field, value);
        }
        default:
            break;
    }
    // std::string value = DataShareJSUtils::ConvertAny2String(env, args[1]);
    // GetNativePredicates(env, info)->LessThanOrEqualTo(field, value);
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
    GetNativePredicates(env, info)->OrderByAsc(field);
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
    GetNativePredicates(env, info)->OrderByDesc(field);
    return thiz;
}

napi_value DataSharePredicatesProxy::Distinct(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::Distinct on called.");
    napi_value thiz;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    GetNativePredicates(env, info)->Distinct();
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
    napi_get_value_int32(env, args[0], &number);
    int offset = 0;
    napi_get_value_int32(env, args[1], &offset);
    // GetNativePredicates(env, info)->Limit(number, offset);
    return thiz;
}

napi_value DataSharePredicatesProxy::Offset(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::Offset on called.");
    napi_value thiz;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::Offset Invalid argvs!");
    int32_t offset = 0;
    napi_get_value_int32(env, args[0], &offset);
    GetNativePredicates(env, info)->Offset(offset);
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
    GetNativePredicates(env, info)->GroupBy(fields);
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
    GetNativePredicates(env, info)->IndexedBy(indexName);
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
    GetNativePredicates(env, info)->In(field, values);
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
    GetNativePredicates(env, info)->NotIn(field, values);
    return thiz;
}

std::shared_ptr<DataSharePredicates> DataSharePredicatesProxy::GetPredicates() const
{
    return this->predicates_;
}

napi_value DataSharePredicatesProxy::SetSuggestIndex(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::SetSuggestIndex on called.");
    napi_value thiz;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::SetSuggestIndex Invalid argvs!");
    std::string index = DataShareJSUtils::Convert2String(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    GetNativePredicates(env, info)->SetSuggestIndex(index);
    return thiz;
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
    GetNativePredicates(env, info)->KeyPrefix(prefix);
    return thiz;
}

napi_value DataSharePredicatesProxy::InDevices(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::InDevices on called.");
    napi_value thiz;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    NAPI_ASSERT(env, argc > 0, "DataSharePredicatesProxy::InDevices Invalid argvs!");
    std::vector<std::string> devices = DataShareJSUtils::Convert2StrVector(env, args[0], DataShareJSUtils::DEFAULT_BUF_SIZE);
    GetNativePredicates(env, info)->InDevices(devices);
    return thiz;
}

napi_value DataSharePredicatesProxy::InAllDevices(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DataSharePredicatesProxy::InAllDevices on called.");
    napi_value thiz;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    GetNativePredicates(env, info)->InAllDevices();
    return thiz;
}
} // namespace DataShare
} // namespace OHOS
napi_value OHOS::DataShare::GetNapiObject(napi_env env, OHOS::DataShare::DataSharePredicates *predicates)
{
    return OHOS::DataShare::DataSharePredicatesProxy::NewInstance(
        env, std::shared_ptr<OHOS::DataShare::DataSharePredicates>(predicates));
}
OHOS::DataShare::DataSharePredicates *OHOS::DataShare::GetNativePredicatesObject(const napi_env &env, const napi_value &arg)
{
    auto predicates = OHOS::DataShare::DataSharePredicatesProxy::GetNativePredicates(env, arg);
    return predicates.get();
}
