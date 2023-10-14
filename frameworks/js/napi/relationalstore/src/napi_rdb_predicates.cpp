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

#include "napi_rdb_predicates.h"

#include "js_utils.h"
#include "logger.h"
#include "napi_rdb_error.h"
#include "napi_rdb_trace.h"

using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;
using namespace OHOS::AppDataMgrJsKit;

namespace OHOS {
namespace RelationalStoreJsKit {
static __thread napi_ref constructor_ = nullptr;

void RdbPredicatesProxy::Init(napi_env env, napi_value exports)
{
    LOG_INFO("RdbPredicatesProxy::Init");
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
        DECLARE_NAPI_FUNCTION("limitAs", Limit),
        DECLARE_NAPI_FUNCTION("offsetAs", Offset),
        DECLARE_NAPI_FUNCTION("groupBy", GroupBy),
        DECLARE_NAPI_FUNCTION("indexedBy", IndexedBy),
        DECLARE_NAPI_FUNCTION("in", In),
        DECLARE_NAPI_FUNCTION("notIn", NotIn),
        DECLARE_NAPI_FUNCTION("using", Using),
        DECLARE_NAPI_FUNCTION("leftOuterJoin", LeftOuterJoin),
        DECLARE_NAPI_FUNCTION("innerJoin", InnerJoin),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("clear", Clear),
        DECLARE_NAPI_FUNCTION("crossJoin", CrossJoin),
        DECLARE_NAPI_GETTER_SETTER("joinCount", GetJoinCount, SetJoinCount),
        DECLARE_NAPI_GETTER_SETTER("joinConditions", GetJoinConditions, SetJoinConditions),
        DECLARE_NAPI_GETTER_SETTER("joinNames", GetJoinTableNames, SetJoinTableNames),
        DECLARE_NAPI_GETTER_SETTER("joinTypes", GetJoinTypes, SetJoinTypes),
        DECLARE_NAPI_GETTER("statement", GetStatement),
        DECLARE_NAPI_GETTER("bindArgs", GetBindArgs),
        DECLARE_NAPI_FUNCTION("inDevices", InDevices),
        DECLARE_NAPI_FUNCTION("inAllDevices", InAllDevices),
    };

    napi_value cons = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_define_class(env, "RdbPredicates", NAPI_AUTO_LENGTH, New, nullptr,
                                   sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors, &cons));
    NAPI_CALL_RETURN_VOID(env, napi_create_reference(env, cons, 1, &constructor_));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, exports, "RdbPredicates", cons));

    LOG_DEBUG("RdbPredicatesProxy::Init end");
}

napi_value RdbPredicatesProxy::New(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::New begin.");
    napi_value new_target = nullptr;
    NAPI_CALL(env, napi_get_new_target(env, info, &new_target));
    bool is_constructor = (new_target != nullptr);

    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_value thiz = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thiz, nullptr));

    if (is_constructor) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, args[0], &valueType));
        RDB_NAPI_ASSERT(env, valueType == napi_string, std::make_shared<ParamError>("name", "not empty"));
        std::string tableName = JSUtils::Convert2String(env, args[0]);
        RDB_NAPI_ASSERT(env, !tableName.empty(), std::make_shared<ParamError>("name", "not empty"));
        auto *proxy = new (std::nothrow) RdbPredicatesProxy(tableName);
        if (proxy == nullptr) {
            LOG_ERROR("RdbPredicatesProxy::New new failed, proxy is nullptr");
            return nullptr;
        }
        napi_status status = napi_wrap(env, thiz, proxy, RdbPredicatesProxy::Destructor, nullptr, nullptr);
        if (status != napi_ok) {
            LOG_ERROR("RdbPredicatesProxy::New napi_wrap failed! napi_status:%{public}d!", status);
            delete proxy;
            return nullptr;
        }
        return thiz;
    }

    argc = 1;
    napi_value argv[1] = { args[0] };

    napi_value cons = nullptr;
    NAPI_CALL(env, napi_get_reference_value(env, constructor_, &cons));

    napi_value output = nullptr;
    NAPI_CALL(env, napi_new_instance(env, cons, argc, argv, &output));
    LOG_DEBUG("RdbPredicatesProxy::New end");
    return output;
}

napi_value RdbPredicatesProxy::NewInstance(napi_env env, std::shared_ptr<NativeRdb::RdbPredicates> value)
{
    LOG_DEBUG("RdbPredicatesProxy::NewInstance begin.");
    napi_value cons = nullptr;
    napi_status status = napi_get_reference_value(env, constructor_, &cons);
    if (status != napi_ok) {
        LOG_ERROR("RdbPredicatesProxy::NewInstance get constructor failed! napi_status:%{public}d!", status);
        return nullptr;
    }
    size_t argc = 1;
    napi_value args[1] = { JSUtils::Convert2JSValue(env, value->GetTableName()) };
    napi_value instance = nullptr;
    status = napi_new_instance(env, cons, argc, args, &instance);
    if (status != napi_ok) {
        LOG_ERROR("RdbPredicatesProxy::NewInstance napi_new_instance failed! napi_status:%{public}d!", status);
        return nullptr;
    }

    RdbPredicatesProxy *proxy = nullptr;
    status = napi_unwrap(env, instance, reinterpret_cast<void **>(&proxy));
    if (status != napi_ok) {
        LOG_ERROR("RdbPredicatesProxy::NewInstance native instance is nullptr! napi_status:%{public}d!", status);
        return instance;
    }
    proxy->predicates_ = std::move(value);
    LOG_DEBUG("RdbPredicatesProxy::NewInstance end");
    return instance;
}

void RdbPredicatesProxy::Destructor(napi_env env, void *nativeObject, void *)
{
    RdbPredicatesProxy *proxy = static_cast<RdbPredicatesProxy *>(nativeObject);
    delete proxy;
}

RdbPredicatesProxy::~RdbPredicatesProxy()
{
    LOG_DEBUG("RdbPredicatesProxy destructor");
}

RdbPredicatesProxy::RdbPredicatesProxy(std::string &tableName)
    : predicates_(std::make_shared<NativeRdb::RdbPredicates>(tableName))
{
}

RdbPredicatesProxy *RdbPredicatesProxy::GetNativePredicates(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::GetNativePredicates begin.");
    napi_value thiz = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);

    RdbPredicatesProxy *proxy = nullptr;
    napi_unwrap(env, thiz, reinterpret_cast<void **>(&proxy));
    RDB_NAPI_ASSERT(env, proxy && proxy->predicates_, std::make_shared<ParamError>("predicates", "null"));
    return proxy;
}

RdbPredicatesProxy *RdbPredicatesProxy::ParseFieldArrayByName(napi_env env, napi_callback_info info, napi_value &thiz,
    std::vector<std::string> &fieldarray, const std::string fieldName, const std::string fieldType)
{
    size_t argc = 1;
    napi_value args[1] = { nullptr };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    RDB_NAPI_ASSERT(env, argc == 1, std::make_shared<ParamNumError>("1"));

    int32_t ret = JSUtils::Convert2Value(env, args[0], fieldarray);
    if (ret != napi_ok && fieldName == "devices") {
        std::string field;
        ret = JSUtils::Convert2Value(env, args[0], field);
        RDB_NAPI_ASSERT(env, ret == napi_ok, std::make_shared<ParamError>(fieldName, "a " + fieldType + " array."));
        fieldarray.push_back(field);
    }
    RDB_NAPI_ASSERT(env, ret == napi_ok, std::make_shared<ParamError>(fieldName, "a " + fieldType + " array."));

    RdbPredicatesProxy *proxy = nullptr;
    napi_unwrap(env, thiz, reinterpret_cast<void **>(&proxy));
    RDB_NAPI_ASSERT(env, proxy && proxy->predicates_, std::make_shared<ParamError>("predicates", "null"));
    return proxy;
}

RdbPredicatesProxy *RdbPredicatesProxy::ParseFieldByName(
    napi_env env, napi_callback_info info, napi_value &thiz, std::string &field, const std::string fieldName)
{
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    RDB_NAPI_ASSERT(env, argc == 1, std::make_shared<ParamNumError>("1"));

    field = JSUtils::Convert2String(env, args[0]);
    RDB_NAPI_ASSERT(env, !field.empty(), std::make_shared<ParamError>(fieldName, "not empty"));

    RdbPredicatesProxy *proxy = nullptr;
    napi_unwrap(env, thiz, reinterpret_cast<void **>(&proxy));
    RDB_NAPI_ASSERT(env, proxy && proxy->predicates_, std::make_shared<ParamError>("predicates", "null"));
    return proxy;
}

RdbPredicatesProxy *RdbPredicatesProxy::ParseInt32FieldByName(
    napi_env env, napi_callback_info info, napi_value &thiz, int32_t &field, const std::string fieldName)
{
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    RDB_NAPI_ASSERT(env, argc == 1, std::make_shared<ParamNumError>("1"));

    napi_status status = napi_get_value_int32(env, args[0], &field);
    RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<ParamError>(fieldName, "a number."));

    RdbPredicatesProxy *proxy = nullptr;
    napi_unwrap(env, thiz, reinterpret_cast<void **>(&proxy));
    RDB_NAPI_ASSERT(env, proxy && proxy->predicates_, std::make_shared<ParamError>("predicates", "null"));
    return proxy;
}

RdbPredicatesProxy *RdbPredicatesProxy::ParseFieldAndValueArray(napi_env env, napi_callback_info info,
    napi_value &thiz, std::string &field, std::vector<ValueObject> &value, const std::string valueType)
{
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    RDB_NAPI_ASSERT(env, argc == 2, std::make_shared<ParamNumError>("2"));

    field = JSUtils::Convert2String(env, args[0]);
    RDB_NAPI_ASSERT(env, !field.empty(), std::make_shared<ParamError>("field", "not empty"));

    int32_t ret = JSUtils::Convert2Value(env, args[1], value);
    RDB_NAPI_ASSERT(env, ret == napi_ok, std::make_shared<ParamError>("value", "a " + valueType + " array."));

    RdbPredicatesProxy *proxy = nullptr;
    napi_unwrap(env, thiz, reinterpret_cast<void **>(&proxy));
    RDB_NAPI_ASSERT(env, proxy && proxy->predicates_, std::make_shared<ParamError>("predicates", "null"));
    return proxy;
}

RdbPredicatesProxy *RdbPredicatesProxy::ParseFieldAndValue(napi_env env, napi_callback_info info, napi_value &thiz,
    std::string &field, ValueObject &value, const std::string valueType)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    RDB_NAPI_ASSERT(env, argc == 2, std::make_shared<ParamNumError>("2"));

    field = JSUtils::Convert2String(env, args[0]);
    RDB_NAPI_ASSERT(env, !field.empty(), std::make_shared<ParamError>("field", "not empty"));

    int32_t ret = JSUtils::Convert2Value(env, args[1], value);
    RDB_NAPI_ASSERT(env, ret == napi_ok, std::make_shared<ParamError>("value", "a " + valueType + " array."));

    RdbPredicatesProxy *proxy = nullptr;
    napi_unwrap(env, thiz, reinterpret_cast<void **>(&proxy));
    RDB_NAPI_ASSERT(env, proxy && proxy->predicates_, std::make_shared<ParamError>("predicates", "null"));
    return proxy;
}

RdbPredicatesProxy *RdbPredicatesProxy::ParseFieldAndStringValue(napi_env env, napi_callback_info info,
    napi_value &thiz, std::string &field, std::string &value, const std::string valueType)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    RDB_NAPI_ASSERT(env, argc == 2, std::make_shared<ParamNumError>("2"));

    field = JSUtils::Convert2String(env, args[0]);
    RDB_NAPI_ASSERT(env, !field.empty(), std::make_shared<ParamError>("field", "not empty"));

    int32_t ret = JSUtils::Convert2Value(env, args[1], value);
    RDB_NAPI_ASSERT(env, ret == napi_ok, std::make_shared<ParamError>("value", "a string."));

    RdbPredicatesProxy *proxy = nullptr;
    napi_unwrap(env, thiz, reinterpret_cast<void **>(&proxy));
    RDB_NAPI_ASSERT(env, proxy && proxy->predicates_, std::make_shared<ParamError>("predicates", "null"));
    return proxy;
}

RdbPredicatesProxy *RdbPredicatesProxy::ParseFieldLowAndHigh(
    napi_env env, napi_callback_info info, napi_value &thiz, std::string &field, ValueObject &low, ValueObject &high)
{
    size_t argc = 3;
    napi_value args[3] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    RDB_NAPI_ASSERT(env, argc == 3, std::make_shared<ParamNumError>("3"));

    field = JSUtils::Convert2String(env, args[0]);
    RDB_NAPI_ASSERT(env, !field.empty(), std::make_shared<ParamError>("field", "not empty"));

    int32_t ret = JSUtils::Convert2Value(env, args[1], low);
    RDB_NAPI_ASSERT(env, ret == napi_ok, std::make_shared<ParamError>("low", "a valueType."));

    ret = JSUtils::Convert2Value(env, args[2], high);
    RDB_NAPI_ASSERT(env, ret == napi_ok, std::make_shared<ParamError>("high", "a valueType."));

    RdbPredicatesProxy *proxy = nullptr;
    napi_unwrap(env, thiz, reinterpret_cast<void **>(&proxy));
    RDB_NAPI_ASSERT(env, proxy && proxy->predicates_, std::make_shared<ParamError>("predicates", "null"));
    return proxy;
}

napi_value RdbPredicatesProxy::EqualTo(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RdbPredicatesProxy::EqualTo begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    ValueObject value;
    auto predicatesProxy = ParseFieldAndValue(env, info, thiz, field, value, "ValueType");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->EqualTo(field, value);
    return thiz;
}

napi_value RdbPredicatesProxy::NotEqualTo(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::NotEqualTo begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    ValueObject value;
    auto predicatesProxy = ParseFieldAndValue(env, info, thiz, field, value, "ValueType");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->NotEqualTo(field, value);
    return thiz;
}

napi_value RdbPredicatesProxy::BeginWrap(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::BeginWrap begin.");
    napi_value thiz = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    RdbPredicatesProxy *predicatesProxy = GetNativePredicates(env, info);
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->BeginWrap();
    return thiz;
}

napi_value RdbPredicatesProxy::EndWrap(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::EndWrap begin.");
    napi_value thiz = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    RdbPredicatesProxy *predicatesProxy = GetNativePredicates(env, info);
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->EndWrap();
    return thiz;
}

napi_value RdbPredicatesProxy::Or(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::Or begin.");
    napi_value thiz = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    RdbPredicatesProxy *predicatesProxy = GetNativePredicates(env, info);
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->Or();
    return thiz;
}

napi_value RdbPredicatesProxy::And(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::And begin.");
    napi_value thiz = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    RdbPredicatesProxy *predicatesProxy = GetNativePredicates(env, info);
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->And();
    return thiz;
}

napi_value RdbPredicatesProxy::Contains(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::Contains begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    std::string value = "";
    auto predicatesProxy = ParseFieldAndStringValue(env, info, thiz, field, value, "string");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->Contains(field, value);
    return thiz;
}

napi_value RdbPredicatesProxy::BeginsWith(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::BeginsWith begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    std::string value = "";
    auto predicatesProxy = ParseFieldAndStringValue(env, info, thiz, field, value, "string");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->BeginsWith(field, value);
    return thiz;
}

napi_value RdbPredicatesProxy::EndsWith(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::EndsWith begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    std::string value = "";
    auto predicatesProxy = ParseFieldAndStringValue(env, info, thiz, field, value, "string");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->EndsWith(field, value);
    return thiz;
}

napi_value RdbPredicatesProxy::IsNull(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::IsNull begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    auto predicatesProxy = ParseFieldByName(env, info, thiz, field, "field");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->IsNull(field);
    return thiz;
}

napi_value RdbPredicatesProxy::IsNotNull(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::IsNotNull begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    auto predicatesProxy = ParseFieldByName(env, info, thiz, field, "field");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->IsNotNull(field);
    return thiz;
}

napi_value RdbPredicatesProxy::Like(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::Like begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    std::string value = "";
    auto predicatesProxy = ParseFieldAndStringValue(env, info, thiz, field, value, "string");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->Like(field, value);
    return thiz;
}

napi_value RdbPredicatesProxy::Glob(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::Glob begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    std::string value = "";
    auto predicatesProxy = ParseFieldAndStringValue(env, info, thiz, field, value, "string");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->Glob(field, value);
    return thiz;
}

napi_value RdbPredicatesProxy::Between(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::Between begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    ValueObject low;
    ValueObject high;
    auto predicatesProxy = ParseFieldLowAndHigh(env, info, thiz, field, low, high);
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->Between(field, low, high);
    return thiz;
}

napi_value RdbPredicatesProxy::NotBetween(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::NotBetween begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    ValueObject low;
    ValueObject high;
    auto predicatesProxy = ParseFieldLowAndHigh(env, info, thiz, field, low, high);
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->NotBetween(field, low, high);
    return thiz;
}

napi_value RdbPredicatesProxy::GreaterThan(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::GreaterThan begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    ValueObject value;
    auto predicatesProxy = ParseFieldAndValue(env, info, thiz, field, value, "ValueType");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->GreaterThan(field, value);
    return thiz;
}

napi_value RdbPredicatesProxy::LessThan(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::LessThan begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    ValueObject value;
    auto predicatesProxy = ParseFieldAndValue(env, info, thiz, field, value, "ValueType");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->LessThan(field, value);
    return thiz;
}

napi_value RdbPredicatesProxy::GreaterThanOrEqualTo(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::GreaterThanOrEqualTo begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    ValueObject value;
    auto predicatesProxy = ParseFieldAndValue(env, info, thiz, field, value, "ValueType");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->GreaterThanOrEqualTo(field, value);
    return thiz;
}

napi_value RdbPredicatesProxy::LessThanOrEqualTo(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::LessThanOrEqualTo begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    ValueObject value;
    auto predicatesProxy = ParseFieldAndValue(env, info, thiz, field, value, "ValueType");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->LessThanOrEqualTo(field, value);
    return thiz;
}

napi_value RdbPredicatesProxy::OrderByAsc(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::OrderByAsc begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    auto predicatesProxy = ParseFieldByName(env, info, thiz, field, "field");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->OrderByAsc(field);
    return thiz;
}

napi_value RdbPredicatesProxy::OrderByDesc(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::OrderByDesc begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    auto predicatesProxy = ParseFieldByName(env, info, thiz, field, "field");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->OrderByDesc(field);
    return thiz;
}

napi_value RdbPredicatesProxy::Distinct(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::Distinct begin.");
    napi_value thiz = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    RdbPredicatesProxy *predicatesProxy = GetNativePredicates(env, info);
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->Distinct();
    return thiz;
}

napi_value RdbPredicatesProxy::Limit(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::Limit begin.");
    napi_value thiz = nullptr;
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    RdbPredicatesProxy *predicatesProxy = GetNativePredicates(env, info);
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    //Ensure that the number of parameters is 1 or 2
    RDB_NAPI_ASSERT(env, argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 or 2"));

    int32_t offset = AbsPredicates::INIT_OFFSET_VALUE;
    int32_t limit = AbsPredicates::INIT_LIMIT_VALUE;
    if (argc == 1) {
        napi_status status = napi_get_value_int32(env, args[0], &limit);
        RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<ParamError>("limit", "a number."));
        predicatesProxy->predicates_->Limit(limit);
    } else {
        napi_status status = napi_get_value_int32(env, args[0], &offset);
        RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<ParamError>("offset", "a number."));

        status = napi_get_value_int32(env, args[1], &limit);
        RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<ParamError>("limit", "a number."));
        predicatesProxy->predicates_->Limit(offset, limit);
    }

    return thiz;
}

napi_value RdbPredicatesProxy::Offset(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::Offset begin.");
    napi_value thiz = nullptr;
    int32_t offset = AbsPredicates::INIT_OFFSET_VALUE;
    auto predicatesProxy = ParseInt32FieldByName(env, info, thiz, offset, "rowOffset");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->Offset(offset);
    return thiz;
}

napi_value RdbPredicatesProxy::GroupBy(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::GroupBy begin.");
    napi_value thiz = nullptr;
    std::vector<std::string> fields;
    auto predicatesProxy = ParseFieldArrayByName(env, info, thiz, fields, "fields", "string");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->GroupBy(fields);
    return thiz;
}

napi_value RdbPredicatesProxy::IndexedBy(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::IndexedBy begin.");
    napi_value thiz = nullptr;
    std::string indexName = "";
    auto predicatesProxy = ParseFieldByName(env, info, thiz, indexName, "fields");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->IndexedBy(indexName);
    return thiz;
}

napi_value RdbPredicatesProxy::In(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::In begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    std::vector<ValueObject> values;
    auto predicatesProxy = ParseFieldAndValueArray(env, info, thiz, field, values, "ValueType");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->In(field, values);
    return thiz;
}

napi_value RdbPredicatesProxy::NotIn(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::NotIn begin.");
    napi_value thiz = nullptr;
    std::string field = "";
    std::vector<ValueObject> values;
    auto predicatesProxy = ParseFieldAndValueArray(env, info, thiz, field, values, "ValueType");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->NotIn(field, values);
    return thiz;
}

napi_value RdbPredicatesProxy::Using(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::Using begin.");
    napi_value thiz = nullptr;
    std::vector<std::string> fields;
    auto predicatesProxy = ParseFieldArrayByName(env, info, thiz, fields, "fields", "string");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->Using(fields);
    return thiz;
}

napi_value RdbPredicatesProxy::LeftOuterJoin(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::LeftOuterJoin begin.");
    napi_value thiz = nullptr;
    std::string tablename = "";
    auto predicatesProxy = ParseFieldByName(env, info, thiz, tablename, "tablename");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->LeftOuterJoin(tablename);
    return thiz;
}

napi_value RdbPredicatesProxy::InnerJoin(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::InnerJoin begin.");
    napi_value thiz = nullptr;
    std::string tablename = "";
    auto predicatesProxy = ParseFieldByName(env, info, thiz, tablename, "tablename");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->InnerJoin(tablename);
    return thiz;
}

napi_value RdbPredicatesProxy::On(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::On begin.");
    napi_value thiz = nullptr;
    std::vector<std::string> clauses;
    auto predicatesProxy = ParseFieldArrayByName(env, info, thiz, clauses, "clauses", "string");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->On(clauses);
    return thiz;
}

napi_value RdbPredicatesProxy::GetStatement(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    RdbPredicatesProxy *predicatesProxy = GetNativePredicates(env, info);
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);

    std::string statement = predicatesProxy->predicates_->GetStatement();
    return JSUtils::Convert2JSValue(env, statement);
}

napi_value RdbPredicatesProxy::GetBindArgs(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    RdbPredicatesProxy *predicatesProxy = GetNativePredicates(env, info);
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);

    std::vector<ValueObject> bindArgs = predicatesProxy->predicates_->GetBindArgs();
    return JSUtils::Convert2JSValue(env, bindArgs);
}

napi_value RdbPredicatesProxy::Clear(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::Clear begin.");
    napi_value thiz = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    RdbPredicatesProxy *predicatesProxy = GetNativePredicates(env, info);
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->Clear();
    return thiz;
}

napi_value RdbPredicatesProxy::CrossJoin(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::CrossJoin begin.");
    napi_value thiz = nullptr;
    std::string tablename = "";
    auto predicatesProxy = ParseFieldByName(env, info, thiz, tablename, "tablename");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->CrossJoin(tablename);
    return thiz;
}

napi_value RdbPredicatesProxy::GetJoinCount(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::GetJoinCount begin.");
    napi_value thiz = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    RdbPredicatesProxy *predicatesProxy = GetNativePredicates(env, info);
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    int errCode = predicatesProxy->predicates_->GetJoinCount();
    return JSUtils::Convert2JSValue(env, errCode);
}

napi_value RdbPredicatesProxy::SetJoinCount(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::SetJoinCount begin.");
    napi_value thiz;
    int32_t joinCount = 0;
    auto predicatesProxy = ParseInt32FieldByName(env, info, thiz, joinCount, "joinCount");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->SetJoinCount(joinCount);
    return thiz;
}

napi_value RdbPredicatesProxy::GetJoinTypes(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::GetJoinTypes begin.");
    napi_value thiz = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    RdbPredicatesProxy *predicatesProxy = GetNativePredicates(env, info);
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    auto joinTypes = predicatesProxy->predicates_->GetJoinTypes();
    return JSUtils::Convert2JSValue(env, joinTypes);
}

napi_value RdbPredicatesProxy::GetJoinTableNames(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::GetJoinTableNames begin.");
    napi_value thiz = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    RdbPredicatesProxy *predicatesProxy = GetNativePredicates(env, info);
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    auto joinTableNames = predicatesProxy->predicates_->GetJoinTableNames();
    return JSUtils::Convert2JSValue(env, joinTableNames);
}

napi_value RdbPredicatesProxy::GetJoinConditions(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::GetJoinConditions begin.");
    napi_value thiz = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    RdbPredicatesProxy *predicatesProxy = GetNativePredicates(env, info);
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    auto joinConditions = predicatesProxy->predicates_->GetJoinConditions();
    return JSUtils::Convert2JSValue(env, joinConditions);
}

napi_value RdbPredicatesProxy::SetJoinConditions(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::SetJoinConditions begin.");
    napi_value thiz = nullptr;
    std::vector<std::string> joinConditions;
    auto predicatesProxy = ParseFieldArrayByName(env, info, thiz, joinConditions, "joinConditions", "string");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->SetJoinConditions(joinConditions);
    return thiz;
}

napi_value RdbPredicatesProxy::SetJoinTableNames(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::SetJoinTableNames begin.");
    napi_value thiz = nullptr;
    std::vector<std::string> joinNames;
    auto predicatesProxy = ParseFieldArrayByName(env, info, thiz, joinNames, "joinNames", "string");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->SetJoinTableNames(joinNames);
    return thiz;
}

napi_value RdbPredicatesProxy::SetJoinTypes(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::SetJoinTypes begin.");
    napi_value thiz = nullptr;
    std::vector<std::string> joinTypes;
    auto predicatesProxy = ParseFieldArrayByName(env, info, thiz, joinTypes, "joinTypes", "string");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->SetJoinTypes(joinTypes);
    return thiz;
}

std::shared_ptr<NativeRdb::RdbPredicates> RdbPredicatesProxy::GetPredicates() const
{
    return this->predicates_;
}

napi_value RdbPredicatesProxy::InDevices(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::InDevices begin.");
    napi_value thiz = nullptr;
    std::vector<std::string> devices;
    auto predicatesProxy = ParseFieldArrayByName(env, info, thiz, devices, "devices", "string");
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->InDevices(devices);
    return thiz;
}

napi_value RdbPredicatesProxy::InAllDevices(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbPredicatesProxy::InAllDevices begin.");
    napi_value thiz = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr);
    auto predicatesProxy = GetNativePredicates(env, info);
    CHECK_RETURN_NULL(predicatesProxy && predicatesProxy->predicates_);
    predicatesProxy->predicates_->InAllDevices();
    return thiz;
}
} // namespace RelationalStoreJsKit
} // namespace OHOS
