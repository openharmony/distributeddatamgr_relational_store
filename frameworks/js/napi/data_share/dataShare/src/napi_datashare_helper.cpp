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

#include "napi_datashare_helper.h"

#include <uv.h>
#include <cstring>
#include <vector>

#include "datashare_helper.h"
#include "data_ability_observer_interface.h"
#include "uri.h"

#include "datashare_log.h"
#include "message_parcel.h"
#include "napi_base_context.h"
#include "datashare_predicates_proxy.h"
#include "datashare_result_set_proxy.h"
#include "securec.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace DataShare {
namespace {
const std::string DATASHARE_CLASS_NAME = "DataShareHelper";
constexpr int NO_ERROR = 0;
constexpr int INVALID_PARAMETER = -1;

std::string NapiValueToStringUtf8(napi_env env, napi_value value)
{
    std::string result = "";
    return UnwrapStringFromJS(env, value, result);
}

bool NapiValueToArrayStringUtf8(napi_env env, napi_value param, std::vector<std::string> &result)
{
    return UnwrapArrayStringFromJS(env, param, result);
}
} // namespace

std::list<std::shared_ptr<DataShareHelper>> g_dataShareHelperList;
static napi_ref g_constructorRef = nullptr;

/**
 * @brief acquireDataAbilityHelper processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param dataShareHelperCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value AcquireDataShareHelperWrap(napi_env env, napi_callback_info info, DataShareHelperCB *dataShareHelperCB)
{
    LOG_INFO("%{public}s,called", __func__);
    if (dataShareHelperCB == nullptr) {
        LOG_ERROR("%{public}s,dataShareHelperCB == nullptr", __func__);
        return nullptr;
    }

    size_t requireArgc = ARGS_THREE;
    size_t argc = ARGS_THREE;
    napi_value args[ARGS_THREE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr));
    if (argc > requireArgc) {
        LOG_ERROR("%{public}s, Wrong argument count %{public}zu.", __func__, argc);
        return nullptr;
    }

    napi_value result = nullptr;
    napi_value cons = nullptr;
    if (napi_get_reference_value(env, g_constructorRef, &cons) != napi_ok) {
        return nullptr;
    }
    NAPI_CALL(env, napi_new_instance(env, cons, ARGS_THREE, args, &result));

    if (!IsTypeForNapiValue(env, result, napi_object)) {
        LOG_ERROR("%{public}s, IsTypeForNapiValue isn`t object", __func__);
        return nullptr;
    }

    if (IsTypeForNapiValue(env, result, napi_null)) {
        LOG_ERROR("%{public}s, IsTypeForNapiValue is null", __func__);
        return nullptr;
    }

    if (IsTypeForNapiValue(env, result, napi_undefined)) {
        LOG_ERROR("%{public}s, IsTypeForNapiValue is undefined", __func__);
        return nullptr;
    }

    delete dataShareHelperCB;
    LOG_INFO("%{public}s,end", __func__);
    return result;
}

/**
 * @brief AcquireDataAbilityHelper.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_AcquireDataShareHelperCommon(napi_env env, napi_callback_info info, AbilityType abilityType)
{
    LOG_INFO("%{public}s,called", __func__);
    DataShareHelperCB *dataShareHelperCB = new (std::nothrow) DataShareHelperCB;
    if (dataShareHelperCB == nullptr) {
        LOG_ERROR("%{public}s, dataShareHelperCB == nullptr", __func__);
        return WrapVoidToJS(env);
    }

    dataShareHelperCB->cbBase.cbInfo.env = env;
    dataShareHelperCB->cbBase.errCode = NAPI_ERR_NO_ERROR;
    dataShareHelperCB->cbBase.abilityType = abilityType;
    napi_value ret = AcquireDataShareHelperWrap(env, info, dataShareHelperCB);
    if (ret == nullptr) {
        LOG_ERROR("%{public}s, ret == nullptr", __func__);
        delete dataShareHelperCB;
        dataShareHelperCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

/**
 * @brief DataShareHelper NAPI method : CreateDataShareHelper.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_CreateDataShareHelper(napi_env env, napi_callback_info info)
{
    LOG_INFO("%{public}s, called", __func__);
    return NAPI_AcquireDataShareHelperCommon(env, info, AbilityType::EXTENSION);
}

/**
 * @brief DataShareHelper NAPI module registration.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param exports An empty object via the exports parameter as a convenience.
 *
 * @return The return value from Init is treated as the exports object for the module.
 */
napi_value DataShareHelperInit(napi_env env, napi_value exports)
{
    LOG_INFO("%{public}s,called", __func__);
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("insert", NAPI_Insert),
        DECLARE_NAPI_FUNCTION("notifyChange", NAPI_NotifyChange),
        DECLARE_NAPI_FUNCTION("on", NAPI_Register),
        DECLARE_NAPI_FUNCTION("off", NAPI_UnRegister),
        DECLARE_NAPI_FUNCTION("delete", NAPI_Delete),
        DECLARE_NAPI_FUNCTION("query", NAPI_Query),
        DECLARE_NAPI_FUNCTION("update", NAPI_Update),
        DECLARE_NAPI_FUNCTION("batchInsert", NAPI_BatchInsert),
        DECLARE_NAPI_FUNCTION("openFile", NAPI_OpenFile),
        DECLARE_NAPI_FUNCTION("getType", NAPI_GetType),
        DECLARE_NAPI_FUNCTION("getFileTypes", NAPI_GetFileTypes),
        DECLARE_NAPI_FUNCTION("normalizeUri", NAPI_NormalizeUri),
        DECLARE_NAPI_FUNCTION("denormalizeUri", NAPI_DenormalizeUri),
        DECLARE_NAPI_FUNCTION("release", NAPI_Release),
    };

    napi_value cons = nullptr;
    NAPI_CALL(env,
        napi_define_class(env,
            DATASHARE_CLASS_NAME.c_str(),
            NAPI_AUTO_LENGTH,
            DataShareHelperConstructor,
            nullptr,
            sizeof(properties) / sizeof(*properties),
            properties,
            &cons));
    g_dataShareHelperList.clear();
    NAPI_CALL(env, napi_create_reference(env, cons, 1, &g_constructorRef));
    NAPI_CALL(env, napi_set_named_property(env, exports, DATASHARE_CLASS_NAME.c_str(), cons));

    napi_property_descriptor export_properties[] = {
        DECLARE_NAPI_FUNCTION("createDataShareHelper", NAPI_CreateDataShareHelper),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(export_properties) / sizeof(export_properties[0]),
        export_properties));
    return exports;
}

napi_value DataShareHelperConstructor(napi_env env, napi_callback_info info)
{
    LOG_INFO("%{public}s, called", __func__);
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    NAPI_ASSERT(env, argc > 0, "Wrong number of arguments");
    std::string strUri;
    std::shared_ptr<DataShareHelper> dataShareHelper = nullptr;
    bool isStageMode = false;
    napi_status status = AbilityRuntime::IsStageContext(env, argv[PARAM0], isStageMode);
    if (status != napi_ok || !isStageMode) {
        auto ability = OHOS::AbilityRuntime::GetCurrentAbility(env);
        strUri = NapiValueToStringUtf8(env, argv[PARAM0]);
        NAPI_ASSERT(env, ability != nullptr, "DataShareHelperConstructor: failed to get native ability");
        LOG_INFO("FA Model: strUri = %{public}s", strUri.c_str());
        dataShareHelper = DataShareHelper::Creator(ability->GetContext(), strUri);
    } else {
        auto context = OHOS::AbilityRuntime::GetStageModeContext(env, argv[PARAM0]);
        strUri = NapiValueToStringUtf8(env, argv[PARAM1]);
        NAPI_ASSERT(env, context != nullptr, "DataShareHelperConstructor: failed to get native context");
        LOG_INFO("Stage Model: strUri = %{public}s", strUri.c_str());
        dataShareHelper = DataShareHelper::Creator(context, strUri);
    }
    NAPI_ASSERT(env, dataShareHelper != nullptr, "DataShareHelperConstructor: dataShareHelper is nullptr");
    g_dataShareHelperList.emplace_back(dataShareHelper);
    napi_wrap(env, thisVar, dataShareHelper.get(), [](napi_env env, void *data, void *hint) {
            DataShareHelper *objectInfo = static_cast<DataShareHelper *>(data);
            auto helper = std::find_if(registerInstances_.begin(), registerInstances_.end(),
                [&objectInfo](const DSHelperOnOffCB *helper) { return helper->dataShareHelper == objectInfo; });
            if (helper != registerInstances_.end()) {
                LOG_INFO("DataShareHelper finalize_cb find helper");
                (*helper)->dataShareHelper->Release();
                delete *helper;
                registerInstances_.erase(helper);
            }
            g_dataShareHelperList.remove_if([objectInfo](const std::shared_ptr<DataShareHelper> &dataShareHelper) {
                    return objectInfo == dataShareHelper.get();
                });
        }, nullptr, nullptr);
    LOG_INFO("%{public}s,called end", __func__);
    return thisVar;
}

/**
 * @brief DataShareHelper NAPI method : insert.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_Insert(napi_env env, napi_callback_info info)
{
    LOG_INFO("%{public}s, called", __func__);
    DSHelperInsertCB *insertCB = new (std::nothrow) DSHelperInsertCB;
    if (insertCB == nullptr) {
        LOG_ERROR("%{public}s, insertCB == nullptr.", __func__);
        return WrapVoidToJS(env);
    }
    insertCB->cbBase.cbInfo.env = env;
    insertCB->cbBase.asyncWork = nullptr;
    insertCB->cbBase.deferred = nullptr;
    insertCB->cbBase.ability = nullptr;

    napi_value ret = InsertWrap(env, info, insertCB);
    if (ret == nullptr) {
        LOG_ERROR("%{public}s, ret == nullptr.", __func__);
        delete insertCB;
        insertCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("%{public}s,called end", __func__);
    return ret;
}

/**
 * @brief Insert processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param insertCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value InsertWrap(napi_env env, napi_callback_info info, DSHelperInsertCB *insertCB)
{
    LOG_INFO("%{public}s,called", __func__);
    size_t argcAsync = ARGS_THREE;
    const size_t argcPromise = ARGS_TWO;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    napi_value thisVar = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        LOG_ERROR("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valuetype));
    if (valuetype == napi_string) {
        insertCB->uri = NapiValueToStringUtf8(env, args[PARAM0]);
        LOG_INFO("%{public}s,uri=%{public}s", __func__, insertCB->uri.c_str());
    } else {
        LOG_ERROR("%{public}s, Wrong argument type.", __func__);
    }

    insertCB->valueBucket.Clear();
    AnalysisValuesBucket(insertCB->valueBucket, env, args[PARAM1]);

    DataShareHelper *objectInfo = nullptr;
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    LOG_INFO("%{public}s,set DataShareHelper objectInfo", __func__);
    insertCB->dataShareHelper = objectInfo;

    if (argcAsync > argcPromise) {
        ret = InsertAsync(env, args, ARGS_TWO, insertCB);
    } else {
        ret = InsertPromise(env, insertCB);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

void AnalysisValuesBucket(DataShareValuesBucket &valuesBucket, const napi_env &env, const napi_value &arg)
{
    napi_value keys = 0;
    napi_get_property_names(env, arg, &keys);
    uint32_t arrLen = 0;
    napi_status status = napi_get_array_length(env, keys, &arrLen);
    if (status != napi_ok) {
        LOG_ERROR("ValuesBucket errr");
        return;
    }
    LOG_INFO("ValuesBucket num:%{public}d ", arrLen);
    for (size_t i = 0; i < arrLen; ++i) {
        napi_value key = 0;
        status = napi_get_element(env, keys, i, &key);
        std::string keyStr = UnwrapStringFromJS(env, key);
        napi_value value = 0;
        napi_get_property(env, arg, key, &value);

        SetValuesBucketObject(valuesBucket, env, keyStr, value);
    }
}

void SetValuesBucketObject(
    DataShareValuesBucket &valuesBucket, const napi_env &env, std::string keyStr, napi_value value)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    if (valueType == napi_string) {
        std::string valueString = UnwrapStringFromJS(env, value);
        LOG_INFO("ValueObject type:%{public}d, key:%{public}s, value:%{public}s",
            valueType,
            keyStr.c_str(),
            valueString.c_str());
        valuesBucket.PutString(keyStr, valueString);
    } else if (valueType == napi_number) {
        double valueNumber = 0;
        napi_get_value_double(env, value, &valueNumber);
        valuesBucket.PutDouble(keyStr, valueNumber);
        LOG_INFO(
            "ValueObject type:%{public}d, key:%{public}s, value:%{public}lf", valueType, keyStr.c_str(), valueNumber);
    } else if (valueType == napi_boolean) {
        bool valueBool = false;
        napi_get_value_bool(env, value, &valueBool);
        LOG_INFO(
            "ValueObject type:%{public}d, key:%{public}s, value:%{public}d", valueType, keyStr.c_str(), valueBool);
        valuesBucket.PutBool(keyStr, valueBool);
    } else if (valueType == napi_null) {
        valuesBucket.PutNull(keyStr);
        LOG_INFO("ValueObject type:%{public}d, key:%{public}s, value:null", valueType, keyStr.c_str());
    } else if (valueType == napi_object) {
        LOG_INFO("ValueObject type:%{public}d, key:%{public}s, value:Uint8Array", valueType, keyStr.c_str());
        valuesBucket.PutBlob(keyStr, ConvertU8Vector(env, value));
    } else {
        LOG_ERROR("valuesBucket error");
    }
}
napi_value InsertAsync(napi_env env, napi_value *args, const size_t argCallback, DSHelperInsertCB *insertCB)
{
    LOG_INFO("%{public}s, asyncCallback.", __func__);
    if (args == nullptr || insertCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], 1, &insertCB->cbBase.cbInfo.callback));
    }

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            InsertExecuteCB,
            InsertAsyncCompleteCB,
            (void *)insertCB,
            &insertCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, insertCB->cbBase.asyncWork));
    napi_value result = 0;
    NAPI_CALL(env, napi_get_null(env, &result));
    LOG_INFO("%{public}s, asyncCallback end", __func__);
    return result;
}

napi_value InsertPromise(napi_env env, DSHelperInsertCB *insertCB)
{
    LOG_INFO("%{public}s, promise.", __func__);
    if (insertCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = 0;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    insertCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            InsertExecuteCB,
            InsertPromiseCompleteCB,
            (void *)insertCB,
            &insertCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, insertCB->cbBase.asyncWork));
    LOG_INFO("%{public}s, promise end", __func__);
    return promise;
}

void InsertExecuteCB(napi_env env, void *data)
{
    LOG_INFO("NAPI_Insert, worker pool thread execute.");
    DSHelperInsertCB *insertCB = static_cast<DSHelperInsertCB *>(data);
    if (insertCB->dataShareHelper != nullptr) {
        insertCB->execResult = INVALID_PARAMETER;
        if (!insertCB->uri.empty()) {
            OHOS::Uri uri(insertCB->uri);
            insertCB->result = insertCB->dataShareHelper->Insert(uri, insertCB->valueBucket);
            insertCB->execResult = NO_ERROR;
        }
    } else {
        LOG_ERROR("NAPI_Insert, dataShareHelper == nullptr.");
    }
    LOG_INFO("NAPI_Insert, worker pool thread execute end.");
}

void InsertAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_Insert, main event thread complete.");
    DSHelperInsertCB *insertCB = static_cast<DSHelperInsertCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, insertCB->cbBase.cbInfo.callback, &callback));

    result[PARAM0] = GetCallbackErrorValue(env, insertCB->execResult);
    napi_create_int32(env, insertCB->result, &result[PARAM1]);
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (insertCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, insertCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, insertCB->cbBase.asyncWork));
    delete insertCB;
    insertCB = nullptr;
    LOG_INFO("NAPI_Insert, main event thread complete end.");
}

void InsertPromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_Insert,  main event thread complete.");
    DSHelperInsertCB *insertCB = static_cast<DSHelperInsertCB *>(data);
    napi_value result = nullptr;
    napi_create_int32(env, insertCB->result, &result);
    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, insertCB->cbBase.deferred, result));
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, insertCB->cbBase.asyncWork));
    delete insertCB;
    insertCB = nullptr;
    LOG_INFO("NAPI_Insert,  main event thread complete end.");
}

/**
 * @brief Parse the ValuesBucket parameters.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param args Indicates the arguments passed into the callback.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value UnwrapValuesBucket(std::string &value, napi_env env, napi_value args)
{
    LOG_INFO("%{public}s,called", __func__);
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, args, &valueType);
    if (valueType != napi_object) {
        LOG_ERROR("%{public}s, valueType != napi_object.", __func__);
        return nullptr;
    }

    std::string strValue = "";
    if (UnwrapStringByPropertyName(env, args, "value", strValue)) {
        LOG_INFO("%{public}s,strValue=%{public}s", __func__, strValue.c_str());
        value = strValue;
    } else {
        LOG_ERROR("%{public}s, value == nullptr.", __func__);
        return nullptr;
    }

    napi_value result;
    NAPI_CALL(env, napi_create_int32(env, 1, &result));
    LOG_INFO("%{public}s,end", __func__);
    return result;
}

/**
 * @brief DataShareHelper NAPI method : notifyChange.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_NotifyChange(napi_env env, napi_callback_info info)
{
    LOG_INFO("%{public}s,called", __func__);
    DSHelperNotifyChangeCB *notifyChangeCB = new (std::nothrow) DSHelperNotifyChangeCB;
    if (notifyChangeCB == nullptr) {
        LOG_ERROR("%{public}s, notifyChangeCB == nullptr.", __func__);
        return WrapVoidToJS(env);
    }
    notifyChangeCB->cbBase.cbInfo.env = env;
    notifyChangeCB->cbBase.asyncWork = nullptr;
    notifyChangeCB->cbBase.deferred = nullptr;
    notifyChangeCB->cbBase.ability = nullptr;

    napi_value ret = NotifyChangeWrap(env, info, notifyChangeCB);
    if (ret == nullptr) {
        LOG_ERROR("%{public}s, ret == nullptr.", __func__);
        delete notifyChangeCB;
        notifyChangeCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

/**
 * @brief NotifyChange processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param notifyChangeCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value NotifyChangeWrap(napi_env env, napi_callback_info info, DSHelperNotifyChangeCB *notifyChangeCB)
{
    LOG_INFO("%{public}s,called", __func__);
    size_t argcAsync = ARGS_TWO;
    const size_t argcPromise = ARGS_ONE;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    napi_value thisVar = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        LOG_ERROR("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valuetype));
    if (valuetype == napi_string) {
        notifyChangeCB->uri = NapiValueToStringUtf8(env, args[PARAM0]);
        LOG_INFO("%{public}s,uri=%{public}s", __func__, notifyChangeCB->uri.c_str());
    } else {
        LOG_ERROR("%{public}s, Wrong argument type.", __func__);
    }

    DataShareHelper *objectInfo = nullptr;
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    LOG_INFO("Set DataShareHelper objectInfo");
    notifyChangeCB->dataShareHelper = objectInfo;

    if (argcAsync > argcPromise) {
        ret = NotifyChangeAsync(env, args, argcAsync, argcPromise, notifyChangeCB);
    } else {
        ret = NotifyChangePromise(env, notifyChangeCB);
    }
    return ret;
}

napi_value NotifyChangeAsync(
    napi_env env, napi_value *args, size_t argcAsync, const size_t argcPromise, DSHelperNotifyChangeCB *notifyChangeCB)
{
    LOG_INFO("%{public}s, asyncCallback.", __func__);
    if (args == nullptr || notifyChangeCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argcPromise], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argcPromise], 1, &notifyChangeCB->cbBase.cbInfo.callback));
    }

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            NotifyChangeExecuteCB,
            NotifyChangeAsyncCompleteCB,
            (void *)notifyChangeCB,
            &notifyChangeCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, notifyChangeCB->cbBase.asyncWork));
    napi_value result = 0;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

napi_value NotifyChangePromise(napi_env env, DSHelperNotifyChangeCB *notifyChangeCB)
{
    LOG_INFO("%{public}s, promise.", __func__);
    if (notifyChangeCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = 0;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    notifyChangeCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            NotifyChangeExecuteCB,
            NotifyChangePromiseCompleteCB,
            (void *)notifyChangeCB,
            &notifyChangeCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, notifyChangeCB->cbBase.asyncWork));
    return promise;
}

void NotifyChangeExecuteCB(napi_env env, void *data)
{
    LOG_INFO("NAPI_NotifyChange, worker pool thread execute.");
    DSHelperNotifyChangeCB *notifyChangeCB = static_cast<DSHelperNotifyChangeCB *>(data);
    if (notifyChangeCB->dataShareHelper != nullptr) {
        notifyChangeCB->execResult = INVALID_PARAMETER;
        if (!notifyChangeCB->uri.empty()) {
            OHOS::Uri uri(notifyChangeCB->uri);
            notifyChangeCB->dataShareHelper->NotifyChange(uri);
            notifyChangeCB->execResult = NO_ERROR;
        } else {
            LOG_ERROR("%{public}s, notifyChangeCB uri is empty.", __func__);
        }
    }
}

void NotifyChangeAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_NotifyChange, main event thread complete.");
    DSHelperNotifyChangeCB *notifyChangeCB = static_cast<DSHelperNotifyChangeCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, notifyChangeCB->cbBase.cbInfo.callback, &callback));

    if (!IsTypeForNapiValue(env, callback, napi_function)) {
        delete notifyChangeCB;
        notifyChangeCB = nullptr;
        LOG_INFO("NAPI_NotifyChange, callback is invalid.");
        return;
    }

    result[PARAM0] = GetCallbackErrorValue(env, notifyChangeCB->execResult);
    result[PARAM1] = WrapVoidToJS(env);
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (notifyChangeCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, notifyChangeCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, notifyChangeCB->cbBase.asyncWork));
    delete notifyChangeCB;
    notifyChangeCB = nullptr;
}

void NotifyChangePromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_NotifyChange,  main event thread complete.");
    DSHelperNotifyChangeCB *notifyChangeCB = static_cast<DSHelperNotifyChangeCB *>(data);
    napi_value result = nullptr;
    napi_create_int32(env, 0, &result);
    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, notifyChangeCB->cbBase.deferred, result));
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, notifyChangeCB->cbBase.asyncWork));
    delete notifyChangeCB;
    notifyChangeCB = nullptr;
}

/**
 * @brief DataShareHelper NAPI method : on.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_Register(napi_env env, napi_callback_info info)
{
    LOG_INFO("%{public}s,called", __func__);
    DSHelperOnOffCB *onCB = new (std::nothrow) DSHelperOnOffCB;
    if (onCB == nullptr) {
        LOG_ERROR("%{public}s, onCB == nullptr.", __func__);
        return WrapVoidToJS(env);
    }
    onCB->cbBase.cbInfo.env = env;
    onCB->cbBase.asyncWork = nullptr;
    onCB->cbBase.deferred = nullptr;
    onCB->cbBase.ability = nullptr;

    napi_value ret = RegisterWrap(env, info, onCB);
    if (ret == nullptr) {
        LOG_ERROR("%{public}s, ret == nullptr.", __func__);
        delete onCB;
        onCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("%{public}s,called end", __func__);
    return ret;
}

/**
 * @brief On processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param insertCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value RegisterWrap(napi_env env, napi_callback_info info, DSHelperOnOffCB *onCB)
{
    LOG_INFO("%{public}s,called", __func__);
    size_t argcAsync = ARGS_THREE;
    const size_t argcPromise = ARGS_TWO;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    napi_value thisVar = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        LOG_ERROR("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }

    onCB->result = NO_ERROR;
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valuetype));
    if (valuetype == napi_string) {
        std::string type = NapiValueToStringUtf8(env, args[PARAM0]);
        if (type == "dataChange") {
            LOG_INFO("%{public}s, Wrong type=%{public}s", __func__, type.c_str());
        } else {
            LOG_ERROR("%{public}s, Wrong argument type is %{public}s.", __func__, type.c_str());
            onCB->result = INVALID_PARAMETER;
        }
    } else {
        LOG_ERROR("%{public}s, Wrong argument type.", __func__);
        onCB->result = INVALID_PARAMETER;
    }

    NAPI_CALL(env, napi_typeof(env, args[PARAM1], &valuetype));
    if (valuetype == napi_string) {
        onCB->uri = NapiValueToStringUtf8(env, args[PARAM1]);
        LOG_INFO("%{public}s,uri=%{public}s", __func__, onCB->uri.c_str());
    } else {
        LOG_ERROR("%{public}s, Wrong argument type.", __func__);
        onCB->result = INVALID_PARAMETER;
    }

    DataShareHelper *objectInfo = nullptr;
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    LOG_INFO("Set DataShareHelper objectInfo");
    onCB->dataShareHelper = objectInfo;

    ret = RegisterAsync(env, args, argcAsync, argcPromise, onCB);
    return ret;
}

napi_value RegisterAsync(
    napi_env env, napi_value *args, size_t argcAsync, const size_t argcPromise, DSHelperOnOffCB *onCB)
{
    LOG_INFO("%{public}s, asyncCallback.", __func__);
    if (args == nullptr || onCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argcPromise], &valuetype));
    if (valuetype == napi_function) {
        LOG_INFO("valuetype is napi_function");
        NAPI_CALL(env, napi_create_reference(env, args[argcPromise], 1, &onCB->cbBase.cbInfo.callback));
    } else {
        LOG_INFO("not valuetype isn't napi_function");
        onCB->result = INVALID_PARAMETER;
    }

    sptr<NAPIDataShareObserver> observer(new (std::nothrow) NAPIDataShareObserver());
    observer->SetEnv(env);
    observer->SetCallbackRef(onCB->cbBase.cbInfo.callback);
    onCB->observer = observer;

    if (onCB->result == NO_ERROR) {
        registerInstances_.emplace_back(onCB);
    }

    NAPI_CALL(env,
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            RegisterExecuteCB,
            RegisterCompleteCB,
            (void *)onCB,
            &onCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, onCB->cbBase.asyncWork));
    napi_value result = 0;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

void RegisterExecuteCB(napi_env env, void *data)
{
    LOG_INFO("NAPI_Register, worker pool thread execute.");
    DSHelperOnOffCB *onCB = static_cast<DSHelperOnOffCB *>(data);
    if (onCB->dataShareHelper != nullptr) {
        if (onCB->result != INVALID_PARAMETER && !onCB->uri.empty() && onCB->cbBase.cbInfo.callback != nullptr) {
            OHOS::Uri uri(onCB->uri);
            onCB->dataShareHelper->RegisterObserver(uri, onCB->observer);
        } else {
            LOG_ERROR("%{public}s, dataShareHelper uri is empty or callback is nullptr.", __func__);
        }
    }
}

void RegisterCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_Register, main event thread complete.");
    DSHelperOnOffCB *onCB = static_cast<DSHelperOnOffCB *>(data);
    if (onCB == nullptr) {
        LOG_ERROR("%{public}s, input params onCB is nullptr.", __func__);
        return;
    }
    if (onCB->result == NO_ERROR) {
        return;
    }
    LOG_INFO("NAPI_Register, input params onCB is invalid params, will be release");
    if (onCB->observer) {
        LOG_INFO("NAPI_Register, call ReleaseJSCallback");
        onCB->observer->ReleaseJSCallback();
    }
    delete onCB;
    onCB = nullptr;
    LOG_INFO("NAPI_Register, main event thread complete over an release invalid onCB.");
}

/**
 * @brief DataShareHelper NAPI method : Off.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_UnRegister(napi_env env, napi_callback_info info)
{
    LOG_INFO("%{public}s,called", __func__);
    DSHelperOnOffCB *offCB = new (std::nothrow) DSHelperOnOffCB;
    if (offCB == nullptr) {
        LOG_ERROR("%{public}s, offCB == nullptr.", __func__);
        return WrapVoidToJS(env);
    }
    offCB->cbBase.cbInfo.env = env;
    offCB->cbBase.asyncWork = nullptr;
    offCB->cbBase.deferred = nullptr;
    offCB->cbBase.ability = nullptr;

    napi_value ret = UnRegisterWrap(env, info, offCB);
    if (ret == nullptr) {
        LOG_ERROR("%{public}s, ret == nullptr.", __func__);
        delete offCB;
        offCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("%{public}s,called end", __func__);
    return ret;
}

/**
 * @brief Off processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param insertCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value UnRegisterWrap(napi_env env, napi_callback_info info, DSHelperOnOffCB *offCB)
{
    LOG_INFO("%{public}s,called", __func__);
    size_t argc = ARGS_THREE;
    const size_t argcPromise = ARGS_TWO;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thisVar, nullptr));
    NAPI_ASSERT(env, argc <= argCountWithAsync && argc <= ARGS_MAX_COUNT, "UnRegisterWrap: Wrong argument count");
    offCB->result = INVALID_PARAMETER;
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valuetype));
    if (valuetype == napi_string) {
        std::string type = NapiValueToStringUtf8(env, args[PARAM0]);
        if (type == "dataChange") {
            offCB->result = NO_ERROR;
        }
    }
    offCB->uri = "";
    if (argc > ARGS_TWO) {
        NAPI_CALL(env, napi_typeof(env, args[PARAM1], &valuetype));
        if (valuetype == napi_string) {
            offCB->uri = NapiValueToStringUtf8(env, args[PARAM1]);
        } else {
            offCB->result = INVALID_PARAMETER;
        }
        NAPI_CALL(env, napi_typeof(env, args[PARAM2], &valuetype));
        if (valuetype == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, args[PARAM2], 1, &offCB->cbBase.cbInfo.callback));
        } else {
            offCB->result = INVALID_PARAMETER;
        }
    } else {
        NAPI_CALL(env, napi_typeof(env, args[PARAM1], &valuetype));
        if (valuetype == napi_string) {
            offCB->uri = NapiValueToStringUtf8(env, args[PARAM1]);
        } else if (valuetype == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, args[PARAM1], 1, &offCB->cbBase.cbInfo.callback));
        } else {
            offCB->result = INVALID_PARAMETER;
        }
    }
    LOG_INFO("%{public}s,uri=%{public}s", __func__, offCB->uri.c_str());
    DataShareHelper *objectInfo = nullptr;
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    offCB->dataShareHelper = objectInfo;
    ret = UnRegisterAsync(env, args, argc, argcPromise, offCB);
    return ret;
}

napi_value UnRegisterAsync(
    napi_env env, napi_value *args, size_t argc, const size_t argcPromise, DSHelperOnOffCB *offCB)
{
    LOG_INFO("%{public}s, asyncCallback.", __func__);
    if (args == nullptr || offCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    if (offCB->result == NO_ERROR) {
        FindRegisterObs(env, offCB);
    }

    NAPI_CALL(env,
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            UnRegisterExecuteCB,
            UnRegisterCompleteCB,
            (void *)offCB,
            &offCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, offCB->cbBase.asyncWork));
    napi_value result = 0;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

static void FindRegisterObsByCallBack(napi_env env, DSHelperOnOffCB *data)
{
    LOG_INFO("NAPI_UnRegister, UnRegisterExecuteCB callback is not null.");
    if (data == nullptr || data->dataShareHelper == nullptr) {
        LOG_ERROR("NAPI_UnRegister, param is null.");
        return;
    }
    napi_value callbackA = 0;
    napi_get_reference_value(data->cbBase.cbInfo.env, data->cbBase.cbInfo.callback, &callbackA);
    std::string strUri = data->uri;
    do {
        auto helper = std::find_if(
            registerInstances_.begin(),
            registerInstances_.end(),
            [callbackA, strUri](const DSHelperOnOffCB *helper) {
                bool result = false;
                if (helper == nullptr || helper->cbBase.cbInfo.callback == nullptr) {
                    LOG_ERROR("%{public}s is nullptr", ((helper == nullptr) ? "helper" : "cbBase.cbInfo.callback"));
                    return result;
                }
                if (helper->uri != strUri) {
                    LOG_ERROR("uri inconsistent, h=[%{public}s] u=[%{public}s]", helper->uri.c_str(), strUri.c_str());
                    return result;
                }
                napi_value callbackB = 0;
                napi_get_reference_value(helper->cbBase.cbInfo.env, helper->cbBase.cbInfo.callback, &callbackB);
                auto ret = napi_strict_equals(helper->cbBase.cbInfo.env, callbackA, callbackB, &result);
                LOG_INFO("NAPI_UnRegister cb equals status=%{public}d result=%{public}d.", ret, result);
                return result;
            });
        if (helper != registerInstances_.end()) {
            data->NotifyList.emplace_back(*helper);
            registerInstances_.erase(helper);
            LOG_INFO("NAPI_UnRegister Instances erase size = %{public}zu", registerInstances_.size());
        } else {
            LOG_INFO("NAPI_UnRegister not match any callback. %{public}zu", registerInstances_.size());
            break;
        }
    } while (true);
    LOG_INFO("NAPI_UnRegister, UnRegisterExecuteCB FindRegisterObsByCallBack Called End.");
}

void FindRegisterObs(napi_env env, DSHelperOnOffCB *data)
{
    LOG_INFO("NAPI_UnRegister, FindRegisterObs main event thread execute.");
    if (data == nullptr || data->dataShareHelper == nullptr) {
        LOG_ERROR("NAPI_UnRegister, param is null.");
        return;
    }
    if (data->cbBase.cbInfo.callback != nullptr) {
        LOG_INFO("NAPI_UnRegister, UnRegisterExecuteCB callback is not null.");
        FindRegisterObsByCallBack(env, data);
    } else {
        if (data->uri.empty()) {
            LOG_ERROR("NAPI_UnRegister, error: uri is empty.");
            return;
        }

        LOG_INFO("NAPI_UnRegister, uri=%{public}s.", data->uri.c_str());
        std::string strUri = data->uri;
        do {
            auto helper = std::find_if(registerInstances_.begin(), registerInstances_.end(),
                [strUri](const DSHelperOnOffCB *helper) { return helper->uri == strUri; });
            if (helper != registerInstances_.end()) {
                OHOS::Uri uri((*helper)->uri);
                data->NotifyList.emplace_back(*helper);
                registerInstances_.erase(helper);
                LOG_INFO("NAPI_UnRegister Instances erase size = %{public}zu", registerInstances_.size());
            } else {
                LOG_INFO("NAPI_UnRegister not match any uri.");
                break;
            }
        } while (true);
    }
    LOG_INFO("NAPI_UnRegister, FindRegisterObs main event thread execute.end %{public}zu", data->NotifyList.size());
}

void UnRegisterExecuteCB(napi_env env, void *data)
{
    LOG_INFO("NAPI_UnRegister, UnRegisterExecuteCB main event thread execute.");
    DSHelperOnOffCB *offCB = static_cast<DSHelperOnOffCB *>(data);
    if (offCB == nullptr || offCB->dataShareHelper == nullptr) {
        LOG_ERROR("NAPI_UnRegister, param is null.");
        if (offCB != nullptr) {
            delete offCB;
            offCB = nullptr;
        }
        return;
    }
    LOG_INFO("NAPI_UnRegister, offCB->DestoryList size is %{public}zu", offCB->NotifyList.size());
    for (auto &iter : offCB->NotifyList) {
        if (iter != nullptr && iter->observer != nullptr) {
            OHOS::Uri uri(iter->uri);
            iter->dataShareHelper->UnregisterObserver(uri, iter->observer);
            offCB->DestoryList.emplace_back(iter);
        }
    }
    offCB->NotifyList.clear();
    LOG_INFO("NAPI_UnRegister, UnRegisterExecuteCB main event thread execute. end");
}

void UnRegisterCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_UnRegister, main event thread complete.");
    // cannot run it in executeCB, because need to use napi_strict_equals compare callbacks.
    DSHelperOnOffCB *offCB = static_cast<DSHelperOnOffCB *>(data);
    if (offCB == nullptr || offCB->dataShareHelper == nullptr) {
        LOG_ERROR("NAPI_UnRegister, param is null.");
        if (offCB != nullptr) {
            delete offCB;
            offCB = nullptr;
        }
        return;
    }
    LOG_INFO("NAPI_UnRegister, offCB->DestoryList size is %{public}zu", offCB->DestoryList.size());
    for (auto &iter : offCB->DestoryList) {
        LOG_INFO("NAPI_UnRegister ReleaseJSCallback. 1 ---");
        if (iter->observer != nullptr) {
            if (iter->observer->GetWorkPre() == 1 && iter->observer->GetWorkRun() == 0) {
                iter->observer->SetAssociatedObject(iter);
                iter->observer->ChangeWorkInt();
                LOG_INFO("NAPI_UnRegister ReleaseJSCallback. 3 ---");
            } else {
                iter->observer->ReleaseJSCallback();
                delete iter;
                iter = nullptr;
                LOG_INFO("NAPI_UnRegister ReleaseJSCallback. 4 ---");
            }
        }
    }

    offCB->DestoryList.clear();
    delete offCB;
    offCB = nullptr;
    LOG_INFO("NAPI_UnRegister, main event thread complete. end");
}

napi_value NAPI_GetType(napi_env env, napi_callback_info info)
{
    LOG_INFO("%{public}s,called", __func__);
    DSHelperGetTypeCB *gettypeCB = new (std::nothrow) DSHelperGetTypeCB;
    if (gettypeCB == nullptr) {
        LOG_ERROR("%{public}s, gettypeCB == nullptr.", __func__);
        return WrapVoidToJS(env);
    }
    gettypeCB->cbBase.cbInfo.env = env;
    gettypeCB->cbBase.asyncWork = nullptr;
    gettypeCB->cbBase.deferred = nullptr;
    gettypeCB->cbBase.ability = nullptr;

    napi_value ret = GetTypeWrap(env, info, gettypeCB);
    if (ret == nullptr) {
        LOG_ERROR("%{public}s,ret == nullptr", __func__);
        delete gettypeCB;
        gettypeCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

napi_value GetTypeWrap(napi_env env, napi_callback_info info, DSHelperGetTypeCB *gettypeCB)
{
    LOG_INFO("%{public}s,called", __func__);
    size_t argcAsync = ARGS_TWO;
    const size_t argcPromise = ARGS_ONE;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    napi_value thisVar = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        LOG_ERROR("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valuetype));
    if (valuetype == napi_string) {
        gettypeCB->uri = NapiValueToStringUtf8(env, args[PARAM0]);
        LOG_INFO("%{public}s,uri=%{public}s", __func__, gettypeCB->uri.c_str());
    } else {
        LOG_ERROR("%{public}s, Wrong argument type.", __func__);
    }

    DataShareHelper *objectInfo = nullptr;
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    LOG_INFO("%{public}s,DataShareHelper objectInfo = %{public}p", __func__, objectInfo);
    gettypeCB->dataShareHelper = objectInfo;

    if (argcAsync > argcPromise) {
        ret = GetTypeAsync(env, args, ARGS_ONE, gettypeCB);
    } else {
        ret = GetTypePromise(env, gettypeCB);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

napi_value GetTypeAsync(napi_env env, napi_value *args, const size_t argCallback, DSHelperGetTypeCB *gettypeCB)
{
    LOG_INFO("%{public}s, asyncCallback.", __func__);
    if (args == nullptr || gettypeCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], 1, &gettypeCB->cbBase.cbInfo.callback));
    }

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            GetTypeExecuteCB,
            GetTypeAsyncCompleteCB,
            (void *)gettypeCB,
            &gettypeCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, gettypeCB->cbBase.asyncWork));
    napi_value result = 0;
    NAPI_CALL(env, napi_get_null(env, &result));
    LOG_INFO("%{public}s, asyncCallback end", __func__);
    return result;
}

napi_value GetTypePromise(napi_env env, DSHelperGetTypeCB *gettypeCB)
{
    LOG_INFO("%{public}s, promise.", __func__);
    if (gettypeCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = 0;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    gettypeCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            GetTypeExecuteCB,
            GetTypePromiseCompleteCB,
            (void *)gettypeCB,
            &gettypeCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, gettypeCB->cbBase.asyncWork));
    LOG_INFO("%{public}s, promise end.", __func__);
    return promise;
}

void GetTypeExecuteCB(napi_env env, void *data)
{
    LOG_INFO("NAPI_GetType, worker pool thread execute.");
    DSHelperGetTypeCB *gettypeCB = static_cast<DSHelperGetTypeCB *>(data);
    if (gettypeCB->dataShareHelper != nullptr) {
        gettypeCB->execResult = INVALID_PARAMETER;
        if (!gettypeCB->uri.empty()) {
            OHOS::Uri uri(gettypeCB->uri);
            gettypeCB->result = gettypeCB->dataShareHelper->GetType(uri);
            gettypeCB->execResult = NO_ERROR;
        } else {
            LOG_ERROR("NAPI_GetType, dataShareHelper uri is empty.");
        }
    } else {
        LOG_ERROR("NAPI_GetType, dataShareHelper == nullptr.");
    }
    LOG_INFO("NAPI_GetType, worker pool thread execute end.");
}

void GetTypeAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_GetType, main event thread complete.");
    DSHelperGetTypeCB *gettypeCB = static_cast<DSHelperGetTypeCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, gettypeCB->cbBase.cbInfo.callback, &callback));

    result[PARAM0] = GetCallbackErrorValue(env, gettypeCB->execResult);
    napi_create_string_utf8(env, gettypeCB->result.c_str(), NAPI_AUTO_LENGTH, &result[PARAM1]);

    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (gettypeCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, gettypeCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, gettypeCB->cbBase.asyncWork));
    delete gettypeCB;
    gettypeCB = nullptr;
    LOG_INFO("NAPI_GetType, main event thread complete end.");
}

void GetTypePromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_GetType,  main event thread complete.");
    DSHelperGetTypeCB *gettypeCB = static_cast<DSHelperGetTypeCB *>(data);
    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, gettypeCB->result.c_str(), NAPI_AUTO_LENGTH, &result));
    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, gettypeCB->cbBase.deferred, result));
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, gettypeCB->cbBase.asyncWork));
    delete gettypeCB;
    gettypeCB = nullptr;
    LOG_INFO("NAPI_GetType,  main event thread complete end.");
}

napi_value NAPI_GetFileTypes(napi_env env, napi_callback_info info)
{
    LOG_INFO("%{public}s,called", __func__);
    DSHelperGetFileTypesCB *getfiletypesCB = new (std::nothrow) DSHelperGetFileTypesCB;
    if (getfiletypesCB == nullptr) {
        LOG_ERROR("%{public}s, getfiletypesCB == nullptr.", __func__);
        return WrapVoidToJS(env);
    }
    getfiletypesCB->cbBase.cbInfo.env = env;
    getfiletypesCB->cbBase.asyncWork = nullptr;
    getfiletypesCB->cbBase.deferred = nullptr;
    getfiletypesCB->cbBase.ability = nullptr;

    napi_value ret = GetFileTypesWrap(env, info, getfiletypesCB);
    if (ret == nullptr) {
        LOG_ERROR("%{public}s,ret == nullptr", __func__);
        delete getfiletypesCB;
        getfiletypesCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

napi_value GetFileTypesWrap(napi_env env, napi_callback_info info, DSHelperGetFileTypesCB *getfiletypesCB)
{
    LOG_INFO("%{public}s,called", __func__);
    size_t argcAsync = ARGS_THREE;
    const size_t argcPromise = ARGS_TWO;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    napi_value thisVar = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        LOG_ERROR("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valuetype));
    if (valuetype == napi_string) {
        getfiletypesCB->uri = NapiValueToStringUtf8(env, args[PARAM0]);
        LOG_INFO("%{public}s,uri=%{public}s", __func__, getfiletypesCB->uri.c_str());
    }

    NAPI_CALL(env, napi_typeof(env, args[PARAM1], &valuetype));
    if (valuetype == napi_string) {
        getfiletypesCB->mimeTypeFilter = NapiValueToStringUtf8(env, args[PARAM1]);
        LOG_INFO("%{public}s,mimeTypeFilter=%{public}s", __func__, getfiletypesCB->mimeTypeFilter.c_str());
    }

    DataShareHelper *objectInfo = nullptr;
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    LOG_INFO("%{public}s,DataShareHelper objectInfo = %{public}p", __func__, objectInfo);
    getfiletypesCB->dataShareHelper = objectInfo;

    if (argcAsync > argcPromise) {
        ret = GetFileTypesAsync(env, args, ARGS_TWO, getfiletypesCB);
    } else {
        ret = GetFileTypesPromise(env, getfiletypesCB);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}
napi_value GetFileTypesAsync(
    napi_env env, napi_value *args, const size_t argCallback, DSHelperGetFileTypesCB *getfiletypesCB)
{
    LOG_INFO("%{public}s, asyncCallback.", __func__);
    if (args == nullptr || getfiletypesCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], 1, &getfiletypesCB->cbBase.cbInfo.callback));
    }

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            GetFileTypesExecuteCB,
            GetFileTypesAsyncCompleteCB,
            (void *)getfiletypesCB,
            &getfiletypesCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, getfiletypesCB->cbBase.asyncWork));
    napi_value result = 0;
    NAPI_CALL(env, napi_get_null(env, &result));
    LOG_INFO("%{public}s, asyncCallback end.", __func__);
    return result;
}

napi_value GetFileTypesPromise(napi_env env, DSHelperGetFileTypesCB *getfiletypesCB)
{
    LOG_INFO("%{public}s, promise.", __func__);
    if (getfiletypesCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = 0;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    getfiletypesCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            GetFileTypesExecuteCB,
            GetFileTypesPromiseCompleteCB,
            (void *)getfiletypesCB,
            &getfiletypesCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, getfiletypesCB->cbBase.asyncWork));
    LOG_INFO("%{public}s, promise end.", __func__);
    return promise;
}

void GetFileTypesExecuteCB(napi_env env, void *data)
{
    LOG_INFO("NAPI_GetFileTypes, worker pool thread execute.");
    DSHelperGetFileTypesCB *getfiletypesCB = static_cast<DSHelperGetFileTypesCB *>(data);
    if (getfiletypesCB->dataShareHelper != nullptr) {
        getfiletypesCB->execResult = INVALID_PARAMETER;
        if (!getfiletypesCB->uri.empty()) {
            OHOS::Uri uri(getfiletypesCB->uri);
            LOG_INFO("NAPI_GetFileTypes, uri:%{public}s", uri.ToString().c_str());
            LOG_INFO("NAPI_GetFileTypes, mimeTypeFilter:%{public}s", getfiletypesCB->mimeTypeFilter.c_str());
            getfiletypesCB->result = getfiletypesCB->dataShareHelper->GetFileTypes(
                uri,
                getfiletypesCB->mimeTypeFilter);
            getfiletypesCB->execResult = NO_ERROR;
        } else {
            LOG_INFO("NAPI_GetFileTypes, dataShareHelper uri is empty.");
        }
    } else {
        LOG_INFO("NAPI_GetFileTypes, dataShareHelper == nullptr.");
    }
    LOG_INFO("NAPI_GetFileTypes, worker pool thread execute end.");
}

void GetFileTypesAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_GetFileTypes, main event thread complete.");
    DSHelperGetFileTypesCB *getfiletypesCB = static_cast<DSHelperGetFileTypesCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;

    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, getfiletypesCB->cbBase.cbInfo.callback, &callback));

    result[PARAM0] = GetCallbackErrorValue(env, getfiletypesCB->execResult);
    result[PARAM1] = WrapGetFileTypesCB(env, *getfiletypesCB);

    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (getfiletypesCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, getfiletypesCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, getfiletypesCB->cbBase.asyncWork));
    delete getfiletypesCB;
    getfiletypesCB = nullptr;
    LOG_INFO("NAPI_GetFileTypes, main event thread complete end.");
}

napi_value WrapGetFileTypesCB(napi_env env, const DSHelperGetFileTypesCB &getfiletypesCB)
{
    LOG_INFO("WrapGetFileTypesCB, called.");
    LOG_INFO("NAPI_GetFileTypes, result.size:%{public}zu", getfiletypesCB.result.size());
    for (size_t i = 0; i < getfiletypesCB.result.size(); i++) {
        LOG_INFO("NAPI_GetFileTypes, result[%{public}zu]:%{public}s", i, getfiletypesCB.result.at(i).c_str());
    }
    napi_value proValue = nullptr;

    napi_value jsArrayresult = nullptr;
    NAPI_CALL(env, napi_create_array(env, &jsArrayresult));
    for (size_t i = 0; i < getfiletypesCB.result.size(); i++) {
        proValue = nullptr;
        NAPI_CALL(env, napi_create_string_utf8(env, getfiletypesCB.result.at(i).c_str(), NAPI_AUTO_LENGTH, &proValue));
        NAPI_CALL(env, napi_set_element(env, jsArrayresult, i, proValue));
    }
    LOG_INFO("WrapGetFileTypesCB, end.");
    return jsArrayresult;
}

void GetFileTypesPromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_GetFileTypes,  main event thread complete.");
    DSHelperGetFileTypesCB *getfiletypesCB = static_cast<DSHelperGetFileTypesCB *>(data);
    napi_value result = nullptr;

    result = WrapGetFileTypesCB(env, *getfiletypesCB);
    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, getfiletypesCB->cbBase.deferred, result));
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, getfiletypesCB->cbBase.asyncWork));
    delete getfiletypesCB;
    getfiletypesCB = nullptr;
    LOG_INFO("NAPI_GetFileTypes,  main event thread complete end.");
}

napi_value NAPI_NormalizeUri(napi_env env, napi_callback_info info)
{
    LOG_INFO("%{public}s,called", __func__);
    DSHelperNormalizeUriCB *normalizeuriCB = new (std::nothrow) DSHelperNormalizeUriCB;
    if (normalizeuriCB == nullptr) {
        LOG_ERROR("%{public}s, normalizeuriCB == nullptr.", __func__);
        return WrapVoidToJS(env);
    }
    normalizeuriCB->cbBase.cbInfo.env = env;
    normalizeuriCB->cbBase.asyncWork = nullptr;
    normalizeuriCB->cbBase.deferred = nullptr;
    normalizeuriCB->cbBase.ability = nullptr;

    napi_value ret = NormalizeUriWrap(env, info, normalizeuriCB);
    if (ret == nullptr) {
        LOG_ERROR("%{public}s,ret == nullptr", __func__);
        delete normalizeuriCB;
        normalizeuriCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

napi_value NormalizeUriWrap(napi_env env, napi_callback_info info, DSHelperNormalizeUriCB *normalizeuriCB)
{
    LOG_INFO("%{public}s,called", __func__);
    size_t argcAsync = ARGS_TWO;
    const size_t argcPromise = ARGS_ONE;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    napi_value thisVar = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        LOG_ERROR("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valuetype));
    if (valuetype == napi_string) {
        normalizeuriCB->uri = NapiValueToStringUtf8(env, args[PARAM0]);
        LOG_INFO("%{public}s,uri=%{public}s", __func__, normalizeuriCB->uri.c_str());
    }

    DataShareHelper *objectInfo = nullptr;
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    LOG_INFO("%{public}s,DataShareHelper objectInfo = %{public}p", __func__, objectInfo);
    normalizeuriCB->dataShareHelper = objectInfo;

    if (argcAsync > argcPromise) {
        ret = NormalizeUriAsync(env, args, ARGS_ONE, normalizeuriCB);
    } else {
        ret = NormalizeUriPromise(env, normalizeuriCB);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}
napi_value NormalizeUriAsync(
    napi_env env, napi_value *args, const size_t argCallback, DSHelperNormalizeUriCB *normalizeuriCB)
{
    LOG_INFO("%{public}s, asyncCallback.", __func__);
    if (args == nullptr || normalizeuriCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], 1, &normalizeuriCB->cbBase.cbInfo.callback));
    }

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            NormalizeUriExecuteCB,
            NormalizeUriAsyncCompleteCB,
            (void *)normalizeuriCB,
            &normalizeuriCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, normalizeuriCB->cbBase.asyncWork));
    napi_value result = 0;
    NAPI_CALL(env, napi_get_null(env, &result));
    LOG_INFO("%{public}s, asyncCallback end.", __func__);
    return result;
}

napi_value NormalizeUriPromise(napi_env env, DSHelperNormalizeUriCB *normalizeuriCB)
{
    LOG_INFO("%{public}s, promise.", __func__);
    if (normalizeuriCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = 0;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    normalizeuriCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            NormalizeUriExecuteCB,
            NormalizeUriPromiseCompleteCB,
            (void *)normalizeuriCB,
            &normalizeuriCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, normalizeuriCB->cbBase.asyncWork));
    LOG_INFO("%{public}s, promise end.", __func__);
    return promise;
}

void NormalizeUriExecuteCB(napi_env env, void *data)
{
    LOG_INFO("NAPI_NormalizeUri, worker pool thread execute.");
    DSHelperNormalizeUriCB *normalizeuriCB = static_cast<DSHelperNormalizeUriCB *>(data);
    Uri uriValue(normalizeuriCB->uri);
    if (normalizeuriCB->dataShareHelper != nullptr) {
        normalizeuriCB->execResult = INVALID_PARAMETER;
        if (!normalizeuriCB->uri.empty()) {
        OHOS::Uri uri(normalizeuriCB->uri);
            uriValue = normalizeuriCB->dataShareHelper->NormalizeUri(uri);
            normalizeuriCB->result = uriValue.ToString();
            normalizeuriCB->execResult = NO_ERROR;
        }
    } else {
        LOG_INFO("NAPI_NormalizeUri, dataShareHelper == nullptr");
    }
    LOG_INFO("NAPI_NormalizeUri, worker pool thread execute end.");
}

void NormalizeUriAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_NormalizeUri, main event thread complete.");
    DSHelperNormalizeUriCB *normalizeuriCB = static_cast<DSHelperNormalizeUriCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, normalizeuriCB->cbBase.cbInfo.callback, &callback));

    result[PARAM0] = GetCallbackErrorValue(env, normalizeuriCB->execResult);
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, normalizeuriCB->result.c_str(), NAPI_AUTO_LENGTH, &result[PARAM1]));

    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (normalizeuriCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, normalizeuriCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, normalizeuriCB->cbBase.asyncWork));
    delete normalizeuriCB;
    normalizeuriCB = nullptr;
    LOG_INFO("NAPI_NormalizeUri, main event thread complete end.");
}

void NormalizeUriPromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_NormalizeUri,  main event thread complete.");
    DSHelperNormalizeUriCB *normalizeuriCB = static_cast<DSHelperNormalizeUriCB *>(data);
    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, normalizeuriCB->result.c_str(), NAPI_AUTO_LENGTH, &result));
    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, normalizeuriCB->cbBase.deferred, result));
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, normalizeuriCB->cbBase.asyncWork));
    delete normalizeuriCB;
    normalizeuriCB = nullptr;
    LOG_INFO("NAPI_NormalizeUri,  main event thread complete end.");
}

napi_value NAPI_DenormalizeUri(napi_env env, napi_callback_info info)
{
    LOG_INFO("%{public}s,called", __func__);
    DSHelperDenormalizeUriCB *denormalizeuriCB = new (std::nothrow) DSHelperDenormalizeUriCB;
    if (denormalizeuriCB == nullptr) {
        LOG_ERROR("%{public}s, denormalizeuriCB == nullptr.", __func__);
        return WrapVoidToJS(env);
    }
    denormalizeuriCB->cbBase.cbInfo.env = env;
    denormalizeuriCB->cbBase.asyncWork = nullptr;
    denormalizeuriCB->cbBase.deferred = nullptr;
    denormalizeuriCB->cbBase.ability = nullptr;

    napi_value ret = DenormalizeUriWrap(env, info, denormalizeuriCB);
    if (ret == nullptr) {
        LOG_ERROR("%{public}s,ret == nullptr", __func__);
        delete denormalizeuriCB;
        denormalizeuriCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

napi_value DenormalizeUriWrap(napi_env env, napi_callback_info info, DSHelperDenormalizeUriCB *denormalizeuriCB)
{
    LOG_INFO("%{public}s,called", __func__);
    size_t argcAsync = ARGS_TWO;
    const size_t argcPromise = ARGS_ONE;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    napi_value thisVar = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        LOG_ERROR("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valuetype));
    if (valuetype == napi_string) {
        denormalizeuriCB->uri = NapiValueToStringUtf8(env, args[PARAM0]);
        LOG_INFO("%{public}s,uri=%{public}s", __func__, denormalizeuriCB->uri.c_str());
    }

    DataShareHelper *objectInfo = nullptr;
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    LOG_INFO("%{public}s,DataShareHelper objectInfo = %{public}p", __func__, objectInfo);
    denormalizeuriCB->dataShareHelper = objectInfo;

    if (argcAsync > argcPromise) {
        ret = DenormalizeUriAsync(env, args, ARGS_ONE, denormalizeuriCB);
    } else {
        ret = DenormalizeUriPromise(env, denormalizeuriCB);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}
napi_value DenormalizeUriAsync(
    napi_env env, napi_value *args, const size_t argCallback, DSHelperDenormalizeUriCB *denormalizeuriCB)
{
    LOG_INFO("%{public}s, asyncCallback.", __func__);
    if (args == nullptr || denormalizeuriCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], 1, &denormalizeuriCB->cbBase.cbInfo.callback));
    }

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            DenormalizeUriExecuteCB,
            DenormalizeUriAsyncCompleteCB,
            (void *)denormalizeuriCB,
            &denormalizeuriCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, denormalizeuriCB->cbBase.asyncWork));
    napi_value result = 0;
    NAPI_CALL(env, napi_get_null(env, &result));
    LOG_INFO("%{public}s, asyncCallback end.", __func__);
    return result;
}

napi_value DenormalizeUriPromise(napi_env env, DSHelperDenormalizeUriCB *denormalizeuriCB)
{
    LOG_INFO("%{public}s, promise.", __func__);
    if (denormalizeuriCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = 0;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    denormalizeuriCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            DenormalizeUriExecuteCB,
            DenormalizeUriPromiseCompleteCB,
            (void *)denormalizeuriCB,
            &denormalizeuriCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, denormalizeuriCB->cbBase.asyncWork));
    LOG_INFO("%{public}s, promise end.", __func__);
    return promise;
}

void DenormalizeUriExecuteCB(napi_env env, void *data)
{
    LOG_INFO("NAPI_DenormalizeUri, worker pool thread execute.");
    DSHelperDenormalizeUriCB *denormalizeuriCB = static_cast<DSHelperDenormalizeUriCB *>(data);
    Uri uriValue(denormalizeuriCB->uri);
    if (denormalizeuriCB->dataShareHelper != nullptr) {
        denormalizeuriCB->execResult = INVALID_PARAMETER;
        if (!denormalizeuriCB->uri.empty()) {
            OHOS::Uri uri(denormalizeuriCB->uri);
            uriValue = denormalizeuriCB->dataShareHelper->DenormalizeUri(uri);
            denormalizeuriCB->result = uriValue.ToString();
            denormalizeuriCB->execResult = NO_ERROR;
        } else {
            LOG_ERROR("NAPI_DenormalizeUri, dataShareHelper uri is empty");
        }
    } else {
        LOG_ERROR("NAPI_DenormalizeUri, dataShareHelper == nullptr");
    }
    LOG_INFO("NAPI_DenormalizeUri, worker pool thread execute end.");
}

void DenormalizeUriAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_DenormalizeUri, main event thread complete.");
    DSHelperDenormalizeUriCB *denormalizeuriCB = static_cast<DSHelperDenormalizeUriCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, denormalizeuriCB->cbBase.cbInfo.callback, &callback));

    result[PARAM0] = GetCallbackErrorValue(env, denormalizeuriCB->execResult);
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, denormalizeuriCB->result.c_str(), NAPI_AUTO_LENGTH, &result[PARAM1]));

    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (denormalizeuriCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, denormalizeuriCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, denormalizeuriCB->cbBase.asyncWork));
    delete denormalizeuriCB;
    denormalizeuriCB = nullptr;
    LOG_INFO("NAPI_DenormalizeUri, main event thread complete end.");
}

void DenormalizeUriPromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_DenormalizeUri,  main event thread complete.");
    DSHelperDenormalizeUriCB *denormalizeuriCB = static_cast<DSHelperDenormalizeUriCB *>(data);
    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, denormalizeuriCB->result.c_str(), NAPI_AUTO_LENGTH, &result));
    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, denormalizeuriCB->cbBase.deferred, result));
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, denormalizeuriCB->cbBase.asyncWork));
    delete denormalizeuriCB;
    denormalizeuriCB = nullptr;
    LOG_INFO("NAPI_DenormalizeUri,  main event thread complete end.");
}

void UnwrapDataSharePredicates(DataSharePredicates &predicates, napi_env env, napi_value value)
{
    auto tempPredicates = DataSharePredicatesProxy::GetNativePredicates(env, value);
    if (tempPredicates == nullptr) {
        LOG_ERROR("%{public}s, GetNativePredicates retval Marshalling failed.", __func__);
        return;
    }
    predicates = *tempPredicates;
}

/**
 * @brief DataShareHelper NAPI method : insert.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_Delete(napi_env env, napi_callback_info info)
{
    LOG_INFO("%{public}s,called", __func__);
    DSHelperDeleteCB *deleteCB = new (std::nothrow) DSHelperDeleteCB;
    if (deleteCB == nullptr) {
        LOG_ERROR("%{public}s, deleteCB == nullptr.", __func__);
        return WrapVoidToJS(env);
    }
    deleteCB->cbBase.cbInfo.env = env;
    deleteCB->cbBase.asyncWork = nullptr;
    deleteCB->cbBase.deferred = nullptr;
    deleteCB->cbBase.ability = nullptr;

    napi_value ret = DeleteWrap(env, info, deleteCB);
    if (ret == nullptr) {
        LOG_ERROR("%{public}s,ret == nullptr", __func__);
        delete deleteCB;
        deleteCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

/**
 * @brief Insert processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param insertCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value DeleteWrap(napi_env env, napi_callback_info info, DSHelperDeleteCB *deleteCB)
{
    LOG_INFO("%{public}s,called", __func__);
    size_t argcAsync = ARGS_THREE;
    const size_t argcPromise = ARGS_TWO;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    napi_value thisVar = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        LOG_ERROR("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valuetype));
    if (valuetype == napi_string) {
        deleteCB->uri = NapiValueToStringUtf8(env, args[PARAM0]);
        LOG_INFO("%{public}s,uri=%{public}s", __func__, deleteCB->uri.c_str());
    }

    UnwrapDataSharePredicates(deleteCB->predicates, env, args[PARAM1]);
    DataShareHelper *objectInfo = nullptr;
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    LOG_INFO("%{public}s,DataShareHelper objectInfo = %{public}p", __func__, objectInfo);
    deleteCB->dataShareHelper = objectInfo;

    if (argcAsync > argcPromise) {
        ret = DeleteAsync(env, args, ARGS_TWO, deleteCB);
    } else {
        ret = DeletePromise(env, deleteCB);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

napi_value DeleteAsync(napi_env env, napi_value *args, const size_t argCallback, DSHelperDeleteCB *deleteCB)
{
    LOG_INFO("%{public}s, asyncCallback.", __func__);
    if (args == nullptr || deleteCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], 1, &deleteCB->cbBase.cbInfo.callback));
    }

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            DeleteExecuteCB,
            DeleteAsyncCompleteCB,
            (void *)deleteCB,
            &deleteCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, deleteCB->cbBase.asyncWork));
    napi_value result = 0;
    NAPI_CALL(env, napi_get_null(env, &result));
    LOG_INFO("%{public}s, asyncCallback end.", __func__);
    return result;
}

napi_value DeletePromise(napi_env env, DSHelperDeleteCB *deleteCB)
{
    LOG_INFO("%{public}s, promise.", __func__);
    if (deleteCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = 0;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    deleteCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            DeleteExecuteCB,
            DeletePromiseCompleteCB,
            (void *)deleteCB,
            &deleteCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, deleteCB->cbBase.asyncWork));
    LOG_INFO("%{public}s, promise end.", __func__);
    return promise;
}

void DeleteExecuteCB(napi_env env, void *data)
{
    LOG_INFO("NAPI_Delete, worker pool thread execute.");
    DSHelperDeleteCB *deleteCB = static_cast<DSHelperDeleteCB *>(data);
    if (deleteCB->dataShareHelper != nullptr) {
        deleteCB->execResult = INVALID_PARAMETER;
        if (!deleteCB->uri.empty()) {
            OHOS::Uri uri(deleteCB->uri);
            deleteCB->result = deleteCB->dataShareHelper->Delete(uri, deleteCB->predicates);
            deleteCB->execResult = NO_ERROR;
        } else {
            LOG_ERROR("NAPI_Delete, dataShareHelper uri is empty");
        }
    } else {
        LOG_ERROR("NAPI_Delete, dataShareHelper == nullptr");
    }
    LOG_INFO("NAPI_Delete, worker pool thread execute end.");
}

void DeleteAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_Delete, main event thread complete.");
    DSHelperDeleteCB *DeleteCB = static_cast<DSHelperDeleteCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, DeleteCB->cbBase.cbInfo.callback, &callback));

    result[PARAM0] = GetCallbackErrorValue(env, DeleteCB->execResult);
    napi_create_int32(env, DeleteCB->result, &result[PARAM1]);
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (DeleteCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, DeleteCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, DeleteCB->cbBase.asyncWork));
    delete DeleteCB;
    DeleteCB = nullptr;
    LOG_INFO("NAPI_Delete, main event thread complete end.");
}

void DeletePromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_Delete,  main event thread complete.");
    DSHelperDeleteCB *DeleteCB = static_cast<DSHelperDeleteCB *>(data);
    napi_value result = nullptr;
    napi_create_int32(env, DeleteCB->result, &result);
    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, DeleteCB->cbBase.deferred, result));
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, DeleteCB->cbBase.asyncWork));
    delete DeleteCB;
    DeleteCB = nullptr;
    LOG_INFO("NAPI_Delete,  main event thread complete end.");
}

/**
 * @brief DataShareHelper NAPI method : insert.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_Update(napi_env env, napi_callback_info info)
{
    LOG_INFO("%{public}s,called", __func__);
    DSHelperUpdateCB *updateCB = new (std::nothrow) DSHelperUpdateCB;
    if (updateCB == nullptr) {
        LOG_ERROR("%{public}s, updateCB == nullptr.", __func__);
        return WrapVoidToJS(env);
    }
    updateCB->cbBase.cbInfo.env = env;
    updateCB->cbBase.asyncWork = nullptr;
    updateCB->cbBase.deferred = nullptr;
    updateCB->cbBase.ability = nullptr;

    napi_value ret = UpdateWrap(env, info, updateCB);
    if (ret == nullptr) {
        LOG_ERROR("%{public}s,ret == nullptr", __func__);
        delete updateCB;
        updateCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

/**
 * @brief Insert processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param insertCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value UpdateWrap(napi_env env, napi_callback_info info, DSHelperUpdateCB *updateCB)
{
    LOG_INFO("%{public}s,called", __func__);
    size_t argcAsync = ARGS_FOUR;
    const size_t argcPromise = ARGS_THREE;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    napi_value thisVar = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        LOG_ERROR("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valuetype));
    if (valuetype == napi_string) {
        updateCB->uri = NapiValueToStringUtf8(env, args[PARAM0]);
        LOG_INFO("%{public}s,uri=%{public}s", __func__, updateCB->uri.c_str());
    }

    UnwrapDataSharePredicates(updateCB->predicates, env, args[PARAM1]);
    updateCB->valueBucket.Clear();
    AnalysisValuesBucket(updateCB->valueBucket, env, args[PARAM2]);
    DataShareHelper *objectInfo = nullptr;
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    LOG_INFO("%{public}s,DataShareHelper objectInfo = %{public}p", __func__, objectInfo);
    updateCB->dataShareHelper = objectInfo;

    if (argcAsync > argcPromise) {
        ret = UpdateAsync(env, args, ARGS_THREE, updateCB);
    } else {
        ret = UpdatePromise(env, updateCB);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

napi_value UpdateAsync(napi_env env, napi_value *args, const size_t argCallback, DSHelperUpdateCB *updateCB)
{
    LOG_INFO("%{public}s, asyncCallback.", __func__);
    if (args == nullptr || updateCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], 1, &updateCB->cbBase.cbInfo.callback));
    }

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            UpdateExecuteCB,
            UpdateAsyncCompleteCB,
            (void *)updateCB,
            &updateCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, updateCB->cbBase.asyncWork));
    napi_value result = 0;
    NAPI_CALL(env, napi_get_null(env, &result));
    LOG_INFO("%{public}s, asyncCallback end.", __func__);
    return result;
}

napi_value UpdatePromise(napi_env env, DSHelperUpdateCB *updateCB)
{
    LOG_INFO("%{public}s, promise.", __func__);
    if (updateCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = 0;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    updateCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            UpdateExecuteCB,
            UpdatePromiseCompleteCB,
            (void *)updateCB,
            &updateCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, updateCB->cbBase.asyncWork));
    LOG_INFO("%{public}s, promise end.", __func__);
    return promise;
}

void UpdateExecuteCB(napi_env env, void *data)
{
    LOG_INFO("NAPI_Update, worker pool thread execute.");
    DSHelperUpdateCB *updateCB = static_cast<DSHelperUpdateCB *>(data);
    if (updateCB->dataShareHelper != nullptr) {
        updateCB->execResult = INVALID_PARAMETER;
        if (!updateCB->uri.empty()) {
            OHOS::Uri uri(updateCB->uri);
            updateCB->result = updateCB->dataShareHelper->Update(uri, updateCB->valueBucket, updateCB->predicates);
            updateCB->execResult = NO_ERROR;
        } else {
            LOG_ERROR("NAPI_Update, dataShareHelper uri is empty");
        }
    } else {
        LOG_ERROR("NAPI_Update, dataShareHelper == nullptr");
    }
    LOG_INFO("NAPI_Update, worker pool thread execute end.");
}

void UpdateAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_Update, main event thread complete.");
    DSHelperUpdateCB *updateCB = static_cast<DSHelperUpdateCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, updateCB->cbBase.cbInfo.callback, &callback));

    result[PARAM0] = GetCallbackErrorValue(env, updateCB->execResult);
    napi_create_int32(env, updateCB->result, &result[PARAM1]);
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (updateCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, updateCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, updateCB->cbBase.asyncWork));
    delete updateCB;
    updateCB = nullptr;
    LOG_INFO("NAPI_Update, main event thread complete end.");
}

void UpdatePromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_Update,  main event thread complete.");
    DSHelperUpdateCB *updateCB = static_cast<DSHelperUpdateCB *>(data);
    napi_value result = nullptr;
    napi_create_int32(env, updateCB->result, &result);
    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, updateCB->cbBase.deferred, result));
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, updateCB->cbBase.asyncWork));
    delete updateCB;
    updateCB = nullptr;
    LOG_INFO("NAPI_Update,  main event thread complete end.");
}

/**
 * @brief DataShareHelper NAPI method : insert.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_OpenFile(napi_env env, napi_callback_info info)
{
    LOG_INFO("%{public}s,called", __func__);
    DSHelperOpenFileCB *openFileCB = new (std::nothrow) DSHelperOpenFileCB;
    if (openFileCB == nullptr) {
        LOG_ERROR("%{public}s, openFileCB == nullptr.", __func__);
        return WrapVoidToJS(env);
    }
    openFileCB->cbBase.cbInfo.env = env;
    openFileCB->cbBase.asyncWork = nullptr;
    openFileCB->cbBase.deferred = nullptr;
    openFileCB->cbBase.ability = nullptr;

    napi_value ret = OpenFileWrap(env, info, openFileCB);
    if (ret == nullptr) {
        LOG_ERROR("%{public}s,ret == nullptr", __func__);
        delete openFileCB;
        openFileCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

/**
 * @brief Insert processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param insertCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value OpenFileWrap(napi_env env, napi_callback_info info, DSHelperOpenFileCB *openFileCB)
{
    LOG_INFO("%{public}s,called", __func__);
    size_t argcAsync = ARGS_THREE;
    const size_t argcPromise = ARGS_TWO;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    napi_value thisVar = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        LOG_ERROR("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valuetype));
    if (valuetype == napi_string) {
        openFileCB->uri = NapiValueToStringUtf8(env, args[PARAM0]);
        LOG_INFO("%{public}s,uri=%{public}s", __func__, openFileCB->uri.c_str());
    }

    NAPI_CALL(env, napi_typeof(env, args[PARAM1], &valuetype));
    if (valuetype == napi_string) {
        openFileCB->mode = NapiValueToStringUtf8(env, args[PARAM1]);
        LOG_INFO("%{public}s,mode=%{public}s", __func__, openFileCB->mode.c_str());
    }

    DataShareHelper *objectInfo = nullptr;
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    LOG_INFO("%{public}s,DataShareHelper objectInfo", __func__);
    openFileCB->dataShareHelper = objectInfo;

    if (argcAsync > argcPromise) {
        ret = OpenFileAsync(env, args, ARGS_TWO, openFileCB);
    } else {
        ret = OpenFilePromise(env, openFileCB);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

napi_value OpenFileAsync(napi_env env, napi_value *args, const size_t argCallback, DSHelperOpenFileCB *openFileCB)
{
    LOG_INFO("%{public}s, asyncCallback.", __func__);
    if (args == nullptr || openFileCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], 1, &openFileCB->cbBase.cbInfo.callback));
    }

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            OpenFileExecuteCB,
            OpenFileAsyncCompleteCB,
            (void *)openFileCB,
            &openFileCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, openFileCB->cbBase.asyncWork));
    napi_value result = 0;
    NAPI_CALL(env, napi_get_null(env, &result));
    LOG_INFO("%{public}s, asyncCallback end.", __func__);
    return result;
}

napi_value OpenFilePromise(napi_env env, DSHelperOpenFileCB *openFileCB)
{
    LOG_INFO("%{public}s, promise.", __func__);
    if (openFileCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = 0;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    openFileCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            OpenFileExecuteCB,
            OpenFilePromiseCompleteCB,
            (void *)openFileCB,
            &openFileCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, openFileCB->cbBase.asyncWork));
    LOG_INFO("%{public}s, promise end.", __func__);
    return promise;
}

void OpenFileExecuteCB(napi_env env, void *data)
{
    LOG_INFO("NAPI_OpenFile, worker pool thread execute.");
    DSHelperOpenFileCB *OpenFileCB = static_cast<DSHelperOpenFileCB *>(data);
    if (OpenFileCB->dataShareHelper != nullptr) {
        OpenFileCB->execResult = INVALID_PARAMETER;
        if (!OpenFileCB->uri.empty()) {
            OHOS::Uri uri(OpenFileCB->uri);
            OpenFileCB->result = OpenFileCB->dataShareHelper->OpenFile(uri, OpenFileCB->mode);
            OpenFileCB->execResult = NO_ERROR;
        } else {
            LOG_ERROR("NAPI_OpenFile, dataShareHelper uri is empty");
        }
    } else {
        LOG_ERROR("NAPI_OpenFile, dataShareHelper == nullptr");
    }
    LOG_INFO("NAPI_OpenFile, worker pool thread execute end.");
}

void OpenFileAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_OpenFile, main event thread complete.");
    DSHelperOpenFileCB *OpenFileCB = static_cast<DSHelperOpenFileCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, OpenFileCB->cbBase.cbInfo.callback, &callback));

    result[PARAM0] = GetCallbackErrorValue(env, OpenFileCB->execResult);
    napi_create_int32(env, OpenFileCB->result, &result[PARAM1]);
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (OpenFileCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, OpenFileCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, OpenFileCB->cbBase.asyncWork));
    delete OpenFileCB;
    OpenFileCB = nullptr;
    LOG_INFO("NAPI_OpenFile, main event thread complete end.");
}

void OpenFilePromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_OpenFileCB,  main event thread complete.");
    DSHelperOpenFileCB *OpenFileCB = static_cast<DSHelperOpenFileCB *>(data);
    napi_value result = nullptr;
    napi_create_int32(env, OpenFileCB->result, &result);
    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, OpenFileCB->cbBase.deferred, result));
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, OpenFileCB->cbBase.asyncWork));
    delete OpenFileCB;
    OpenFileCB = nullptr;
    LOG_INFO("NAPI_OpenFileCB,  main event thread complete end.");
}

/**
 * @brief DataShareHelper NAPI method : insert.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_BatchInsert(napi_env env, napi_callback_info info)
{
    LOG_INFO("%{public}s,called", __func__);
    DSHelperBatchInsertCB *BatchInsertCB = new (std::nothrow) DSHelperBatchInsertCB;
    if (BatchInsertCB == nullptr) {
        LOG_ERROR("%{public}s, BatchInsertCB == nullptr.", __func__);
        return WrapVoidToJS(env);
    }
    BatchInsertCB->cbBase.cbInfo.env = env;
    BatchInsertCB->cbBase.asyncWork = nullptr;
    BatchInsertCB->cbBase.deferred = nullptr;
    BatchInsertCB->cbBase.ability = nullptr;

    napi_value ret = BatchInsertWrap(env, info, BatchInsertCB);
    if (ret == nullptr) {
        LOG_ERROR("%{public}s,ret == nullptr", __func__);
        delete BatchInsertCB;
        BatchInsertCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

std::vector<DataShareValuesBucket> NapiValueObject(napi_env env, napi_value param)
{
    LOG_INFO("%{public}s,called", __func__);
    std::vector<DataShareValuesBucket> result;
    UnwrapArrayObjectFromJS(env, param, result);
    return result;
}

bool UnwrapArrayObjectFromJS(napi_env env, napi_value param, std::vector<DataShareValuesBucket> &value)
{
    LOG_INFO("%{public}s,called", __func__);
    uint32_t arraySize = 0;
    napi_value jsValue = nullptr;
    std::string strValue = "";

    if (!IsArrayForNapiValue(env, param, arraySize)) {
        LOG_INFO("%{public}s, IsArrayForNapiValue is false", __func__);
        return false;
    }

    value.clear();
    for (uint32_t i = 0; i < arraySize; i++) {
        jsValue = nullptr;
        if (napi_get_element(env, param, i, &jsValue) != napi_ok) {
            LOG_INFO("%{public}s, napi_get_element is false", __func__);
            return false;
        }

        DataShareValuesBucket valueBucket;
        valueBucket.Clear();
        AnalysisValuesBucket(valueBucket, env, jsValue);

        value.push_back(valueBucket);
    }
    LOG_INFO("%{public}s,end", __func__);
    return true;
}

/**
 * @brief Insert processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param insertCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value BatchInsertWrap(napi_env env, napi_callback_info info, DSHelperBatchInsertCB *batchInsertCB)
{
    LOG_INFO("%{public}s,called", __func__);
    size_t argcAsync = ARGS_THREE;
    const size_t argcPromise = ARGS_TWO;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    napi_value thisVar = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        LOG_ERROR("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valuetype));
    if (valuetype == napi_string) {
        batchInsertCB->uri = NapiValueToStringUtf8(env, args[PARAM0]);
        LOG_INFO("%{public}s,uri=%{public}s", __func__, batchInsertCB->uri.c_str());
    }

    batchInsertCB->values = NapiValueObject(env, args[PARAM1]);

    DataShareHelper *objectInfo = nullptr;
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    LOG_INFO("%{public}s,DataShareHelper objectInfo = %{public}p", __func__, objectInfo);
    batchInsertCB->dataShareHelper = objectInfo;

    if (argcAsync > argcPromise) {
        ret = BatchInsertAsync(env, args, ARGS_TWO, batchInsertCB);
    } else {
        ret = BatchInsertPromise(env, batchInsertCB);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

napi_value BatchInsertAsync(
    napi_env env, napi_value *args, const size_t argCallback, DSHelperBatchInsertCB *batchInsertCB)
{
    LOG_INFO("%{public}s, asyncCallback.", __func__);
    if (args == nullptr || batchInsertCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], 1, &batchInsertCB->cbBase.cbInfo.callback));
    }

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            BatchInsertExecuteCB,
            BatchInsertAsyncCompleteCB,
            (void *)batchInsertCB,
            &batchInsertCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, batchInsertCB->cbBase.asyncWork));
    napi_value result = 0;
    NAPI_CALL(env, napi_get_null(env, &result));
    LOG_INFO("%{public}s, asyncCallback end.", __func__);
    return result;
}

napi_value BatchInsertPromise(napi_env env, DSHelperBatchInsertCB *batchInsertCB)
{
    LOG_INFO("%{public}s, promise.", __func__);
    if (batchInsertCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = 0;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    batchInsertCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            BatchInsertExecuteCB,
            BatchInsertPromiseCompleteCB,
            (void *)batchInsertCB,
            &batchInsertCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, batchInsertCB->cbBase.asyncWork));
    LOG_INFO("%{public}s, promise end.", __func__);
    return promise;
}

void BatchInsertExecuteCB(napi_env env, void *data)
{
    LOG_INFO("NAPI_BatchInsert, worker pool thread execute.");
    DSHelperBatchInsertCB *batchInsertCB = static_cast<DSHelperBatchInsertCB *>(data);
    if (batchInsertCB->dataShareHelper != nullptr) {
        batchInsertCB->execResult = INVALID_PARAMETER;
        if (!batchInsertCB->uri.empty()) {
            OHOS::Uri uri(batchInsertCB->uri);
            batchInsertCB->result = batchInsertCB->dataShareHelper->BatchInsert(uri, batchInsertCB->values);
            batchInsertCB->execResult = NO_ERROR;
        } else {
            LOG_ERROR("NAPI_BatchInsert, dataShareHelper uri is empyt");
        }
    } else {
        LOG_ERROR("NAPI_BatchInsert, dataShareHelper == nullptr");
    }
    LOG_INFO("NAPI_BatchInsert, worker pool thread execute end.");
}

void BatchInsertAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_BatchInsert, main event thread complete.");
    DSHelperBatchInsertCB *BatchInsertCB = static_cast<DSHelperBatchInsertCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, BatchInsertCB->cbBase.cbInfo.callback, &callback));

    result[PARAM0] = GetCallbackErrorValue(env, BatchInsertCB->execResult);
    napi_create_int32(env, BatchInsertCB->result, &result[PARAM1]);
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (BatchInsertCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, BatchInsertCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, BatchInsertCB->cbBase.asyncWork));
    delete BatchInsertCB;
    BatchInsertCB = nullptr;
    LOG_INFO("NAPI_BatchInsert, main event thread complete end.");
}

void BatchInsertPromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_BatchInsertCB,  main event thread complete.");
    DSHelperBatchInsertCB *BatchInsertCB = static_cast<DSHelperBatchInsertCB *>(data);
    napi_value result = nullptr;
    napi_create_int32(env, BatchInsertCB->result, &result);
    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, BatchInsertCB->cbBase.deferred, result));
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, BatchInsertCB->cbBase.asyncWork));
    delete BatchInsertCB;
    BatchInsertCB = nullptr;
    LOG_INFO("NAPI_BatchInsertCB,  main event thread complete end.");
}

/**
 * @brief DataShareHelper NAPI method : insert.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_Query(napi_env env, napi_callback_info info)
{
    LOG_INFO("%{public}s,called", __func__);
    DSHelperQueryCB *QueryCB = new (std::nothrow) DSHelperQueryCB;
    if (QueryCB == nullptr) {
        LOG_ERROR("%{public}s, QueryCB == nullptr.", __func__);
        return WrapVoidToJS(env);
    }
    QueryCB->cbBase.cbInfo.env = env;
    QueryCB->cbBase.asyncWork = nullptr;
    QueryCB->cbBase.deferred = nullptr;
    QueryCB->cbBase.ability = nullptr;

    napi_value ret = QueryWrap(env, info, QueryCB);
    if (ret == nullptr) {
        LOG_ERROR("%{public}s,ret == nullptr", __func__);
        delete QueryCB;
        QueryCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

/**
 * @brief Insert processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param insertCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value QueryWrap(napi_env env, napi_callback_info info, DSHelperQueryCB *queryCB)
{
    LOG_INFO("%{public}s,called", __func__);
    size_t argcAsync = ARGS_FOUR;
    const size_t argcPromise = ARGS_THREE;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    napi_value thisVar = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        LOG_ERROR("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valuetype));
    if (valuetype == napi_string) {
        queryCB->uri = NapiValueToStringUtf8(env, args[PARAM0]);
        LOG_INFO("%{public}s,uri=%{public}s", __func__, queryCB->uri.c_str());
    }

    UnwrapDataSharePredicates(queryCB->predicates, env, args[PARAM1]);

    std::vector<std::string> result;
    bool arrayStringbool = false;
    arrayStringbool = NapiValueToArrayStringUtf8(env, args[PARAM2], result);
    if (!arrayStringbool) {
        LOG_ERROR("%{public}s, The return value of arraystringbool is false", __func__);
    }
    queryCB->columns = result;
    for (size_t i = 0; i < queryCB->columns.size(); i++) {
        LOG_INFO("%{public}s,columns=%{public}s", __func__, queryCB->columns.at(i).c_str());
    }

    DataShareHelper *objectInfo = nullptr;
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    LOG_INFO("%{public}s,DataShareHelper objectInfo = %{public}p", __func__, objectInfo);
    queryCB->dataShareHelper = objectInfo;

    if (argcAsync > argcPromise) {
        ret = QueryAsync(env, args, ARGS_THREE, queryCB);
    } else {
        ret = QueryPromise(env, queryCB);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

napi_value QueryAsync(napi_env env, napi_value *args, const size_t argCallback, DSHelperQueryCB *queryCB)
{
    LOG_INFO("%{public}s, asyncCallback.", __func__);
    if (args == nullptr || queryCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], 1, &queryCB->cbBase.cbInfo.callback));
    }

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            QueryExecuteCB,
            QueryAsyncCompleteCB,
            (void *)queryCB,
            &queryCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, queryCB->cbBase.asyncWork));
    napi_value result = 0;
    NAPI_CALL(env, napi_get_null(env, &result));
    LOG_INFO("%{public}s, asyncCallback end.", __func__);
    return result;
}

napi_value QueryPromise(napi_env env, DSHelperQueryCB *queryCB)
{
    LOG_INFO("%{public}s, promise.", __func__);
    if (queryCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = 0;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    queryCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            QueryExecuteCB,
            QueryPromiseCompleteCB,
            (void *)queryCB,
            &queryCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, queryCB->cbBase.asyncWork));
    LOG_INFO("%{public}s, promise end.", __func__);
    return promise;
}

void QueryPromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_DSHelperQueryCB,  main event thread complete.");
    DSHelperQueryCB *QueryCB = static_cast<DSHelperQueryCB *>(data);
    napi_value result = nullptr;
    result = WrapResultSet(env, QueryCB->result);
    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, QueryCB->cbBase.deferred, result));
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, QueryCB->cbBase.asyncWork));
    delete QueryCB;
    QueryCB = nullptr;
    LOG_INFO("NAPI_DSHelperQueryCB,  main event thread complete end.");
}

void QueryExecuteCB(napi_env env, void *data)
{
    LOG_INFO("NAPI_Query, worker pool thread execute.");
    DSHelperQueryCB *queryCB = static_cast<DSHelperQueryCB *>(data);
    if (queryCB->dataShareHelper != nullptr) {
        queryCB->execResult = INVALID_PARAMETER;
        if (!queryCB->uri.empty()) {
            OHOS::Uri uri(queryCB->uri);
            auto resultset = queryCB->dataShareHelper->Query(uri, queryCB->columns, queryCB->predicates);
            if (resultset != nullptr) {
                queryCB->result = resultset;
                queryCB->execResult = NO_ERROR;
            } else {
                LOG_INFO("NAPI_Query, resultset == nullptr.");
            }
        } else {
            LOG_ERROR("NAPI_Query, dataShareHelper uri is empty");
        }
    } else {
        LOG_ERROR("NAPI_Query, dataShareHelper == nullptr");
    }
    LOG_INFO("NAPI_Query, worker pool thread execute end.");
}

void QueryAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_Query, main event thread complete.");
    DSHelperQueryCB *queryCB = static_cast<DSHelperQueryCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, queryCB->cbBase.cbInfo.callback, &callback));

    result[PARAM0] = GetCallbackErrorValue(env, queryCB->execResult);
    result[PARAM1] = WrapResultSet(env, queryCB->result);

    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (queryCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, queryCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, queryCB->cbBase.asyncWork));
    delete queryCB;
    queryCB = nullptr;
    LOG_INFO("NAPI_Query, main event thread complete end.");
}

napi_value WrapResultSet(napi_env env, const std::shared_ptr<DataShareResultSet> &resultSet)
{
    LOG_INFO("%{public}s,called", __func__);
    if (resultSet == nullptr) {
        LOG_ERROR("%{public}s, input parameter resultSet is nullptr", __func__);
        return WrapVoidToJS(env);
    }

    return DataShareResultSetProxy::NewInstance(env, resultSet);
}

napi_value NAPI_Release(napi_env env, napi_callback_info info)
{
    LOG_INFO("%{public}s,called", __func__);
    DSHelperReleaseCB *releaseCB = new (std::nothrow) DSHelperReleaseCB;
    if (releaseCB == nullptr) {
        LOG_ERROR("%{public}s, releaseCB == nullptr.", __func__);
        return WrapVoidToJS(env);
    }
    releaseCB->cbBase.cbInfo.env = env;
    releaseCB->cbBase.asyncWork = nullptr;
    releaseCB->cbBase.deferred = nullptr;

    napi_value ret = ReleaseWrap(env, info, releaseCB);
    if (ret == nullptr) {
        LOG_ERROR("%{public}s,ret == nullptr", __func__);
        delete releaseCB;
        releaseCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

napi_value ReleaseWrap(napi_env env, napi_callback_info info, DSHelperReleaseCB *releaseCB)
{
    LOG_INFO("%{public}s,called", __func__);
    size_t argcAsync = ARGS_ONE;
    const size_t argcPromise = ARGS_ZERO;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = nullptr;
    napi_value thisVar = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        LOG_ERROR("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }

    DataShareHelper *objectInfo = nullptr;
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    LOG_INFO("DataShareHelper ReleaseWrap objectInfo = %{public}p", objectInfo);
    releaseCB->dataShareHelper = objectInfo;

    if (argcAsync > argcPromise) {
        ret = ReleaseAsync(env, args, PARAM0, releaseCB);
    } else {
        ret = ReleasePromise(env, releaseCB);
    }
    LOG_INFO("%{public}s,end", __func__);
    return ret;
}

napi_value ReleaseAsync(napi_env env, napi_value *args, const size_t argCallback, DSHelperReleaseCB *releaseCB)
{
    LOG_INFO("%{public}s, asyncCallback.", __func__);
    if (args == nullptr || releaseCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], 1, &releaseCB->cbBase.cbInfo.callback));
    }

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            ReleaseExecuteCB,
            ReleaseAsyncCompleteCB,
            (void *)releaseCB,
            &releaseCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, releaseCB->cbBase.asyncWork));
    napi_value result = 0;
    NAPI_CALL(env, napi_get_null(env, &result));
    LOG_INFO("%{public}s, asyncCallback end.", __func__);
    return result;
}

napi_value ReleasePromise(napi_env env, DSHelperReleaseCB *releaseCB)
{
    LOG_INFO("%{public}s, promise.", __func__);
    if (releaseCB == nullptr) {
        LOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = 0;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    releaseCB->cbBase.deferred = deferred;

    NAPI_CALL(env,
        napi_create_async_work(env,
            nullptr,
            resourceName,
            ReleaseExecuteCB,
            ReleasePromiseCompleteCB,
            (void *)releaseCB,
            &releaseCB->cbBase.asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, releaseCB->cbBase.asyncWork));
    LOG_INFO("%{public}s, promise end.", __func__);
    return promise;
}

void ReleaseExecuteCB(napi_env env, void *data)
{
    LOG_INFO("NAPI_Release, worker pool thread execute.");
    DSHelperReleaseCB *releaseCB = static_cast<DSHelperReleaseCB *>(data);
    if (releaseCB->dataShareHelper != nullptr) {
        releaseCB->result = releaseCB->dataShareHelper->Release();
    } else {
        LOG_ERROR("NAPI_Release, dataShareHelper == nullptr");
    }
    LOG_INFO("NAPI_Release, worker pool thread execute end.");
}

void ReleaseAsyncCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_Release, main event thread complete.");
    DSHelperReleaseCB *releaseCB = static_cast<DSHelperReleaseCB *>(data);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, releaseCB->cbBase.cbInfo.callback, &callback));

    result[PARAM0] = GetCallbackErrorValue(env, NO_ERROR);
    napi_get_boolean(env, releaseCB->result, &result[PARAM1]);
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult));

    if (releaseCB->cbBase.cbInfo.callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, releaseCB->cbBase.cbInfo.callback));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, releaseCB->cbBase.asyncWork));
    delete releaseCB;
    releaseCB = nullptr;
    LOG_INFO("NAPI_Release, main event thread complete end.");
}

void ReleasePromiseCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("NAPI_Release,  main event thread complete.");
    DSHelperReleaseCB *releaseCB = static_cast<DSHelperReleaseCB *>(data);
    napi_value result = nullptr;
    napi_get_boolean(env, releaseCB->result, &result);
    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, releaseCB->cbBase.deferred, result));
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, releaseCB->cbBase.asyncWork));
    delete releaseCB;
    releaseCB = nullptr;
    LOG_INFO("NAPI_Release,  main event thread complete end.");
}
}  // namespace DataShare
}  // namespace OHOS
