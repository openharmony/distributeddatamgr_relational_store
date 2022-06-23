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

#include "napi_common_util.h"
#include "datashare_helper.h"
#include "datashare_log.h"
#include "data_share_common.h"
#include "napi_base_context.h"
#include "napi_datashare_values_bucket.h"
#include "datashare_predicates_proxy.h"
#include "datashare_result_set_proxy.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace DataShare {
constexpr int NO_ERROR = 0;
constexpr int INVALID_PARAMETER = -1;

static std::vector<DSHelperOnOffCB *> registerInstances_;
std::list<std::shared_ptr<DataShareHelper>> g_dataShareHelperList;

void UnwrapDataSharePredicates(DataSharePredicates &predicates, napi_env env, napi_value value)
{
    auto tempPredicates = DataSharePredicatesProxy::GetNativePredicates(env, value);
    if (tempPredicates == nullptr) {
        LOG_ERROR("UnwrapDataSharePredicates GetNativePredicates retval Marshalling failed.");
        return;
    }
    predicates = *tempPredicates;
}

bool UnwrapValuesBucketArrayFromJS(napi_env env, napi_value param, std::vector<DataShareValuesBucket> &value)
{
    LOG_INFO("UnwrapValuesBucketArrayFromJS in");
    uint32_t arraySize = 0;
    napi_value jsValue = nullptr;
    std::string strValue = "";

    if (!IsArrayForNapiValue(env, param, arraySize)) {
        LOG_INFO("IsArrayForNapiValue is false");
        return false;
    }

    value.clear();
    for (uint32_t i = 0; i < arraySize; i++) {
        jsValue = nullptr;
        if (napi_get_element(env, param, i, &jsValue) != napi_ok) {
            LOG_INFO("napi_get_element is false");
            return false;
        }

        DataShareValuesBucket valueBucket;
        valueBucket.Clear();
        GetValueBucketObject(valueBucket, env, jsValue);

        value.push_back(valueBucket);
    }
    LOG_INFO("UnwrapValuesBucketArrayFromJS out");
    return true;
}

std::vector<DataShareValuesBucket> GetValuesBucketArray(napi_env env, napi_value param)
{
    LOG_INFO("NapiValueObject in");
    std::vector<DataShareValuesBucket> result;
    UnwrapValuesBucketArrayFromJS(env, param, result);
    return result;
}

napi_value NapiDataShareHelper::Napi_CreateDataShareHelper(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Napi_CreateDataShareHelper in");
    struct CreateContextInfo {
        napi_ref ref = nullptr;
    };
    auto ctxInfo = std::make_shared<CreateContextInfo>();
    auto input = [ctxInfo](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        LOG_DEBUG("CreateDataShareHelper parser to native params %{public}d", static_cast<int>(argc));
        NAPI_ASSERT_BASE(env, (argc > 1) && (argc < 4), " need 2 or 3 parameters!", napi_invalid_arg);
        napi_value helperProxy = nullptr;
        napi_status status = napi_new_instance(env, GetConstructor(env), argc, argv, &helperProxy);
        if ((helperProxy == nullptr) || (status != napi_ok)) {
            return napi_generic_failure;
        }
        napi_create_reference(env, helperProxy, 1, &(ctxInfo->ref));
        return napi_ok;
    };
    auto output = [ctxInfo](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_reference_value(env, ctxInfo->ref, result);
        napi_delete_reference(env, ctxInfo->ref);
        return status;
    };
    auto context = std::make_shared<AsyncCall::Context>(input, output);
    AsyncCall asyncCall(env, info, context);
    return asyncCall.Call(env);
}

napi_value NapiDataShareHelper::GetConstructor(napi_env env)
{
    napi_value cons = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("openFile", Napi_OpenFile),
        DECLARE_NAPI_FUNCTION("on", Napi_On),
        DECLARE_NAPI_FUNCTION("off", Napi_Off),
        DECLARE_NAPI_FUNCTION("insert", Napi_Insert),
        DECLARE_NAPI_FUNCTION("delete", Napi_Delete),
        DECLARE_NAPI_FUNCTION("query", Napi_Query),
        DECLARE_NAPI_FUNCTION("update", Napi_Update),
        DECLARE_NAPI_FUNCTION("batchInsert", Napi_BatchInsert),
        DECLARE_NAPI_FUNCTION("getType", Napi_GetType),
        DECLARE_NAPI_FUNCTION("getFileTypes", Napi_GetFileTypes),
        DECLARE_NAPI_FUNCTION("normalizeUri", Napi_NormalizeUri),
        DECLARE_NAPI_FUNCTION("denormalizeUri", Napi_DenormalizeUri),
        DECLARE_NAPI_FUNCTION("notifyChange", Napi_NotifyChange),
    };
    NAPI_CALL(env, napi_define_class(env, "DataShareHelper", NAPI_AUTO_LENGTH, Initialize, nullptr,
        sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    g_dataShareHelperList.clear();
    return cons;
}

napi_value NapiDataShareHelper::Initialize(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Initialize in");
    napi_value self = nullptr;
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &self, nullptr));
    NAPI_ASSERT(env, argc > 1, "Wrong number of arguments");

    auto *proxy = new NapiDataShareHelper();
    std::string strUri;
    bool isStageMode = false;
    napi_status status = AbilityRuntime::IsStageContext(env, argv[PARAM0], isStageMode);
    if (status != napi_ok || !isStageMode) {
        auto ability = OHOS::AbilityRuntime::GetCurrentAbility(env);
        strUri = DataShareJSUtils::Convert2String(env, argv[PARAM0]);
        NAPI_ASSERT(env, ability != nullptr, "DataShareHelperConstructor: failed to get native ability");
        LOG_INFO("FA Model: strUri = %{public}s", strUri.c_str());
        proxy->datashareHelper_ = DataShareHelper::Creator(ability->GetContext(), strUri);
    } else {
        auto context = OHOS::AbilityRuntime::GetStageModeContext(env, argv[PARAM0]);
        strUri = DataShareJSUtils::Convert2String(env, argv[PARAM1]);
        NAPI_ASSERT(env, context != nullptr, "DataShareHelperConstructor: failed to get native context");
        LOG_INFO("Stage Model: strUri = %{public}s", strUri.c_str());
        proxy->datashareHelper_ = DataShareHelper::Creator(context, strUri);
    }
    NAPI_ASSERT(env, proxy->datashareHelper_ != nullptr, "proxy->datashareHelper_ is nullptr");
    g_dataShareHelperList.emplace_back(proxy->datashareHelper_);
    auto finalize = [](napi_env env, void * data, void * hint) {
        NapiDataShareHelper *proxy = reinterpret_cast<NapiDataShareHelper *>(data);
        auto helper = std::find_if(registerInstances_.begin(), registerInstances_.end(),
            [&proxy](const DSHelperOnOffCB *helper) {
                return helper->dataShareHelper == proxy->datashareHelper_.get();
            });
        if (helper != registerInstances_.end()) {
            LOG_INFO("DataShareHelper finalize_cb find helper");
            (*helper)->dataShareHelper->Release();
            delete *helper;
            registerInstances_.erase(helper);
        }
    };
    if (napi_wrap(env, self, proxy, finalize, nullptr, nullptr) != napi_ok) {
        finalize(env, proxy, nullptr);
        return nullptr;
    }
    return self;
}

napi_value NapiDataShareHelper::Napi_OpenFile(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Napi_OpenFile in");
    auto context = std::make_shared<ContextInfo>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 2 || argc == 3, " should 2 or 3 parameters!", napi_invalid_arg);
        LOG_DEBUG("argc : %{public}d", static_cast<int>(argc));

        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, argv[PARAM0], &valuetype);
        if (valuetype == napi_string) {
            context->uri = DataShareJSUtils::Convert2String(env, argv[PARAM0]);
            LOG_INFO("uri : %{public}s", context->uri.c_str());
        } else {
            LOG_INFO("wrong type, should be napi_string");
        }

        napi_typeof(env, argv[PARAM1], &valuetype);
        if (valuetype == napi_string) {
            context->mode = DataShareJSUtils::Convert2String(env, argv[PARAM1]);
            LOG_INFO("mode : %{public}s", context->mode.c_str());
        } else {
            LOG_INFO("wrong type, should be napi_string");
        }
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_create_int32(env, context->resultNumber, result);
        return napi_ok;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        if (context->proxy->datashareHelper_ != nullptr) {
            if (!context->uri.empty()) {
                OHOS::Uri uri(context->uri);
                context->resultNumber = context->proxy->datashareHelper_->OpenFile(uri, context->mode);
                context->status = napi_ok;
            } else {
                LOG_ERROR("context->uri is empty");
            }
        } else {
            LOG_ERROR("dataShareHelper_ == nullptr");
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiDataShareHelper::Napi_Insert(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Napi_Insert in");
    auto context = std::make_shared<ContextInfo>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 2 || argc == 3, " should 2 or 3 parameters!", napi_invalid_arg);
        LOG_DEBUG("argc : %{public}d", static_cast<int>(argc));

        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, argv[PARAM0], &valuetype);
        if (valuetype == napi_string) {
            context->uri = DataShareJSUtils::Convert2String(env, argv[PARAM0]);
            LOG_INFO("uri : %{public}s", context->uri.c_str());
        } else {
            LOG_INFO("wrong type, should be napi_string");
        }

        context->valueBucket.Clear();
        GetValueBucketObject(context->valueBucket, env, argv[PARAM1]);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_create_int32(env, context->resultNumber, result);
        return napi_ok;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        if (context->proxy->datashareHelper_ != nullptr) {
            if (!context->uri.empty()) {
                OHOS::Uri uri(context->uri);
                context->resultNumber = context->proxy->datashareHelper_->Insert(uri, context->valueBucket);
                context->status = napi_ok;
            } else {
                LOG_ERROR("context->uri is empty");
            }
        } else {
            LOG_ERROR("dataShareHelper_ == nullptr");
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiDataShareHelper::Napi_Delete(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Napi_Delete in");
    auto context = std::make_shared<ContextInfo>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 2 || argc == 3, " should 2 or 3 parameters!", napi_invalid_arg);
        LOG_DEBUG("argc : %{public}d", static_cast<int>(argc));

        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, argv[PARAM0], &valuetype);
        if (valuetype == napi_string) {
            context->uri = DataShareJSUtils::Convert2String(env, argv[PARAM0]);
            LOG_INFO("uri : %{public}s", context->uri.c_str());
        } else {
            LOG_INFO("wrong type, should be napi_string");
        }

        UnwrapDataSharePredicates(context->predicates, env, argv[PARAM1]);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_create_int32(env, context->resultNumber, result);
        return napi_ok;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        if (context->proxy->datashareHelper_ != nullptr) {
            if (!context->uri.empty()) {
                OHOS::Uri uri(context->uri);
                context->resultNumber = context->proxy->datashareHelper_->Delete(uri, context->predicates);
                context->status = napi_ok;
            } else {
                LOG_ERROR("context->uri is empty");
            }
        } else {
            LOG_ERROR("dataShareHelper_ == nullptr");
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiDataShareHelper::Napi_Query(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Napi_Query in");
    auto context = std::make_shared<ContextInfo>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 3 || argc == 4, " should 3 or 4 parameters!", napi_invalid_arg);
        LOG_DEBUG("argc : %{public}d", static_cast<int>(argc));

        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, argv[PARAM0], &valuetype);
        if (valuetype == napi_string) {
            context->uri = DataShareJSUtils::Convert2String(env, argv[PARAM0]);
            LOG_INFO("uri : %{public}s", context->uri.c_str());
        } else {
            LOG_INFO("wrong type, should be napi_string");
        }

        UnwrapDataSharePredicates(context->predicates, env, argv[PARAM1]);

        context->columns = DataShareJSUtils::Convert2StrVector(env, argv[PARAM2], DataShareJSUtils::DEFAULT_BUF_SIZE);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        *result = DataShareResultSetProxy::NewInstance(env, context->resultObject);
        return napi_ok;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        if (context->proxy->datashareHelper_ != nullptr) {
            if (!context->uri.empty()) {
                OHOS::Uri uri(context->uri);
                context->resultObject =
                    context->proxy->datashareHelper_->Query(uri, context->predicates, context->columns);
                context->status = napi_ok;
            } else {
                LOG_ERROR("context->uri is empty");
            }
        } else {
            LOG_ERROR("dataShareHelper_ == nullptr");
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiDataShareHelper::Napi_Update(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Napi_Update in");
    auto context = std::make_shared<ContextInfo>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 3 || argc == 4, " should 3 or 4 parameters!", napi_invalid_arg);
        LOG_DEBUG("argc : %{public}d", static_cast<int>(argc));

        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, argv[PARAM0], &valuetype);
        if (valuetype == napi_string) {
            context->uri = DataShareJSUtils::Convert2String(env, argv[PARAM0]);
            LOG_INFO("uri : %{public}s", context->uri.c_str());
        } else {
            LOG_INFO("wrong type, should be napi_string");
        }

        UnwrapDataSharePredicates(context->predicates, env, argv[PARAM1]);

        context->valueBucket.Clear();
        GetValueBucketObject(context->valueBucket, env, argv[PARAM2]);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_create_int32(env, context->resultNumber, result);
        return napi_ok;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        if (context->proxy->datashareHelper_ != nullptr) {
            if (!context->uri.empty()) {
                OHOS::Uri uri(context->uri);
                context->resultNumber =
                    context->proxy->datashareHelper_->Update(uri, context->predicates, context->valueBucket);
                context->status = napi_ok;
            } else {
                LOG_ERROR("context->uri is empty");
            }
        } else {
            LOG_ERROR("dataShareHelper_ == nullptr");
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiDataShareHelper::Napi_BatchInsert(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Napi_BatchInsert in");
    auto context = std::make_shared<ContextInfo>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 2 || argc == 3, " should 2 or 3 parameters!", napi_invalid_arg);
        LOG_DEBUG("argc : %{public}d", static_cast<int>(argc));

        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, argv[PARAM0], &valuetype);
        if (valuetype == napi_string) {
            context->uri = DataShareJSUtils::Convert2String(env, argv[PARAM0]);
            LOG_INFO("uri : %{public}s", context->uri.c_str());
        } else {
            LOG_INFO("wrong type, should be napi_string");
        }

        context->values = GetValuesBucketArray(env, argv[PARAM1]);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_create_int32(env, context->resultNumber, result);
        return napi_ok;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        if (context->proxy->datashareHelper_ != nullptr) {
            if (!context->uri.empty()) {
                OHOS::Uri uri(context->uri);
                context->resultNumber = context->proxy->datashareHelper_->BatchInsert(uri, context->values);
                context->status = napi_ok;
            } else {
                LOG_ERROR("context->uri is empty");
            }
        } else {
            LOG_ERROR("dataShareHelper_ == nullptr");
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiDataShareHelper::Napi_GetType(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Napi_GetType in");
    auto context = std::make_shared<ContextInfo>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1 || argc == 2, " should 1 or 2 parameters!", napi_invalid_arg);
        LOG_DEBUG("argc : %{public}d", static_cast<int>(argc));

        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, argv[PARAM0], &valuetype);
        if (valuetype == napi_string) {
            context->uri = DataShareJSUtils::Convert2String(env, argv[PARAM0]);
            LOG_INFO("uri : %{public}s", context->uri.c_str());
        } else {
            LOG_INFO("wrong type, should be napi_string");
        }
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_create_string_utf8(env, context->resultString.c_str(), NAPI_AUTO_LENGTH, result);
        return napi_ok;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        if (context->proxy->datashareHelper_ != nullptr) {
            if (!context->uri.empty()) {
                OHOS::Uri uri(context->uri);
                context->resultString = context->proxy->datashareHelper_->GetType(uri);
                context->status = napi_ok;
            } else {
                LOG_ERROR("context->uri is empty");
            }
        } else {
            LOG_ERROR("dataShareHelper_ == nullptr");
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiDataShareHelper::Napi_GetFileTypes(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Napi_GetFileTypes in");
    auto context = std::make_shared<ContextInfo>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 2 || argc == 3, " should 2 or 3 parameters!", napi_invalid_arg);
        LOG_DEBUG("argc : %{public}d", static_cast<int>(argc));

        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, argv[PARAM0], &valuetype);
        if (valuetype == napi_string) {
            context->uri = DataShareJSUtils::Convert2String(env, argv[PARAM0]);
            LOG_INFO("uri : %{public}s", context->uri.c_str());
        } else {
            LOG_INFO("wrong type, should be napi_string");
        }

        napi_typeof(env, argv[PARAM1], &valuetype);
        if (valuetype == napi_string) {
            context->mimeTypeFilter = DataShareJSUtils::Convert2String(env, argv[PARAM1]);
            LOG_INFO("mimeTypeFilter : %{public}s", context->mimeTypeFilter.c_str());
        } else {
            LOG_INFO("wrong type, should be napi_string");
        }
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        *result = DataShareJSUtils::Convert2JSValue(env, context->resultStrArr);
        return napi_ok;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        if (context->proxy->datashareHelper_ != nullptr) {
            if (!context->uri.empty()) {
                OHOS::Uri uri(context->uri);
                context->resultStrArr = context->proxy->datashareHelper_->GetFileTypes(uri, context->mimeTypeFilter);
                context->status = napi_ok;
            } else {
                LOG_ERROR("context->uri is empty");
            }
        } else {
            LOG_ERROR("dataShareHelper_ == nullptr");
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiDataShareHelper::Napi_NormalizeUri(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Napi_NormalizeUri in");
    auto context = std::make_shared<ContextInfo>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1 || argc == 2, " should 1 or 2 parameters!", napi_invalid_arg);
        LOG_DEBUG("argc : %{public}d", static_cast<int>(argc));

        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, argv[PARAM0], &valuetype);
        if (valuetype == napi_string) {
            context->uri = DataShareJSUtils::Convert2String(env, argv[PARAM0]);
            LOG_INFO("uri : %{public}s", context->uri.c_str());
        } else {
            LOG_INFO("wrong type, should be napi_string");
        }
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_create_string_utf8(env, context->resultString.c_str(), NAPI_AUTO_LENGTH, result);
        return napi_ok;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        if (context->proxy->datashareHelper_ != nullptr) {
            if (!context->uri.empty()) {
                OHOS::Uri uri(context->uri);
                Uri uriValue = context->proxy->datashareHelper_->NormalizeUri(uri);
                context->resultString = uriValue.ToString();
                context->status = napi_ok;
            } else {
                LOG_ERROR("context->uri is empty");
            }
        } else {
            LOG_ERROR("dataShareHelper_ == nullptr");
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiDataShareHelper::Napi_DenormalizeUri(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Napi_DenormalizeUri in");
    auto context = std::make_shared<ContextInfo>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1 || argc == 2, " should 1 or 2 parameters!", napi_invalid_arg);
        LOG_DEBUG("argc : %{public}d", static_cast<int>(argc));

        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, argv[PARAM0], &valuetype);
        if (valuetype == napi_string) {
            context->uri = DataShareJSUtils::Convert2String(env, argv[PARAM0]);
            LOG_INFO("uri : %{public}s", context->uri.c_str());
        } else {
            LOG_INFO("wrong type, should be napi_string");
        }
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_create_string_utf8(env, context->resultString.c_str(), NAPI_AUTO_LENGTH, result);
        return napi_ok;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        if (context->proxy->datashareHelper_ != nullptr) {
            if (!context->uri.empty()) {
                OHOS::Uri uri(context->uri);
                Uri uriValue = context->proxy->datashareHelper_->DenormalizeUri(uri);
                context->resultString = uriValue.ToString();
                context->status = napi_ok;
            } else {
                LOG_ERROR("context->uri is empty");
            }
        } else {
            LOG_ERROR("dataShareHelper_ == nullptr");
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiDataShareHelper::Napi_NotifyChange(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Napi_NotifyChange in");
    auto context = std::make_shared<ContextInfo>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1 || argc == 2, " should 1 or 2 parameters!", napi_invalid_arg);
        LOG_DEBUG("argc : %{public}d", static_cast<int>(argc));

        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, argv[PARAM0], &valuetype);
        if (valuetype == napi_string) {
            context->uri = DataShareJSUtils::Convert2String(env, argv[PARAM0]);
            LOG_INFO("uri : %{public}s", context->uri.c_str());
        } else {
            LOG_INFO("wrong type, should be napi_string");
        }
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_get_null(env, result);
        return napi_ok;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        if (context->proxy->datashareHelper_ != nullptr) {
            if (!context->uri.empty()) {
                OHOS::Uri uri(context->uri);
                context->proxy->datashareHelper_->NotifyChange(uri);
                context->status = napi_ok;
            } else {
                LOG_ERROR("context->uri is empty");
            }
        } else {
            LOG_ERROR("dataShareHelper_ == nullptr");
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiDataShareHelper::Napi_On(napi_env env, napi_callback_info info)
{
    LOG_INFO("Napi_On in");
    DSHelperOnOffCB *onCB = new (std::nothrow) DSHelperOnOffCB;
    if (onCB == nullptr) {
        LOG_ERROR("Napi_On onCB == nullptr.");
        return WrapVoidToJS(env);
    }
    onCB->cbBase.cbInfo.env = env;
    onCB->cbBase.asyncWork = nullptr;
    onCB->cbBase.deferred = nullptr;
    onCB->cbBase.ability = nullptr;

    napi_value ret = RegisterWrap(env, info, onCB);
    if (ret == nullptr) {
        LOG_ERROR("ret == nullptr.");
        delete onCB;
        onCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("Napi_On out");
    return ret;
}

napi_value NapiDataShareHelper::RegisterWrap(napi_env env, napi_callback_info info, DSHelperOnOffCB *onCB)
{
    LOG_INFO("RegisterWrap in");
    size_t argcAsync = ARGS_THREE;
    const size_t argcPromise = ARGS_TWO;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    napi_value thisVar = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        LOG_ERROR("Wrong argument count.");
        return nullptr;
    }

    onCB->result = NO_ERROR;
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valuetype));
    if (valuetype == napi_string) {
        std::string type = DataShareJSUtils::Convert2String(env, args[PARAM0]);
        if (type == "dataChange") {
            LOG_INFO("Wrong type : %{public}s", type.c_str());
        } else {
            LOG_ERROR("Wrong argument type is %{public}s.", type.c_str());
            onCB->result = INVALID_PARAMETER;
        }
    } else {
        LOG_ERROR("Wrong argument type.");
        onCB->result = INVALID_PARAMETER;
    }

    NAPI_CALL(env, napi_typeof(env, args[PARAM1], &valuetype));
    if (valuetype == napi_string) {
        onCB->uri = DataShareJSUtils::Convert2String(env, args[PARAM1]);
        LOG_INFO("uri : %{public}s", onCB->uri.c_str());
    } else {
        LOG_ERROR("Wrong argument type.");
        onCB->result = INVALID_PARAMETER;
    }

    NapiDataShareHelper *objectInfo = nullptr;
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    LOG_INFO("Set NapiDataShareHelper objectInfo");
    onCB->dataShareHelper = objectInfo->datashareHelper_.get();

    ret = RegisterAsync(env, args, argcAsync, argcPromise, onCB);
    return ret;
}

napi_value NapiDataShareHelper::RegisterAsync(
    napi_env env, napi_value *args, size_t argcAsync, const size_t argcPromise, DSHelperOnOffCB *onCB)
{
    LOG_INFO("RegisterAsync in.");
    if (args == nullptr || onCB == nullptr) {
        LOG_ERROR("param == nullptr.");
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

void NapiDataShareHelper::RegisterExecuteCB(napi_env env, void *data)
{
    LOG_INFO("RegisterExecuteCB in.");
    DSHelperOnOffCB *onCB = static_cast<DSHelperOnOffCB *>(data);
    if (onCB->dataShareHelper != nullptr) {
        if (onCB->result != INVALID_PARAMETER && !onCB->uri.empty() && onCB->cbBase.cbInfo.callback != nullptr) {
            OHOS::Uri uri(onCB->uri);
            onCB->dataShareHelper->RegisterObserver(uri, onCB->observer);
        } else {
            LOG_ERROR("dataShareHelper uri is empty or callback is nullptr.");
        }
    }
}

void NapiDataShareHelper::RegisterCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("RegisterCompleteCB in.");
    DSHelperOnOffCB *onCB = static_cast<DSHelperOnOffCB *>(data);
    if (onCB == nullptr) {
        LOG_ERROR("input params onCB is nullptr.");
        return;
    }
    if (onCB->result == NO_ERROR) {
        return;
    }
    if (onCB->observer) {
        LOG_INFO("RegisterCompleteCB, call ReleaseJSCallback");
        onCB->observer->ReleaseJSCallback();
    }
    delete onCB;
    onCB = nullptr;
    LOG_INFO("RegisterCompleteCB out.");
}

napi_value NapiDataShareHelper::Napi_Off(napi_env env, napi_callback_info info)
{
    LOG_INFO("Napi_Off in");
    DSHelperOnOffCB *offCB = new (std::nothrow) DSHelperOnOffCB;
    if (offCB == nullptr) {
        LOG_ERROR("offCB == nullptr.");
        return WrapVoidToJS(env);
    }
    offCB->cbBase.cbInfo.env = env;
    offCB->cbBase.asyncWork = nullptr;
    offCB->cbBase.deferred = nullptr;
    offCB->cbBase.ability = nullptr;

    napi_value ret = UnRegisterWrap(env, info, offCB);
    if (ret == nullptr) {
        LOG_ERROR("ret == nullptr.");
        delete offCB;
        offCB = nullptr;
        ret = WrapVoidToJS(env);
    }
    LOG_INFO("Napi_Off out");
    return ret;
}

napi_value NapiDataShareHelper::UnRegisterWrap(napi_env env, napi_callback_info info, DSHelperOnOffCB *offCB)
{
    LOG_INFO("UnRegisterWrap in");
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
        std::string type = DataShareJSUtils::Convert2String(env, args[PARAM0]);
        if (type == "dataChange") {
            offCB->result = NO_ERROR;
        }
    }
    offCB->uri = "";
    if (argc > ARGS_TWO) {
        NAPI_CALL(env, napi_typeof(env, args[PARAM1], &valuetype));
        if (valuetype == napi_string) {
            offCB->uri = DataShareJSUtils::Convert2String(env, args[PARAM1]);
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
            offCB->uri = DataShareJSUtils::Convert2String(env, args[PARAM1]);
        } else if (valuetype == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, args[PARAM1], 1, &offCB->cbBase.cbInfo.callback));
        } else {
            offCB->result = INVALID_PARAMETER;
        }
    }
    LOG_INFO("uri : %{public}s", offCB->uri.c_str());
    NapiDataShareHelper *objectInfo = nullptr;
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    offCB->dataShareHelper = objectInfo->datashareHelper_.get();
    ret = UnRegisterAsync(env, args, argc, argcPromise, offCB);
    return ret;
}

napi_value NapiDataShareHelper::UnRegisterAsync(
    napi_env env, napi_value *args, size_t argc, const size_t argcPromise, DSHelperOnOffCB *offCB)
{
    LOG_INFO("UnRegisterAsync in.");
    if (args == nullptr || offCB == nullptr) {
        LOG_ERROR("param == nullptr.");
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

void NapiDataShareHelper::UnRegisterExecuteCB(napi_env env, void *data)
{
    LOG_INFO("UnRegisterExecuteCB in.");
    DSHelperOnOffCB *offCB = static_cast<DSHelperOnOffCB *>(data);
    if (offCB == nullptr || offCB->dataShareHelper == nullptr) {
        LOG_ERROR("NAPI_UnRegister, param is null.");
        if (offCB != nullptr) {
            delete offCB;
            offCB = nullptr;
        }
        return;
    }
    LOG_INFO("UnRegisterExecuteCB, offCB->DestoryList size is %{public}zu", offCB->NotifyList.size());
    for (auto &iter : offCB->NotifyList) {
        if (iter != nullptr && iter->observer != nullptr) {
            OHOS::Uri uri(iter->uri);
            iter->dataShareHelper->UnregisterObserver(uri, iter->observer);
            offCB->DestoryList.emplace_back(iter);
        }
    }
    offCB->NotifyList.clear();
    LOG_INFO("UnRegisterExecuteCB out.");
}

void NapiDataShareHelper::UnRegisterCompleteCB(napi_env env, napi_status status, void *data)
{
    LOG_INFO("UnRegisterCompleteCB in.");
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
    LOG_INFO("UnRegisterCompleteCB, offCB->DestoryList size is %{public}zu", offCB->DestoryList.size());
    for (auto &iter : offCB->DestoryList) {
        if (iter->observer != nullptr) {
            if (iter->observer->GetWorkPre() == 1 && iter->observer->GetWorkRun() == 0) {
                iter->observer->SetAssociatedObject(iter);
                iter->observer->ChangeWorkInt();
                LOG_INFO("UnRegisterCompleteCB ChangeWorkInt");
            } else {
                iter->observer->ReleaseJSCallback();
                delete iter;
                iter = nullptr;
                LOG_INFO("UnRegisterCompleteCB ReleaseJSCallback");
            }
        }
    }

    offCB->DestoryList.clear();
    delete offCB;
    offCB = nullptr;
    LOG_INFO("UnRegisterCompleteCB out");
}

void NapiDataShareHelper::FindRegisterObs(napi_env env, DSHelperOnOffCB *data)
{
    LOG_INFO("FindRegisterObs in.");
    if (data == nullptr || data->dataShareHelper == nullptr) {
        LOG_ERROR("FindRegisterObs, param is null.");
        return;
    }
    if (data->cbBase.cbInfo.callback != nullptr) {
        LOG_INFO("FindRegisterObs, UnRegisterExecuteCB callback is not null.");
        FindRegisterObsByCallBack(env, data);
    } else {
        if (data->uri.empty()) {
            LOG_ERROR("FindRegisterObs, error: uri is empty.");
            return;
        }

        LOG_INFO("FindRegisterObs, uri : %{public}s.", data->uri.c_str());
        std::string strUri = data->uri;
        do {
            auto helper = std::find_if(registerInstances_.begin(), registerInstances_.end(),
                [strUri](const DSHelperOnOffCB *helper) { return helper->uri == strUri; });
            if (helper != registerInstances_.end()) {
                OHOS::Uri uri((*helper)->uri);
                data->NotifyList.emplace_back(*helper);
                registerInstances_.erase(helper);
                LOG_INFO("FindRegisterObs Instances erase size : %{public}zu", registerInstances_.size());
            } else {
                LOG_INFO("FindRegisterObs not match any uri.");
                break;
            }
        } while (true);
    }
    LOG_INFO("FindRegisterObs out, data->NotifyList.size : %{public}zu", data->NotifyList.size());
}

void NapiDataShareHelper::FindRegisterObsByCallBack(napi_env env, DSHelperOnOffCB *data)
{
    LOG_INFO("FindRegisterObsByCallBack in.");
    if (data == nullptr || data->dataShareHelper == nullptr) {
        LOG_ERROR("FindRegisterObsByCallBack, param is null.");
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
                LOG_INFO("FindRegisterObsByCallBack cb equals status : %{public}d result : %{public}d.", ret, result);
                return result;
            });
        if (helper != registerInstances_.end()) {
            data->NotifyList.emplace_back(*helper);
            registerInstances_.erase(helper);
            LOG_INFO("FindRegisterObsByCallBack Instances erase size = %{public}zu", registerInstances_.size());
        } else {
            LOG_INFO("FindRegisterObsByCallBack not match any callback. %{public}zu", registerInstances_.size());
            break;
        }
    } while (true);
    LOG_INFO("FindRegisterObsByCallBack out.");
}
}  // namespace DataShare
}  // namespace OHOS
