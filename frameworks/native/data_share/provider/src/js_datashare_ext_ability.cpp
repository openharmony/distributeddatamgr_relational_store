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

#include "js_datashare_ext_ability.h"

#include "ability_info.h"
#include "accesstoken_kit.h"
#include "dataobs_mgr_client.h"
#include "datashare_stub_impl.h"
#include "datashare_log.h"
#include "ipc_skeleton.h"
#include "js_datashare_ext_ability_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "napi_remote_object.h"

#include "napi_datashare_values_bucket.h"
#include "datashare_result_set_proxy.h"
#include "datashare_predicates_proxy.h"

namespace OHOS {
namespace DataShare {
using namespace AbilityRuntime;
namespace {
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr size_t ARGC_THREE = 3;
constexpr int INVALID_VALUE = -1;
}

using namespace OHOS::AppExecFwk;
using OHOS::Security::AccessToken::AccessTokenKit;
using DataObsMgrClient = OHOS::AAFwk::DataObsMgrClient;

JsDataShareExtAbility* JsDataShareExtAbility::Create(const std::unique_ptr<Runtime>& runtime)
{
    return new JsDataShareExtAbility(static_cast<JsRuntime&>(*runtime));
}

JsDataShareExtAbility::JsDataShareExtAbility(JsRuntime& jsRuntime) : jsRuntime_(jsRuntime) {}

JsDataShareExtAbility::~JsDataShareExtAbility() {}

void JsDataShareExtAbility::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    DataShareExtAbility::Init(record, application, handler, token);
    std::string srcPath = "";
    GetSrcPath(srcPath);
    if (srcPath.empty()) {
        LOG_ERROR("Failed to get srcPath");
        return;
    }

    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    LOG_INFO("module:%{public}s, srcPath:%{public}s.", moduleName.c_str(), srcPath.c_str());
    HandleScope handleScope(jsRuntime_);
    auto& engine = jsRuntime_.GetNativeEngine();

    jsObj_ = jsRuntime_.LoadModule(moduleName, srcPath);
    if (jsObj_ == nullptr) {
        LOG_ERROR("Failed to get jsObj_");
        return;
    }
    LOG_INFO("JsDataShareExtAbility::Init ConvertNativeValueTo.");
    NativeObject* obj = ConvertNativeValueTo<NativeObject>(jsObj_->Get());
    if (obj == nullptr) {
        LOG_ERROR("Failed to get JsDataShareExtAbility object");
        return;
    }

    auto context = GetContext();
    if (context == nullptr) {
        LOG_ERROR("Failed to get context");
        return;
    }
    LOG_INFO("JsDataShareExtAbility::Init CreateJsDataShareExtAbilityContext.");
    NativeValue* contextObj = CreateJsDataShareExtAbilityContext(engine, context);
    auto contextRef = jsRuntime_.LoadSystemModule("application.DataShareExtensionAbilityContext",
        &contextObj, ARGC_ONE);
    contextObj = contextRef->Get();
    LOG_INFO("JsDataShareExtAbility::Init Bind.");
    context->Bind(jsRuntime_, contextRef.release());
    LOG_INFO("JsDataShareExtAbility::SetProperty.");
    obj->SetProperty("context", contextObj);

    auto nativeObj = ConvertNativeValueTo<NativeObject>(contextObj);
    if (nativeObj == nullptr) {
        LOG_ERROR("Failed to get datashare extension ability native object");
        return;
    }

    LOG_INFO("Set datashare extension ability context pointer: %{public}p", context.get());

    nativeObj->SetNativePointer(new std::weak_ptr<AbilityRuntime::Context>(context),
        [](NativeEngine*, void* data, void*) {
            LOG_INFO("Finalizer for weak_ptr datashare extension ability context is called");
            delete static_cast<std::weak_ptr<AbilityRuntime::Context>*>(data);
        }, nullptr);

    LOG_INFO("JsDataShareExtAbility::Init end.");
}

void JsDataShareExtAbility::OnStart(const AAFwk::Want &want)
{
    LOG_INFO("begin.");
    Extension::OnStart(want);
    HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, want);
    NativeValue* nativeWant = reinterpret_cast<NativeValue*>(napiWant);
    NativeValue* argv[] = {nativeWant};
    CallObjectMethod("onCreate", argv, ARGC_ONE);
    LOG_INFO("end.");
}

sptr<IRemoteObject> JsDataShareExtAbility::OnConnect(const AAFwk::Want &want)
{
    LOG_INFO("begin.");
    Extension::OnConnect(want);
    sptr<DataShareStubImpl> remoteObject = new (std::nothrow) DataShareStubImpl(
        std::static_pointer_cast<JsDataShareExtAbility>(shared_from_this()),
        reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine()));
    if (remoteObject == nullptr) {
        LOG_ERROR("%{public}s No memory allocated for DataShareStubImpl", __func__);
        return nullptr;
    }
    LOG_INFO("end.");
    return remoteObject->AsObject();
}

NativeValue* JsDataShareExtAbility::CallObjectMethod(const char* name, NativeValue* const* argv, size_t argc)
{
    LOG_INFO("JsDataShareExtAbility::CallObjectMethod(%{public}s), begin", name);

    if (!jsObj_) {
        LOG_WARN("Not found DataShareExtAbility.js");
        return nullptr;
    }

    HandleScope handleScope(jsRuntime_);
    auto& nativeEngine = jsRuntime_.GetNativeEngine();

    NativeValue* value = jsObj_->Get();
    NativeObject* obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        LOG_ERROR("Failed to get DataShareExtAbility object");
        return nullptr;
    }

    NativeValue* method = obj->GetProperty(name);
    if (method == nullptr) {
        LOG_ERROR("Failed to get '%{public}s' from DataShareExtAbility object", name);
        return nullptr;
    }
    LOG_INFO("JsDataShareExtAbility::CallFunction(%{public}s), success", name);
    return handleScope.Escape(nativeEngine.CallFunction(value, method, argv, argc));
}

void JsDataShareExtAbility::GetSrcPath(std::string &srcPath)
{
    if (!Extension::abilityInfo_->isStageBasedModel) {
        /* temporary compatibility api8 + config.json */
        srcPath.append(Extension::abilityInfo_->package);
        srcPath.append("/assets/js/");
        if (!Extension::abilityInfo_->srcPath.empty()) {
            srcPath.append(Extension::abilityInfo_->srcPath);
        }
        srcPath.append("/").append(Extension::abilityInfo_->name).append(".abc");
        return;
    }

    if (!Extension::abilityInfo_->srcEntrance.empty()) {
        srcPath.append(Extension::abilityInfo_->moduleName + "/");
        srcPath.append(Extension::abilityInfo_->srcEntrance);
        srcPath.erase(srcPath.rfind('.'));
        srcPath.append(".abc");
    }
}

std::vector<std::string> JsDataShareExtAbility::GetFileTypes(const Uri &uri, const std::string &mimeTypeFilter)
{
    LOG_INFO("begin.");
    auto ret = DataShareExtAbility::GetFileTypes(uri, mimeTypeFilter);
    HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());

    napi_value napiUri = nullptr;
    napi_create_string_utf8(env, uri.ToString().c_str(), NAPI_AUTO_LENGTH, &napiUri);
    napi_value napiMimeTypeFilter = nullptr;
    napi_create_string_utf8(env, mimeTypeFilter.c_str(), NAPI_AUTO_LENGTH, &napiMimeTypeFilter);

    NativeValue* nativeUri = reinterpret_cast<NativeValue*>(napiUri);
    NativeValue* nativeMimeTypeFilter = reinterpret_cast<NativeValue*>(napiMimeTypeFilter);
    NativeValue* argv[] = {nativeUri, nativeMimeTypeFilter};
    NativeValue* nativeResult = CallObjectMethod("getFileTypes", argv, ARGC_TWO);
    if (nativeResult == nullptr) {
        LOG_ERROR("%{public}s call getFileTypes with return null.", __func__);
        return ret;
    }

    if (!OHOS::AppExecFwk::UnwrapArrayStringFromJS(env, reinterpret_cast<napi_value>(nativeResult), ret)) {
        LOG_ERROR("%{public}s call UnwrapArrayStringFromJS failed", __func__);
        return ret;
    }

    LOG_INFO("end.");
    return ret;
}

int JsDataShareExtAbility::OpenFile(const Uri &uri, const std::string &mode)
{
    LOG_INFO("begin.");
    auto ret = DataShareExtAbility::OpenFile(uri, mode);
    HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());

    napi_value napiUri = nullptr;
    napi_create_string_utf8(env, uri.ToString().c_str(), NAPI_AUTO_LENGTH, &napiUri);
    napi_value napiMode = nullptr;
    napi_create_string_utf8(env, mode.c_str(), NAPI_AUTO_LENGTH, &napiMode);

    NativeValue* nativeUri = reinterpret_cast<NativeValue*>(napiUri);
    NativeValue* nativeMode = reinterpret_cast<NativeValue*>(napiMode);
    NativeValue* argv[] = {nativeUri, nativeMode};
    NativeValue* nativeResult = CallObjectMethod("openFile", argv, ARGC_TWO);
    if (nativeResult == nullptr) {
        LOG_ERROR("%{public}s call openFile with return null.", __func__);
        return ret;
    }

    ret = OHOS::AppExecFwk::UnwrapInt32FromJS(env, reinterpret_cast<napi_value>(nativeResult));
    LOG_INFO("end.");
    return ret;
}

int JsDataShareExtAbility::OpenRawFile(const Uri &uri, const std::string &mode)
{
    LOG_INFO("begin.");
    auto ret = DataShareExtAbility::OpenRawFile(uri, mode);
    HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());

    napi_value napiUri = nullptr;
    napi_create_string_utf8(env, uri.ToString().c_str(), NAPI_AUTO_LENGTH, &napiUri);
    napi_value napiMode = nullptr;
    napi_create_string_utf8(env, mode.c_str(), NAPI_AUTO_LENGTH, &napiMode);

    NativeValue* nativeUri = reinterpret_cast<NativeValue*>(napiUri);
    NativeValue* nativeMode = reinterpret_cast<NativeValue*>(napiMode);
    NativeValue* argv[] = {nativeUri, nativeMode};
    NativeValue* nativeResult = CallObjectMethod("openRawFile", argv, ARGC_TWO);
    if (nativeResult == nullptr) {
        LOG_ERROR("%{public}s call openRawFile with return null.", __func__);
        return ret;
    }

    ret = OHOS::AppExecFwk::UnwrapInt32FromJS(env, reinterpret_cast<napi_value>(nativeResult));
    LOG_INFO("end.");
    return ret;
}

int JsDataShareExtAbility::Insert(const Uri &uri, const DataShareValuesBucket &value)
{
    LOG_INFO("begin.");
    int ret = INVALID_VALUE;
    if (!CheckCallingPermission(abilityInfo_->writePermission)) {
        LOG_ERROR("%{public}s Check calling permission failed.", __func__);
        return ret;
    }

    ret = DataShareExtAbility::Insert(uri, value);
    HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());
    napi_value napiUri = nullptr;
    napi_create_string_utf8(env, uri.ToString().c_str(), NAPI_AUTO_LENGTH, &napiUri);
    napi_value napiValue = DataShareValueBucketNewInstance(env, const_cast<DataShareValuesBucket&>(value));
    if (napiValue == nullptr) {
        LOG_ERROR("%{public}s failed to make new instance of rdbValueBucket.", __func__);
        return ret;
    }

    NativeValue* nativeUri = reinterpret_cast<NativeValue*>(napiUri);
    NativeValue* nativeValue = reinterpret_cast<NativeValue*>(napiValue);
    NativeValue* argv[] = {nativeUri, nativeValue};
    NativeValue* nativeResult = CallObjectMethod("insert", argv, ARGC_TWO);
    if (nativeResult == nullptr) {
        LOG_ERROR("%{public}s call insert with return null.", __func__);
        return ret;
    }

    ret = OHOS::AppExecFwk::UnwrapInt32FromJS(env, reinterpret_cast<napi_value>(nativeResult));
    LOG_INFO("end.");
    return ret;
}

int JsDataShareExtAbility::Update(const Uri &uri, const DataShareValuesBucket &value,
    const DataSharePredicates &predicates)
{
    LOG_INFO("begin.");
    int ret = INVALID_VALUE;
    if (!CheckCallingPermission(abilityInfo_->writePermission)) {
        LOG_ERROR("%{public}s Check calling permission failed.", __func__);
        return ret;
    }

    ret = DataShareExtAbility::Update(uri, value, predicates);

    HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());
    napi_value napiUri = nullptr;
    napi_create_string_utf8(env, uri.ToString().c_str(), NAPI_AUTO_LENGTH, &napiUri);
    napi_value napiValue = DataShareValueBucketNewInstance(env, const_cast<DataShareValuesBucket&>(value));
    if (napiValue == nullptr) {
        LOG_ERROR("%{public}s failed to make new instance of rdbValueBucket.", __func__);
        return ret;
    }

    napi_value napiPredicates = MakePredicates(env, predicates);
    if (napiPredicates == nullptr) {
        LOG_ERROR("%{public}s failed to make new instance of dataAbilityPredicates.", __func__);
        return ret;
    }

    NativeValue* nativeUri = reinterpret_cast<NativeValue*>(napiUri);
    NativeValue* nativeValue = reinterpret_cast<NativeValue*>(napiValue);
    NativeValue* nativePredicates = reinterpret_cast<NativeValue*>(napiPredicates);
    NativeValue* argv[] = {nativeUri, nativeValue, nativePredicates};
    NativeValue* nativeResult = CallObjectMethod("update", argv, ARGC_THREE);
    if (nativeResult == nullptr) {
        LOG_ERROR("%{public}s call update with return null.", __func__);
        return ret;
    }

    ret = OHOS::AppExecFwk::UnwrapInt32FromJS(env, reinterpret_cast<napi_value>(nativeResult));
    LOG_INFO("end.");
    return ret;
}

int JsDataShareExtAbility::Delete(const Uri &uri, const DataSharePredicates &predicates)
{
    LOG_INFO("begin.");
    int ret = INVALID_VALUE;
    if (!CheckCallingPermission(abilityInfo_->writePermission)) {
        LOG_ERROR("%{public}s Check calling permission failed.", __func__);
        return ret;
    }

    ret = DataShareExtAbility::Delete(uri, predicates);
    HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());
    napi_value napiUri = nullptr;
    napi_create_string_utf8(env, uri.ToString().c_str(), NAPI_AUTO_LENGTH, &napiUri);

    napi_value napiPredicates = MakePredicates(env, predicates);
    if (napiPredicates == nullptr) {
        LOG_ERROR("%{public}s failed to make new instance of dataAbilityPredicates.", __func__);
        return ret;
    }

    NativeValue* nativeUri = reinterpret_cast<NativeValue*>(napiUri);
    NativeValue* nativePredicates = reinterpret_cast<NativeValue*>(napiPredicates);
    NativeValue* argv[] = {nativeUri, nativePredicates};
    NativeValue* nativeResult = CallObjectMethod("delete", argv, ARGC_TWO);
    if (nativeResult == nullptr) {
        LOG_ERROR("%{public}s call delete with return null.", __func__);
        return ret;
    }

    ret = OHOS::AppExecFwk::UnwrapInt32FromJS(env, reinterpret_cast<napi_value>(nativeResult));
    LOG_INFO("end.");
    return ret;
}

std::shared_ptr<DataShareResultSet> JsDataShareExtAbility::Query(const Uri &uri,
    std::vector<std::string> &columns, const DataSharePredicates &predicates)
{
    LOG_INFO("begin.");
    std::shared_ptr<DataShareResultSet> ret;
    if (!CheckCallingPermission(abilityInfo_->readPermission)) {
        LOG_ERROR("%{public}s Check calling permission failed.", __func__);
        return ret;
    }

    ret = DataShareExtAbility::Query(uri, columns, predicates);

    HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());
    napi_value napiUri = nullptr;
    napi_create_string_utf8(env, uri.ToString().c_str(), NAPI_AUTO_LENGTH, &napiUri);

    napi_value napiColumns = nullptr;
    napi_create_array(env, &napiColumns);
    bool isArray = false;
    if (napi_is_array(env, napiColumns, &isArray) != napi_ok || !isArray) {
        LOG_ERROR("JsDataShareExtAbility create array failed");
        return ret;
    }
    int32_t index = 0;
    for (const auto &column : columns) {
        napi_value result = nullptr;
        napi_create_string_utf8(env, column.c_str(), column.length(), &result);
        napi_set_element(env, napiColumns, index++, result);
    }

    napi_value napiPredicates = MakePredicates(env, predicates);
    if (napiPredicates == nullptr) {
        LOG_ERROR("%{public}s failed to make new instance of dataAbilityPredicates.", __func__);
        return ret;
    }

    NativeValue* nativeUri = reinterpret_cast<NativeValue*>(napiUri);
    NativeValue* nativeColumns = reinterpret_cast<NativeValue*>(napiColumns);
    NativeValue* nativePredicates = reinterpret_cast<NativeValue*>(napiPredicates);
    NativeValue* argv[] = {nativeUri, nativeColumns, nativePredicates};
    NativeValue* nativeResult = CallObjectMethod("query", argv, ARGC_THREE);
    if (nativeResult == nullptr) {
        LOG_ERROR("%{public}s call query with return null.", __func__);
        return ret;
    }

    auto nativeObject = GetResultSetProxyObject(env, reinterpret_cast<napi_value>(nativeResult));
    if (nativeObject == nullptr) {
        return ret;
    }

    ret.reset(nativeObject);
    LOG_INFO("end.");
    return ret;
}

std::string JsDataShareExtAbility::GetType(const Uri &uri)
{
    LOG_INFO("begin.");
    auto ret = DataShareExtAbility::GetType(uri);
    HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());

    napi_value napiUri = nullptr;
    napi_create_string_utf8(env, uri.ToString().c_str(), NAPI_AUTO_LENGTH,
        &napiUri);
    NativeValue* nativeUri = reinterpret_cast<NativeValue*>(napiUri);
    NativeValue* argv[] = {nativeUri};
    NativeValue* nativeResult = CallObjectMethod("getType", argv, ARGC_ONE);
    if (nativeResult == nullptr) {
        LOG_ERROR("%{public}s call getType with return null.", __func__);
        return ret;
    }

    ret = OHOS::AppExecFwk::UnwrapStringFromJS(env, reinterpret_cast<napi_value>(nativeResult));
    LOG_INFO("end.");
    return ret;
}

int JsDataShareExtAbility::BatchInsert(const Uri &uri, const std::vector<DataShareValuesBucket> &values)
{
    LOG_INFO("begin.");
    int ret = INVALID_VALUE;
    if (!CheckCallingPermission(abilityInfo_->writePermission)) {
        LOG_ERROR("%{public}s Check calling permission failed.", __func__);
        return ret;
    }

    ret = DataShareExtAbility::BatchInsert(uri, values);

    HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());
    napi_value napiUri = nullptr;
    napi_create_string_utf8(env, uri.ToString().c_str(), NAPI_AUTO_LENGTH, &napiUri);

    napi_value napiValues = nullptr;
    napi_create_array(env, &napiValues);
    bool isArray = false;
    if (napi_is_array(env, napiValues, &isArray) != napi_ok || !isArray) {
        LOG_ERROR("JsDataShareExtAbility create array failed");
        return ret;
    }
    int32_t index = 0;
    for (const auto &value : values) {
        napi_value result = DataShareValueBucketNewInstance(env, const_cast<DataShareValuesBucket&>(value));
        if (result == nullptr) {
            LOG_ERROR("%{public}s failed to make new instance of rdbValueBucket.", __func__);
            return ret;
        }
        napi_set_element(env, napiValues, index++, result);
    }

    NativeValue* nativeUri = reinterpret_cast<NativeValue*>(napiUri);
    NativeValue* nativeValues = reinterpret_cast<NativeValue*>(napiValues);
    NativeValue* argv[] = {nativeUri, nativeValues};
    NativeValue* nativeResult = CallObjectMethod("batchInsert", argv, ARGC_TWO);
    if (nativeResult == nullptr) {
        LOG_ERROR("%{public}s call batchInsert with return null.", __func__);
        return ret;
    }

    ret = OHOS::AppExecFwk::UnwrapInt32FromJS(env, reinterpret_cast<napi_value>(nativeResult));
    LOG_INFO("end.");
    return ret;
}

bool JsDataShareExtAbility::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    LOG_INFO("begin.");
    DataShareExtAbility::RegisterObserver(uri, dataObserver);
    auto obsMgrClient = DataObsMgrClient::GetInstance();
    if (obsMgrClient == nullptr) {
        LOG_ERROR("%{public}s obsMgrClient is nullptr", __func__);
        return false;
    }

    ErrCode ret = obsMgrClient->RegisterObserver(uri, dataObserver);
    if (ret != ERR_OK) {
        LOG_ERROR("%{public}s obsMgrClient->RegisterObserver error return %{public}d", __func__, ret);
        return false;
    }
    LOG_INFO("end.");
    return true;
}

bool JsDataShareExtAbility::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    LOG_INFO("begin.");
    DataShareExtAbility::UnregisterObserver(uri, dataObserver);
    auto obsMgrClient = DataObsMgrClient::GetInstance();
    if (obsMgrClient == nullptr) {
        LOG_ERROR("%{public}s obsMgrClient is nullptr", __func__);
        return false;
    }

    ErrCode ret = obsMgrClient->UnregisterObserver(uri, dataObserver);
    if (ret != ERR_OK) {
        LOG_ERROR("%{public}s obsMgrClient->UnregisterObserver error return %{public}d", __func__, ret);
        return false;
    }
    LOG_INFO("end.");
    return true;
}

bool JsDataShareExtAbility::NotifyChange(const Uri &uri)
{
    LOG_INFO("begin.");
    DataShareExtAbility::NotifyChange(uri);
    auto obsMgrClient = DataObsMgrClient::GetInstance();
    if (obsMgrClient == nullptr) {
        LOG_ERROR("%{public}s obsMgrClient is nullptr", __func__);
        return false;
    }

    ErrCode ret = obsMgrClient->NotifyChange(uri);
    if (ret != ERR_OK) {
        LOG_ERROR("%{public}s obsMgrClient->NotifyChange error return %{public}d", __func__, ret);
        return false;
    }
    LOG_INFO("end.");
    return true;
}

Uri JsDataShareExtAbility::NormalizeUri(const Uri &uri)
{
    LOG_INFO("begin.");
    auto ret = DataShareExtAbility::NormalizeUri(uri);
    HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());

    napi_value napiUri = nullptr;
    napi_create_string_utf8(env, uri.ToString().c_str(), NAPI_AUTO_LENGTH, &napiUri);
    NativeValue* nativeUri = reinterpret_cast<NativeValue*>(napiUri);
    NativeValue* argv[] = {nativeUri};
    NativeValue* nativeResult = CallObjectMethod("normalizeUri", argv, ARGC_ONE);
    if (nativeResult == nullptr) {
        LOG_ERROR("%{public}s call normalizeUri with return null.", __func__);
        return ret;
    }

    ret = Uri(OHOS::AppExecFwk::UnwrapStringFromJS(env, reinterpret_cast<napi_value>(nativeResult)));
    LOG_INFO("end.");
    return ret;
}

Uri JsDataShareExtAbility::DenormalizeUri(const Uri &uri)
{
    LOG_INFO("begin.");
    auto ret = DataShareExtAbility::DenormalizeUri(uri);
    HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());

    napi_value napiUri = nullptr;
    napi_create_string_utf8(env, uri.ToString().c_str(), NAPI_AUTO_LENGTH, &napiUri);
    NativeValue* nativeUri = reinterpret_cast<NativeValue*>(napiUri);
    NativeValue* argv[] = {nativeUri};
    NativeValue* nativeResult = CallObjectMethod("denormalizeUri", argv, ARGC_ONE);
    if (nativeResult == nullptr) {
        LOG_ERROR("%{public}s call denormalizeUri with return null.", __func__);
        return ret;
    }

    ret = Uri(OHOS::AppExecFwk::UnwrapStringFromJS(env, reinterpret_cast<napi_value>(nativeResult)));
    LOG_INFO("end.");
    return ret;
}

std::vector<std::shared_ptr<DataShareResult>> JsDataShareExtAbility::ExecuteBatch(
    const std::vector<std::shared_ptr<DataShareOperation>> &operations)
{
    LOG_INFO("begin.");
    auto ret = DataShareExtAbility::ExecuteBatch(operations);
    LOG_INFO("end.");
    return ret;
}

bool JsDataShareExtAbility::CheckCallingPermission(const std::string &permission)
{
    LOG_INFO("begin, permission:%{public}s", permission.c_str());
    if (!permission.empty() && AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(), permission)
        != AppExecFwk::Constants::PERMISSION_GRANTED) {
        LOG_ERROR("%{public}s permission not granted.", __func__);
        return false;
    }
    LOG_INFO("end.");
    return true;
}

napi_value JsDataShareExtAbility::MakePredicates(napi_env env, const DataSharePredicates &predicates)
{
    LOG_INFO("begin.");
    DataSharePredicates* predicatesPtr = new (std::nothrow) DataSharePredicates();
    if (predicatesPtr == nullptr) {
        LOG_ERROR("%{public}s No memory allocated for predicates", __func__);
        return nullptr;
    }
    *predicatesPtr = predicates;
    napi_value napiPredicates = GetNapiObject(env, predicatesPtr);
    if (napiPredicates == nullptr) {
        LOG_ERROR("%{public}s failed to make new instance of DataSharePredicates.", __func__);
        delete predicatesPtr;
    }
    LOG_INFO("end.");
    return napiPredicates;
}
} // namespace DataShare
} // namespace OHOS