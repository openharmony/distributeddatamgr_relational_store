/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define LOG_TAG "GdbJSUtil"
#include "napi_gdb_js_utils.h"

#include "gdb_utils.h"
#include "js_ability.h"
#include "securec.h"

namespace OHOS::AppDataMgrJsKit::JSUtils {
constexpr int MAX_PATH_LENGTH = 1024;

int32_t GetCurrentAbilityParam(napi_env env, napi_value jsValue, ContextParam &param)
{
    std::shared_ptr<Context> context = JSAbility::GetCurrentAbility(env, jsValue);
    if (context == nullptr) {
        return napi_invalid_arg;
    }
    param.baseDir = context->GetDatabaseDir();
    param.moduleName = context->GetModuleName();
    param.area = context->GetArea();
    param.bundleName = context->GetBundleName();
    param.isSystemApp = context->IsSystemAppCalled();
    return napi_ok;
}

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, ContextParam &param)
{
    if (jsValue == nullptr) {
        LOG_INFO("hasProp is false -> fa stage");
        param.isStageMode = false;
        return GetCurrentAbilityParam(env, jsValue, param);
    }

    int32_t status = GetNamedProperty(env, jsValue, "stageMode", param.isStageMode);
    ASSERT(status == napi_ok, "get stageMode param failed", napi_invalid_arg);
    if (!param.isStageMode) {
        LOG_WARN("isStageMode is false -> fa stage");
        return GetCurrentAbilityParam(env, jsValue, param);
    }
    LOG_DEBUG("stage mode branch");
    status = GetNamedProperty(env, jsValue, "databaseDir", param.baseDir);
    ASSERT(status == napi_ok, "get databaseDir failed.", napi_invalid_arg);
    status = GetNamedProperty(env, jsValue, "area", param.area, true);
    ASSERT(status == napi_ok, "get area failed.", napi_invalid_arg);

    napi_value hapInfo = nullptr;
    GetNamedProperty(env, jsValue, "currentHapModuleInfo", hapInfo);
    if (hapInfo != nullptr) {
        status = GetNamedProperty(env, hapInfo, "name", param.moduleName);
        ASSERT(status == napi_ok, "get currentHapModuleInfo.name failed.", napi_invalid_arg);
    }

    napi_value appInfo = nullptr;
    GetNamedProperty(env, jsValue, "applicationInfo", appInfo);
    if (appInfo != nullptr) {
        status = GetNamedProperty(env, appInfo, "name", param.bundleName);
        ASSERT(status == napi_ok, "get applicationInfo.name failed.", napi_invalid_arg);
        status = GetNamedProperty(env, appInfo, "systemApp", param.isSystemApp, true);
        ASSERT(status == napi_ok, "get applicationInfo.systemApp failed.", napi_invalid_arg);
        int32_t hapVersion = JSAbility::GetHapVersion(env, jsValue);
        JSUtils::SetHapVersion(hapVersion);
    }
    return napi_ok;
}

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, StoreConfig &config)
{
    std::string name;
    auto status = GetNamedProperty(env, jsValue, "name", name);
    ASSERT(OK == status, "get name failed.", napi_invalid_arg);
    config.SetName(name);

    int32_t securityLevel;
    status = GetNamedProperty(env, jsValue, "securityLevel", securityLevel);
    ASSERT(OK == status, "get securityLevel failed.", napi_invalid_arg);
    config.SetSecurityLevel(securityLevel);
    return napi_ok;
}

template<>
napi_value Convert2JSValue(napi_env env, const std::shared_ptr<Result> &result)
{
    std::vector<napi_property_descriptor> descriptors = {
        DECLARE_JS_PROPERTY(env, "records", result->GetAllData()),
    };

    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(
        napi_create_object_with_properties(env, &object, descriptors.size(), descriptors.data()), object);
    return object;
}

template<>
napi_value Convert2JSValue(napi_env env, const std::shared_ptr<Vertex> &vertex)
{
    std::vector<napi_property_descriptor> descriptors = {
        DECLARE_JS_PROPERTY(env, "vid", vertex->GetId()),
        DECLARE_JS_PROPERTY(env, "labels", vertex->GetLabels()),
        DECLARE_JS_PROPERTY(env, "properties", vertex->GetProperties()),
    };

    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(
        napi_create_object_with_properties(env, &object, descriptors.size(), descriptors.data()), object);
    return object;
}

template<>
napi_value Convert2JSValue(napi_env env, const std::shared_ptr<Edge> &edge)
{
    std::vector<napi_property_descriptor> descriptors = {
        DECLARE_JS_PROPERTY(env, "eid", edge->GetId()),
        DECLARE_JS_PROPERTY(env, "edgeType", edge->GetLabel()),
        DECLARE_JS_PROPERTY(env, "startVid", edge->GetSourceId()),
        DECLARE_JS_PROPERTY(env, "endVid", edge->GetTargetId()),
        DECLARE_JS_PROPERTY(env, "properties", edge->GetProperties()),
    };

    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(
        napi_create_object_with_properties(env, &object, descriptors.size(), descriptors.data()), object);
    return object;
}

template<>
napi_value Convert2JSValue(napi_env env, const std::shared_ptr<PathSegment> &pathSegment)
{
    std::vector<napi_property_descriptor> descriptors = {
        DECLARE_JS_PROPERTY(env, "start", pathSegment->GetSourceVertex()),
        DECLARE_JS_PROPERTY(env, "end", pathSegment->GetTargetVertex()),
        DECLARE_JS_PROPERTY(env, "edge", pathSegment->GetEdge()),
    };

    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(
        napi_create_object_with_properties(env, &object, descriptors.size(), descriptors.data()), object);
    return object;
}

template<>
napi_value Convert2JSValue(napi_env env, const std::shared_ptr<Path> &path)
{
    std::vector<napi_property_descriptor> descriptors = {
        DECLARE_JS_PROPERTY(env, "start", path->GetStart()),
        DECLARE_JS_PROPERTY(env, "end", path->GetEnd()),
        DECLARE_JS_PROPERTY(env, "length", path->GetPathLength()),
        DECLARE_JS_PROPERTY(env, "segments", path->GetSegments()),
    };

    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(
        napi_create_object_with_properties(env, &object, descriptors.size(), descriptors.data()), object);
    return object;
}

std::tuple<int32_t, std::shared_ptr<Error>> GetRealPath(StoreConfig &config, ContextParam &param)
{
    CHECK_RETURN_CORE(config.GetName().find(PATH_SPLIT) == std::string::npos, GDB_DO_NOTHING,
        std::make_tuple(ERR, std::make_shared<ParamError>("StoreConfig.name", "a database name without path.")));
    std::string databaseDir;
    databaseDir.append(param.baseDir).append("/gdb");
    auto errorCode = DistributedDataAip::GdbUtils::CreateDirectory(databaseDir);
    std::string realPath = databaseDir + "/" + config.GetName();
    CHECK_RETURN_CORE(errorCode == E_OK && realPath.length() <= MAX_PATH_LENGTH, GDB_DO_NOTHING,
        std::make_tuple(ERR, std::make_shared<ParamError>("database path", "a valid path.")));
    config.SetPath(databaseDir);
    return std::make_tuple(E_OK, nullptr);
}
}