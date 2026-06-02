/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "js_extension_context.h"
#include "extra_params.h"
namespace OHOS::AbilityRuntime {
HandleScope::HandleScope(JsRuntime& jsRuntime) {}
HandleScope::~HandleScope() {}
HandleEscape::HandleEscape(JsRuntime& jsRuntime) {}
HandleEscape::~HandleEscape() {}
napi_value HandleEscape::Escape(napi_value value)
{
    return nullptr;
}
std::unique_ptr<NativeReference> JsRuntime::LoadModule(const std::string &moduleName, const std::string &modulePath,
    const std::string &hapPath, bool esmodule, bool useCommonChunk)
{
    return std::unique_ptr<NativeReference>();
}
std::unique_ptr<NativeReference> JsRuntime::LoadSystemModule(
    const std::string& moduleName, const napi_value* argv, size_t argc)
{
    return nullptr;
}
NativeEngine& JsRuntime::GetNativeEngine() const
{
    NativeEngine *engine;
    return *engine;
}
void JsRuntime::PostTask(const std::function<void()> &task, const std::string &name, int64_t delayTime) {}
void JsRuntime::RemoveTask(const std::string &name) {}
void JsRuntime::DumpHeapSnapshot(bool isPrivate) {}
void JsRuntime::NotifyApplicationState(bool isBackground) {}
//bool JsRuntime::RunSandboxScript(const std::string &path) { return false; }
bool JsRuntime::Initialize(const Runtime::Options &options) { return false; }
void JsRuntime::Deinitialize() {}
void JsRuntime::FreeNativeReference(std::unique_ptr<NativeReference> reference) {}
void JsRuntime::StartDebugMode(bool needBreakPoint) {}
void JsRuntime::PreloadSystemModule(const std::string &moduleName) {}
void JsRuntime::FinishPreload() {}
bool JsRuntime::LoadRepairPatch(const std::string &patchFile, const std::string &baseFile)
{
    return false;
}
bool JsRuntime::NotifyHotReloadPage()
{
    return false;
}
bool JsRuntime::UnLoadRepairPatch(const std::string &patchFile)
{
    return false;
}
void JsRuntime::RegisterQuickFixQueryFunc(const std::map<std::string, std::string>& moduleAndPath) {}
napi_env JsRuntime::GetNapiEnv() const
{
    return nullptr;
}

napi_value CreateJsExtensionContext(napi_env env, const std::shared_ptr<ExtensionContext>& context,
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo) { return nullptr; }
}
