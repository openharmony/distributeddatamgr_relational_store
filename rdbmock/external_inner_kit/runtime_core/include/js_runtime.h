/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_JS_RUNTIME_H
#define OHOS_ABILITY_RUNTIME_JS_RUNTIME_H

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "native_engine/native_engine.h"
#include "runtime.h"

namespace panda::ecmascript {
class EcmaVM;
} // namespace panda::ecmascript
namespace panda {
struct HmsMap;
}
namespace OHOS {
namespace AppExecFwk {
class EventHandler;
} // namespace AppExecFwk

namespace AbilityBase {
class Extractor;
class FileMapper;
} // namespace AbilityBase

namespace JsEnv {
class JsEnvironment;
class SourceMapOperator;
struct ErrorObject;
struct UncaughtExceptionInfo;
using UncatchableTask = std::function<void(std::string summary, const JsEnv::ErrorObject errorObject, napi_env env,
    napi_value exception)>;
} // namespace JsEnv

using AppLibPathMap = std::map<std::string, std::vector<std::string>>;

#ifdef APP_USE_ARM
constexpr char ARK_DEBUGGER_LIB_PATH[] = "libark_inspector.z.so";
#elif defined(APP_USE_X86_64)
constexpr char ARK_DEBUGGER_LIB_PATH[] = "libark_inspector.z.so";
#else
constexpr char ARK_DEBUGGER_LIB_PATH[] = "libark_inspector.z.so";
#endif

namespace AbilityRuntime {
class TimerTask;

inline void *DetachCallbackFunc(napi_env env, void *value, void *)
{
    return value;
}

class JsRuntime : public Runtime {
public:
    using Runtime::PreloadModule;
    static std::unique_ptr<JsRuntime> Create(const Options& options);

    static void SetAppLibPath(const AppLibPathMap& appLibPaths, const bool& isSystemApp = false);
    static void SetOrUpdateLibPath(const AppLibPathMap& appLibPaths, const bool& isSystemApp = false);
    static void InheritPluginNamespace(const std::vector<std::string> &moduleNames);
    static void CreatePluginDefaultNamespace(const std::string &lddictorys);

    static bool ReadSourceMapData(const std::string& hapPath, const std::string& sourceMapPath, std::string& content);
    JsRuntime();
    ~JsRuntime() override;

    NativeEngine& GetNativeEngine() const;
    napi_env GetNapiEnv() const;

    Language GetLanguage() const override
    {
        return Language::JS;
    }

    void PostTask(const std::function<void()>& task, const std::string& name, int64_t delayTime);
    void PostSyncTask(const std::function<void()>& task, const std::string& name);
    void RemoveTask(const std::string& name);
    void DumpHeapSnapshot(bool isPrivate) override;
    void DumpCpuProfile() override;
    void DestroyHeapProfiler() override;
    void ForceFullGC() override;
    void ForceFullGC(uint32_t tid) override;
    void DumpHeapSnapshot(uint32_t tid, bool isFullGC, bool isBinary = false) override;
    void DumpHeapSnapshot(uint32_t tid, const OHOS::AbilityRuntime::Runtime::JsHeapDumpParam &param) override;
    void AllowCrossThreadExecution() override;
    void GetHeapPrepare() override;
    void NotifyApplicationState(bool isBackground) override;
    bool SuspendVM(uint32_t tid) override;
    void ResumeVM(uint32_t tid) override;

    bool RunSandboxScript(const std::string& path, const std::string& hapPath);
    bool RunScript(const std::string& path, const std::string& hapPath, bool useCommonChunk = false,
        const std::string& srcEntrance = "");

    void PreloadSystemModule(const std::string& moduleName) override;

    void PreloadMainAbility(const std::string& moduleName, const std::string& srcPath,
        const std::string& hapPath,  bool isEsMode, const std::string& srcEntrance) override;
    void PreloadModule(const std::string& moduleName, const std::string& srcPath,
        const std::string& hapPath, bool isEsMode, bool useCommonTrunk) override;
    bool PopPreloadObj(const std::string& key, std::unique_ptr<NativeReference>& obj);
    void StartDebugMode(const DebugOption debugOption) override;
    bool ShouldSkipDebugMode(const DebugOption debugOption);
    void SetDebugOption(const DebugOption debugOption) override;
    void StartLocalDebugMode(bool isDebugFromLocal) override;
    void DebuggerConnectionHandler(bool isDebugApp, bool isStartWithDebug);
    void StopDebugMode();
    bool LoadRepairPatch(const std::string& hqfFile, const std::string& hapPath) override;
    bool UnLoadRepairPatch(const std::string& hqfFile) override;
    bool NotifyHotReloadPage() override;
    void RegisterUncaughtExceptionHandler(const JsEnv::UncaughtExceptionInfo& uncaughtExceptionInfo,
        bool isStatic = false);
    void RegisterUncatchableExceptionHandler(const JsEnv::UncatchableTask& uncatchableTask, bool isStatic = false);
    bool LoadScript(const std::string& path, std::vector<uint8_t>* buffer = nullptr, bool isBundle = false);
    bool LoadScript(const std::string& path, uint8_t* buffer, size_t len, bool isBundle,
        const std::string& srcEntrance = "");
    bool StartDebugger(bool needBreakPoint, uint32_t instanceId);
    void StopDebugger();

    NativeEngine* GetNativeEnginePointer() const;
    panda::ecmascript::EcmaVM* GetEcmaVm() const;

    void UpdateModuleNameAndAssetPath(const std::string& moduleName);
    void RegisterQuickFixQueryFunc(const std::map<std::string, std::string>& moduleAndPath) override;
    static bool GetFileBuffer(const std::string& filePath, std::string& fileFullName, std::vector<uint8_t>& buffer,
                              bool isABC = true);
    static std::shared_ptr<AbilityBase::FileMapper> GetSafeData(const std::string& path, std::string& fileFullName);

    void InitSourceMap(const std::shared_ptr<JsEnv::SourceMapOperator> operatorImpl);
    void InitSourceMap(const std::string hqfFilePath);
    void FreeNativeReference(std::unique_ptr<NativeReference> reference);
    void FreeNativeReference(std::shared_ptr<NativeReference>&& reference);
    void StartProfiler(const DebugOption debugOption) override;
    void SetExtensionApiCheckCallback(
        std::function<bool(const std::string &className, const std::string &fileName)> &cb) override {}
    void DebuggerConnectionManager(bool isDebugApp, bool isStartWithDebug, const DebugOption dOption);

    void ReloadFormComponent(); // Reload ArkTS-Card component
    void SetModuleLoadChecker(const std::shared_ptr<ModuleCheckerDelegate> moduleCheckerDelegate) const override;

    static std::unique_ptr<NativeReference> LoadSystemModuleByEngine(napi_env env,
        const std::string& moduleName, const napi_value* argv, size_t argc);
    std::unique_ptr<NativeReference> LoadModule(const std::string& moduleName, const std::string& modulePath,
        const std::string& hapPath, bool esmodule = false, bool useCommonChunk = false,
        const std::string& srcEntrance = "");
    std::unique_ptr<NativeReference> LoadSystemModule(
        const std::string& moduleName, const napi_value* argv = nullptr, size_t argc = 0);

    std::unique_ptr<AbilityBase::FileMapper> ExecuteSecureWithOhmUrl(const std::string &moduleName,
        const std::string &hapPath, const std::string &srcEntrance);
    napi_value GetExportObjectFromOhmUrl(const std::string &srcEntrance, const std::string &key);

    void SetDeviceDisconnectCallback(const std::function<bool()> &cb) override;
    void SetStopPreloadSoCallback(const std::function<void()> &callback);
    void SetPkgContextInfoJson(std::string moduleName, std::string hapPath, std::string packageName);
    void UpdatePkgContextInfoJson(const std::string& moduleName, const std::string& hapPath,
        const std::string& packageName);
    bool Init(const Options& options);

    size_t GetHeapTotalSize();
    size_t GetHeapObjectSize();

private:
    void FinishPreload() override;
    bool Initialize(const Options& options);
    void Deinitialize();
    int32_t JsperfProfilerCommandParse(const std::string &command, int32_t defaultValue);

    napi_value LoadJsBundle(const std::string& path, const std::string& hapPath, bool useCommonChunk = false);
    napi_value LoadJsModule(const std::string& path, const std::string& hapPath, const std::string& srcEntrance = "");

    bool preloaded_ = false;
    bool isBundle_ = true;
    bool isOhmUrl_ = false;
    std::string codePath_;
    std::string moduleName_;
    std::unique_ptr<NativeReference> methodRequireNapiRef_;
    std::unordered_map<std::string, NativeReference*> modules_;
    std::shared_ptr<JsEnv::JsEnvironment> jsEnv_ = nullptr;
    uint32_t instanceId_ = 0;
    std::string bundleName_;
    int32_t apiTargetVersion_ = 0;
    std::map<std::string, std::string> pkgContextInfoJsonStringMap_;
    std::map<std::string, std::string> packageNameList_;
    std::map<std::string, std::unique_ptr<NativeReference>> preloadList_;

    static std::atomic<bool> hasInstance;
    DebugOption debugOption_;

private:
    bool CreateJsEnv(const Options& options);
    void PreloadAce(const Options& options);
    bool InitLoop(bool isStage = true);
    inline bool IsUseAbilityRuntime(const Options& options) const;
    void FreeNativeReference(std::unique_ptr<NativeReference> uniqueNativeRef,
        std::shared_ptr<NativeReference>&& sharedNativeRef);
    void InitConsoleModule();
    void InitTimerModule();
    void InitWorkerModule(const Options& options);
    void ReInitJsEnvImpl(const Options& options);
    void PostPreload(const Options& options);
    void LoadAotFile(const Options& options);
    void SetRequestAotCallback();

    std::string GetSystemKitPath();
    std::vector<panda::HmsMap> GetSystemKitsMap(uint32_t version);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_JS_RUNTIME_H
