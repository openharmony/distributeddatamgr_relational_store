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

#ifndef DATASHARE_COMMON_H
#define DATASHARE_COMMON_H
#include "ability.h"
#include "datashare_abs_shared_result_set.h"
#include "datashare_predicates.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_common.h"
#include "napi_common_util.h"
#include "want.h"
#include "datashare_values_bucket.h"
#include "datashare_result.h"
#include "datashare_operation.h"
#include "datashare_helper.h"

using Want = OHOS::AAFwk::Want;
using Ability = OHOS::AppExecFwk::Ability;
using AbilityStartSetting = OHOS::AppExecFwk::AbilityStartSetting;

namespace OHOS {
namespace DataShare {
using namespace AppExecFwk;
struct CallAbilityParam {
    Want want;
    int requestCode = 0;
    bool forResultOption = false;
    std::shared_ptr<AbilityStartSetting> setting = nullptr;
};

struct OnAbilityCallback {
    int requestCode = 0;
    int resultCode = 0;
    Want resultData;
    CallbackInfo cb;
};

struct ContinueAbilityOptionsInfo {
    bool reversible = false;
    std::string deviceId;
};

struct AsyncCallbackInfo {
    CallbackInfo cbInfo;
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    Ability *ability = nullptr;
    CallAbilityParam param;
    CallbackInfo aceCallback;
    bool native_result;
    AbilityType abilityType = AbilityType::UNKNOWN;
    int errCode = 0;
    ContinueAbilityOptionsInfo optionInfo;
};

struct CBBase {
    CallbackInfo cbInfo;
    napi_async_work asyncWork;
    napi_deferred deferred;
    Ability *ability = nullptr;
    AbilityType abilityType = AbilityType::UNKNOWN;
    int errCode = 0;
};

struct AppInfo_ {
    std::string name;
    std::string description;
    int32_t descriptionId = 0;
    bool systemApp = false;
    bool enabled = true;  // no data
    std::string label;
    std::string labelId;
    std::string icon;
    std::string iconId;
    std::string process;
    int32_t supportedModes = 0;
    std::vector<std::string> moduleSourceDirs;
    std::vector<std::string> permissions;
    std::vector<ModuleInfo> moduleInfos;
    std::string entryDir;
};

struct AppInfoCB {
    CBBase cbBase;
    AppInfo_ appInfo;
};

struct AppTypeCB {
    CBBase cbBase;
    std::string name;
};

struct AbilityInfo_ {
    std::string bundleName;
    std::string name;
    std::string label;
    std::string description;
    std::string icon;
    int32_t labelId;
    int32_t descriptionId;
    int32_t iconId;
    std::string moduleName;
    std::string process;
    std::string targetAbility;  // no data
    int32_t backgroundModes;    // no data
    bool isVisible = true;
    bool formEnabled = false;  // no data
    int32_t type = 0;
    int32_t subType = 0;  // no data
    int32_t orientation = 0;
    int32_t launchMode = 0;
    std::vector<std::string> permissions;
    std::vector<std::string> deviceTypes;
    std::vector<std::string> deviceCapabilities;
    std::string readPermission;   // no data
    std::string writePermission;  // no data
    AppInfo_ appInfo;
    int32_t formEntity;         // no data
    int32_t minFormHeight;      // no data
    int32_t defaultFormHeight;  // no data
    int32_t minFormWidth;       // no data
    int32_t defaultFormWidth;   // no data
    std::string uri;
};
struct AbilityInfoCB {
    CBBase cbBase;
    AbilityInfo_ abilityInfo;
};

struct AbilityNameCB {
    CBBase cbBase;
    std::string name;
};

struct ProcessInfoCB {
    CBBase cbBase;
    pid_t pid = 0;
    std::string processName;
};

struct ProcessNameCB {
    CBBase cbBase;
    std::string processName;
};

struct CallingBundleCB {
    CBBase cbBase;
    std::string callingBundleName;
};

struct GetOrCreateLocalDirCB {
    CBBase cbBase;
    std::string rootDir;
};

struct DatabaseDirCB {
    CBBase cbBase;
    std::string dataBaseDir;
};

struct PreferencesDirCB {
    CBBase cbBase;
    std::string preferencesDir;
};

struct ElementNameCB {
    CBBase cbBase;
    std::string deviceId;
    std::string bundleName;
    std::string abilityName;
    std::string uri;
    std::string shortName;
};

struct HapModuleInfo_ {
    std::string name;
    std::string description;
    int32_t descriptionId = 0;  // no data
    std::string icon;
    std::string label;
    int32_t labelId = 0;  // no data
    int32_t iconId = 0;   // no data
    std::string backgroundImg;
    int32_t supportedModes = 0;
    std::vector<std::string> reqCapabilities;
    std::vector<std::string> deviceTypes;
    std::vector<AbilityInfo_> abilityInfos;
    std::string moduleName;
    std::string mainAbilityName;  // no data
    bool installationFree;        // no data
};

struct HapModuleInfoCB {
    CBBase cbBase;
    HapModuleInfo_ hapModuleInfo;
};

struct DataShareHelperCB {
    CBBase cbBase;
    napi_ref uri = nullptr;
    napi_value result = nullptr;
};

struct DSHelperInsertCB {
    CBBase cbBase;
    DataShareHelper *dataShareHelper = nullptr;
    std::string uri;
    DataShareValuesBucket valueBucket;
    int result = 0;
    int execResult;
};

class NAPIAbilityConnection;
struct AbilityConnectionCB {
    napi_env env;
    napi_ref callback[3] = {0};  // onConnect/onDisconnect/onFailed
    int resultCode = 0;
    ElementName elementName;
    sptr<IRemoteObject> connection;
};
struct ConnectAbilityCB {
    CBBase cbBase;
    Want want;
    sptr<NAPIAbilityConnection> abilityConnection;
    AbilityConnectionCB abilityConnectionCB;
    int64_t id;
    bool result;
    int errCode = 0;
};

struct DSHelperNotifyChangeCB {
    CBBase cbBase;
    DataShareHelper *dataShareHelper = nullptr;
    std::string uri;
    int execResult;
};

class NAPIDataShareObserver;
struct DSHelperOnOffCB {
    CBBase cbBase;
    DataShareHelper *dataShareHelper = nullptr;
    sptr<NAPIDataShareObserver> observer;
    std::string uri;
    int result = 0;
    std::vector<DSHelperOnOffCB *> NotifyList;
    std::vector<DSHelperOnOffCB *> DestoryList;
};

struct ShowOnLockScreenCB {
    CBBase cbBase;
    bool isShow;
};

struct DSHelperGetTypeCB {
    CBBase cbBase;
    DataShareHelper *dataShareHelper = nullptr;
    std::string uri;
    std::string result = "";
    int execResult;
};

struct DSHelperGetFileTypesCB {
    CBBase cbBase;
    DataShareHelper *dataShareHelper = nullptr;
    std::string uri;
    std::string mimeTypeFilter;
    std::vector<std::string> result;
    int execResult;
};

struct DSHelperNormalizeUriCB {
    CBBase cbBase;
    DataShareHelper *dataShareHelper = nullptr;
    std::string uri;
    std::string result = "";
    int execResult;
};

struct DSHelperDenormalizeUriCB {
    CBBase cbBase;
    DataShareHelper *dataShareHelper = nullptr;
    std::string uri;
    std::string result = "";
    int execResult;
};

struct DSHelperDeleteCB {
    CBBase cbBase;
    DataShareHelper *dataShareHelper = nullptr;
    std::string uri;
    DataSharePredicates predicates;
    int result = 0;
    int execResult;
};

struct DSHelperQueryCB {
    CBBase cbBase;
    DataShareHelper *dataShareHelper = nullptr;
    std::string uri;
    std::vector<std::string> columns;
    DataSharePredicates predicates;
    std::shared_ptr<DataShareAbsSharedResultSet> result;
    int execResult;
};

struct DSHelperUpdateCB {
    CBBase cbBase;
    DataShareHelper *dataShareHelper = nullptr;
    std::string uri;
    DataShareValuesBucket valueBucket;
    DataSharePredicates predicates;
    int result = 0;
    int execResult;
};

struct DSHelperBatchInsertCB {
    CBBase cbBase;
    DataShareHelper *dataShareHelper = nullptr;
    std::string uri;
    std::vector<DataShareValuesBucket> values;
    int result = 0;
    int execResult;
};

struct DSHelperOpenFileCB {
    CBBase cbBase;
    DataShareHelper *dataShareHelper = nullptr;
    std::string uri;
    std::string mode;
    int result = 0;
    int execResult;
};

struct DSHelperReleaseCB {
    CBBase cbBase;
    DataShareHelper *dataShareHelper = nullptr;
    bool result = false;
};

struct DSHelperExecuteBatchCB {
    CBBase cbBase;
    std::string uri;
    std::vector<std::shared_ptr<DataShareOperation>> operations;
    DataShareHelper *dataShareHelper = nullptr;
    std::vector<std::shared_ptr<DataShareResult>> result;
};
}  // namespace DataShare
}  // namespace OHOS
#endif /* DATASHARE_COMMON_H */
