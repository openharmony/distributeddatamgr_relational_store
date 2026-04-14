/*
* Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CLOUD_DATA_JS_CONFIG_H
#define CLOUD_DATA_JS_CONFIG_H

#include "cloud_manager.h"
#include "js_const_properties.h"
#include "js_uv_queue.h"
#include "napi_cloud_sync_info_observer.h"
#include "napi_queue.h"
#include <map>
#include <mutex>

namespace OHOS::CloudData {
using namespace OHOS::AppDataMgrJsKit;
class JsConfig {
public:
    JsConfig();
    ~JsConfig();
    static napi_value InitConfig(napi_env env, napi_value exports);
    static napi_value New(napi_env env, napi_callback_info info);

    enum {
        /* exported js ClearAction  is (CloudData::ClearAction-1) */
        CLEAR_CLOUD_INFO = 0,
        CLEAR_CLOUD_DATA_AND_INFO = 1,
        CLEAR_CLOUD_NONE = 2,
    };

    struct ExtraData {
        std::string eventId;
        std::string extraData;
    };

    static inline bool ValidSubscribeType(int32_t type)
    {
        return (CLEAR_CLOUD_INFO <= type) && (type <= CLEAR_CLOUD_NONE);
    }

    static inline bool VerifyExtraData(const ExtraData &data)
    {
        return (!data.eventId.empty()) && (!data.extraData.empty());
    }

    static napi_value EnableCloud(napi_env env, napi_callback_info info);
    static napi_value DisableCloud(napi_env env, napi_callback_info info);
    static napi_value ChangeAppCloudSwitch(napi_env env, napi_callback_info info);
    static napi_value Clean(napi_env env, napi_callback_info info);
    static napi_value NotifyDataChange(napi_env env, napi_callback_info info);
    static napi_value QueryStatistics(napi_env env, napi_callback_info info);
    static napi_value SetGlobalCloudStrategy(napi_env env, napi_callback_info info);
    static napi_value QueryLastSyncInfo(napi_env env, napi_callback_info info);
    static napi_value CloudSync(napi_env env, napi_callback_info info);
    static napi_value OnSyncInfoChanged(napi_env env, napi_callback_info info);
    static napi_value OffSyncInfoChanged(napi_env env, napi_callback_info info);
    static napi_value StopCloudSync(napi_env env, napi_callback_info info);

private:
    struct QueryLastSyncInfoContext : public ContextBase {
        std::string accountId;
        std::string bundleName;
        std::string storeId;
        std::vector<CloudData::BundleInfo> bundleInfos;
        bool isBatch = false;
        QueryLastResults results;
        BatchQueryLastResults batchResults;
    };
    static void ParseQueryParams(napi_env env, napi_callback_info info, std::shared_ptr<QueryLastSyncInfoContext> ctxt);
    struct CloudSyncContext : public ContextBase {
        std::string bundleName;
        std::string storeId;
        int32_t syncMode;
        bool downloadOnly = false;
        napi_ref asyncHolder = nullptr;
        std::shared_ptr<UvQueue> queue;
    };
    static void HandleCloudSyncArgs(napi_env env, napi_callback_info info,
        std::shared_ptr<CloudSyncContext> ctxt);
    static void ParseCloudSyncArgs(napi_env env, size_t argc, napi_value *argv,
        std::shared_ptr<CloudSyncContext> ctxt);
    static void ParseCloudSyncArgsWithConfig(napi_env env, size_t argc, napi_value *argv,
        std::shared_ptr<CloudSyncContext> ctxt);
    static uint32_t GetSeqNum();
    static bool ValidClearConfig(const std::map<std::string, CloudData::ClearConfig> &configs);
    static bool IsDbInfoValid(const std::map<std::string, CloudData::DBActionInfo> &dbInfos);
    static bool IsTablesValid(const std::map<std::string, int32_t> &tableInfo);
    static std::atomic<uint32_t> seqNum_;
    using UnsubscribeInfo = std::map<std::shared_ptr<NapiCloudSyncInfoObserver>, std::vector<CloudData::BundleInfo>>;

    static std::vector<CloudData::BundleInfo> CollectSubscribeInfos(
        const std::vector<CloudData::BundleInfo> &toSubscribe, napi_value callback);
    static UnsubscribeInfo CollectUnsubscribeInfos(
        const std::vector<CloudData::BundleInfo> &toUnsubscribe, napi_value callback, bool hasCallback);

    static std::mutex syncInfoObserversMutex_;
    static std::map<std::string, std::map<std::string, std::vector<std::shared_ptr<NapiCloudSyncInfoObserver>>>>
        syncInfoObservers_;
};

} // namespace OHOS::CloudData
#endif //CLOUD_DATA_JS_CONFIG_H