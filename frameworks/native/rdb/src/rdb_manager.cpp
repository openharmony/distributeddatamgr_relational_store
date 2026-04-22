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

#define LOG_TAG "RdbManager"
#include "rdb_manager.h"

#include "logger.h"
#include "rdb_errno.h"

namespace OHOS::DistributedRdb {
using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;
std::mutex RdbManager::mutex_;
RdbManager* RdbManager::instance_ = nullptr;
bool RdbManager::registered_ = false;

RdbManager &RdbManager::GetInstance()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (instance_ == nullptr && !registered_) {
        static RdbManager defaultInstance;
        instance_ = &defaultInstance;
    }
    return *instance_;
}

bool RdbManager::RegisterInstance(RdbManager *instance)
{
    if (instance == nullptr) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (registered_) {
        return false;
    }
    instance_ = instance;
    registered_ = true;
    return true;
}

RdbManager::RdbManager()
{
    LOG_WARN("no instance, using default RdbManager");
}

std::pair<int32_t, std::shared_ptr<RdbService>> RdbManager::GetRdbService(const RdbSyncerParam &param)
{
    return { E_NOT_SUPPORT, nullptr };
}

std::string RdbManager::GetSelfBundleName()
{
    return "";
}

void RdbManager::OnRemoteDied()
{
}

} // namespace OHOS::DistributedRdb