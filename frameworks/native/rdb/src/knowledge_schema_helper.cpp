/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define LOG_TAG "KnowledgeSchemaHelper"
#include "knowledge_schema_helper.h"

#ifndef CROSS_PLATFORM
#include <dlfcn.h>
#endif
#include <fstream>
#include <sstream>
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_fault_hiview_reporter.h"
#include "sqlite_utils.h"
#include "task_executor.h"

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;

static constexpr int AIP_MODULE_ID = 13;
constexpr ErrCode AIP_ERR_OFFSET = ErrCodeOffset(SUBSYS_DISTRIBUTEDDATAMNG, AIP_MODULE_ID);
constexpr int32_t KNOWLEDGE_BASE_ERROR_CODE_OFFSET{ 20000 };
constexpr ErrCode KNOWLEDGE_BASE_FAIL = AIP_ERR_OFFSET + KNOWLEDGE_BASE_ERROR_CODE_OFFSET;
constexpr ErrCode KNOWLEDGE_SCHEMA_NOT_VALID = KNOWLEDGE_BASE_FAIL + 1;

KnowledgeSchemaHelper::~KnowledgeSchemaHelper()
{
    std::unique_lock<std::shared_mutex> writeLock(libMutex_);
    if (schemaManager_ != nullptr) {
        schemaManager_->StopTask(dbName_);
        delete schemaManager_;
        schemaManager_ = nullptr;
    }
#ifndef CROSS_PLATFORM
    if (dlHandle_ != nullptr) {
        dlclose(dlHandle_);
        dlHandle_ = nullptr;
    }
#endif
}

void KnowledgeSchemaHelper::Init(const RdbStoreConfig &config, const DistributedRdb::RdbKnowledgeSchema &schema)
{
    LoadKnowledgeLib();
    if (!IsLoadLib()) {
        LOG_WARN("skip init by miss lib");
        return;
    }
    std::unique_lock<std::shared_mutex> writeLock(libMutex_);
    if (schemaManager_ == nullptr) {
        LOG_WARN("skip init by miss manager");
        return;
    }
    schemaManager_->Init(config, schema);
    bundleName_ = config.GetBundleName();
    dbName_ = config.GetName();
    inited_ = true;
}

std::pair<int, DistributedRdb::RdbKnowledgeSchema> KnowledgeSchemaHelper::GetRdbKnowledgeSchema(
    const std::string &dbName)
{
    std::pair<int, DistributedRdb::RdbKnowledgeSchema> res;
    auto &[errCode, schema] = res;
    LoadKnowledgeLib();
    if (!IsLoadLib()) {
        LOG_WARN("skip get donate data by miss lib");
        errCode = E_ERROR;
        return res;
    }
    std::shared_lock<std::shared_mutex> readLock(libMutex_);
    if (schemaManager_ == nullptr) {
        LOG_WARN("skip get donate data by miss manager");
        errCode = E_ERROR;
        return res;
    }
    errCode = E_OK;
    auto kSchema = schemaManager_->GetRdbKnowledgeSchema(dbName);
    if (kSchema == nullptr) {
        LOG_WARN("unable to get knowledge schema.");
        RdbFaultHiViewReporter::ReportRAGFault("Parse knowledge schema failed", "ParseRdbKnowledgeSchema", bundleName_,
            KNOWLEDGE_BASE_FAIL, KNOWLEDGE_SCHEMA_NOT_VALID);
        errCode = E_ERROR;
        return res;
    }
    schema = *kSchema;
    return res;
}

void KnowledgeSchemaHelper::DonateKnowledgeData(const DistributedRdb::RdbChangedData &rdbChangedData)
{
    if (!inited_) {
        LOG_WARN("knowledge schema helper not init.");
        return;
    }
    LoadKnowledgeLib();
    if (!IsLoadLib()) {
        LOG_WARN("skip donate data by miss lib");
        return;
    }
    auto executor = TaskExecutor::GetInstance().GetExecutor();
    if (executor == nullptr) {
        LOG_WARN("skip donate data by miss pool");
        return;
    }
    std::shared_lock<std::shared_mutex> readLock(libMutex_);
    if (schemaManager_ == nullptr) {
        LOG_WARN("skip donate data by miss manager");
        return;
    }
    std::weak_ptr<KnowledgeSchemaHelper> helper = shared_from_this();
    executor->Execute([helper, rdbChangedData]() {
        auto realHelper = helper.lock();
        if (realHelper == nullptr) {
            LOG_WARN("knowledge helper is null");
            return;
        }
        realHelper->StartTask(rdbChangedData);
    });
}

void KnowledgeSchemaHelper::LoadKnowledgeLib()
{
#ifndef CROSS_PLATFORM
    std::unique_lock<std::shared_mutex> writeLock(libMutex_);
    if (dlHandle_ != nullptr) {
        return;
    }
    auto handle = dlopen("libaip_knowledge_process.z.so", RTLD_LAZY);
    if (handle != nullptr) {
        LoadKnowledgeSchemaManager(handle);
        dlHandle_ = handle;
    } else {
        LOG_WARN("unable to load lib, errno: %{public}d, %{public}s", errno, dlerror());
    }
#endif
}

void KnowledgeSchemaHelper::LoadKnowledgeSchemaManager(void *handle)
{
#ifndef CROSS_PLATFORM
    typedef DistributedRdb::IKnowledgeSchemaManager* (*CreateKnowledgeSchemaManager)();
    auto creator = (CreateKnowledgeSchemaManager)(dlsym(handle, "CreateKnowledgeSchemaManager"));
    if (creator == nullptr) {
        LOG_WARN("unable to load creator, errno: %{public}d, %{public}s", errno, dlerror());
        return;
    }
    schemaManager_ = creator();
    if (schemaManager_ != nullptr) {
        LOG_INFO("load creator success");
    } else {
        LOG_WARN("load creator failed with oom");
    }
#endif
}

bool KnowledgeSchemaHelper::IsLoadLib() const
{
#ifndef CROSS_PLATFORM
    std::shared_lock<std::shared_mutex> readLock(libMutex_);
    return dlHandle_ != nullptr;
#else
    return false;
#endif
}

void KnowledgeSchemaHelper::StartTask(const DistributedRdb::RdbChangedData &rdbChangedData)
{
    DistributedRdb::IKnowledgeSchemaManager *manager = nullptr;
    {
        std::shared_lock<std::shared_mutex> readLock(libMutex_);
        if (schemaManager_ == nullptr) {
            LOG_WARN("skip execute donate data by miss manager");
            return;
        }
        manager = schemaManager_;
    }
    manager->StartTask(dbName_, rdbChangedData);
}

void KnowledgeSchemaHelper::Close()
{
    std::unique_lock<std::shared_mutex> writeLock(libMutex_);
    if (schemaManager_ != nullptr) {
        schemaManager_->StopTask(dbName_);
    }
}
}