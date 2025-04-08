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
#define LOG_TAG "KnowledgeSchemaUtils"
#include "knowledge_schema_helper.h"

#ifndef CROSS_PLATFORM
#include <dlfcn.h>
#endif
#include <fstream>
#include <sstream>
#include "knowledge_schema.h"
#include "logger.h"
#include "rdb_errno.h"
#include "task_executor.h"

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
KnowledgeSchemaHelper::~KnowledgeSchemaHelper()
{
    std::unique_lock<std::shared_mutex> writeLock(libMutex_);
    if (schemaManager_ != nullptr) {
        delete schemaManager_;
        schemaManager_ = nullptr;
    }
#ifndef CROSS_PLATFORM
    if (dlHandle_ != nullptr) {
        dlclose(dlHandle_);
        dlHandle_ = nullptr;
    }
#endif
    isLoadKnowledgeLib_ = false;
}

void KnowledgeSchemaHelper::Init(const RdbStoreConfig &config, const DistributedRdb::RdbKnowledgeSchema &schema)
{
    LoadKnowledgeLib();
    if (!IsLoadLib()) {
        LOG_WARN("skip init by miss lib");
        return;
    }
    std::shared_lock<std::shared_mutex> readLock(libMutex_);
    if (schemaManager_ == nullptr) {
        LOG_WARN("skip init by miss manager");
        return;
    }
    schemaManager_->Init(config, schema);
}

std::vector<KnowledgeSchemaHelper::Json> KnowledgeSchemaHelper::ParseSchema(const std::vector<std::string> &schemaStr)
{
    std::vector<Json> schema;
    for (const auto &item : schemaStr) {
        auto config = Serializable::ToJson(item);
        if (config.is_null() || config.empty()) {
            continue;
        }
        schema.push_back(std::move(config));
    }
    return schema;
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
    auto jsons = KnowledgeSchemaHelper::ParseSchema(schemaManager_->GetJsonSchema());
    for (const auto &json : jsons) {
        schema = ParseRdbKnowledgeSchema(json, dbName);
        if (!schema.dbName.empty()) {
            return res;
        }
    }
    LOG_WARN("not found db schema in source schema.");
    return res;
}

void KnowledgeSchemaHelper::DonateKnowledgeData()
{
    LoadKnowledgeLib();
    if (!IsLoadLib()) {
        LOG_WARN("skip donate data by miss lib");
        return;
    }
    std::shared_lock<std::shared_mutex> readLock(libMutex_);
    if (schemaManager_ == nullptr) {
        LOG_WARN("skip donate data by miss manager");
        return;
    }
    auto executor = TaskExecutor::GetInstance().GetExecutor();
    if (executor == nullptr) {
        LOG_WARN("skip donate data by miss pool");
        return;
    }
    auto helper = shared_from_this();
    executor->Execute([this, helper]() {
        IKnowledgeSchemaManager *manager = nullptr;
        {
            std::shared_lock<std::shared_mutex> readLock(libMutex_);
            if (schemaManager_ == nullptr) {
                LOG_WARN("skip execute donate data by miss manager");
                return;
            }
            manager = schemaManager_;
        }
        manager->StartTask();
    });
}

void KnowledgeSchemaHelper::LoadKnowledgeLib()
{
#ifndef CROSS_PLATFORM
    std::unique_lock<std::shared_mutex> writeLock(libMutex_);
    if (isLoadKnowledgeLib_) {
        return;
    }
    auto handle = dlopen("libaip_knowledge_process.z.so", RTLD_LAZY);
    if (handle != nullptr) {
        isLoadKnowledgeLib_ = true;
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
    typedef IKnowledgeSchemaManager* (*CreateKnowledgeSchemaManager)();
    auto creator = (CreateKnowledgeSchemaManager)(dlsym(handle, "CreateKnowledgeSchemaManager"));
    if (creator == nullptr) {
        LOG_WARN("unable to load creator, errno: %{public}d, %{public}s", errno, dlerror());
        return;
    }
    schemaManager_ = creator();
    LOG_INFO("load creator success");
#endif
}

DistributedRdb::RdbKnowledgeSchema KnowledgeSchemaHelper::ParseRdbKnowledgeSchema(const Json &json,
    const std::string &dbName)
{
    KnowledgeSource source;
    if (!Serializable::GetValue(json, "", source)) {
        LOG_WARN("parse knowledge schema failed.");
        return {};
    }
    auto sourceSchema = source.GetKnowledgeSchema();
    auto find = std::find_if(sourceSchema.begin(), sourceSchema.end(), [&dbName](const KnowledgeSchema &item) {
        return item.GetDBName() == dbName;
    });
    if (find == sourceSchema.end()) {
        return {};
    }
    DistributedRdb::RdbKnowledgeSchema schema;
    KnowledgeSchema knowledgeSchema = *find;
    schema.dbName = knowledgeSchema.GetDBName();
    auto tables = knowledgeSchema.GetTables();
    for (const auto &table : tables) {
        DistributedRdb::RdbKnowledgeTable knowledgeTable;
        knowledgeTable.tableName = table.GetTableName();
        auto fields = table.GetKnowledgeFields();
        for (const auto &item : fields) {
            DistributedRdb::RdbKnowledgeField field;
            field.columnName = item.GetColumnName();
            field.type = item.GetType();
            field.description = item.GetDescription();
            field.parser = item.GetParser();
            knowledgeTable.knowledgeFields.push_back(std::move(field));
        }
        knowledgeTable.referenceFields = table.GetReferenceFields();
        schema.tables.push_back(knowledgeTable);
    }
    return schema;
}

bool KnowledgeSchemaHelper::IsLoadLib() const
{
    std::shared_lock<std::shared_mutex> readLock(libMutex_);
    return isLoadKnowledgeLib_;
}
}