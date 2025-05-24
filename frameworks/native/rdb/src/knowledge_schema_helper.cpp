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
#include <regex>
#include "logger.h"
#include "nlohmann/json.hpp"
#include "rdb_errno.h"
#include "rdb_fault_hiview_reporter.h"
#include "sqlite_utils.h"
#include "task_executor.h"

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
using Json = nlohmann::json;

constexpr uint16_t SCHEMA_FIELD_MIN_LEN = 1;
constexpr uint16_t SCHEMA_FIELD_MAX_LEN = 255;
constexpr uint16_t SCHEMA_DB_NAME_MAX_LEN = 120;
constexpr uint16_t SCHEMA_TYPE_MAX_LEN = 64;
constexpr int64_t SCHEMA_VERSION_MAX = 0x7fffffff;

constexpr char const *TYPE_TEXT = "Text";
constexpr char const *TYPE_SCALAR = "Scalar";
constexpr char const *TYPE_JSON = "Json";
constexpr char const *TYPE_FILE = "File";
const std::regex SCHEMA_FIELD_PATTERN("^[0-9a-zA-Z_]{1,}$");
const std::regex SCHEMA_DB_NAME_PATTERN("^[0-9a-zA-Z_\\.]{1,}$");

static constexpr int AIP_MODULE_ID = 13;
constexpr ErrCode AIP_ERR_OFFSET = ErrCodeOffset(SUBSYS_DISTRIBUTEDDATAMNG, AIP_MODULE_ID);
constexpr int32_t KNOWLEDGE_BASE_ERROR_CODE_OFFSET{ 20000 };
constexpr ErrCode KNOWLEDGE_BASE_FAIL = AIP_ERR_OFFSET + KNOWLEDGE_BASE_ERROR_CODE_OFFSET;
constexpr ErrCode KNOWLEDGE_SCHEMA_NOT_VALID = KNOWLEDGE_BASE_FAIL + 1;

bool KnowledgeSchemaHelper::CheckSchemaField(const std::string &fieldStr)
{
    return fieldStr.size() >= SCHEMA_FIELD_MIN_LEN && fieldStr.size() <= SCHEMA_FIELD_MAX_LEN &&
        std::regex_match(fieldStr, SCHEMA_FIELD_PATTERN);
}

bool KnowledgeSchemaHelper::CheckSchemaDBName(const std::string &fieldStr)
{
    return fieldStr.size() >= SCHEMA_FIELD_MIN_LEN && fieldStr.size() <= SCHEMA_DB_NAME_MAX_LEN &&
        std::regex_match(fieldStr, SCHEMA_DB_NAME_PATTERN);
}

bool KnowledgeSchemaHelper::CheckSchemaFieldParsers(const KnowledgeField &field)
{
    const auto &parsers = field.GetParser();
    const auto &fields = field.GetType();
    auto find = std::find(fields.begin(), fields.end(), std::string(TYPE_JSON));
    if (find != fields.end() && parsers.empty()) {
        LOG_ERROR("No parser for json field.");
        return false;
    }

    for (const KnowledgeParser &parser : parsers) {
        const std::string &type = parser.GetType();
        if (type != std::string(TYPE_FILE)) {
            LOG_ERROR("Wrong field parser type: %{public}s", SqliteUtils::Anonymous(type).c_str());
            return false;
        }
        if (parser.GetPath().empty()) {
            LOG_ERROR("No parser path.");
            return false;
        }
        if (parser.GetPath().length() > SCHEMA_FIELD_MAX_LEN) {
            LOG_ERROR("Wrong field parser path length: %{public}zu", parser.GetPath().length());
            return false;
        }
    }
    return true;
}

bool KnowledgeSchemaHelper::CheckKnowledgeFields(const std::vector<KnowledgeField> &fields)
{
    for (const KnowledgeField &field : fields) {
        if (!CheckSchemaField(field.GetColumnName())) {
            LOG_ERROR("Wrong column name: %{public}s", SqliteUtils::Anonymous(field.GetColumnName()).c_str());
            return false;
        }
        std::vector<std::string> fieldType = field.GetType();
        if (fieldType.size() != 1 || fieldType.front().size() < SCHEMA_FIELD_MIN_LEN ||
            fieldType.front().size() > SCHEMA_TYPE_MAX_LEN) {
            LOG_ERROR("Wrong column type, size: %{public}zu", fieldType.size());
            return false;
        }
        for (auto &type : fieldType) {
            if (type != std::string(TYPE_TEXT) && type != std::string(TYPE_SCALAR) &&
                type != std::string(TYPE_JSON) && type != std::string(TYPE_FILE)) {
                LOG_ERROR("Wrong field type: %{public}s", SqliteUtils::Anonymous(type).c_str());
                return false;
            }
        }
        if (!CheckSchemaFieldParsers(field)) {
            return false;
        }
        std::string description = field.GetDescription();
        if (fieldType.front() == std::string(TYPE_SCALAR) && (description.size() < SCHEMA_FIELD_MIN_LEN ||
            description.size() > SCHEMA_FIELD_MAX_LEN)) {
            LOG_ERROR("Wrong description: %{public}s", SqliteUtils::Anonymous(description).c_str());
            return false;
        }
    }
    return true;
}

bool KnowledgeSchemaHelper::CheckKnowledgeSchema(const KnowledgeSchema &schema)
{
    if (schema.GetVersion() < 1 || schema.GetVersion() > SCHEMA_VERSION_MAX) {
        LOG_ERROR("Wrong schema version: %{public}" PRId64, schema.GetVersion());
        return false;
    }
    if (!schema.IsDefaultName() && !CheckSchemaDBName(schema.GetDBName())) {
        LOG_ERROR("Wrong schema db name: %{public}s", SqliteUtils::Anonymous(schema.GetDBName()).c_str());
        return false;
    }
    for (const KnowledgeTable &table : schema.GetTables()) {
        if (!CheckSchemaField(table.GetTableName())) {
            LOG_ERROR("Wrong table name: %{public}s", SqliteUtils::Anonymous(table.GetTableName()).c_str());
            return false;
        }
        if (table.GetReferenceFields().size() != 1 || !CheckSchemaField(table.GetReferenceFields().front())) {
            LOG_ERROR("Wrong reference field, size: %{public}zu", table.GetReferenceFields().size());
            return false;
        }
        if (!CheckKnowledgeFields(table.GetKnowledgeFields())) {
            LOG_ERROR("Wrong knowledge field");
            return false;
        }
    }
    return true;
}

bool IsContainsColumnName(const std::vector<DistributedRdb::RdbKnowledgeField> &KnowledgeFields,
    const std::string &colName)
{
    for (const auto &field : KnowledgeFields) {
        if (field.columnName == colName) {
            return true;
        }
    }
    return false;
}

bool KnowledgeSchemaHelper::ParseRdbKnowledgeSchemaInner(const std::string &json, const std::string &dbName,
    DistributedRdb::RdbKnowledgeSchema &schema)
{
    KnowledgeSource source;
    if (!Serializable::Unmarshall(json, source)) {
        LOG_WARN("Parse knowledge schema failed.");
        return false;
    }
    auto sourceSchema = source.GetKnowledgeSchema();
    auto find = std::find_if(sourceSchema.begin(), sourceSchema.end(), [&dbName](const KnowledgeSchema &item) {
        return item.IsDefaultName() || item.GetDBName() == dbName;
    });
    if (find == sourceSchema.end()) {
        LOG_WARN("Not found same db:%{public}s schema.", SqliteUtils::Anonymous(dbName).c_str());
        return false;
    }
    KnowledgeSchema knowledgeSchema = *find;
    if (!CheckKnowledgeSchema(knowledgeSchema)) {
        LOG_WARN("Check knowledge schema failed.");
        return false;
    }
    schema.dbName = knowledgeSchema.IsDefaultName() ? dbName : knowledgeSchema.GetDBName();
    auto tables = knowledgeSchema.GetTables();
    for (const auto &table : tables) {
        DistributedRdb::RdbKnowledgeTable knowledgeTable;
        knowledgeTable.tableName = table.GetTableName();
        auto fields = table.GetKnowledgeFields();
        for (const auto &item : fields) {
            auto colName = item.GetColumnName();
            if (IsContainsColumnName(knowledgeTable.knowledgeFields, colName)) {
                LOG_ERROR("Duplicate field column name:%{public}s.", SqliteUtils::Anonymous(colName).c_str());
                return false;
            }
            DistributedRdb::RdbKnowledgeField field;
            field.columnName = item.GetColumnName();
            field.type = item.GetType();
            field.description = item.GetDescription();
            for (const auto &parser : item.GetParser()) {
                field.parser.push_back({parser.GetType(), parser.GetPath()});
            }
            knowledgeTable.knowledgeFields.push_back(std::move(field));
        }
        knowledgeTable.referenceFields = table.GetReferenceFields();
        schema.tables.push_back(std::move(knowledgeTable));
    }
    return true;
}

bool KnowledgeSchemaHelper::ParseRdbKnowledgeSchema(const std::string &json, const std::string &dbName,
    DistributedRdb::RdbKnowledgeSchema &schema)
{
    bool isValid = ParseRdbKnowledgeSchemaInner(json, dbName, schema);
    if (!isValid) {
        LOG_WARN("Parse knowledge schema inner failed.");   // stay as warning as inside
        RdbFaultHiViewReporter::ReportRAGFault("Parse knowledge schema failed", "ParseRdbKnowledgeSchema", bundleName_,
            KNOWLEDGE_BASE_FAIL, KNOWLEDGE_SCHEMA_NOT_VALID);
    }
    return isValid;
}

KnowledgeSchemaHelper::~KnowledgeSchemaHelper()
{
    std::unique_lock<std::shared_mutex> writeLock(libMutex_);
    if (schemaManager_ != nullptr) {
        schemaManager_->StopTask();
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
    auto jsons = schemaManager_->GetJsonSchema();
    for (const auto &json : jsons) {
        if (!ParseRdbKnowledgeSchema(json, dbName, schema)) {
            errCode = E_ERROR;
            return res;
        }
    }
    LOG_WARN("not found db schema in source schema.");
    return res;
}

void KnowledgeSchemaHelper::DonateKnowledgeData()
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
    auto helper = shared_from_this();
    executor->Execute([helper]() {
        helper->StartTask();
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

void KnowledgeSchemaHelper::StartTask()
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
    manager->StartTask();
}

void KnowledgeSchemaHelper::Close()
{
    std::unique_lock<std::shared_mutex> writeLock(libMutex_);
    if (schemaManager_ != nullptr) {
        schemaManager_->StopTask();
    }
}
}