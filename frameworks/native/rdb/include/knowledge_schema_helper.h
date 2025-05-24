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

#ifndef DISTRIBUTED_RDB_KNOWLEDGE_SCHEMA_HELPER_H
#define DISTRIBUTED_RDB_KNOWLEDGE_SCHEMA_HELPER_H

#include <memory>
#include <vector>
#include <shared_mutex>
#include <string>

#include "knowledge_schema.h"
#include "knowledge_types.h"
#include "rdb_types.h"

namespace OHOS::NativeRdb {
class KnowledgeSchemaHelper : public std::enable_shared_from_this<KnowledgeSchemaHelper> {
public:
    KnowledgeSchemaHelper() = default;
    ~KnowledgeSchemaHelper();

    void Init(const RdbStoreConfig &config, const DistributedRdb::RdbKnowledgeSchema &schema);
    std::pair<int, DistributedRdb::RdbKnowledgeSchema> GetRdbKnowledgeSchema(const std::string &dbName);
    void DonateKnowledgeData();
    void Close();
    bool ParseRdbKnowledgeSchema(const std::string &json, const std::string &dbName,
        DistributedRdb::RdbKnowledgeSchema &schema);
private:
    void LoadKnowledgeLib();
    void LoadKnowledgeSchemaManager(void *handle);
    bool IsLoadLib() const;
    void StartTask();
    bool CheckSchemaFieldParsers(const KnowledgeField &field);
    bool CheckSchemaField(const std::string &fieldStr);
    bool CheckSchemaDBName(const std::string &fieldStr);
    bool CheckKnowledgeFields(const std::vector<KnowledgeField> &fields);
    bool CheckKnowledgeSchema(const KnowledgeSchema &schema);
    bool ParseRdbKnowledgeSchemaInner(const std::string &json, const std::string &dbName,
        DistributedRdb::RdbKnowledgeSchema &schema);

    mutable std::shared_mutex libMutex_;
    DistributedRdb::IKnowledgeSchemaManager *schemaManager_ = nullptr;
    bool inited_ = false;
#ifndef CROSS_PLATFORM
    void *dlHandle_ = nullptr;
#endif
    std::string bundleName_ = "";
};
}
#endif // DISTRIBUTED_RDB_KNOWLEDGE_SCHEMA_HELPER_H
