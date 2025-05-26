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

#ifndef DISTRIBUTED_RDB_KNOWLEDGE_TYPES_H
#define DISTRIBUTED_RDB_KNOWLEDGE_TYPES_H

#include <string>
#include <vector>
#include <unordered_map>
#include "rdb_store_config.h"

namespace OHOS::DistributedRdb {
struct RdbKnowledgeParser {
    std::string type;
    std::string path;
};

struct RdbKnowledgeField {
    std::string columnName;
    std::vector<std::string> type;
    std::vector<RdbKnowledgeParser> parser;
    std::string description;
};

struct RdbKnowledgeTable {
    std::string tableName;
    std::vector<std::string> referenceFields;
    std::vector<RdbKnowledgeField> knowledgeFields;
    std::unordered_map<std::string, std::vector<std::string>> pipelineHandlers;
};

struct RdbKnowledgeSchema {
    int64_t version = 0;
    std::string dbName;
    std::vector<RdbKnowledgeTable> tables;
};

class API_EXPORT IKnowledgeSchemaManager {
public:
    API_EXPORT virtual ~IKnowledgeSchemaManager() = default;

    /**
     * @brief Init with database config and schema.
     */
    API_EXPORT virtual void Init(const NativeRdb::RdbStoreConfig &config,
        const DistributedRdb::RdbKnowledgeSchema &schema) = 0;

    /**
     * @brief Start build knowledge data task.
     */
    API_EXPORT virtual void StartTask() = 0;

    /**
     * @brief Stop build knowledge data task.
     */
    API_EXPORT virtual void StopTask() = 0;

    /**
     * @brief Get knowledge schema from manager.
     */
    API_EXPORT virtual std::vector<std::string> GetJsonSchema() = 0;
};
}
#endif // DISTRIBUTED_RDB_KNOWLEDGE_TYPES_H