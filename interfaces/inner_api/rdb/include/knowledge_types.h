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

constexpr int DEFAULT_CHUNK_SIZE = 3072;
constexpr int DEFAULT_SEGMENT_SIZE = 300;
constexpr double DEFAULT_OVERLAP_RATIO = 0.1;
constexpr int DEFAULT_TEXT_EMBEDDING_MAX_CNT = 50;
constexpr int DEFAULT_IMAGE_EMBEDDING_MAX_CNT = 10;
constexpr int DEFAULT_PARSE_FILE_MAX_CNT = 10;

struct RdbKnowledgeParser {
    std::string type;
    std::string path;
};

struct RdbKnowledgeField {
    std::string columnName;
    std::vector<std::string> type;
    std::vector<RdbKnowledgeParser> parser;
    std::string description;
    bool createIndex = false;
};

struct RdbKnowledgeTable {
    std::string tableName;
    std::string tokenizer;
    std::vector<std::string> referenceFields;
    std::vector<RdbKnowledgeField> knowledgeFields;
    std::unordered_map<std::string, std::vector<std::string>> pipelineHandlers;
};

struct RdbKnowledgeProcess {
    struct {
        std::string modelVersion;
    } embeddingModelCfgs;
    struct {
        int chunkSize{DEFAULT_CHUNK_SIZE};
        int segmentSize{DEFAULT_SEGMENT_SIZE};
        double overlapRatio{DEFAULT_OVERLAP_RATIO};
    } chunkSplitter;
    struct {
        int textEmbeddingMaxCnt{DEFAULT_TEXT_EMBEDDING_MAX_CNT};
        int imageEmbeddingMaxCnt{DEFAULT_IMAGE_EMBEDDING_MAX_CNT};
        int parseFileMaxCnt{DEFAULT_PARSE_FILE_MAX_CNT};
    } perRecordLimit;
};

struct RdbKnowledgeSchema {
    int64_t version = 0;
    std::string dbName;
    std::vector<RdbKnowledgeTable> tables;
    RdbKnowledgeProcess knowledgeProcess;
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
    API_EXPORT virtual void StartTask(const std::string &dbName) = 0;

    /**
     * @brief Stop build knowledge data task.
     */
    API_EXPORT virtual void StopTask(const std::string &dbName) = 0;

    /**
     * @brief Get rdb knowledge schema.
     */
    API_EXPORT virtual std::shared_ptr<RdbKnowledgeSchema> GetRdbKnowledgeSchema(const std::string &dbName) = 0;
};
}
#endif // DISTRIBUTED_RDB_KNOWLEDGE_TYPES_H