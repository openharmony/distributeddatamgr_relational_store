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

#ifndef DISTRIBUTED_RDB_KNOWLEDGE_SCHEMA_H
#define DISTRIBUTED_RDB_KNOWLEDGE_SCHEMA_H

#include "serializable.h"

namespace OHOS::NativeRdb {
class KnowledgeField final : public Serializable {
public:
    KnowledgeField() = default;

    bool Marshal(json &node) const override;
    bool Unmarshal(const json &node) override;

    std::string GetColumnName() const;
    std::vector<std::string> GetType() const;
    std::string GetParser() const;
    std::string GetDescription() const;
private:
    std::string columnName_;
    std::vector<std::string> type_;
    std::string parser_;
    std::string description_;
};

class KnowledgeTable final : public Serializable {
public:
    KnowledgeTable() = default;

    bool Marshal(json &node) const override;
    bool Unmarshal(const json &node) override;

    std::string GetTableName() const;
    std::vector<std::string> GetUniqueFields() const;
    std::vector<KnowledgeField> GetKnowledgeFields() const;
private:
    std::string tableName_;
    std::vector<std::string> uniqueFields_;
    std::vector<KnowledgeField> knowledgeFields_;
};

class KnowledgeSchema final : public Serializable {
public:
    KnowledgeSchema() = default;

    bool Marshal(json &node) const override;
    bool Unmarshal(const json &node) override;

    int64_t GetVersion() const;
    std::string GetDBName() const;
    std::vector<KnowledgeTable> GetTables() const;
private:
    int64_t version_ = 0;
    std::string dbName_;
    std::vector<KnowledgeTable> tables_;
};

class KnowledgeSource final : public Serializable {
public:
    KnowledgeSource() = default;

    bool Marshal(json &node) const override;
    bool Unmarshal(const json &node) override;

    std::vector<KnowledgeSchema> GetKnowledgeSchema() const;
private:
    std::vector<KnowledgeSchema> knowledgeSource_;
};
}
#endif // DISTRIBUTED_RDB_KNOWLEDGE_SCHEMA_H
