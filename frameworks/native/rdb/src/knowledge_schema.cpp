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

#include "knowledge_schema.h"

namespace OHOS::NativeRdb {
bool KnowledgeField::Marshal(json &node) const
{
    SetValue(node[GET_NAME(columnName)], columnName_);
    SetValue(node[GET_NAME(type)], type_);
    SetValue(node[GET_NAME(parser)], parser_);
    SetValue(node[GET_NAME(description)], description_);
    return true;
}

bool KnowledgeField::Unmarshal(const json &node)
{
    bool isUnmarshalSuccess = true;
    isUnmarshalSuccess = GetValue(node, GET_NAME(columnName), columnName_) && isUnmarshalSuccess;
    isUnmarshalSuccess = GetValue(node, GET_NAME(type), type_) && isUnmarshalSuccess;
    (void)GetValue(node, GET_NAME(parser), parser_);
    (void)GetValue(node, GET_NAME(description), description_);
    return isUnmarshalSuccess;
}

std::string KnowledgeField::GetColumnName() const
{
    return columnName_;
}

std::vector<std::string> KnowledgeField::GetType() const
{
    return type_;
}

std::string KnowledgeField::GetParser() const
{
    return parser_;
}

std::string KnowledgeField::GetDescription() const
{
    return description_;
}

bool KnowledgeTable::Marshal(json &node) const
{
    SetValue(node[GET_NAME(tableName)], tableName_);
    SetValue(node[GET_NAME(referenceFields)], referenceFields_);
    SetValue(node[GET_NAME(knowledgeFields)], knowledgeFields_);
    return true;
}

bool KnowledgeTable::Unmarshal(const json &node)
{
    bool isUnmarshalSuccess = true;
    isUnmarshalSuccess = GetValue(node, GET_NAME(tableName), tableName_) && isUnmarshalSuccess;
    isUnmarshalSuccess = GetValue(node, GET_NAME(referenceFields), referenceFields_) && isUnmarshalSuccess;
    isUnmarshalSuccess = GetValue(node, GET_NAME(knowledgeFields), knowledgeFields_) && isUnmarshalSuccess;
    return isUnmarshalSuccess;
}

std::string KnowledgeTable::GetTableName() const
{
    return tableName_;
}

std::vector<KnowledgeField> KnowledgeTable::GetKnowledgeFields() const
{
    return knowledgeFields_;
}

std::vector<std::string> KnowledgeTable::GetReferenceFields() const
{
    return referenceFields_;
}

bool KnowledgeSchema::Marshal(json &node) const
{
    SetValue(node[GET_NAME(version)], version_);
    SetValue(node[GET_NAME(dbName)], dbName_);
    SetValue(node[GET_NAME(tables)], tables_);
    return true;
}

bool KnowledgeSchema::Unmarshal(const json &node)
{
    bool isUnmarshalSuccess = true;
    isUnmarshalSuccess = GetValue(node, GET_NAME(version), version_) && isUnmarshalSuccess;
    isUnmarshalSuccess = GetValue(node, GET_NAME(dbName), dbName_) && isUnmarshalSuccess;
    isUnmarshalSuccess = GetValue(node, GET_NAME(tables), tables_) && isUnmarshalSuccess;
    return isUnmarshalSuccess;
}

int64_t KnowledgeSchema::GetVersion() const
{
    return version_;
}

std::string KnowledgeSchema::GetDBName() const
{
    return dbName_;
}

std::vector<KnowledgeTable> KnowledgeSchema::GetTables() const
{
    return tables_;
}

bool KnowledgeSource::Marshal(json &node) const
{
    SetValue(node[GET_NAME(knowledgeSource)], knowledgeSource_);
    return true;
}

bool KnowledgeSource::Unmarshal(const json &node)
{
    return GetValue(node, GET_NAME(knowledgeSource), knowledgeSource_);
}

std::vector<KnowledgeSchema> KnowledgeSource::GetKnowledgeSchema() const
{
    return knowledgeSource_;
}
}