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

#define LOG_TAG "RdbSqlUtils"
#include "rdb_sql_utils.h"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <regex>

#include "acl.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_fault_hiview_reporter.h"
#include "rdb_platform.h"
#include "sqlite_sql_builder.h"
#include "sqlite_utils.h"

namespace OHOS {
using namespace Rdb;
namespace NativeRdb {
using namespace OHOS::DATABASE_UTILS;
const int32_t FIELDS_LIMIT = 4;
int RdbSqlUtils::CreateDirectory(const std::string &databaseDir)
{
    std::string tempDirectory = databaseDir;
    std::vector<std::string> directories;

    size_t pos = tempDirectory.find('/');
    while (pos != std::string::npos) {
        std::string directory = tempDirectory.substr(0, pos);
        directories.push_back(directory);
        tempDirectory = tempDirectory.substr(pos + 1);
        pos = tempDirectory.find('/');
    }
    directories.push_back(tempDirectory);

    std::string databaseDirectory;
    for (const std::string &directory : directories) {
        databaseDirectory = databaseDirectory + "/" + directory;
        if (MkDir(databaseDirectory)) {
            if (errno == EEXIST) {
                continue;
            }
            LOG_ERROR("failed to mkdir errno[%{public}d] %{public}s, parent dir modes: %{public}s", errno,
                SqliteUtils::Anonymous(databaseDirectory).c_str(),
                SqliteUtils::GetParentModes(databaseDirectory).c_str());
            RdbFaultHiViewReporter::ReportFault(RdbFaultEvent(FT_EX_FILE, E_CREATE_FOLDER_FAIL, BUNDLE_NAME_COMMON,
                "failed to mkdir errno[ " + std::to_string(errno) + "]," + databaseDirectory +
                "parent dir modes:" + SqliteUtils::GetParentModes(databaseDirectory)));
            return E_CREATE_FOLDER_FAIL;
        }
        // Set the default ACL attribute to the database root directory to ensure that files created by the server
        // also have permission to operate on the client side.
        Acl aclDefault(databaseDirectory, Acl::ACL_XATTR_DEFAULT);
        aclDefault.SetDefaultGroup(GetUid(), Acl::R_RIGHT | Acl::W_RIGHT);
    }
    return E_OK;
}

std::pair<std::string, int> RdbSqlUtils::GetCustomDatabasePath(
    const std::string &rootDir, const std::string &name, const std::string &customDir)
{
    std::string databasePath;
    databasePath.append(rootDir).append("/").append(customDir).append("/").append(name);

    struct stat fileStat;
    if (stat(databasePath.c_str(), &fileStat) != 0) {
        LOG_ERROR("File state error. path: %{public}s, errno: %{public}d",
            SqliteUtils::Anonymous(databasePath).c_str(), errno);
        return std::make_pair("", E_INVALID_FILE_PATH);
    }
    return std::make_pair(databasePath, E_OK);
}

/**
 * @brief get custom data base path.
 */
std::pair<std::string, int> RdbSqlUtils::GetDefaultDatabasePath(
    const std::string &baseDir, const std::string &name, const std::string &customDir)
{
    int errorCode = E_OK;
    if (customDir.empty()) {
        return std::make_pair(GetDefaultDatabasePath(baseDir, name, errorCode), errorCode);
    }

    std::string databaseDir;
    databaseDir.append(baseDir).append("/rdb/").append(customDir);

    errorCode = CreateDirectory(databaseDir);
    if (errorCode != E_OK) {
        LOG_ERROR("failed errno[%{public}d] baseDir : %{public}s name : %{public}s customDir : %{public}s", errno,
            SqliteUtils::Anonymous(baseDir).c_str(), SqliteUtils::Anonymous(name).c_str(),
            SqliteUtils::Anonymous(customDir).c_str());
    }
    return std::make_pair(databaseDir.append("/").append(name), errorCode);
}

/**
 * Get and Check default path.
 */
std::string RdbSqlUtils::GetDefaultDatabasePath(const std::string &baseDir, const std::string &name, int &errorCode)
{
    std::string databaseDir = baseDir + "/rdb";
    errorCode = CreateDirectory(databaseDir);
    if (errorCode != E_OK) {
        LOG_ERROR("failed errno[%{public}d] baseDir : %{public}s name : %{public}s", errno,
            SqliteUtils::Anonymous(baseDir).c_str(), SqliteUtils::Anonymous(name).c_str());
    }
    return databaseDir.append("/").append(name);
}

std::string RdbSqlUtils::GetDataBaseDirFromRealPath(
    const std::string &path, bool persist, const std::string &customDir, const std::string &name)
{
    if (!persist) {
        return path;
    }
    if (path.empty() || name.empty()) {
        return "";
    }
    size_t lastSlash = path.find_last_of('/');
    if (lastSlash == std::string::npos) {
        return "";
    }
    if (path.substr(lastSlash + 1) != name) {
        return "";
    }
    std::string dir = path.substr(0, lastSlash);

    if (!customDir.empty()) {
        std::string customSeg = "/" + customDir;
        size_t segLen = customSeg.length();
        if (dir.length() >= segLen && dir.substr(dir.length() - segLen) == customSeg) {
            dir = dir.substr(0, dir.length() - segLen);
        } else {
            return "";
        }
    }
    const std::string rdbSeg = "/rdb";
    size_t rdbLen = rdbSeg.length();
    if (dir.length() < rdbLen || dir.substr(dir.length() - rdbLen) != rdbSeg) {
        return "";
    }
    return dir.substr(0, dir.length() - rdbLen);
}

std::string RdbSqlUtils::BuildQueryString(const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    return SqliteSqlBuilder::BuildQueryString(predicates, columns);
}

std::pair<int, SqlInfo> RdbSqlUtils::GetInsertSqlInfo(const std::string &table, const Row &row, Resolution resolution)
{
    SqlInfo sqlInfo;
    if (table.empty()) {
        return std::make_pair(E_EMPTY_TABLE_NAME, sqlInfo);
    }

    if (row.IsEmpty()) {
        return std::make_pair(E_EMPTY_VALUES_BUCKET, sqlInfo);
    }

    auto conflictClause = SqliteUtils::GetConflictClause(static_cast<int>(resolution));
    if (conflictClause == nullptr) {
        return std::make_pair(E_INVALID_CONFLICT_FLAG, sqlInfo);
    }
    std::string sql;
    sql.append("INSERT").append(conflictClause).append(" INTO ").append(table).append("(");
    size_t bindArgsSize = row.values_.size();
    std::vector<ValueObject> bindArgs;
    bindArgs.reserve(bindArgsSize);
    const char *split = "";
    for (const auto &[key, val] : row.values_) {
        sql.append(split).append(key);
        if (val.GetType() == ValueObject::TYPE_ASSETS && resolution == ConflictResolution::ON_CONFLICT_REPLACE) {
            return std::make_pair(E_INVALID_ARGS, sqlInfo);
        }
        SqliteSqlBuilder::UpdateAssetStatus(val, AssetValue::STATUS_INSERT);
        bindArgs.push_back(val); // columnValue
        split = ",";
    }

    sql.append(") VALUES (");
    if (bindArgsSize > 0) {
        sql.append(SqliteSqlBuilder::GetSqlArgs(bindArgsSize));
    }

    sql.append(")");
    sqlInfo.sql = std::move(sql);
    sqlInfo.args = std::move(bindArgs);
    return std::make_pair(E_OK, sqlInfo);
}

std::pair<int, SqlInfo> RdbSqlUtils::GetUpdateSqlInfo(
    const AbsRdbPredicates &predicates, const Row &row, Resolution resolution)
{
    SqlInfo sqlInfo;
    auto table = predicates.GetTableName();
    auto args = predicates.GetBindArgs();
    auto where = predicates.GetWhereClause();
    if (table.empty()) {
        return std::make_pair(E_EMPTY_TABLE_NAME, sqlInfo);
    }

    if (row.IsEmpty()) {
        return std::make_pair(E_EMPTY_VALUES_BUCKET, sqlInfo);
    }

    auto clause = SqliteUtils::GetConflictClause(static_cast<int>(resolution));
    if (clause == nullptr) {
        return std::make_pair(E_INVALID_CONFLICT_FLAG, sqlInfo);
    }
    std::string sql;
    sql.append("UPDATE").append(clause).append(" ").append(table).append(" SET ");
    std::vector<ValueObject> tmpBindArgs;
    size_t tmpBindSize = row.values_.size() + args.size();
    tmpBindArgs.reserve(tmpBindSize);
    const char *split = "";
    for (auto &[key, val] : row.values_) {
        sql.append(split);
        if (val.GetType() == ValueObject::TYPE_ASSETS) {
            sql.append(key).append("=merge_assets(").append(key).append(", ?)"); // columnName
        } else if (val.GetType() == ValueObject::TYPE_ASSET) {
            sql.append(key).append("=merge_asset(").append(key).append(", ?)"); // columnName
        } else {
            sql.append(key).append("=?"); // columnName
        }
        tmpBindArgs.push_back(val); // columnValue
        split = ",";
    }
    if (!where.empty()) {
        sql.append(" WHERE ").append(where);
    }
    tmpBindArgs.insert(tmpBindArgs.end(), args.begin(), args.end());

    sqlInfo.sql = std::move(sql);
    sqlInfo.args = std::move(tmpBindArgs);
    return std::make_pair(E_OK, sqlInfo);
}

std::pair<int, SqlInfo> RdbSqlUtils::GetDeleteSqlInfo(const AbsRdbPredicates &predicates)
{
    SqlInfo sqlInfo;
    auto table = predicates.GetTableName();
    auto where = predicates.GetWhereClause();
    if (table.empty()) {
        return std::make_pair(E_EMPTY_TABLE_NAME, sqlInfo);
    }
    std::string sql;
    sql.append("DELETE FROM ").append(table);
    if (!where.empty()) {
        sql.append(" WHERE ").append(where);
    }
    sqlInfo.sql = std::move(sql);
    sqlInfo.args = predicates.GetBindArgs();
    return std::make_pair(E_OK, sqlInfo);
}

std::pair<int, SqlInfo> RdbSqlUtils::GetQuerySqlInfo(const AbsRdbPredicates &predicates, const Fields &columns)
{
    SqlInfo sqlInfo;
    std::string sql = SqliteSqlBuilder::BuildQueryString(predicates, columns);
    sqlInfo.sql = std::move(sql);
    sqlInfo.args = predicates.GetBindArgs();
    return std::make_pair(E_OK, sqlInfo);
}

bool RdbSqlUtils::IsValidTableName(const std::string &tableName)
{
    if (tableName.empty()) {
        return false;
    }
    std::regex validName("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)?$");
    return std::regex_match(tableName, validName);
}

bool RdbSqlUtils::IsValidFields(const std::vector<std::string> &fields)
{
    if (fields.size() <= 0 || fields.size() > FIELDS_LIMIT) {
        return false;
    }
    std::regex pattern("[\\*, ]");
    for (const auto& field : fields) {
        if (std::regex_search(field, pattern)) {
            return false;
        }
    }
    return true;
}

std::string RdbSqlUtils::Trim(const std::string &str)
{
    auto start = str.find_first_not_of(" \t\n\r\f\v");
    if (start == std::string::npos) {
        return "";
    }
    auto end = str.find_last_not_of(" \t\n\r\f\v");
    return str.substr(start, end - start + 1);
}

std::vector<std::string> RdbSqlUtils::BatchTrim(const std::vector<std::string> &value)
{
    std::vector<std::string> res;
    for (auto str : value) {
        res.push_back(Trim(str));
    }
    return res;
}

bool RdbSqlUtils::IsValidReturningMaxCount(int32_t maxCount)
{
    if (maxCount <= 0 || maxCount > ReturningConfig::MAX_RETURNING_COUNT) {
        LOG_ERROR("illegal maxCount %{public}d.", maxCount);
        return false;
    }
    return true;
}

bool RdbSqlUtils::HasDuplicateAssets(const ValueObject &value)
{
    auto *assets = std::get_if<ValueObject::Assets>(&value.value);
    if (assets == nullptr) {
        return false;
    }
    std::set<std::string> names;
    auto item = assets->begin();
    while (item != assets->end()) {
        if (!names.insert(item->name).second) {
            LOG_ERROR("Duplicate assets! name = %{public}.6s", item->name.c_str());
            return true;
        }
        item++;
    }
    return false;
}

bool RdbSqlUtils::HasDuplicateAssets(const std::vector<ValueObject> &values)
{
    for (auto &val : values) {
        if (HasDuplicateAssets(val)) {
            return true;
        }
    }
    return false;
}

bool RdbSqlUtils::HasDuplicateAssets(const ValuesBucket &value)
{
    for (auto &[key, val] : value.values_) {
        if (HasDuplicateAssets(val)) {
            return true;
        }
    }
    return false;
}

bool RdbSqlUtils::HasDuplicateAssets(const ValuesBuckets &values)
{
    const auto &[fields, vals] = values.GetFieldsAndValues();
    for (const auto &valueObject : *vals) {
        if (HasDuplicateAssets(valueObject)) {
            return true;
        }
    }
    return false;
}
} // namespace NativeRdb
} // namespace OHOS