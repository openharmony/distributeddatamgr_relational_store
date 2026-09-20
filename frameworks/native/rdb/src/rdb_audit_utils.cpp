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

#include "rdb_audit_utils.h"

#include <cstring>

namespace OHOS {
namespace NativeRdb {
namespace RdbAuditUtils {

namespace {

size_t SkipSpaces(const std::string &sql, size_t pos)
{
    while (pos < sql.size() && std::isspace(static_cast<unsigned char>(sql[pos]))) {
        ++pos;
    }
    return pos;
}

size_t SkipWord(const std::string &sql, size_t pos)
{
    while (pos < sql.size() && !std::isspace(static_cast<unsigned char>(sql[pos]))) {
        ++pos;
    }
    return pos;
}

bool MatchPrefix(const std::string &sql, size_t pos, const char *prefix)
{
    size_t len = std::strlen(prefix);
    if (pos + len > sql.size()) {
        return false;
    }
    for (size_t i = 0; i < len; ++i) {
        if (std::tolower(static_cast<unsigned char>(sql[pos + i])) != prefix[i]) {
            return false;
        }
    }
    for (size_t i = pos + len; i < sql.size(); ++i) {
        char c = sql[i];
        if (!std::isspace(static_cast<unsigned char>(c)) && c != ';') {
            return false;
        }
    }
    return true;
}

bool MatchKeyword(const std::string &sql, size_t pos, const char *word)
{
    size_t len = std::strlen(word);
    if (pos + len > sql.size() || strncasecmp(sql.c_str() + pos, word, len) != 0) {
        return false;
    }
    return (pos + len == sql.size()) || std::isspace(static_cast<unsigned char>(sql[pos + len]));
}

bool MatchTableAfter(const std::string &sql, size_t pos, int keywordLen)
{
    size_t after = SkipSpaces(sql, pos + keywordLen);
    return after + 5 <= sql.size() && strncasecmp(sql.c_str() + after, "TABLE", 5) == 0;
}

size_t SkipIfExists(const std::string &sql, size_t pos)
{
    pos = SkipSpaces(sql, pos);
    if (pos + 2 > sql.size() || strncasecmp(sql.c_str() + pos, "IF", 2) != 0) {
        return pos;
    }
    pos = SkipSpaces(sql, pos + 2);
    if (pos + 6 > sql.size() || strncasecmp(sql.c_str() + pos, "EXISTS", 6) != 0) {
        return pos;
    }
    return SkipSpaces(sql, pos + 6);
}

} // namespace

bool IsPragmaIntegrityCheck(const std::string &sql)
{
    if (sql.size() < 6) { // minimum: "PRAGMA" = 6
        return false;
    }
    size_t pos = SkipSpaces(sql, 0);
    if (pos + 6 > sql.size()) {
        return false;
    }
    for (int i = 0; i < 6; ++i) {
        if (std::toupper(static_cast<unsigned char>(sql[pos + i])) != "PRAGMA"[i]) {
            return false;
        }
    }
    pos = SkipSpaces(sql, pos + 6);
    return MatchPrefix(sql, pos, "integrity_check") || MatchPrefix(sql, pos, "quick_check");
}

IntegrityMode ParsePragmaMode(const std::string &sql)
{
    size_t pos = SkipSpaces(sql, 0);
    pos = SkipSpaces(sql, pos + 6); // skip "PRAGMA"
    if (pos < sql.size() && std::tolower(static_cast<unsigned char>(sql[pos])) == 'q') {
        return IntegrityMode::QUICK;
    }
    return IntegrityMode::FULL;
}

std::string ParseDropTruncateOp(const std::string &sql)
{
    size_t pos = SkipSpaces(sql, 0);
    if (MatchKeyword(sql, pos, "DROP")) {
        if (MatchTableAfter(sql, pos, 4)) {
            return "DROP";
        }
    } else if (MatchKeyword(sql, pos, "TRUNCATE")) {
        if (MatchTableAfter(sql, pos, 8)) {
            return "TRUNCATE";
        }
    }
    return "";
}

std::string ParseDropTruncateTable(const std::string &sql)
{
    size_t pos = SkipSpaces(sql, 0);
    pos = SkipSpaces(sql, SkipWord(sql, pos));
    pos = SkipSpaces(sql, SkipWord(sql, pos));
    pos = SkipIfExists(sql, pos);
    size_t start = pos;
    while (pos < sql.size() && !std::isspace(static_cast<unsigned char>(sql[pos])) && sql[pos] != ';' &&
           sql[pos] != '(') {
        ++pos;
    }
    if (start == pos) {
        return "";
    }
    return sql.substr(start, pos - start);
}

} // namespace RdbAuditUtils
} // namespace NativeRdb
} // namespace OHOS
