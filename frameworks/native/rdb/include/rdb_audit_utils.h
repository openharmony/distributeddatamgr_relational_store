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

#ifndef RDB_AUDIT_UTILS_H
#define RDB_AUDIT_UTILS_H

#include <string>

namespace OHOS {
namespace NativeRdb {
namespace RdbAuditUtils {

// Classify a DDL statement as DROP TABLE or TRUNCATE TABLE.
// Returns "DROP", "TRUNCATE", or "" (empty = not a drop/truncate-table statement).
// Case-insensitive; tolerates leading whitespace. Validates the TABLE keyword
// follows, so DROP INDEX / DROP VIEW / DROP TRIGGER are NOT matched.
std::string ParseDropTruncateOp(const std::string &sql);

// Extract the table name from a DROP TABLE or TRUNCATE TABLE statement.
// Returns empty string if the table name cannot be parsed.
// Example: "DROP TABLE IF EXISTS foo" -> "foo", "TRUNCATE TABLE bar" -> "bar"
std::string ParseDropTruncateTable(const std::string &sql);

} // namespace RdbAuditUtils
} // namespace NativeRdb
} // namespace OHOS

#endif // RDB_AUDIT_UTILS_H
