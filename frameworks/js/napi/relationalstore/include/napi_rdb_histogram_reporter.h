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

#ifndef RDB_HISTOGRAM_REPORTER_H
#define RDB_HISTOGRAM_REPORTER_H

#include <chrono>
#include <cstdint>
#include <string>

namespace OHOS::NativeRdb {

void ReportHistogramBoolean(const std::string &name, int32_t sample);
void ReportHistogramEnumeration(const std::string &name, int32_t sample, int32_t boundary);
void ReportHistogramTimes(const std::string &name, int32_t duration);

enum class HistogramErrCode : int32_t {
    ERR_OK = 0,
    ERR_PERMISSION_DENIED,
    ERR_NON_SYSTEM_APP,
    ERR_INVALID_ARGS,
    ERR_INVALID_ARGS_NEW,
    ERR_NOT_SUPPORT,
    ERR_INNER_ERROR,
    ERR_INVALID_FILE_PATH,
    ERR_ROW_OUT_RANGE,
    ERR_COLUMN_OUT_RANGE,
    ERR_CONFIG_INVALID_CHANGE,
    ERR_ALREADY_CLOSED,
    ERR_DATABASE_BUSY,
    ERR_ATTACHED_DATABASE_EXIST,
    ERR_NO_ROW_IN_QUERY,
    ERR_NOT_SELECT,
    ERR_INVALID_SECRET_KEY,
    ERR_SQLITE_ERROR,
    ERR_SQLITE_ABORT,
    ERR_SQLITE_PERM,
    ERR_SQLITE_BUSY,
    ERR_SQLITE_LOCKED,
    ERR_SQLITE_NOMEM,
    ERR_SQLITE_READONLY,
    ERR_SQLITE_IOERR,
    ERR_SQLITE_CORRUPT,
    ERR_SQLITE_FULL,
    ERR_SQLITE_CANTOPEN,
    ERR_SQLITE_TOOBIG,
    ERR_SQLITE_CONSTRAINT,
    ERR_SQLITE_MISMATCH,
    ERR_SQLITE_MISUSE,
    ERR_NOT_STAGE_MODE,
    ERR_DATA_GROUP_ID_INVALID,
    ERR_WAL_SIZE_OVER_LIMIT,
    ERR_INVALID_OBJECT_TYPE,
    ERR_DB_NOT_EXIST,
    ERR_NOT_SUPPORT_NEW,
    ERR_GET_DATAOBSMGRCLIENT_FAIL,
    ERR_TYPE_MISMATCH,
    ERR_OTHER,
    ERR_BOUNDARY
};

enum class HistogramType : uint8_t {
    NONE = 0,
    TIME = 1 << 0,
    BOOL = 1 << 1,
    ENUM = 1 << 2,
};

inline constexpr HistogramType operator|(HistogramType lhs, HistogramType rhs)
{
    return static_cast<HistogramType>(static_cast<uint8_t>(lhs) | static_cast<uint8_t>(rhs));
}

inline constexpr bool operator&(HistogramType lhs, HistogramType rhs)
{
    return (static_cast<uint8_t>(lhs) & static_cast<uint8_t>(rhs)) != 0;
}

class HistogramReporter {
public:
    HistogramReporter(std::string name, HistogramType type,
        std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now());
    ~HistogramReporter() noexcept;

    void SetErrCode(int32_t errCode);
    void SetName(const std::string &name);

    HistogramReporter(const HistogramReporter &) = delete;
    HistogramReporter &operator=(const HistogramReporter &) = delete;

private:
    std::string name_;
    std::chrono::steady_clock::time_point start_;
    int32_t errCode_;
    HistogramType type_;
};

} // namespace OHOS::NativeRdb

#endif // RDB_HISTOGRAM_REPORTER_H
