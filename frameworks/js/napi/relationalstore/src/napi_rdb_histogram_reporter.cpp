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

#include "napi_rdb_histogram_reporter.h"

#include <algorithm>

#include "histogram_plugin_macros.h"

namespace OHOS::NativeRdb {

void ReportHistogramBoolean(const std::string &name, int32_t sample)
{
    HISTOGRAM_BOOLEAN(name.c_str(), sample);
}

void ReportHistogramEnumeration(const std::string &name, int32_t sample, int32_t boundary)
{
    HISTOGRAM_ENUMERATION(name.c_str(), sample, boundary);
}

void ReportHistogramTimes(const std::string &name, int32_t duration)
{
    HISTOGRAM_TIMES(name.c_str(), duration);
}

struct JsErrMap {
    int32_t jsCode;
    HistogramErrCode code;
};

static constexpr JsErrMap JS_ERR_TO_HISTOGRAM[] = {
    { 0,        HistogramErrCode::ERR_OK },
    { 201,      HistogramErrCode::ERR_PERMISSION_DENIED },
    { 202,      HistogramErrCode::ERR_NON_SYSTEM_APP },
    { 401,      HistogramErrCode::ERR_INVALID_ARGS },
    { 801,      HistogramErrCode::ERR_NOT_SUPPORT },
    { 14800000, HistogramErrCode::ERR_INNER_ERROR },
    { 14800001, HistogramErrCode::ERR_INVALID_ARGS_NEW },
    { 14800010, HistogramErrCode::ERR_INVALID_FILE_PATH },
    { 14800011, HistogramErrCode::ERR_SQLITE_CORRUPT },
    { 14800012, HistogramErrCode::ERR_ROW_OUT_RANGE },
    { 14800013, HistogramErrCode::ERR_COLUMN_OUT_RANGE },
    { 14800014, HistogramErrCode::ERR_ALREADY_CLOSED },
    { 14800015, HistogramErrCode::ERR_DATABASE_BUSY },
    { 14800016, HistogramErrCode::ERR_ATTACHED_DATABASE_EXIST },
    { 14800017, HistogramErrCode::ERR_CONFIG_INVALID_CHANGE },
    { 14800018, HistogramErrCode::ERR_NO_ROW_IN_QUERY },
    { 14800019, HistogramErrCode::ERR_NOT_SELECT },
    { 14800020, HistogramErrCode::ERR_INVALID_SECRET_KEY },
    { 14800021, HistogramErrCode::ERR_SQLITE_ERROR },
    { 14800022, HistogramErrCode::ERR_SQLITE_ABORT },
    { 14800023, HistogramErrCode::ERR_SQLITE_PERM },
    { 14800024, HistogramErrCode::ERR_SQLITE_BUSY },
    { 14800025, HistogramErrCode::ERR_SQLITE_LOCKED },
    { 14800026, HistogramErrCode::ERR_SQLITE_NOMEM },
    { 14800027, HistogramErrCode::ERR_SQLITE_READONLY },
    { 14800028, HistogramErrCode::ERR_SQLITE_IOERR },
    { 14800029, HistogramErrCode::ERR_SQLITE_FULL },
    { 14800030, HistogramErrCode::ERR_SQLITE_CANTOPEN },
    { 14800031, HistogramErrCode::ERR_SQLITE_TOOBIG },
    { 14800032, HistogramErrCode::ERR_SQLITE_CONSTRAINT },
    { 14800033, HistogramErrCode::ERR_SQLITE_MISMATCH },
    { 14800034, HistogramErrCode::ERR_SQLITE_MISUSE },
    { 14800041, HistogramErrCode::ERR_INVALID_OBJECT_TYPE },
    { 14800042, HistogramErrCode::ERR_DB_NOT_EXIST },
    { 14800043, HistogramErrCode::ERR_NOT_SUPPORT_NEW },
    { 14800047, HistogramErrCode::ERR_WAL_SIZE_OVER_LIMIT },
    { 14800051, HistogramErrCode::ERR_TYPE_MISMATCH },
    { 14801001, HistogramErrCode::ERR_NOT_STAGE_MODE },
    { 14801002, HistogramErrCode::ERR_DATA_GROUP_ID_INVALID },
    { 14801050, HistogramErrCode::ERR_GET_DATAOBSMGRCLIENT_FAIL },
};
static constexpr size_t JS_ERR_MAP_SIZE = std::size(JS_ERR_TO_HISTOGRAM);

static constexpr bool IsJsErrMapIncreasing()
{
    for (size_t i = 1; i < JS_ERR_MAP_SIZE; i++) {
        if (JS_ERR_TO_HISTOGRAM[i].jsCode <= JS_ERR_TO_HISTOGRAM[i - 1].jsCode) {
            return false;
        }
    }
    return true;
}
static_assert(IsJsErrMapIncreasing());

static int32_t MapJsCodeToHistogram(int32_t jsCode)
{
    auto target = JsErrMap{ jsCode, HistogramErrCode::ERR_OTHER };
    auto *end = JS_ERR_TO_HISTOGRAM + JS_ERR_MAP_SIZE;
    auto iter = std::lower_bound(JS_ERR_TO_HISTOGRAM, end, target,
        [](const JsErrMap &lhs, const JsErrMap &rhs) { return lhs.jsCode < rhs.jsCode; });
    if (iter != end && iter->jsCode == jsCode) {
        return static_cast<int32_t>(iter->code);
    }
    return static_cast<int32_t>(HistogramErrCode::ERR_OTHER);
}

HistogramReporter::HistogramReporter(std::string name, HistogramType type,
    std::chrono::steady_clock::time_point start)
    : name_(std::move(name)), start_(start),
      errCode_(static_cast<int32_t>(HistogramErrCode::ERR_OK)), type_(type)
{
}

void HistogramReporter::SetName(const std::string &newName)
{
    name_ = newName;
}

HistogramReporter::~HistogramReporter() noexcept
{
    if (type_ & HistogramType::BOOL) {
        ReportHistogramBoolean(name_ + ".Bool",
            errCode_ == static_cast<int32_t>(HistogramErrCode::ERR_OK) ? 1 : 0);
    }
    if (errCode_ != static_cast<int32_t>(HistogramErrCode::ERR_OK)) {
        if (type_ & HistogramType::ENUM) {
            ReportHistogramEnumeration(
                name_ + ".Enum", errCode_, static_cast<int32_t>(HistogramErrCode::ERR_BOUNDARY));
        }
        return;
    }
    if (type_ & HistogramType::TIME) {
        auto elapsed = std::chrono::steady_clock::now() - start_;
        int32_t duration = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        if (duration < 0) {
            duration = 0;
        }
        ReportHistogramTimes(name_ + ".Time", duration);
    }
    if (type_ & HistogramType::ENUM) {
        ReportHistogramEnumeration(
            name_ + ".Enum", errCode_, static_cast<int32_t>(HistogramErrCode::ERR_BOUNDARY));
    }
}

void HistogramReporter::SetErrCode(int32_t newErrCode)
{
    errCode_ = MapJsCodeToHistogram(newErrCode);
}

} // namespace OHOS::NativeRdb
