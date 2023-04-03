/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef NATIVE_RDB_RESULT_SET_H
#define NATIVE_RDB_RESULT_SET_H

#include <string>
#include <vector>
#include "values_bucket.h"
namespace OHOS {
namespace NativeRdb {

enum class ColumnType {
    TYPE_NULL = 0,
    TYPE_INTEGER,
    TYPE_FLOAT,
    TYPE_STRING,
    TYPE_BLOB,
};


class  ResultSet {
public:
    enum {
        CMD_GET_ALL_COLUMN_NAMES,
        CMD_GET_COLUMN_COUNT,
        CMD_GET_COLUMN_TYPE,
        CMD_GET_COLUMN_INDEX,
        CMD_GET_COLUMN_NAME,
        CMD_GET_ROW_COUNT,
        CMD_GET_ROW_INDEX,
        CMD_GO_TO,
        CMD_GO_TO_ROW,
        CMD_GO_TO_FIRST_ROW,
        CMD_GO_TO_LAST_ROW,
        CMD_GO_TO_NEXT_ROW,
        CMD_GO_TO_PREV_ROW,
        CMD_IS_ENDED_ROW,
        CMD_IS_STARTED_ROW,
        CMD_IS_AT_FIRST_ROW,
        CMD_IS_AT_LAST_ROW,
        CMD_GET_BLOB,
        CMD_GET_STRING,
        CMD_GET_INT,
        CMD_GET_LONG,
        CMD_GET_DOUBLE,
        CMD_IS_COLUMN_NULL,
        CMD_IS_CLOSED,
        CMD_CLOSE,
        CMD_MAX
    };

    virtual ~ResultSet() {}

    virtual int GetAllColumnNames(std::vector<std::string> &columnNames) = 0;

    virtual int GetColumnCount(int &count) = 0;

    virtual int GetColumnType(int columnIndex, ColumnType &columnType) = 0;

    virtual int GetColumnIndex(const std::string &columnName, int &columnIndex) = 0;

    virtual int GetColumnName(int columnIndex, std::string &columnName) = 0;

    virtual int GetRowCount(int &count) = 0;

    virtual int GetRowIndex(int &position) const = 0;

    virtual int GoTo(int offset) = 0;

    virtual int GoToRow(int position) = 0;

    virtual int GoToFirstRow() = 0;

    virtual int GoToLastRow() = 0;

    virtual int GoToNextRow() = 0;

    virtual int GoToPreviousRow() = 0;

    virtual int IsEnded(bool &result) = 0;

    virtual int IsStarted(bool &result) const = 0;

    virtual int IsAtFirstRow(bool &result) const = 0;

    virtual int IsAtLastRow(bool &result) = 0;

    virtual int GetBlob(int columnIndex, std::vector<uint8_t> &blob) = 0;

    virtual int GetString(int columnIndex, std::string &value) = 0;

    virtual int GetInt(int columnIndex, int &value) = 0;

    virtual int GetLong(int columnIndex, int64_t &value) = 0;

    virtual int GetDouble(int columnIndex, double &value) = 0;

    virtual int IsColumnNull(int columnIndex, bool &isNull) = 0;

    virtual int GetRow(std::vector<std::string> &columns, ValuesBucket &valuesBucket) = 0;

    virtual bool IsClosed() const = 0;

    virtual int Close() = 0;
};

} // namespace NativeRdb
} // namespace OHOS
#endif
