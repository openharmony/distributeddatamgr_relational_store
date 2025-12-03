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
#define LOG_TAG "OH_RDB_TYPES"
#include "oh_rdb_types.h"

#include "logger.h"
#include "oh_data_define.h"
#include "rdb_sql_utils.h"
#include "relational_cursor.h"
#include "relational_store_error_code.h"
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbNdk;
bool OH_RDB_ReturningContext::IsValid() const
{
    return id == OH_CRYPTO_PARAM_ID;
}

OH_RDB_ReturningContext *OH_RDB_CreateReturningContext(void)
{
    OH_RDB_ReturningContext *context = new (std::nothrow) OH_RDB_ReturningContext;
    if (context == nullptr) {
        LOG_ERROR("failed to create context.");
        return nullptr;
    }
    context->config.defaultRowIndex = OHOS::NativeRdb::ReturningConfig::DEFAULT_ROW_INDEX;
    return context;
}

void OH_RDB_DestroyReturningContext(OH_RDB_ReturningContext *context)
{
    if (context == nullptr || !context->IsValid()) {
        LOG_ERROR("illegal context.");
        return;
    }
    if (context->cursor != nullptr && context->cursor->destroy != nullptr) {
        context->cursor->destroy(context->cursor);
        context->cursor = nullptr;
    }
    delete context;
}

int OH_RDB_SetReturningFields(OH_RDB_ReturningContext *context, const char *const fields[], int32_t len)
{
    if (context == nullptr || !context->IsValid() || fields == nullptr || len <= 0) {
        LOG_ERROR("failed. [%{public}d, %{public}d]", fields == nullptr, len);
        return RDB_E_INVALID_ARGS;
    }
    std::vector<std::string> columns;
    columns.reserve(len);
    for (int i = 0; i < len; i++) {
        if (fields[i] == nullptr) {
            LOG_ERROR("failed. fields[%{public}d] is nullptr", i);
            return RDB_E_INVALID_ARGS;
        }
        columns.push_back(fields[i]);
    }
    columns = RdbSqlUtils::BatchTrim(columns);
    if (!RdbSqlUtils::IsValidFields(columns)) {
        LOG_ERROR("illegal fields, maybe has [','|' '|'*']");
        return RDB_E_INVALID_ARGS;
    }
    context->config.columns = std::move(columns);
    return RDB_OK;
}

int OH_RDB_SetMaxReturningCount(OH_RDB_ReturningContext *context, int32_t count)
{
    if (context == nullptr || !context->IsValid()) {
        LOG_ERROR("failed. count: %{public}d", count);
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    if (!RdbSqlUtils::IsValidReturningMaxCount(count)) {
        context->config.maxReturningCount = ReturningConfig::ILLEGAL_RETURNING_COUNT;
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    context->config.maxReturningCount = count;
    return RDB_OK;
}

OH_Cursor *OH_RDB_GetReturningValues(OH_RDB_ReturningContext *context)
{
    if (context == nullptr || !context->IsValid()) {
        LOG_ERROR("illegal context.");
        return nullptr;
    }

    return context->cursor;
}

int64_t OH_RDB_GetChangedCount(OH_RDB_ReturningContext *context)
{
    if (context == nullptr || !context->IsValid()) {
        return -1;
    }

    return context->changed;
}