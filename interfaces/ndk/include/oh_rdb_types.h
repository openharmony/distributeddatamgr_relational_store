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

/**
 * @addtogroup RDB
 * @{
 *
 * @brief The relational database (RDB) store manages data based on relational models.
 * With the underlying SQLite database, the RDB store provides a complete mechanism for managing local databases.
 * To satisfy different needs in complicated scenarios, the RDB store offers a series of APIs for performing operations
 * such as adding, deleting, modifying, and querying data, and supports direct execution of SQL statements.
 *
 * @since 10
 */

/**
 * @file oh_rdb_types.h
 *
 * @brief Provides type define related to the data value.
 *
 * @kit ArkData
 * @library libnative_rdb_ndk.z.so
 * @syscap SystemCapability.DistributedDataManager.RelationalStore.Core
 *
 * @since 16
 */

#ifndef OH_RDB_TYPES_H
#define OH_RDB_TYPES_H
#include "oh_cursor.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Describe the security area of the database.
 *
 * @since 16
 */
typedef enum Rdb_ConflictResolution {
    /**
     * @brief Implements no operation when conflict occurs.
     */
    RDB_CONFLICT_NONE = 1,
    /**
     * @brief Implements rollback operation when conflict occurs.
     */
    RDB_CONFLICT_ROLLBACK,
    /**
     * @brief Implements abort operation when conflict occurs.
     */
    RDB_CONFLICT_ABORT,
    /**
     * @brief Implements fail operation when conflict occurs.
     */
    RDB_CONFLICT_FAIL,
    /**
     * @brief Implements ignore operation when conflict occurs.
     */
    RDB_CONFLICT_IGNORE,
    /**
     * @brief Implements replace operation when conflict occurs.
     */
    RDB_CONFLICT_REPLACE,
} Rdb_ConflictResolution;

/**
 * @brief Define the OH_RDB_ReturningContext structure type.
 *
 * @since 23
 */
typedef struct OH_RDB_ReturningContext OH_RDB_ReturningContext;

/**
 * @brief Creates an OH_RDB_ReturningContext instance object.
 *
 * @return Returns a pointer to OH_RDB_ReturningContext instance when the execution is successful.
 * Otherwise, nullptr is returned. The memory must be released through the OH_RDB_DestroyReturningContext
 * interface after the use is complete.
 * @see OH_RDB_DestroyReturningContext.
 * @since 23
 */
OH_RDB_ReturningContext *OH_RDB_CreateReturningContext(void);

/**
 * @brief Destroys an OH_RDB_ReturningContext instance object.
 *
 * @param context Represents a pointer to an instance of OH_RDB_ReturningContext.
 * @since 23
 */
void OH_RDB_DestroyReturningContext(OH_RDB_ReturningContext *context);

/**
 * @brief Get the number of rows affected bu this operation.
 *
 * @param context Represents a pointer to an instance of OH_RDB_ReturningContext.
 * @param columnNames Indicates the columnNames to returning.
 * @param len Indicates the length of columnNames.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 23
 */
int OH_RDB_SetReturningField(OH_RDB_ReturningContext *context, const char *const columnNames[], int32_t len);

/**
 * @brief Get the number of rows affected bu this operation.
 *
 * @param context Represents a pointer to an instance of OH_RDB_ReturningContext.
 * @param count Indicate the maximum entry of the returned result set.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 23
 */
int OH_RDB_SetMaxReturningCount(OH_RDB_ReturningContext *context, int32_t count);

/**
 * @brief Get the cursor of data changes contains a maximun of 1024 records.
 *
 * @param context Represents a pointer to an instance of OH_RDB_ReturningContext.
 * @return a pointer to the instance of the {@link OH_Cursor} structure is returned.
 *         If Get Cursor failed, nullptr is returned.
 * @since 23
 */
OH_Cursor *OH_RDB_GetReturningValues(OH_RDB_ReturningContext *context);

/**
 * @brief Get the number of rows affected bu this operation.
 *
 * @param context Represents a pointer to an instance of OH_RDB_ReturningContext.
 * @return Return the number of entries that have changed.
 *         If Get changed failed, -1 is returned.
 * @since 23
 */
int64_t OH_RDB_GetChanedCount(OH_RDB_ReturningContext *context);
#ifdef __cplusplus
};
#endif
#endif