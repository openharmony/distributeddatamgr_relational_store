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

#ifdef __cplusplus
};
#endif
#endif
