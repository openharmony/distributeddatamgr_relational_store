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

#ifndef RELATIONAL_ERRNO_CODE_H
#define RELATIONAL_ERRNO_CODE_H

/**
 * @addtogroup RDB
 * @{
 *
 * @brief The relational database (RDB) store manages data based on relational models.
 * With the underlying SQLite database, the RDB store provides a complete mechanism for managing local databases.
 * To satisfy different needs in complicated scenarios, the RDB store offers a series of APIs for performing operations
 * such as adding, deleting, modifying, and querying data, and supports direct execution of SQL statements.
 *
 * @syscap SystemCapability.DistributedDataManager.RelationalStore.Core
 * @since 10
 */


/**
 * @file relational_error_code.h
 *
 * @brief Declaration error code information.
 *
 * @since 10
 * @version 1.0
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Indicates the error code information.
 *
 * @since 10
 * @version 1.0
 */
enum OH_Rdb_ErrCode {
    /** Indicates the parameters is invalid.*/
    RDB_ERR_INVALID_ARGS = -2,
    /** Indicates that the function execution exception.*/
    RDB_ERR = -1,
    /** Indicates that the function execution normal.*/
    RDB_ERR_OK = 0
};

#ifdef __cplusplus
};
#endif

#endif // RELATIONAL_ERRNO_CODE_H