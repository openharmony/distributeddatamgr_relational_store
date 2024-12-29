/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_DATA_GDB_JS_NAPI_GDB_COMMON_H
#define OHOS_DISTRIBUTED_DATA_GDB_JS_NAPI_GDB_COMMON_H
#include <cstdint>

namespace OHOS::GraphStoreJsKit {
enum ColumnType : uint32_t {

    /**
     * GRAPH_DB_DATATYPE_LONG: means the column type of the specified column is long.
     *
     * @syscap
     * @since 16
     */
    GRAPH_DB_DATATYPE_LONG = 0,

    /**
     * GRAPH_DB_DATATYPE_DOUBLE: means the column type of the specified column is double.
     *
     * @syscap SystemCapability.DistributedDataManager.DataIntelligence.Core
     * @since 16
     */
    GRAPH_DB_DATATYPE_DOUBLE,

    /**
     * GRAPH_DB_DATATYPE_STRING: means the column type of the specified column is string.
     *
     * @syscap SystemCapability.DistributedDataManager.DataIntelligence.Core
     * @since 16
     */
    GRAPH_DB_DATATYPE_STRING,

    /**
     * GRAPH_DB_DATATYPE_JSONSTR: means the column type of the specified column is string with json format.
     *
     * @syscap SystemCapability.DistributedDataManager.DataIntelligence.Core
     * @since 16
     */
    GRAPH_DB_DATATYPE_JSONSTR,

    GRAPH_DB_DATATYPE_NULL,
};
}

#endif