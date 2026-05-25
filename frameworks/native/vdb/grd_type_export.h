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

#ifndef GRD_TYPE_EXPORT_H
#define GRD_TYPE_EXPORT_H
#include <cstdint>
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifndef _WIN32
#define GRD_API __attribute__((visibility("default")))
#else
#define GRD_API
#endif

typedef struct GRD_DB GRD_DB;
typedef struct GRD_SqlStmt GRD_SqlStmt;
typedef struct GRD_Stmt GRD_StmtT;

typedef uint64_t (*GRD_DbScheduleFunc)(void *func, void *param);
typedef bool (*GRD_DbRemoveFunc)(uint64_t taskId, bool wait);
typedef struct GRD_DbThreadPool {
    GRD_DbScheduleFunc schedule;
    GRD_DbRemoveFunc remove;
} GRD_DbThreadPoolT;

typedef struct GRD_ClstAlgoPara {
    /* Input Parameters */
    uint16_t featureDim;      // Feature vector dimension, currently supports 256D only
    uint32_t oldFeaturesNum;  // Number of historical cluster center vectors
    float *oldFeatures;       // Array of historical cluster center vectors,
                              // stored in row-major order (length: oldFeaturesNum * dim)
    const int32_t *oldClstGroupId;  // Cluster ID for each historical vector (length: oldFeaturesNum)
    const int32_t *oldClstVecNum;   // Number of vectors in each historical cluster (length: oldFeaturesNum)

    uint32_t newFeaturesNum;  // Number of newly collected vectors
    float *newFeatures;       // Array of new feature vectors
                              // stored in row-major order (length: newFeaturesNum * dim)
    int32_t newClusterIdStart;  // Starting cluster ID for new clusters, usually the maximum old cluster ID plus one

    /* Customization Parameters */
    void *customParams;       // Developers need to communicate with the database development team before using it

    /* Output Parameters */
    int32_t *clusterResult;   // Clustering result array, indicating the assigned cluster ID for each new vector
                              // (length: newFeaturesNum)
} GRD_ClstAlgoParaT;

typedef int32_t (*GRD_ClusterAlgoFunc)(GRD_ClstAlgoParaT *para);

/**
 * @brief Open database config
 */
#define GRD_DB_OPEN_ONLY 0x00
#define GRD_DB_OPEN_CREATE 0x01
// check data in database if close abnormally last time, if data is corrupted, rebuild the database
#define GRD_DB_OPEN_CHECK_FOR_ABNORMAL 0x02
// check data in database when open database, if data is corrupted, rebuild the database.
#define GRD_DB_OPEN_CHECK 0x04
#define GRD_DB_OPEN_SHARED_READ_ONLY 0x08
#define GRD_DB_OPEN_IGNORE_DATA_CORRPUPTION 0X10 // open database for ignore the meta data corruption

/**
 * @brief Close database config
 */
#define GRD_DB_CLOSE 0x00
#define GRD_DB_CLOSE_IGNORE_ERROR 0x01

#define GRD_DOC_ID_DISPLAY 0x01
typedef enum {
    GRD_DB_DATATYPE_INTEGER = 0,
    GRD_DB_DATATYPE_FLOAT,
    GRD_DB_DATATYPE_TEXT,
    GRD_DB_DATATYPE_BLOB,
    GRD_DB_DATATYPE_FLOATVECTOR,
    GRD_DB_DATATYPE_JSONSTR,
    GRD_DB_DATATYPE_NULL,
} GRD_DbDataTypeE;

typedef enum {
    GRD_CONFIG_USER_VERSION,
    GRD_CONFIG_BOTTOM,
} GRD_ConfigTypeE;

typedef struct GRD_DbValueT {
    GRD_DbDataTypeE type;
    union {
        int64_t longValue;
        double doubleValue;
        struct {
            const void *strAddr;
            uint32_t length;
        };
    } value;
} GRD_DbValueT;

typedef struct GRD_CipherInfo {
    const char *hexPassword;
} GRD_CipherInfoT;

typedef struct GRD_DB GRD_DB;

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // GRD_TYPE_EXPORT_H