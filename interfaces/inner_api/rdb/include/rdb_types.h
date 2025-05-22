/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTED_RDB_RDB_TYPES_H
#define DISTRIBUTED_RDB_RDB_TYPES_H

#include <cinttypes>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <variant>
#include <vector>

#include "values_buckets.h"

namespace OHOS {
namespace DistributedRdb {
enum RdbStatus {
    RDB_OK,
    RDB_ERROR,
    RDB_NO_META,
};

enum RdbDistributedType {
    RDB_DEVICE_COLLABORATION = 10,
    RDB_DISTRIBUTED_TYPE_MAX
};

struct RdbDebugInfo {
    struct DebugTime {
        int64_t sec_ = 0;
        int64_t nsec_ = 0;
    };
    uint64_t inode_ = 0;
    uint64_t oldInode_ = 0;
    DebugTime atime_;
    DebugTime mtime_;
    DebugTime ctime_;
    ssize_t size_ = 0;
    uint32_t dev_ = 0;
    uint32_t mode_ = 0;
    uint32_t uid_ = 0;
    uint32_t gid_ = 0;
};

struct RdbDfxInfo {
    std::string lastOpenTime_;
    int curUserId_;
};

struct RdbSyncerParam {
    std::string bundleName_;
    std::string hapName_;
    std::string storeName_;
    std::string customDir_;
    int32_t area_ = 0;
    int32_t level_ = 0;
    int32_t haMode_ = 0;
    int32_t type_ = RDB_DEVICE_COLLABORATION;
    uint32_t roleType_ = 0;
    bool isEncrypt_ = false;
    bool isAutoClean_ = true;
    bool isSearchable_ = false;
    std::vector<uint8_t> password_;
    std::map<std::string, RdbDebugInfo> infos_;
    std::vector<uint32_t> tokenIds_;
    std::vector<int32_t> uids_;
    std::string user_;
    std::vector<std::string> permissionNames_ = {};
    bool asyncDownloadAsset_ = false;
    bool enableCloud_ = true;
    int32_t subUser_ = 0;
    RdbDfxInfo dfxInfo_;
    ~RdbSyncerParam()
    {
        password_.assign(password_.size(), 0);
    };
};

struct RdbNotifyConfig {
    uint32_t delay_ = 0;
    bool isFull_ = false;
};

enum SyncMode {
    PUSH,
    PULL,
    PULL_PUSH,
    TIME_FIRST = 4,
    NATIVE_FIRST,
    CLOUD_FIRST,
};

struct SyncOption {
    SyncMode mode;
    bool isBlock;
};

enum DistributedTableType {
    DISTRIBUTED_DEVICE = 0,
    DISTRIBUTED_CLOUD,
    DISTRIBUTED_SEARCH
};

struct RdbStatEvent {
    uint32_t statType = 0;
    std::string bundleName = "";
    std::string storeName = "";
    uint32_t subType = 0;
    uint32_t costTime = 0;

    bool operator<(const RdbStatEvent &other) const
    {
        if (statType != other.statType) {
            return statType < other.statType;
        }
        if (bundleName.size() != other.bundleName.size()) {
            return bundleName.size() < other.bundleName.size();
        }
        if (bundleName != other.bundleName) {
            return bundleName < other.bundleName;
        }
        if (storeName.size() != other.storeName.size()) {
            return storeName.size() < other.storeName.size();
        }
        if (storeName != other.storeName) {
            return storeName < other.storeName;
        }
        if (subType != other.subType) {
            return subType < other.subType;
        }
        return costTime < other.costTime;
    }
};

struct Reference {
    std::string sourceTable;
    std::string targetTable;
    std::map<std::string, std::string> refFields;
};

struct DistributedConfig {
    bool autoSync = true;
    std::vector<Reference> references = {};
    bool isRebuild = false;
    bool asyncDownloadAsset = false;
    bool enableCloud = true;
};

enum Progress {
    SYNC_BEGIN = 0,
    SYNC_IN_PROGRESS,
    SYNC_FINISH,
};

enum ProgressCode {
    SUCCESS = 0,
    UNKNOWN_ERROR,
    NETWORK_ERROR,
    CLOUD_DISABLED,
    LOCKED_BY_OTHERS,
    RECORD_LIMIT_EXCEEDED,
    NO_SPACE_FOR_ASSET,
    BLOCKED_BY_NETWORK_STRATEGY,
};

struct Statistic {
    uint32_t total;
    uint32_t success;
    uint32_t failed;
    uint32_t untreated;
};

struct TableDetail {
    Statistic upload;
    Statistic download;
};

using TableDetails = std::map<std::string, TableDetail>;

struct ProgressDetail {
    int32_t progress;
    int32_t code;
    TableDetails details;
};

using Briefs = std::map<std::string, int>;
using Details = std::map<std::string, ProgressDetail>;
using AsyncBrief = std::function<void(const Briefs &)>;
using AsyncDetail = std::function<void(Details &&)>;

using SyncResult = Briefs;
using SyncCallback = AsyncBrief;

enum RdbPredicateOperator {
    EQUAL_TO,
    NOT_EQUAL_TO,
    AND,
    OR,
    ORDER_BY,
    LIMIT,
    BEGIN_GROUP,
    END_GROUP,
    IN,
    NOT_IN,
    CONTAIN,
    BEGIN_WITH,
    END_WITH,
    IS_NULL,
    IS_NOT_NULL,
    LIKE,
    GLOB,
    BETWEEN,
    NOT_BETWEEN,
    GREATER_THAN,
    GREATER_THAN_OR_EQUAL,
    LESS_THAN,
    LESS_THAN_OR_EQUAL,
    DISTINCT,
    INDEXED_BY,
    NOT_CONTAINS,
    NOT_LIKE,
    ASSETS_ONLY,
    NOT_GLOB,
    OPERATOR_MAX
};

struct RdbPredicateOperation {
    RdbPredicateOperator operator_;
    std::string field_;
    std::vector<std::string> values_;
};

struct PredicatesMemo {
    inline void AddOperation(const RdbPredicateOperator op, const std::string &field, const std::string &value)
    {
        operations_.push_back({ op, field, { value } });
    }
    inline void AddOperation(
        const RdbPredicateOperator op, const std::string &field, const std::vector<std::string> &values)
    {
        operations_.push_back({ op, field, values });
    }

    std::vector<std::string> tables_;
    std::vector<std::string> devices_;
    std::vector<RdbPredicateOperation> operations_;
};

struct Date {
    Date() {}
    Date(int64_t date) : date(date) {}
    operator double() const
    {
        return static_cast<double>(date);
    }
    int64_t date;
};

class DetailProgressObserver {
public:
    virtual ~DetailProgressObserver() {};

    virtual void ProgressNotification(const Details &details) = 0;
};

enum SubscribeMode {
    REMOTE,
    CLOUD,
    CLOUD_DETAIL,
    LOCAL,
    LOCAL_SHARED,
    LOCAL_DETAIL,
    SUBSCRIBE_MODE_MAX
};

struct SubscribeOption {
    SubscribeMode mode;
    std::string event;
};

/**
 * @brief Indicates the column type.
 *
 * Value returned by getColumnType(int)
 */
enum class ColumnType {
    /** Indicates the column type is NULL.*/
    TYPE_NULL = 0,
    /** Indicates the column type is INTEGER.*/
    TYPE_INTEGER,
    /** Indicates the column type is FLOAT.*/
    TYPE_FLOAT,
    /** Indicates the column type is STRING.*/
    TYPE_STRING,
    /** Indicates the column type is BLOB.*/
    TYPE_BLOB,
    /** Indicates the column type is ASSET.*/
    TYPE_ASSET,
    /** Indicates the column type is ASSETS.*/
    TYPE_ASSETS,
    /** Indicates the column type is Float32.*/
    TYPE_FLOAT32_ARRAY,
    /** Indicates the column type is BigInt.*/
    TYPE_BIGINT
};

struct Origin {
    enum OriginType : int32_t {
        ORIGIN_LOCAL,
        ORIGIN_NEARBY,
        ORIGIN_CLOUD,
        ORIGIN_ALL,
        ORIGIN_BUTT,
    };
    enum DataType : int32_t {
        BASIC_DATA,
        ASSET_DATA,
        TYPE_BUTT,
    };
    int32_t origin = ORIGIN_ALL;
    int32_t dataType = BASIC_DATA;
    // origin is ORIGIN_LOCAL, the id is empty
    // origin is ORIGIN_NEARBY, the id is networkId;
    // origin is ORIGIN_CLOUD, the id is the cloud account id
    std::vector<std::string> id;
    std::string store;
};

class RdbStoreObserver {
public:
    enum ChangeType : int32_t {
        CHG_TYPE_INSERT = 0,
        CHG_TYPE_UPDATE,
        CHG_TYPE_DELETE,
        CHG_TYPE_BUTT
    };
    virtual ~RdbStoreObserver() {};
    using PrimaryKey = std::variant<std::monostate, std::string, int64_t, double>;
    using ChangeInfo = std::map<std::string, std::vector<PrimaryKey>[CHG_TYPE_BUTT]>;
    using PrimaryFields = std::map<std::string, std::string>;
    virtual void OnChange(const std::vector<std::string> &devices) = 0; // networkid
    virtual void OnChange(const Origin &origin, const PrimaryFields &fields, ChangeInfo &&changeInfo)
    {
        OnChange(origin.id);
    };
    virtual void OnChange() {};
};

struct DropOption {};

struct Field {
    static constexpr const char *CURSOR_FIELD = "#_cursor";
    static constexpr const char *ORIGIN_FIELD = "#_origin";
    static constexpr const char *DELETED_FLAG_FIELD = "#_deleted_flag";
    static constexpr const char *DATA_STATUS_FIELD = "#_data_status";
    static constexpr const char *OWNER_FIELD = "#_cloud_owner";
    static constexpr const char *PRIVILEGE_FIELD = "#_cloud_privilege";
    static constexpr const char *SHARING_RESOURCE_FIELD = "#_sharing_resource_field";
};

struct RdbChangeProperties {
    bool isTrackedDataChange = false;
    bool isP2pSyncDataChange = false;
    bool isKnowledgeDataChange = false;
};

struct RdbChangedData {
    std::map<std::string, RdbChangeProperties> tableData;
};

class SqlObserver {
public:
    struct SqlExecutionInfo {
        std::vector<std::string> sql_;
        int64_t totalTime_;
        int64_t waitTime_;
        int64_t prepareTime_;
        int64_t executeTime_;
    };
    virtual ~SqlObserver() = default;
    virtual void OnStatistic(const SqlExecutionInfo &info) = 0;
};

class SqlErrorObserver {
public:
    struct ExceptionMessage {
        int32_t code = 0;
        std::string message;
        std::string sql;
    };
    virtual ~SqlErrorObserver() = default;
    virtual void OnErrorLog(const ExceptionMessage &message) = 0;
};
} // namespace DistributedRdb
namespace NativeRdb {
struct Results {
    Results(int32_t count) : changed(count)
    {
    }
    int32_t changed = -1;
    NativeRdb::ValuesBuckets results;
};
} // namespace NativeRdb
} // namespace OHOS
#endif