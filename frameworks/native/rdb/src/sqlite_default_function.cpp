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
#define LOG_TAG "SqliteFunctionRegistry"

#include "sqlite_default_function.h"

#include <sys/stat.h>

#include <vector>

#include "logger.h"
#include "raw_data_parser.h"
#include "sqlite_connection.h"
#include "sqlite_errno.h"
#include "sqlite_utils.h"

#if !defined(CROSS_PLATFORM)
#include "relational/relational_store_sqlite_ext.h"
#endif

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

static constexpr int BACKUP_PAGES_PRE_STEP = 12800; // 1024 * 4 * 12800 == 50m
static constexpr int BACKUP_MAX_RETRY_COUNT = 10000;
static constexpr int BACKUP_MAX_TIME = 10000;
static constexpr int BACKUP_SLEEP_TIME = 1000;

void SqliteFunctionRegistry::MergeAssets(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    // 2 is the number of parameters
    if (ctx == nullptr || argc != 2 || argv == nullptr) {
        LOG_ERROR("Parameter does not meet restrictions. ctx: %{public}d, argc: %{public}d, argv: %{public}d",
            ctx == nullptr, argc, argv == nullptr);
        return;
    }
    std::map<std::string, ValueObject::Asset> assets;
    auto data = static_cast<const uint8_t *>(sqlite3_value_blob(argv[0]));
    if (data != nullptr) {
        int len = sqlite3_value_bytes(argv[0]);
        RawDataParser::ParserRawData(data, len, assets);
    }
    std::map<std::string, ValueObject::Asset> newAssets;
    data = static_cast<const uint8_t *>(sqlite3_value_blob(argv[1]));
    if (data != nullptr) {
        int len = sqlite3_value_bytes(argv[1]);
        RawDataParser::ParserRawData(data, len, newAssets);
    }
    CompAssets(assets, newAssets);
    auto blob = RawDataParser::PackageRawData(assets);
    sqlite3_result_blob(ctx, blob.data(), blob.size(), SQLITE_TRANSIENT);
}

void SqliteFunctionRegistry::MergeAsset(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    // 2 is the number of parameters
    if (ctx == nullptr || argc != 2 || argv == nullptr) {
        LOG_ERROR("Parameter does not meet restrictions. ctx: %{public}d, argc: %{public}d, argv: %{public}d",
            ctx == nullptr, argc, argv == nullptr);
        return;
    }
    ValueObject::Asset asset;
    size_t size = 0;
    auto data = static_cast<const uint8_t *>(sqlite3_value_blob(argv[0]));
    if (data != nullptr) {
        int len = sqlite3_value_bytes(argv[0]);
        size = RawDataParser::ParserRawData(data, len, asset);
    }
    ValueObject::Asset newAsset;
    data = static_cast<const uint8_t *>(sqlite3_value_blob(argv[1]));
    if (data != nullptr) {
        int len = sqlite3_value_bytes(argv[1]);
        RawDataParser::ParserRawData(data, len, newAsset);
    }

    if (size == 0) {
        asset = std::move(newAsset);
        if (asset.status != AssetValue::Status::STATUS_DELETE) {
            asset.status = AssetValue::Status::STATUS_INSERT;
        }
    } else if (asset.name == newAsset.name) {
        MergeAsset(asset, newAsset);
    } else {
        LOG_WARN("name change! old:%{public}s, new:%{public}s", SqliteUtils::Anonymous(asset.name).c_str(),
            SqliteUtils::Anonymous(newAsset.name).c_str());
    }
    auto blob = RawDataParser::PackageRawData(asset);
    sqlite3_result_blob(ctx, blob.data(), blob.size(), SQLITE_TRANSIENT);
}

void SqliteFunctionRegistry::CompAssets(
    std::map<std::string, ValueObject::Asset> &assets, std::map<std::string, ValueObject::Asset> &newAssets)
{
    auto oldIt = assets.begin();
    auto newIt = newAssets.begin();
    for (; oldIt != assets.end() && newIt != newAssets.end();) {
        if (oldIt->first == newIt->first) {
            MergeAsset(oldIt->second, newIt->second);
            oldIt++;
            newIt = newAssets.erase(newIt);
            continue;
        }
        if (oldIt->first < newIt->first) {
            ++oldIt;
            continue;
        }
        newIt++;
    }
    for (auto &[key, value] : newAssets) {
        value.status = ValueObject::Asset::Status::STATUS_INSERT;
        assets.insert(std::pair{ key, std::move(value) });
    }
}

void SqliteFunctionRegistry::MergeAsset(ValueObject::Asset &oldAsset, ValueObject::Asset &newAsset)
{
    using Status = ValueObject::Asset::Status;
    if (newAsset.status == Status::STATUS_DELETE) {
        oldAsset.status = Status::STATUS_DELETE;
        oldAsset.hash = "";
        oldAsset.modifyTime = "";
        oldAsset.size = "";
        return;
    }
    auto status = static_cast<int32_t>(oldAsset.status);
    switch (status) {
        case Status::STATUS_UNKNOWN:  // fallthrough
        case Status::STATUS_NORMAL:   // fallthrough
        case Status::STATUS_ABNORMAL: // fallthrough
        case Status::STATUS_INSERT:   // fallthrough
        case Status::STATUS_UPDATE:   // fallthrough
            if (oldAsset.modifyTime != newAsset.modifyTime || oldAsset.size != newAsset.size ||
                oldAsset.uri != newAsset.uri || oldAsset.path != newAsset.path) {
                if (oldAsset.modifyTime != newAsset.modifyTime || oldAsset.size != newAsset.size ||
                    oldAsset.uri == newAsset.uri || oldAsset.path == newAsset.path) {
                    oldAsset.expiresTime = newAsset.expiresTime;
                    oldAsset.hash = newAsset.hash;
                    oldAsset.status = Status::STATUS_UPDATE;
                }
                oldAsset.version = newAsset.version;
                oldAsset.uri = newAsset.uri;
                oldAsset.createTime = newAsset.createTime;
                oldAsset.modifyTime = newAsset.modifyTime;
                oldAsset.size = newAsset.size;
                oldAsset.path = newAsset.path;
            }
            return;
        default:
            return;
    }
}

void SqliteFunctionRegistry::ImportDB(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    if (ctx == nullptr || argc != 1 || argv == nullptr) {
        LOG_ERROR("Parameter does not meet restrictions. ctx: %{public}d, argc: %{public}d, argv: %{public}d",
            ctx == nullptr, argc, argv == nullptr);
        sqlite3_result_error(ctx, "invalid param", -1);
        sqlite3_result_error_code(ctx, SQLITE_ERROR);
        return;
    }
    std::string path;
    auto data = static_cast<const char *>(sqlite3_value_blob(argv[0]));
    if (data != nullptr) {
        path = std::string(data, sqlite3_value_bytes(argv[0]));
    }

    struct stat fileStat;
    if (stat(path.c_str(), &fileStat) != 0) {
        if (errno != ENOENT) {
            LOG_ERROR(
                "File stat error. path: %{public}s, error: %{public}d", SqliteUtils::Anonymous(path).c_str(), errno);
        }
        sqlite3_result_error(ctx, "backup failed", -1);
        sqlite3_result_error_code(ctx, SQLITE_CANTOPEN);
        return;
    }

    sqlite3 *sourceDbHandle = nullptr;
    int32_t errCode =
        sqlite3_open_v2(path.c_str(), &sourceDbHandle, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (errCode != SQLITE_OK) {
        LOG_ERROR(
            "Open db failed. path: %{public}s, error: %{public}d.", SqliteUtils::Anonymous(path).c_str(), errCode);
    }
    if (errCode != SQLITE_OK || (errCode = IntegrityCheck(sourceDbHandle)) != SQLITE_OK ||
        (errCode = BackUpDB(sourceDbHandle, sqlite3_context_db_handle(ctx))) != SQLITE_DONE) {
        LOG_ERROR("Error during backup. path: %{public}s, error: %{public}d", path.c_str(), errCode);
        sqlite3_close(sourceDbHandle);
        sqlite3_result_error(ctx, "backup failed", -1);
        sqlite3_result_error_code(ctx, errCode);
        return;
    }

    sqlite3_close(sourceDbHandle);
    sqlite3_result_null(ctx);
}

int32_t SqliteFunctionRegistry::IntegrityCheck(sqlite3 *dbHandle)
{
    int32_t errCode = SQLITE_OK;

    errCode = sqlite3_exec(
        dbHandle, "PRAGMA integrity_check",
        [](void *data, int argc, char **argv, char **colNames) -> int {
            if (argc > 0) {
                std::string result = argv[0] ? argv[0] : "";
                if (result == "ok") {
                    return 0;
                }
            }
            return 1;
        },
        nullptr, nullptr);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("Integrity check failed. error: %{public}d.", errCode);
        return SQLITE_CORRUPT;
    }
    return SQLITE_OK;
}

int32_t SqliteFunctionRegistry::BackUpDB(sqlite3 *source, sqlite3 *dest)
{
    sqlite3_backup *pBackup = sqlite3_backup_init(dest, "main", source, "main");
    if (pBackup == nullptr) {
        return SQLITE_BUSY;
    }

    int retryCount = 0;
    int32_t errCode = SQLITE_OK;

    auto startTime = std::chrono::steady_clock::now();
    do {
        errCode = sqlite3_backup_step(pBackup, BACKUP_PAGES_PRE_STEP);
        if (errCode == SQLITE_BUSY || errCode == SQLITE_LOCKED) {
            retryCount++;
        } else {
            retryCount = 0;
        }

        if (retryCount > BACKUP_MAX_RETRY_COUNT) {
            sqlite3_backup_finish(pBackup);
            return SQLITE_ERROR;
        }

        auto now = std::chrono::steady_clock::now();
        auto elapsedTime = now - startTime;
        if (std::chrono::duration_cast<std::chrono::milliseconds>(elapsedTime).count() > BACKUP_MAX_TIME) {
            startTime = now;
            sqlite3_sleep(BACKUP_SLEEP_TIME);
        }
    } while (sqlite3_backup_pagecount(pBackup) != 0 &&
             (errCode == SQLITE_OK || errCode == SQLITE_BUSY || errCode == SQLITE_LOCKED));
    (void)sqlite3_backup_finish(pBackup);
    if (errCode != SQLITE_DONE) {
        LOG_ERROR("Backup failed! error:%{public}d.", errCode);
    }
    return errCode;
}

} // namespace NativeRdb
} // namespace OHOS