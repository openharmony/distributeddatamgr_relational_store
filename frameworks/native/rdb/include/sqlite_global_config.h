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

#ifndef NATIVE_RDB_SQLITE_GLOBAL_CONFIG_H
#define NATIVE_RDB_SQLITE_GLOBAL_CONFIG_H

#include <string>

#include "rdb_store_config.h"

namespace OHOS {
namespace NativeRdb {

class GlobalExpr {
public:
    static constexpr bool CALLBACK_LOG_SWITCH = true;                  /* Sqlite callback log switch */
    static constexpr int SOFT_HEAP_LIMIT = 8 * 1024 * 1024;            /* 8MB */
    static constexpr int DB_PAGE_SIZE = 4096;                          /* default page size : 4k */
    static constexpr int DB_JOURNAL_SIZE = 1024 * 1024;                /* default file size : 1M */
    static constexpr int CLEAR_MEMORY_SIZE = 1024 * 1024;              /* default file size : 1M */
    static constexpr ssize_t DB_WAL_SIZE_LIMIT_MIN = 20 * 1024 * 1024; /* default wal file maximum size : 20M */
    static constexpr ssize_t DB_WAL_WARNING_SIZE = 256 * 1024 * 1024;  /* default wal file maximum size : 256M */
    static constexpr ssize_t DB_WAL_DEFAULT_SIZE = 0x20000000;         /* default wal file size 512M */
    static constexpr ssize_t DB_WAL_SIZE_LIMIT_MAX = 0x7FFFFFFF;       /* default wal file maximum size : 2G - 1 */
    static constexpr int WAL_AUTO_CHECKPOINT = 100;                    /* 100 pages */
    static constexpr int APP_DEFAULT_UMASK = 0002;
    static constexpr int SQLITE_MAX_COLUMN = 2000;
    static constexpr char ATTACH_BACKUP_SQL[] = "ATTACH ? AS backup KEY ?";
    static constexpr char ATTACH_WITH_KEY_SQL[] = "ATTACH DATABASE ? AS ? KEY ?";
    static constexpr char ATTACH_SQL[] = "ATTACH DATABASE ? AS ?";
    static constexpr char DETACH_SQL[] = "DETACH DATABASE ?";
    static constexpr char EXPORT_SQL[] = "SELECT export_database('backup')";
    static constexpr char DETACH_BACKUP_SQL[] = "detach backup";
    static constexpr char PRAGMA_JOUR_MODE_EXP[] = "PRAGMA journal_mode";
    static constexpr char PRAGMA_BACKUP_JOUR_MODE_WAL[] = "PRAGMA backup.journal_mode=WAL";
    static constexpr char PRAGMA_VERSION[] = "PRAGMA user_version";
    static constexpr char JOURNAL_MODE_WAL[] = "WAL";
    static constexpr char DEFAULE_SYNC_MODE[] = "FULL";
    static constexpr char MEMORY_DB_PATH[] = ":memory:";
    static constexpr char SHARED_MEMORY_DB_PATH_PREFIX[] = "file:";
    static constexpr char SHARED_MEMORY_DB_PATH_SUFFIX[] = "?mode=memory&cache=shared";
    static constexpr char CODEC_HMAC_ALGO[] = "PRAGMA codec_hmac_algo=sha256";
    static constexpr char CODEC_HMAC_ALGO_PREFIX[] = "PRAGMA codec_hmac_algo='";
    static constexpr char CODEC_KDF_ALGO_PREFIX[] = "PRAGMA codec_kdf_algo='";
    static constexpr char CODEC_PAGE_SIZE_PREFIX[] = "PRAGMA codec_page_size=";
    static constexpr char CODEC_REKEY_HMAC_ALGO[] = "PRAGMA codec_rekey_hmac_algo=sha256";
    static constexpr char CIPHER_DEFAULT_ALGO[] = "PRAGMA codec_cipher='aes-256-gcm'";
    static constexpr char CIPHER_ALGO_PREFIX[] = "PRAGMA codec_cipher='";
    static constexpr char ALGO_SUFFIX[] = "'";
    static constexpr char CIPHER_KDF_ITER[] = "PRAGMA codec_kdf_iter=";
    static constexpr char CIPHER_DEFAULT_ATTACH_HMAC_ALGO[] = "PRAGMA cipher_default_attach_hmac_algo=sha256";
    static constexpr char CIPHER_DEFAULT_ATTACH_CIPHER_PREFIX[] = "PRAGMA cipher_default_attach_cipher='";
    static constexpr char CIPHER_DEFAULT_ATTACH_HMAC_ALGO_PREFIX[] = "PRAGMA cipher_default_attach_hmac_algo='";
    static constexpr char CIPHER_DEFAULT_ATTACH_KDF_ALGO_PREFIX[] = "PRAGMA cipher_default_attach_kdf_algo='";
    static constexpr char CIPHER_DEFAULT_ATTACH_PAGE_SIZE_PREFIX[] = "PRAGMA cipher_default_attach_page_size=";
    static constexpr char CIPHER_DEFAULT_ATTACH_KDF_ITER_PREFIX[] = "PRAGMA cipher_default_attach_kdf_iter=";
    static constexpr char PRAGMA_META_DOUBLE_WRITE[] = "PRAGMA meta_double_write=enabled";
};

class SqliteGlobalConfig {
public:
    SqliteGlobalConfig();
    ~SqliteGlobalConfig();
    static void InitSqliteGlobalConfig();
    static void Log(const void *data, int err, const char *msg);
    static std::string GetMemoryDbPath();
    static std::string GetSharedMemoryDbPath(const std::string &name);
    static int GetPageSize();
    static std::string GetSyncMode();
    static int GetJournalFileSize();
    static int GetWalAutoCheckpoint();
    static std::string GetDefaultJournalMode();
    static int GetDbPath(const RdbStoreConfig &config, std::string &dbPath);
    static void Corruption(void *arg, const void *msg);
    static std::string GetLastCorruptionMsg();

private:
    static void SqliteErrReport(int err, const char *msg);
};

} // namespace NativeRdb
} // namespace OHOS

#endif
