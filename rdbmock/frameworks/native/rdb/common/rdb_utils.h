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

#ifndef RDB_UTILS_H
#define RDB_UTILS_H

#include <any>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace OHOS {
namespace Rdb {

/**
 * @brief RDB utility class providing common database operations
 */
class RdbUtils {
public:
    /**
     * @brief Default constructor
     */
    RdbUtils();

    /**
     * @brief Destructor
     */
    virtual ~RdbUtils();

    /**
     * @brief Initialize the utility with configuration
     * @param configPath Path to configuration file
     * @return 0 on success, error code otherwise
     */
    int Initialize(const std::string &configPath);

    /**
     * @brief Check if the utility is initialized
     * @return true if initialized, false otherwise
     */
    bool IsInitialized() const;

    /**
     * @brief Get the version of the utility
     * @return Version string
     */
    std::string GetVersion() const;

    /**
     * @brief Set the log level
     * @param level Log level (0-5)
     */
    void SetLogLevel(int level);

    /**
     * @brief Get the current log level
     * @return Current log level
     */
    int GetLogLevel() const;

    /**
     * @brief Register a callback for database events
     * @param eventType Type of event
     * @param callback Callback function
     * @return Registration ID
     */
    int RegisterCallback(
        const std::string &eventType, std::function<void(const std::map<std::string, std::any> &)> callback);

    /**
     * @brief Unregister a callback
     * @param registrationId Registration ID returned by RegisterCallback
     * @return 0 on success, error code otherwise
     */
    int UnregisterCallback(int registrationId);

    /**
     * @brief Execute a SQL statement
     * @param sql SQL statement
     * @param params Parameters for the SQL statement
     * @return Result as a vector of maps
     */
    std::vector<std::map<std::string, std::any>> ExecuteSql(
        const std::string &sql, const std::vector<std::any> &params = {});

    /**
     * @brief Begin a transaction
     * @return Transaction ID
     */
    int BeginTransaction();

    /**
     * @commit a transaction
     * @param transactionId Transaction ID
     * @return 0 on success, error code otherwise
     */
    int CommitTransaction(int transactionId);

    /**
     * @brief Rollback a transaction
     * @param transactionId Transaction ID
     * @return 0 on success, error code otherwise
     */
    int RollbackTransaction(int transactionId);

    /**
     * @brief Check if a table exists
     * @param tableName Table name
     * @return true if table exists, false otherwise
     */
    bool TableExists(const std::string &tableName);

    /**
     * @brief Get the schema of a table
     * @param tableName Table name
     * @return Map of column names to their types
     */
    std::map<std::string, std::string> GetTableSchema(const std::string &tableName);

    /**
     * @brief Backup the database
     * @param backupPath Path to save the backup
     * @return 0 on success, error code otherwise
     */
    int BackupDatabase(const std::string &backupPath);

    /**
     * @brief Restore the database from backup
     * @param backupPath Path to the backup file
     * @return 0 on success, error code otherwise
     */
    int RestoreDatabase(const std::string &backupPath);

    /**
     * @brief Get database statistics
     * @return Map of statistics
     */
    std::map<std::string, std::any> GetStatistics();

    /**
     * @brief Clear all data from the database
     * @return 0 on success, error code otherwise
     */
    int ClearDatabase();

    /**
     * @brief Export data to file
     * @param filePath Path to export file
     * @param format Export format (json, csv, xml)
     * @return 0 on success, error code otherwise
     */
    int ExportData(const std::string &filePath, const std::string &format = "json");

    /**
     * @brief Import data from file
     * @param filePath Path to import file
     * @param format Import format (json, csv, xml)
     * @return 0 on success, error code otherwise
     */
    int ImportData(const std::string &filePath, const std::string &format = "json");

    /**
     * @brief Get the last error message
     * @return Error message string
     */
    std::string GetLastError() const;

    /**
     * @brief Get the last error code
     * @return Error code
     */
    int GetLastErrorCode() const;

    /**
     * @brief Clear the last error
     */
    void ClearError();

    /**
     * @brief Set the database path
     * @param dbPath Path to the database file
     */
    void SetDatabasePath(const std::string &dbPath);

    /**
     * @brief Get the database path
     * @return Database path
     */
    std::string GetDatabasePath() const;

    /**
     * @brief Set the encryption key
     * @param key Encryption key
     * @return 0 on success, error code otherwise
     */
    int SetEncryptionKey(const std::string &key);

    /**
     * @brief Check if database is encrypted
     * @return true if encrypted, false otherwise
     */
    bool IsEncrypted() const;

    /**
     * @brief Set the maximum number of connections
     * @param maxConnections Maximum number of connections
     */
    void SetMaxConnections(int maxConnections);

    /**
     * @brief Get the maximum number of connections
     * @return Maximum number of connections
     */
    int GetMaxConnections() const;

    /**
     * @brief Get the current number of active connections
     * @return Number of active connections
     */
    int GetActiveConnections() const;

    /**
     * @brief Set the connection timeout
     * @param timeout Timeout in milliseconds
     */
    void SetConnectionTimeout(int timeout);

    /**
     * @brief Get the connection timeout
     * @return Timeout in milliseconds
     */
    int GetConnectionTimeout() const;

    /**
     * @brief Set the query timeout
     * @param timeout Timeout in milliseconds
     */
    void SetQueryTimeout(int timeout);

    /**
     * @brief Get the query timeout
     * @return Timeout in milliseconds
     */
    int GetQueryTimeout() const;

    /**
     * @brief Enable or disable query logging
     * @param enable true to enable, false to disable
     */
    void EnableQueryLogging(bool enable);

    /**
     * @brief Check if query logging is enabled
     * @return true if enabled, false otherwise
     */
    bool IsQueryLoggingEnabled() const;

    /**
     * @brief Get the query log
     * @return Vector of query log entries
     */
    std::vector<std::string> GetQueryLog() const;

    /**
     * @brief Clear the query log
     */
    void ClearQueryLog();

    /**
     * @brief Set the cache size
     * @param size Cache size in bytes
     */
    void SetCacheSize(size_t size);

    /**
     * @brief Get the cache size
     * @return Cache size in bytes
     */
    size_t GetCacheSize() const;

    /**
     * @brief Clear the cache
     */
    void ClearCache();

    /**
     * @brief Get the cache hit rate
     * @return Cache hit rate as a percentage
     */
    double GetCacheHitRate() const;

    /**
     * @brief Set the journal mode
     * @param mode Journal mode (delete, truncate, persist, memory, wal, off)
     */
    void SetJournalMode(const std::string &mode);

    /**
     * @brief Get the journal mode
     * @return Journal mode
     */
    std::string GetJournalMode() const;

    /**
     * @brief Set the synchronous mode
     * @param mode Synchronous mode (off, normal, full, extra)
     */
    void SetSynchronousMode(const std::string &mode);

    /**
     * @brief Get the synchronous mode
     * @return Synchronous mode
     */
    std::string GetSynchronousMode() const;

    /**
     * @brief Set the page size
     * @param size Page size in bytes
     */
    void SetPageSize(size_t size);

    /**
     * @brief Get the page size
     * @return Page size in bytes
     */
    size_t GetPageSize() const;

    /**
     * @brief Set the auto-vacuum mode
     * @param mode Auto-vacuum mode (none, full, incremental)
     */
    void SetAutoVacuumMode(const std::string &mode);

    /**
     * @brief Get the auto-vacuum mode
     * @return Auto-vacuum mode
     */
    std::string GetAutoVacuumMode() const;

    /**
     * @brief Run integrity check
     * @return true if database is intact, false otherwise
     */
    bool RunIntegrityCheck();

    /**
     * @brief Compact the database
     * @return 0 on success, error code otherwise
     */
    int CompactDatabase();

    /**
     * @brief Get the database size
     * @return Database size in bytes
     */
    size_t GetDatabaseSize() const;

    /**
     * @brief Get the number of tables
     * @return Number of tables
     */
    int GetTableCount() const;

    /**
     * @brief Get the list of tables
     * @return Vector of table names
     */
    std::vector<std::string> GetTableList() const;

    /**
     * @brief Get the number of rows in a table
     * @param tableName Table name
     * @return Number of rows
     */
    int GetRowCount(const std::string &tableName);

    /**
     * @brief Get the number of columns in a table
     * @param tableName Table name
     * @return Number of columns
     */
    int GetColumnCount(const std::string &tableName);

    /**
     * @brief Get the column names of a table
     * @param tableName Table name
     * @return Vector of column names
     */
    std::vector<std::string> GetColumnNames(const std::string &tableName);

    /**
     * @brief Get the column types of a table
     * @param tableName Table name
     * @return Map of column names to their types
     */
    std::map<std::string, std::string> GetColumnTypes(const std::string &tableName);

    /**
     * @brief Check if a column exists in a table
     * @param tableName Table name
     * @param columnName Column name
     * @return true if column exists, false otherwise
     */
    bool ColumnExists(const std::string &tableName, const std::string &columnName);

    /**
     * @brief Get the primary key columns of a table
     * @param tableName Table name
     * @return Vector of primary key column names
     */
    std::vector<std::string> GetPrimaryKeys(const std::string &tableName);

    /**
     * @brief Get the foreign keys of a table
     * @param tableName Table name
     * @return Map of foreign key columns to their referenced tables and columns
     */
    std::map<std::string, std::pair<std::string, std::string>> GetForeignKeys(const std::string &tableName);

    /**
     * @brief Get the indexes of a table
     * @param tableName Table name
     * @return Vector of index names
     */
    std::vector<std::string> GetIndexes(const std::string &tableName);

    /**
     * @brief Get the triggers of a table
     * @param tableName Table name
     * @return Vector of trigger names
     */
    std::vector<std::string> GetTriggers(const std::string &tableName);

    /**
     * @brief Get the views in the database
     * @return Vector of view names
     */
    std::vector<std::string> GetViews();

    /**
     * @brief Get the definition of a view
     * @param viewName View name
     * @return View definition SQL
     */
    std::string GetViewDefinition(const std::string &viewName);

    /**
     * @brief Create a savepoint
     * @param savepointName Savepoint name
     * @return 0 on success, error code otherwise
     */
    int CreateSavepoint(const std::string &savepointName);

    /**
     * @brief Release a savepoint
     * @param savepointName Savepoint name
     * @return 0 on success, error code otherwise
     */
    int ReleaseSavepoint(const std::string &savepointName);

    /**
     * @brief Rollback to a savepoint
     * @param savepointName Savepoint name
     * @return 0 on success, error code otherwise
     */
    int RollbackToSavepoint(const std::string &savepointName);

    /**
     * @brief Check if a savepoint exists
     * @param savepointName Savepoint name
     * @return true if savepoint exists, false otherwise
     */
    bool SavepointExists(const std::string &savepointName);

    /**
     * @brief Get the list of savepoints
     * @return Vector of savepoint names
     */
    std::vector<std::string> GetSavepoints();

    /**
     * @brief Set the busy timeout
     * @param timeout Timeout in milliseconds
     */
    void SetBusyTimeout(int timeout);

    /**
     * @brief Get the busy timeout
     * @return Timeout in milliseconds
     */
    int GetBusyTimeout() const;

    /**
     * @brief Set the locking mode
     * @param mode Locking mode (normal, exclusive)
     */
    void SetLockingMode(const std::string &mode);

    /**
     * @brief Get the locking mode
     * @return Locking mode
     */
    std::string GetLockingMode() const;

    /**
     * @brief Set the temp store
     * @param store Temp store (default, file, memory)
     */
    void SetTempStore(const std::string &store);

    /**
     * @brief Get the temp store
     * @return Temp store
     */
    std::string GetTempStore() const;

    /**
     * @brief Set the mmap size
     * @param size Mmap size in bytes
     */
    void SetMmapSize(size_t size);

    /**
     * @brief Get the mmap size
     * @return Mmap size in bytes
     */
    size_t GetMmapSize() const;

    /**
     * @brief Set the cache spilling
     * @param enable true to enable, false to disable
     */
    void SetCacheSpilling(bool enable);

    /**
     * @brief Check if cache spilling is enabled
     * @return true if enabled, false otherwise
     */
    bool IsCacheSpillingEnabled() const;

    /**
     * @brief Set the secure delete mode
     * @param mode Secure delete mode (0, 1, 2)
     */
    void SetSecureDeleteMode(int mode);

    /**
     * @brief Get the secure delete mode
     * @return Secure delete mode
     */
    int GetSecureDeleteMode() const;

    /**
     * @brief Set the case sensitive like
     * @param enable true to enable, false to disable
     */
    void SetCaseSensitiveLike(bool enable);

    /**
     * @brief Check if case sensitive like is enabled
     * @return true if enabled, false otherwise
     */
    bool IsCaseSensitiveLikeEnabled() const;

    /**
     * @brief Set the count changes
     * @param enable true to enable, false to disable
     */
    void SetCountChanges(bool enable);

    /**
     * @brief Check if count changes is enabled
     * @return true if enabled, false otherwise
     */
    bool IsCountChangesEnabled() const;

    /**
     * @brief Set the default cache size
     * @param size Cache size in pages
     */
    void SetDefaultCacheSize(int size);

    /**
     * @brief Get the default cache size
     * @return Cache size in pages
     */
    int GetDefaultCacheSize() const;

    /**
     * @brief Set the legacy file format
     * @param enable true to enable, false to disable
     */
    void SetLegacyFileFormat(bool enable);

    /**
     * @brief Check if legacy file format is enabled
     * @return true if enabled, false otherwise
     */
    bool IsLegacyFileFormatEnabled() const;

    /**
     * @brief Set the recursive triggers
     * @param enable true to enable, false to disable
     */
    void SetRecursiveTriggers(bool enable);

    /**
     * @brief Check if recursive triggers is enabled
     * @return true if enabled, false otherwise
     */
    bool IsRecursiveTriggersEnabled() const;

    /**
     * @brief Set the reverse unordered selects
     * @param enable true to enable, false to disable
     */
    void SetReverseUnorderedSelects(bool enable);

    /**
     * @brief Check if reverse unordered selects is enabled
     * @return true if enabled, false otherwise
     */
    bool IsReverseUnorderedSelectsEnabled() const;

    /**
     * @brief Set the short column names
     * @param enable true to enable, false to disable
     */
    void SetShortColumnNames(bool enable);

    /**
     * @brief Check if short column names is enabled
     * @return true if enabled, false otherwise
     */
    bool IsShortColumnNamesEnabled() const;

    /**
     * @brief Set the user version
     * @param version User version
     */
    void SetUserVersion(int version);

    /**
     * @brief Get the user version
     * @return User version
     */
    int GetUserVersion() const;

    /**
     * @brief Set the schema version
     * @param version Schema version
     */
    void SetSchemaVersion(int version);

    /**
     * @brief Get the schema version
     * @return Schema version
     */
    int GetSchemaVersion() const;

    /**
     * @brief Set the data version
     * @param version Data version
     */
    void SetDataVersion(int version);

    *@brief Get the data version *@ return Data version * / int GetDataVersion() const;

    /**
     * @brief Set the application ID
     * @param appId Application ID
     */
    void SetApplicationId(int appId);

    /**
     * @brief Get the application ID
     * @return Application ID
     */
    int GetApplicationId() const;

    /**
     * @brief Set the text encoding
     * @param encoding Text encoding (utf8, utf16, utf16le, utf16be)
     */
    void SetTextEncoding(const std::string &encoding);

    *@brief Get the text encoding *@ return Text encoding * / std::string GetTextEncoding() const;

    /**
     * @brief Set the compile options
     * @param options Vector of compile options
     */
    void SetCompileOptions(const std::vector<std::string> &options);

    /**
     * @brief Get the compile options
     * @return Vector of compile options
     */
    std::vector<std::string> GetCompileOptions() const;

    /**
     * @brief Get the database status
     * @return Map of status information
     */
    std::map<std::string, std::any> GetDatabaseStatus();

    /**
     * @brief Get the connection pool status
     * @return Map of connection pool status
     */
    std::map<std::string, std::any> GetConnectionPoolStatus();

    /**
     * @brief Get the query cache status
     * @return Map of query cache status
     */
    std::map<std::string, std::any> GetQueryCacheStatus();

    /**
     * @brief Get the transaction status
     * @return Map of transaction status
     */
    std::map<std::string, std::any> GetTransactionStatus();

    /**
     * @brief Get the lock status
     * @return Map of lock status
     */
    std::map<std::string, std::any> GetLockStatus();

    /**
     * @brief Get the memory usage
     * @return Map of memory usage information
     */
    std::map<std::string, std::any> GetMemoryUsage();

    /**
     * @brief Get the I/O statistics
     * @return Map of I/O statistics
     */
    std::map<std::string, std::any> GetIOStatistics();

    /**
     * @brief Get the performance metrics
     * @return Map of performance metrics
     */
    std::map<std::string, std::any> GetPerformanceMetrics();

    /**
     * @brief Reset performance metrics
     */
    void ResetPerformanceMetrics();

    /**
     * @brief Get the query execution plan
     * @param sql SQL statement
     * @return Execution plan as a string
     */
    std::string GetQueryExecutionPlan(const std::string &sql);

    /**
     * @brief Analyze a query
     * @param sql SQL statement
     * @return Analysis result as a map
     */
    std::map<std::string, std::any> AnalyzeQuery(const std::string &sql);

    /**
     * @brief Optimize the database
     * @return 0 on success, error code otherwise
     */
    int OptimizeDatabase();

    /**
     * @brief Reindex the database
     * @return 0 on success, error code otherwise
     */
    int ReindexDatabase();

    /**
     * @brief Reindex a table
     * @param tableName Table name
     * @return 0 on success, error code otherwise
     */
    int ReindexTable(const std::string &tableName);

    /**
     * @brief Reindex an index
     * @param indexName Index name
     * @return 0 on success, error code otherwise
     */
    int ReindexIndex(const std::string &indexName);

    /**
     * @brief Analyze the database
     * @return 0 on success, error code otherwise
     */
    int AnalyzeDatabase();

    /**
     * @brief Analyze a table
     * @param tableName Table name
     * @return 0 on success, error code otherwise
     */
    int AnalyzeTable(const std::string &tableName);

    /**
     * @brief Analyze an index
     * @param indexName Index name
     * @return 0 on success, error code otherwise
     */
    int AnalyzeIndex(const std::string &indexName);

    /**
     * @brief Check if the database is read-only
     * @return true if read-only, false otherwise
     */
    bool IsReadOnly() const;

    /**
     * @brief Set the database to read-only
     * @param readOnly true to set read-only, false otherwise
     */
    void SetReadOnly(bool readOnly);

    /**
     * @brief Check if the database is in memory
     * @return true if in memory, false otherwise
     */
    bool IsInMemory() const;

    /**
     * @brief Set the database to in-memory
     * @param inMemory true to set in-memory, false otherwise
     */
    void SetInMemory(bool inMemory);

    /**
     * @brief Check if the database is temporary
     * @return true if temporary, false otherwise
     */
    bool IsTemporary() const;

    /**
     * @brief Set the database to temporary
     * @param temporary true to set temporary, false otherwise
     */
    void SetTemporary(bool temporary);

    /**
     * @brief Check if the database is shared
     * @return true if shared, false otherwise
     */
    bool IsShared() const;

    /**
     * @brief Set the database to shared
     * @param shared true to set shared, false otherwise
     */
    void SetShared(bool shared);

    /**
     * @brief Check if the database is attached
     * @return true if attached, false otherwise
     */
    bool IsAttached() const;

    /**
     * @brief Attach a database
     * @param dbPath Database path
     * @param alias Database alias
     * @return 0 on success, error code otherwise
     */
    int AttachDatabase(const std::string &dbPath, const std::string &alias);

    /**
     * @brief Detach a database
     * @param alias Database alias
     * @return 0 on success, error code otherwise
     */
    int DetachDatabase(const std::string &alias);

    /**
     * @brief Get the list of attached databases
     * @return Vector of database aliases
     */
    std::vector<std::string> GetAttachedDatabases();

    /**
     * @brief Get the main database name
     * @return Main database name
     */
    std::string GetMainDatabaseName() const;

    /**
     * @brief Get the temp database name
     * @return Temp database name
     */
    std::string GetTempDatabaseName() const;

    /**
     * @brief Check if a database is attached
     * @param alias Database alias
     * @return true if attached, false otherwise
     */
    bool IsDatabaseAttached(const std::string &alias);

    /**
     * @brief Get the database path for an alias
     * @param alias Database alias
     * @return Database path
     */
    std::string GetDatabasePathForAlias(const std::string &alias);

    /**
     * @brief Get the database alias for a path
     * @param dbPath Database path
     * @return Database alias
     */
    std::string GetDatabaseAliasForPath(const std::string &dbPath);

    /**
     * @brief Get the list of all databases
     * @return Vector of database information maps
     */
    std::vector<std::map<std::string, std::any>> GetAllDatabases();

    /**
     * @brief Get the database information
     * @param alias Database alias
     * @return Map of database information
     */
    std::map<std::string, std::any> GetDatabaseInfo(const std::string &alias);

    /**
     * @brief Get the database configuration
     * @return Map of configuration
     */
    std::map<std::string, std::any> GetDatabaseConfig();

    /**
     * @brief Set the database configuration
     * @param config Map of configuration
     * @return 0 on success, error code otherwise
     */
    int SetDatabaseConfig(const std::map<std::string, std::any> &config);

    /**
     * @brief Reset the database configuration
     * @return 0 on success, error code otherwise
     */
    int ResetDatabaseConfig();

    /**
     * @brief Get the default configuration
     * @return Map of default configuration
     */
    std::map<std::string, std::any> GetDefaultConfig();

    /**
     * @brief Validate the configuration
     * @param config Map of configuration
     * @return true if valid, false otherwise
     */
    bool ValidateConfig(const std::map<std::string, std::any> &config);

    /**
     * @brief Merge configurations
     * @param base Base configuration
     * @param override Config to override
     * @return Merged configuration
     */
    std::map<std::string, std::any> MergeConfigs(
        const std::map<std::string, std::any> &base, const std::map<std::string, std::any> &override);

    /**
     * @brief Export configuration to file
     * @param filePath Path to export file
     * @return 0 on success, error code otherwise
     */
    int ExportConfig(const std::string &filePath);

    /**
     * @brief Import configuration from file
     * @param filePath Path to import file
     * @return 0 on success, error code otherwise
     */
    int ImportConfig(const std::string &filePath);

    /**
     * @brief Get the configuration schema
     * @return Map of configuration schema
     */
    std::map<std::string, std::any> GetConfigSchema();

    /**
     * @brief Get the configuration defaults
     * @return Map of configuration defaults
     */
    std::map<std::string, std::any> GetConfigDefaults();

    /**
     * @brief Get the configuration validation rules
     * @return Map of validation rules
     */
    std::map<std::string, std::any> GetConfigValidationRules();

    /**
     * @brief Get the configuration documentation
     * @return Map of configuration documentation
     */
    std::map<std::string, std::any> GetConfigDocumentation();

    /**
     * @brief Get the configuration examples
     * @return Vector of example configurations
     */
    std::vector<std::map<std::string, std::any>> GetConfigExamples();

    /**
     * @brief Get the configuration templates
     * @return Map of configuration templates
     */
    std::map<std::string, std::map<std::string, std::any>> GetConfigTemplates();

    /**
     * @brief Apply a configuration template
     * @param templateName Template name
     * @return 0 on success, error code otherwise
     */
    int ApplyConfigTemplate(const std::string &templateName);

    /**
     * @brief Create a configuration template
     * @param templateName Template name
     * @param config Map of configuration
     * @return 0 on success, error code otherwise
     */
    int CreateConfigTemplate(const std::string &templateName, const std::map<std::string, std::any> &config);

    /**
     * @brief Delete a configuration template
     * @param templateName Template name
     * @return 0 on success, error code otherwise
     */
    int DeleteConfigTemplate(const std::string &templateName);

    /**
     * @brief Get the list of configuration templates
     * @return Vector of template names
     */
    std::vector<std::string> GetConfigTemplateList();

    /**
     * @brief Check if a configuration template exists
     * @param templateName Template name
     * @return true if exists, false otherwise
     */
    bool ConfigTemplateExists(const std::string &templateName);

    /**
     * @brief Get the configuration template
     * @param templateName Template name
     * @return Map of configuration
     */
    std::map<std::string, std::any> GetConfigTemplate(const std::string &templateName);

    /**
     * @brief Update a configuration template
     * @param templateName Template name
     * @param config Map of configuration
     * @return 0 on success, error code otherwise
     */
    int UpdateConfigTemplate(const std::string &templateName, const std::map<std::string, std::any> &config);

    /**
     * @brief Get the configuration template schema
     * @return Map of template schema
     */
    std::map<std::string, std::any> GetConfigTemplateSchema();

    /**
     * @brief Get the configuration template defaults
     * @return Map of template defaults
     */
    std::map<std::string, std::any> GetConfigTemplateDefaults();

    /**
     * @brief Get the configuration template validation rules
     * @return Map of validation rules
     */
    std::map<std::string, std::any> GetConfigTemplateValidationRules();

    /**
     * @brief Get the configuration template documentation
     * @return Map of template documentation
     */
    std::map<std::string, std::any> GetConfigTemplateDocumentation();

    /**
     * @brief Get the configuration template examples
     * @return Vector of example templates
     */
    std::vector<std::map<std::string, std::any>> GetConfigTemplateExamples();

    /**
     * @brief Get the configuration template categories
     * @return Vector of categories
     */
    std::vector<std::string> GetConfigTemplateCategories();

    /**
     * @brief Get the configuration template tags
     * @return Vector of tags
     */
    std::vector<std::string> GetConfigTemplateTags();

    /**
     * @brief Search configuration templates
     * @param query Search query
     * @return Vector of matching templates
     */
    std::vector<std::map<std::string, std::any>> SearchConfigTemplates(const std::string &query);

    /**
     * @brief Get the configuration template statistics
     * @return Map of statistics
     */
    std::map<std::string, std::any> GetConfigTemplateStatistics();

    /**
     * @brief Get the configuration template usage
     * @return Map of usage information
     */
    std::map<std::string, std::any> GetConfigTemplateUsage();

    /**
     * @brief Get the configuration template history
     * @return Vector of history entries
     */
    std::vector<std::map<std::string, std::any>> GetConfigTemplateHistory();

    /**
     * @brief Get the configuration template versions
     * @param templateName Template name
     * @return Vector of versions
     */
    std::vector<std::string> GetConfigTemplateVersions(const std::string &templateName);

    /**
     * @brief Get the configuration template version
     * @param templateName Template name
     * @param version Version
     * @return Map of configuration
     */
    std::map<std::string, std::any> GetConfigTemplateVersion(
        const std::string &templateName, const std::string &version);

    /**
     * @brief Create a configuration template version
     * @param templateName Template name
     * @param version Version
     * @param config Map of configuration
     * @return 0 on success, error code otherwise
     */
    int CreateConfigTemplateVersion(
        const std::string &templateName, const std::string &version, const std::map<std::string, std::any> &config);

    /**
     * @brief Delete a configuration template version
     * @param templateName Template name
     * @param version Version
     * @return 0 on success, error code otherwise
     */
    int DeleteConfigTemplateVersion(const std::string &templateName, const std::string &version);

    /**
     * @brief Get the latest configuration template version
     * @param templateName Template name
     * @return Version string
     */
    std::string GetLatestConfigTemplateVersion(const std::string &templateName);

    /**
     * @brief Check if a configuration template version exists
     * @param templateName Template name
     * @param version Version
     * @return true if exists, false otherwise
     */
    bool ConfigTemplateVersionExists(const std::string &templateName, const std::string &version);

    /**
     * @brief Compare configuration template versions
     * @param templateName Template name
     * @param version1 First version
     * @param version2 Second version
     * @return Map of differences
     */
    std::map<std::string, std::any> CompareConfigTemplateVersions(
        const std::string &templateName, const std::string &version1, const std::string &version2);

    /**
     * @brief Merge configuration template versions
     * @param templateName Template name
     * @param version1 First version
     * @param version2 Second version
     * @return Merged configuration
     */
    std::map<std::string, std::any> MergeConfigTemplateVersions(
        const std::string &templateName, const std::string &version1, const std::string &version2);

    /**
     * @brief Get the configuration template version schema
     * @return Map of version schema
     */
    std::map<std::string, std::any> GetConfigTemplateVersionSchema();

    /**
     * @brief Get the configuration template version defaults
     * @return Map of version defaults
     */
    std::map<std::string, std::any> GetConfigTemplateVersionDefaults();

    /**
     * @brief Get the configuration template version validation rules
     * @return Map of validation rules
     */
    std::map<std::string, std::any> GetConfigTemplateVersionValidationRules();

    /**
     * @brief Get the configuration template version documentation
     * @return Map of version documentation
     */
    std::map<std::string, std::any> GetConfigTemplateVersionDocumentation();

    /**
     * @brief Get the configuration template version examples
     * @return Vector of version examples
     */
    std::vector<std::map<std::string, std::any>> GetConfigTemplateVersionExamples();

    /**
     * @brief Get the configuration template version categories
     * @return Vector of categories
     */
    std::vector<std::string> GetConfigTemplateVersionCategories();

    /**
     * @brief Get the configuration template version tags
     * @return Vector of tags
     */
    std::vector<std::string> GetConfigTemplateVersionTags();

    /**
     * @brief Search configuration template versions
     * @param templateName Template name
     * @param query Search query
     * @return Vector of matching versions
     */
    std::vector<std::map<std::string, std::any>> SearchConfigTemplateVersions(
        const std::string &templateName, const std::string &query);

    /**
     * @brief Get the configuration template version statistics
     * @return Map of statistics
     */
    std::map<std::string, std::any> GetConfigTemplateVersionStatistics();

    /**
     * @brief Get the configuration template version usage
     * @return Map of usage information
     */
    std::map<std::string, std::any> GetConfigTemplateVersionUsage();

    /**
     * @brief Get the configuration template version history
     * @return Vector of history entries
     */
    std::vector<std::map<std::string, std::any>> GetConfigTemplateVersionHistory();

private:
    // Private implementation details
    class Impl;
    std::unique_ptr<Impl> pImpl;

    // Internal helper methods
    int ValidateParameters(const std::map<std::string, std::any> &params);
    std::string FormatErrorMessage(const std::string &message, int errorCode);
    void LogMessage(int level, const std::string &message);
    void UpdateStatistics(const std::string &operation, double duration);
    void ClearInternalState();
    int CheckDatabaseConnection();
    int EnsureDatabaseInitialized();
    void NotifyCallbacks(const std::string &eventType, const std::map<std::string, std::any> &eventData);
    std::string SanitizeInput(const std::string &input);
    bool ValidateTableName(const std::string &tableName);
    bool ValidateColumnName(const std::string &columnName);
    bool ValidateSqlStatement(const std::string &sql);
    std::vector<std::any> ConvertParams(const std::vector<std::string> &params);
    std::string EscapeString(const std::string &input);
    std::string UnescapeString(const std::string &input);
    std::vector<uint8_t> SerializeData(const std::map<std::string, std::any> &data);
    std::map<std::string, std::any> DeserializeData(const std::vector<uint8_t> &data);
    std::string ComputeHash(const std::string &data);
    bool VerifyHash(const std::string &data, const std::string &hash);
    std::string GenerateUUID();
    std::chrono::system_clock::time_point GetCurrentTime();
    std::string FormatTime(const std::chrono::system_clock::time_point &time);
    std::chrono::system_clock::time_point ParseTime(const std::string &timeStr);
    size_t GetAvailableMemory();
    size_t GetUsedMemory();
    double GetCpuUsage();
    std::map<std::string, std::any> GetSystemInfo();
    void PerformGarbageCollection();
    void OptimizeMemoryUsage();
    void UpdateCacheStatistics();
    void LogPerformanceMetrics();
    void HandleError(int errorCode, const std::string &message);
    void ClearErrorState();
    void UpdateConnectionPool();
    void CleanupIdleConnections();
    void ValidateConnectionPool();
    void MonitorConnectionHealth();
    void UpdateQueryCache();
    void InvalidateQueryCache();
    void CleanupQueryCache();
    void OptimizeQueryCache();
    void UpdateTransactionState();
    void CleanupTransactions();
    void ValidateTransactions();
    void MonitorTransactionHealth();
    void UpdateLockState();
    void CleanupLocks();
    void ValidateLocks();
    void MonitorLockHealth();
    void UpdateMemoryState();
    void CleanupMemory();
    void ValidateMemory();
    void MonitorMemoryHealth();
    void UpdateIOState();
    void CleanupIO();
    void ValidateIO();
    void MonitorIOHealth();
    void UpdatePerformanceState();
    void CleanupPerformance();
    void ValidatePerformance();
    void MonitorPerformanceHealth();
};

} // namespace Rdb
} // namespace OHOS

#endif // RDB_UTILS_H