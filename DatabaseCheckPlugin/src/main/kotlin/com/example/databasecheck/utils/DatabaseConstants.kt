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
 
package com.example.databasecheck.utils

/**
 * Constants for database robustness rule checking
 */
object DatabaseConstants {
    
    // Database paths that need to be monitored
    val DATABASE_PATHS = listOf(
        // Dynamic path from context
        Regex("""context\.databaseDir"""),
        
        // Static storage paths
        Regex("""/data/storage/el[1-5]/database/?.*"""),
        Regex("""/data/storage/el[1-5]/database/[^/]+/?.*"""),
        
        // App-specific paths  
        Regex("""/data/app/el[1-5]/[^/]+/database/[^/]+/?.*"""),
        Regex("""/data/app/el[1-5]/[^/]+/database/[^/]+/[^/]+/?.*"""),
        
        // Service paths
        Regex("""/data/service/el[1-4]/public/database/[^/]+/?.*"""),
        Regex("""/data/service/el[1-4]/[^/]+/database/[^/]+/?.*""")
    )
    
    // Rule 1: Prohibited file operations on database paths
    // Note: Order matters - more specific operations should be checked first
    val PROHIBITED_FILE_OPERATIONS = listOf(
        // Specific module operations (higher priority)
        "fileIo.open", "fileIo.close", "fileIo.openSync", "fileIo.closeSync",
        "fs.open", "fs.close", "fs.openSync", "fs.closeSync",
        // Generic operations (lower priority)
        "fopen", "fclose", "open", "close", "fcntl", "ftruncate", "flock", "iostream"
    )
    
    // Rule 2: File copy operations that need special handling
    val FILE_COPY_OPERATIONS = setOf(
        "fileIo.copyFile", "fileIo.copyFileSync", "fileIo.copyDir", "fileIo.copyDirSync",
        "fileIo.moveFile", "fileIo.moveFileSync", "fileIo.moveDir", "fileIo.moveDirSync",
        "fs.copyFile", "fs.copyFileSync", "fs.cp", "fs.cpSync"
    )
    
    // Rule 2: Safe RDB operations for database backup/restore
    val SAFE_RDB_OPERATIONS = setOf(
        "rdbStore.backup", "rdbStore.restore", "rdbStore.clone"
    )
    
    // Rule 2: Database directory patterns that should be excluded from backup
    val DATABASE_EXCLUDE_PATTERNS = listOf(
        "data/storage/el1/database/",
        "data/storage/el2/database/",
        "data/storage/el3/database/",
        "data/storage/el4/database/",
        "data/storage/el5/database/"
    )
    
    // Rule 3, 4, 5: Transaction operations
    val TRANSACTION_CREATE_OPERATIONS = setOf(
        "rdbStore.createTransaction", "rdbStore.beginTransaction"
    )
    
    val TRANSACTION_COMMIT_OPERATIONS = setOf(
        "commit", "rollback"
    )
    
    // Rule 3: Database CRUD operations that are allowed in transactions
    val DATABASE_CRUD_OPERATIONS = setOf(
        "insert", "batchInsert", "update", "delete", "execute", "executeSql", "query"
    )
    
    // Rule 3: Prohibited operations in transactions (time-consuming operations)
    val PROHIBITED_TRANSACTION_OPERATIONS = setOf(
        "ipc", "download", "upload", "fetch", "socket", "rpc", "remote",
        "http", "request", "ajax", "websocket", "tcp", "udp"
    )
    
    // Rule 6: Database deletion operations
    val DATABASE_DELETE_OPERATIONS = setOf(
        "deleteRdbStore", "data_relationalStore.deleteRdbStore"
    )
    
    // Rule 7: Permission change operations
    val PERMISSION_OPERATIONS = setOf(
        "fileIo.chmod", "fileIo.chmodSync", "chmod"
    )
    
    // Rule 9: Database error codes that need special handling
    val DATABASE_ERROR_CODES = setOf(
        14800047, 14800024, 14800025, 14800028, 14800029
    )
    
    // Rule 12: Prohibited pragma operations
    val PROHIBITED_PRAGMA_OPERATIONS = setOf(
        "PRAGMA journal_mode = OFF",
        "PRAGMA schema_version =",
        "PRAGMA synchronous=OFF", 
        "PRAGMA synchronous = OFF",
        "PRAGMA journal_mode = MEMORY",
        "PRAGMA writable_schema = ON"
    )
    
    // Rule 14: Database configuration parameters that must be consistent
    val DATABASE_CONFIG_PARAMS = setOf(
        "name", "securityLevel", "encrypt", "isReadOnly", "customDir"
    )
}