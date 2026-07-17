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
 
// Rule 12 Test File: Should NOT trigger SQLite pragma restriction violations
// Safe database operations without prohibited PRAGMA statements

// ========== These should NOT trigger Rule 12 warnings ==========

// Correct 1: Standard database creation without pragma (from specification positive example)
async function CreateRdbStore(context) {
    const config = {
        "name": STORE_NAME,
        securityLevel: relationalStore.SecurityLevel.S3,
    }
    var rdbStore = undefined;
    try {
        rdbStore = await relationalStore.getRdbStore(context, config);
    } catch (err) {
        console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
    }
    return rdbStore
}

// Correct 2: Safe PRAGMA operations (allowed pragmas)
async function safePragmaOperations() {
    try {
        // These are safe pragma operations
        await rdbStore?.execute('PRAGMA table_info(users)');
        await rdbStore?.execute('PRAGMA foreign_key_list(users)');
        await rdbStore?.execute('PRAGMA index_list(users)');
        await rdbStore?.execute('PRAGMA database_list');
    } catch (err) {
        console.error("Safe pragma operations failed:", err);
    }
}

// Correct 3: Regular SQL operations
async function regularSqlOperations() {
    try {
        await rdbStore?.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)');
        await rdbStore?.execute('CREATE INDEX idx_user_name ON users(name)');
        await rdbStore?.execute('INSERT INTO users (name) VALUES (?)');
        await rdbStore?.execute('UPDATE users SET name = ? WHERE id = ?');
        await rdbStore?.execute('DELETE FROM users WHERE id = ?');
    } catch (err) {
        console.error("Regular SQL operations failed:", err);
    }
}

// Correct 4: Database configuration with safe settings
async function safeConfiguration(context) {
    const config = {
        name: "safe_database.db",
        securityLevel: relationalStore.SecurityLevel.S3,
        encrypt: true,
        isReadOnly: false
    };
    
    try {
        const rdbStore = await relationalStore.getRdbStore(context, config);
        return rdbStore;
    } catch (err) {
        console.error("Safe configuration failed:", err);
    }
}

// Correct 5: Transaction operations
async function safeTransactionOperations() {
    try {
        await rdbStore?.beginTransaction();
        
        await rdbStore?.execute('INSERT INTO users (name) VALUES (?)', ['Alice']);
        await rdbStore?.execute('INSERT INTO users (name) VALUES (?)', ['Bob']);
        
        await rdbStore?.commit();
    } catch (err) {
        await rdbStore?.rollback();
        console.error("Transaction failed:", err);
    }
}

// Correct 6: Query operations
async function safeQueryOperations() {
    try {
        let predicates = new relationalStore.RdbPredicates("users");
        predicates.equalTo("name", "Alice");
        
        let resultSet = await rdbStore?.query(predicates);
        
        if (resultSet.goToFirstRow()) {
            const id = resultSet.getLong(0);
            const name = resultSet.getString(1);
            console.log(`User: ${id}, ${name}`);
        }
        
        resultSet.close();
    } catch (err) {
        console.error("Query operations failed:", err);
    }
}

// Correct 7: Batch operations
async function safeBatchOperations() {
    const users = [
        { name: "Alice" },
        { name: "Bob" },
        { name: "Charlie" }
    ];
    
    try {
        await rdbStore?.batchInsert("users", users);
    } catch (err) {
        console.error("Batch operations failed:", err);
    }
}

// Correct 8: Backup and restore operations
async function safeBackupRestore() {
    try {
        await rdbStore?.backup("backup.db");
        console.log("Backup completed successfully");
        
        // Later restore if needed
        await rdbStore?.restore("backup.db");
        console.log("Restore completed successfully");
    } catch (err) {
        console.error("Backup/restore failed:", err);
    }
}

// Correct 9: Safe pragma queries (read-only)
async function safePragmaQueries() {
    try {
        // These are informational pragmas, not modifying dangerous settings
        await rdbStore?.execute('PRAGMA journal_mode'); // Query current mode, not setting
        await rdbStore?.execute('PRAGMA synchronous'); // Query current setting
        await rdbStore?.execute('PRAGMA page_size');
        await rdbStore?.execute('PRAGMA cache_size');
        await rdbStore?.execute('PRAGMA user_version');
    } catch (err) {
        console.error("Pragma queries failed:", err);
    }
}

// Correct 10: Database initialization with proper settings
async function initializeDatabaseProperly(context) {
    const config = {
        name: "proper_database.db",
        securityLevel: relationalStore.SecurityLevel.S3,
        encrypt: true
    };
    
    try {
        const store = await relationalStore.getRdbStore(context, config);
        
        // Create tables with proper SQL
        await store.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Create indexes for performance
        await store.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)');
        
        return store;
    } catch (err) {
        console.error("Database initialization failed:", err);
    }
}

// Correct 11: Data migration operations
async function safeMigrationOperations() {
    try {
        // Safe schema changes
        await rdbStore?.execute('ALTER TABLE users ADD COLUMN phone TEXT');
        await rdbStore?.execute('CREATE TABLE user_profiles (user_id INTEGER, profile TEXT)');
        
        // Safe data migration
        await rdbStore?.execute(`
            INSERT INTO user_profiles (user_id, profile) 
            SELECT id, 'default' FROM users WHERE profile IS NULL
        `);
    } catch (err) {
        console.error("Migration operations failed:", err);
    }
}

// Correct 12: Performance optimization (safe operations)
async function safePerformanceOptimization() {
    try {
        // Safe optimization operations
        await rdbStore?.execute('ANALYZE');
        await rdbStore?.execute('VACUUM');
        await rdbStore?.execute('REINDEX');
    } catch (err) {
        console.error("Performance optimization failed:", err);
    }
}

// Correct 13: Multiple database operations
async function multipleDbOperations(context) {
    try {
        const userStore = await relationalStore.getRdbStore(context, {
            name: "users.db",
            securityLevel: relationalStore.SecurityLevel.S3
        });
        
        const logStore = await relationalStore.getRdbStore(context, {
            name: "logs.db",
            securityLevel: relationalStore.SecurityLevel.S2
        });
        
        // Safe operations on both stores
        await userStore.execute('CREATE TABLE users (id INTEGER, name TEXT)');
        await logStore.execute('CREATE TABLE logs (id INTEGER, message TEXT, timestamp DATETIME)');
        
        return { userStore, logStore };
    } catch (err) {
        console.error("Multiple DB operations failed:", err);
    }
}

// Correct 14: Async database operations
async function asyncDatabaseOperations() {
    const operations = [
        () => rdbStore?.execute('CREATE TABLE table1 (id INTEGER)'),
        () => rdbStore?.execute('CREATE TABLE table2 (id INTEGER)'),
        () => rdbStore?.execute('CREATE TABLE table3 (id INTEGER)')
    ];
    
    try {
        await Promise.all(operations.map(op => op()));
        console.log("All async operations completed");
    } catch (err) {
        console.error("Async operations failed:", err);
    }
}

// Correct 15: Database with custom directory
async function customDirectoryDatabase(context) {
    const config = {
        name: "custom.db",
        customDir: "/data/custom/path",
        securityLevel: relationalStore.SecurityLevel.S3
    };
    
    try {
        const store = await relationalStore.getRdbStore(context, config);
        await store.execute('CREATE TABLE custom_table (id INTEGER, data TEXT)');
        return store;
    } catch (err) {
        console.error("Custom directory DB failed:", err);
    }
}

// Correct 16: Error handling without pragma violations
async function errorHandlingWithoutPragma() {
    try {
        await rdbStore?.execute('CREATE TABLE test (id INTEGER PRIMARY KEY)');
        await rdbStore?.execute('INSERT INTO test (id) VALUES (1)');
    } catch (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
            console.log("Handling constraint violation properly");
        } else {
            console.error("Database error:", err);
        }
    }
}

// Correct 17: Complex queries without pragma
async function complexQueriesWithoutPragma() {
    try {
        // Complex but safe SQL operations
        await rdbStore?.execute(`
            SELECT u.name, COUNT(o.id) as order_count
            FROM users u
            LEFT JOIN orders o ON u.id = o.user_id
            WHERE u.created_at > datetime('now', '-1 month')
            GROUP BY u.id, u.name
            HAVING order_count > 0
            ORDER BY order_count DESC
        `);
    } catch (err) {
        console.error("Complex query failed:", err);
    }
}

// Correct 18: Database maintenance operations
async function safeMaintenanceOperations() {
    try {
        // Safe maintenance operations
        await rdbStore?.execute('DROP TABLE IF EXISTS temp_table');
        await rdbStore?.execute('DELETE FROM logs WHERE timestamp < datetime("now", "-30 days")');
        
        // Safe informational queries
        const dbInfo = await rdbStore?.execute('SELECT COUNT(*) FROM sqlite_master WHERE type="table"');
        console.log("Database info retrieved safely");
    } catch (err) {
        console.error("Maintenance operations failed:", err);
    }
}

// Correct 19: String operations that mention pragma but don't execute it
async function stringOperationsWithPragmaText() {
    // These are just strings, not actual pragma executions
    const helpText = "To check journal mode, use: PRAGMA journal_mode";
    const documentation = "Avoid using PRAGMA synchronous = OFF in production";
    
    console.log("Help:", helpText);
    console.log("Warning:", documentation);
    
    // Safe database operations
    try {
        await rdbStore?.execute('SELECT name FROM sqlite_master WHERE type="table"');
    } catch (err) {
        console.error("String operations failed:", err);
    }
}

// Correct 20: No database operations at all
async function nonDatabaseOperations() {
    try {
        const data = await fetch('/api/users');
        const users = await data.json();
        
        // File operations (not database)
        const fileContent = "Some data content";
        console.log("File content:", fileContent);
        
        // Local storage operations
        localStorage.setItem('key', 'value');
        const value = localStorage.getItem('key');
        
        return { users, value };
    } catch (err) {
        console.error("Non-database operations failed:", err);
    }
}