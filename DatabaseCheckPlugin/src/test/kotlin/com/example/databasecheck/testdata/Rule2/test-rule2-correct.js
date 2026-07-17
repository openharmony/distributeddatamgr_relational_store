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

// Rule 2 Test File: Should NOT trigger database file copy violations

// ========== These should NOT trigger Rule 2 warnings ==========

// Correct 1: Using RDB interfaces for database operations
var rdbStore;
async function properDatabaseBackup() {
    try {
        // Correct - using RDB backup interface
        await rdbStore?.backup("/data/storage/el2/base/.backup/backup/data/storage/el2/database/rdb/main.db");
        
        // Correct - using RDB restore interface
        await rdbStore?.restore("/data/storage/el2/base/.backup/restore/data/storage/el2/database/rdb/main.db");
        
        // Correct - using RDB clone interface
        await rdbStore?.clone("/data/storage/el2/database/rdb/source.db", "/data/storage/el2/database/rdb/clone.db");
    } catch (err) {
        console.error('Database operation failed:', err);
    }
}

// Correct 2: File operations on non-database paths
async function safeFileOperations() {
    // Correct - copying non-database files
    await fileIo.copyFile('/data/storage/el1/files/document.txt', '/backup/document.txt');
    
    // Correct - copying configuration files
    fileIo.copyFileSync('/data/storage/el2/config/settings.json', '/backup/settings.json');
    
    // Correct - copying user data
    await fileIo.copyDir('/data/storage/el1/userdata/', '/backup/userdata/');
}

// Correct 3: File operations outside database directories
function safeDirectoryOperations() {
    // Correct - copying application files
    fs.copyFile('/data/storage/el1/app/main.js', '/backup/app/main.js', (err) => {
        if (err) console.error(err);
    });
    
    // Correct - copying media files
    fs.cp('/data/storage/el2/media/', '/backup/media/', { recursive: true });
}

// Correct 4: Proper backup with RDB and file operations separation
async function properBackupStrategy() {
    try {
        // Step 1: Use RDB interface for database backup
        await rdbStore?.backup("/backup/database/main.db");
        
        // Step 2: Copy other application files separately
        await fileIo.copyDir('/data/storage/el1/assets/', '/backup/assets/');
        await fileIo.copyDir('/data/storage/el1/config/', '/backup/config/');
        
        console.log('Backup completed successfully');
    } catch (err) {
        console.error('Backup failed:', err);
    }
}

// Correct 5: Database operations with proper RDB usage
async function properDatabaseCloning() {
    const sourceDb = '/data/storage/el2/database/rdb/source.db';
    const cloneDb = '/data/storage/el2/database/rdb/clone.db';
    
    try {
        // Correct - using RDB clone instead of file copy
        await rdbStore?.clone(sourceDb, cloneDb);
        
        console.log('Database cloned successfully');
    } catch (err) {
        console.error('Database cloning failed:', err);
        
        // Fallback: proper error handling
        throw new Error('Unable to clone database using RDB interface');
    }
}

// Correct 6: Moving non-database files
async function safeMoveOperations() {
    // Correct - moving log files
    await fileIo.moveFile('/data/storage/el1/logs/old.log', '/data/storage/el1/archive/old.log');
    
    // Correct - moving temporary files
    fileIo.moveFileSync('/data/storage/el2/temp/processing.tmp', '/data/storage/el2/temp/processed.tmp');
    
    // Correct - reorganizing user directories
    await fileIo.moveDir('/data/storage/el1/user/old_structure/', '/data/storage/el1/user/new_structure/');
}

// Correct 7: Application data management
function manageApplicationData() {
    // Correct - copying application resources
    fileIo.copyFile('/data/storage/el1/resources/theme.css', '/backup/resources/theme.css');
    
    // Correct - backing up user preferences
    fileIo.copyFile('/data/storage/el2/preferences/user.json', '/backup/preferences/user.json');
}

// Correct 8: Proper error handling and validation
async function robustFileOperations(sourcePath, targetPath) {
    // Validate paths to ensure they're not database paths
    if (sourcePath.includes('/database/') || targetPath.includes('/database/')) {
        throw new Error('Database operations should use RDB interfaces');
    }
    
    try {
        // Correct - safe file operations with validation
        await fileIo.copyFile(sourcePath, targetPath);
        console.log('File copied successfully');
    } catch (err) {
        console.error('File operation failed:', err);
        throw err;
    }
}

// Correct 9: Batch operations with proper separation
async function batchOperations() {
    const tasks = [
        // Correct - non-database file operations
        () => fileIo.copyFile('/data/storage/el1/docs/readme.txt', '/backup/docs/readme.txt'),
        () => fileIo.copyFile('/data/storage/el1/images/logo.png', '/backup/images/logo.png'),
        () => fileIo.copyDir('/data/storage/el1/cache/', '/backup/cache/'),
        
        // Correct - RDB operations for database
        () => rdbStore?.backup('/backup/database/main.db')
    ];
    
    for (const task of tasks) {
        try {
            await task();
        } catch (err) {
            console.error('Task failed:', err);
        }
    }
}