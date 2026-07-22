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

// Rule 2 Test File: Should trigger database file copy violations

// ========== These should trigger Rule 2 warnings ==========

// Violation 1: Direct file copy operations on database paths
async function unsafeDatabaseCopy(context) {
    // Should trigger warning - fileIo.copyFile on database path
    await fileIo.copyFile('/data/storage/el2/database/source.db', '/data/storage/el2/database/backup.db');
    
    // Should trigger warning - fileIo.copyFileSync on database path
    fileIo.copyFileSync(context.databaseDir + '/original.db', context.databaseDir + '/copy.db');
    
    // Should trigger warning - fileIo.copyDir on database directory
    await fileIo.copyDir('/data/storage/el1/database/', '/backup/database/');
}

// Violation 2: Using fs operations on database paths
function unsafeFsCopy() {
    // Should trigger warning - fs.copyFile on database path
    fs.copyFile('/data/storage/el3/database/test.db', '/backup/test.db', (err) => {
        if (err) console.error(err);
    });
    
    // Should trigger warning - fs.cp on database directory
    fs.cp('/data/storage/el4/database/', '/backup/database/', { recursive: true });
}

// Violation 3: Move operations on database files
async function unsafeDatabaseMove() {
    // Should trigger warning - fileIo.moveFile on database path
    await fileIo.moveFile('/data/storage/el/database/old.db', '/data/storage/el5/database/new.db');
    
    // Should trigger warning - fileIo.moveDir on database directory
    fileIo.moveDirSync('/data/storage/el2/database/old/', '/data/storage/el2/database/new/');
}

// Violation 4: File operations without RDB alternatives
async function backupWithoutRdb() {
    // Should recommend RDB interface - backup operation using file copy
    await fileIo.copyFile('/data/storage/el1/database/main.db', '/backup/restore/main.db');
    
    // Should recommend RDB interface - restore operation using file copy
    await fileIo.copyFile('/backup/restore/main.db', '/data/storage/el1/database/main.db');
}

// Violation 5: Clone operation using file interfaces
function cloneDatabase() {
    // Should recommend RDB interface - cloning database with file operations
    fileIo.copyFileSync('/data/storage/el2/database/source.db', '/data/storage/el2/database/clone.db');
}

// Violation 6: Mixed operations with database files
async function mixedDatabaseOperations() {
    const dbPath = '/data/storage/el1/database/';
    
    // Should trigger warning - copying entire database directory
    await fileIo.copyDir(dbPath, '/backup/database_backup/');
    
    // Should trigger warning - moving database files
    await fileIo.moveFile(dbPath + 'temp.db', dbPath + 'final.db');
}

// Violation 7: Backup operations with .db files
function backupDbFiles() {
    // Should trigger warning and recommend RDB - backup .db file
    fileIo.copyFile('/data/storage/el3/database/user.db', '/backup/user_backup.db');
    
    // Should trigger warning and recommend RDB - restore .db file
    fileIo.copyFile('/backup/config_backup.db', '/data/storage/el3/database/config.db');
}

// Violation 8: Complex path operations
async function complexPathOperations(context, moduleName) {
    const sourcePath = '/data/storage/el2/database/' + context.currentHapModuleInfo.name + '/main.db';
    const targetPath = '/data/storage/el2/database/' + moduleName + '/main.db';
    
    // Should trigger warning - complex database path copy
    await fileIo.copyFile(sourcePath, targetPath);
    
    // Should trigger warning - directory copy with dynamic paths
    await fileIo.copyDir(
        '/data/storage/el4/database/' + context.currentHapModuleInfo.name,
        '/backup/' + moduleName + '_database'
    );
}