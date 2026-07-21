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

// Rule 1 Test File: Should NOT trigger database rule violations

// ========== These should NOT trigger Rule 1 warnings ==========

async function correctUsage1(context) {
    // Correct RDB usage - should NOT trigger warning
    const config = {
        "name": "STORE_NAME",
        securityLevel: relationalStore.SecurityLevel.S3,
    }
    var rdbStore = await relationalStore.getRdbStore(context, config);
    return rdbStore;
}

function correctUsage2() {
    // File operations on non-database paths - should NOT trigger warnings
    var fd1 = fileIo.open('/data/storage/el1/files/document.txt', 0, 0o644);
    var fd2 = fileIo.open('/tmp/tempfile.log', 0, 0o644);
    var fd3 = fileIo.open('/data/config/database_settings.json', 0, 0o644);
    
    fileIo.close(fd1);
    fileIo.close(fd2);
    fileIo.close(fd3);
}

function correctUsage3() {
    // Operations that mention 'database' but not in prohibited paths
    var configPath = '/data/config/database_config.json';
    var logPath = '/var/log/database_operations.log';
    var cachePath = '/data/storage/el1/cache/database_cache.tmp';
    
    fileIo.open(configPath, 0, 0o644);
    fileIo.open(logPath, 0, 0o644);
    fileIo.open(cachePath, 0, 0o644);
}

function correctUsage4(context) {
    // Using non-database context properties - should NOT trigger warnings
    var fd1 = fileIo.open(context.filesDir + '/user_data.txt', 0, 0o644);
    var fd2 = fileIo.open(context.cacheDir + '/temp_file.cache', 0, 0o644);
    
    fileIo.close(fd1);
    fileIo.close(fd2);
}

function correctUsage5() {
    // Normal file operations that don't involve prohibited APIs
    var content = fs.readFileSync('/data/storage/el1/database/config.json');
    console.log('This mentions fileIo.open but does not actually call it on database paths');
}