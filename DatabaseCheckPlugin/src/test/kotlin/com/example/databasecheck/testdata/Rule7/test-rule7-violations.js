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
 
// Rule 7 Test File: Should trigger database permission violations
// Prohibition: chmod operations on database paths

// ========== These should trigger Rule 7 warnings ==========

// Violation 1: Direct chmod on context.databaseDir (from specification)
async function changeMod(context, path) {
    try {
        await fileIo.chmod(context.databaseDir + path, 0o771);
    } catch (err) {
        console.log(`failed, err: ${JSON.stringify(err)}`)
    }
}

// Violation 2: chmod on /data/storage/el1/database/ (from specification)
async function changeModEl1() {
    try {
        await fileIo.chmod('/data/storage/el1/database/' + path, 0o771);
    } catch (err) {
        console.log(`failed, err: ${JSON.stringify(err)}`)
    }
}

// Violation 3: chmod on /data/storage/el2/database/ with HAP name (from specification)
async function changeModEl2WithHap() {
    try {
        await fileIo.chmod('/data/storage/el2/database/' + context.currentHapModuleInfo.name + '/' + path, 0o771);
    } catch (err) {
        console.log(`failed, err: ${JSON.stringify(err)}`)
    }
}

// Violation 4: chmod on /data/storage/el3/database/ (from specification)
async function changeModEl3() {
    try {
        await fileIo.chmod('/data/storage/el3/database/' + path, 0o771);
    } catch (err) {
        console.log(`failed, err: ${JSON.stringify(err)}`)
    }
}

// Violation 5: chmod on /data/storage/el4/database/ (from specification)
async function changeModEl4() {
    try {
        await fileIo.chmod('/data/storage/el4/database/' + path, 0o771);
    } catch (err) {
        console.log(`failed, err: ${JSON.stringify(err)}`)
    }
}

// Violation 6: Direct path chmod (from specification)
async function changeModDirect(path) {
    try {
        await fileIo.chmod(path, 0o771);
    } catch (err) {
        console.log(`failed, err: ${JSON.stringify(err)}`)
    }
}

// Violation 7: fileIo.chmodSync on context.databaseDir
async function changeModSync(context, fileName) {
    try {
        await fileIo.chmodSync(context.databaseDir + "/" + fileName, 0o755);
        console.log("Permission changed successfully");
    } catch (err) {
        console.error("Failed to change permissions:", err);
    }
}

// Violation 8: chmod on all storage levels el1-el5
async function changeModAllLevels() {
    const paths = [
        '/data/storage/el1/database/myapp.db',
        '/data/storage/el2/database/myapp.db',
        '/data/storage/el3/database/myapp.db',
        '/data/storage/el4/database/myapp.db',
        '/data/storage/el5/database/myapp.db'
    ];
    
    for (const path of paths) {
        try {
            await fileIo.chmod(path, 0o644);
        } catch (err) {
            console.error(`Failed to chmod ${path}:`, err);
        }
    }
}

// Violation 9: chmod on app-specific database paths
async function changeModAppPaths() {
    try {
        await fileIo.chmod('/data/app/el1/100/database/com.example.app/data.db', 0o600);
        await fileIo.chmod('/data/app/el2/100/database/com.example.app/cache.db', 0o600);
        await fileIo.chmod('/data/app/el3/100/database/com.example.app/settings.db', 0o600);
    } catch (err) {
        console.error("App database chmod failed:", err);
    }
}

// Violation 10: chmod on app-specific paths with HAP names
async function changeModAppWithHap() {
    try {
        await fileIo.chmod('/data/app/el1/100/database/com.example.app/mymodule/data.db', 0o755);
        await fileIo.chmod('/data/app/el2/100/database/com.example.app/mymodule/index.db', 0o755);
    } catch (err) {
        console.error("App HAP database chmod failed:", err);
    }
}

// Violation 11: chmod on service database paths
async function changeModServicePaths() {
    try {
        await fileIo.chmod('/data/service/el1/public/database/myservice/data.db', 0o644);
        await fileIo.chmod('/data/service/el2/public/database/myservice/config.db', 0o644);
        await fileIo.chmod('/data/service/el3/public/database/myservice/logs.db', 0o644);
        await fileIo.chmod('/data/service/el4/public/database/myservice/cache.db', 0o644);
    } catch (err) {
        console.error("Service database chmod failed:", err);
    }
}

// Violation 12: chmod on service user-specific database paths
async function changeModServiceUserPaths() {
    try {
        await fileIo.chmod('/data/service/el1/100/database/myservice/user.db', 0o600);
        await fileIo.chmod('/data/service/el2/100/database/myservice/profile.db', 0o600);
        await fileIo.chmod('/data/service/el3/100/database/myservice/settings.db', 0o600);
        await fileIo.chmod('/data/service/el4/100/database/myservice/temp.db', 0o600);
    } catch (err) {
        console.error("Service user database chmod failed:", err);
    }
}

// Violation 13: Plain chmod (not fileIo.chmod) on database paths
async function plainChmodOnDatabase() {
    try {
        chmod('/data/storage/el1/database/plain.db', 0o777);
        chmod('/data/storage/el2/database/plain2.db', 0o755);
    } catch (err) {
        console.error("Plain chmod failed:", err);
    }
}

// Violation 14: Complex path construction with database directories
async function changeModComplexPath(context, appName, dbName) {
    const basePath = '/data/storage/el1/database/';
    const fullPath = basePath + appName + '/' + dbName;
    
    try {
        await fileIo.chmod(fullPath, 0o644);
    } catch (err) {
        console.error("Complex path chmod failed:", err);
    }
}

// Violation 15: Template literal with database path
async function changeModTemplateLiteral(userId, packageName) {
    try {
        await fileIo.chmod(`/data/app/el1/${userId}/database/${packageName}/main.db`, 0o755);
    } catch (err) {
        console.error("Template literal chmod failed:", err);
    }
}

// Violation 16: Variable assignment with database path and subsequent chmod
async function changeModWithVariable() {
    const dbPath = '/data/storage/el5/database/myapp/data.db';
    const dbDir = '/data/storage/el4/database/';
    
    try {
        await fileIo.chmod(dbPath, 0o644);
        await fileIo.chmodSync(dbDir + 'config.db', 0o600);
    } catch (err) {
        console.error("Variable path chmod failed:", err);
    }
}

// Violation 17: Nested function with database path chmod
async function processDatabase() {
    async function changePermissions() {
        try {
            await fileIo.chmod('/data/storage/el2/database/nested/test.db', 0o755);
        } catch (err) {
            console.error("Nested chmod failed:", err);
        }
    }
    
    await changePermissions();
}

// Violation 18: Loop with database path chmod operations
async function changeModInLoop() {
    const dbFiles = ['user.db', 'config.db', 'cache.db'];
    const dbBase = '/data/storage/el1/database/myapp/';
    
    for (const file of dbFiles) {
        try {
            await fileIo.chmod(dbBase + file, 0o644);
        } catch (err) {
            console.error(`Failed to chmod ${file}:`, err);
        }
    }
}

// Violation 19: Conditional chmod on database path
async function conditionalChangeModDatabase(shouldSecure) {
    if (shouldSecure) {
        try {
            await fileIo.chmod('/data/storage/el5/database/secure/vault.db', 0o600);
        } catch (err) {
            console.error("Secure chmod failed:", err);
        }
    }
}

// Violation 20: Multiple permission operations in one function
async function multiplePermissionOps(context) {
    try {
        await fileIo.chmod(context.databaseDir + '/main.db', 0o755);
        await fileIo.chmodSync(context.databaseDir + '/cache.db', 0o644);
        chmod('/data/storage/el1/database/backup.db', 0o600);
    } catch (err) {
        console.error("Multiple permission operations failed:", err);
    }
}