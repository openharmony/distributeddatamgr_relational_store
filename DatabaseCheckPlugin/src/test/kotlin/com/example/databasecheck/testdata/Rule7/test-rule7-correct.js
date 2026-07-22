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
 
// Rule 7 Test File: Should NOT trigger database permission violations
// Safe operations: chmod on non-database paths

// ========== These should NOT trigger Rule 7 warnings ==========

// Correct 1: Proper guard against database paths (from specification positive example)
async function changeMod(context, path) {
    try {
        if (path.search('/database/') >= 0) {
            return; // Skip database paths - this is the correct approach
        }
        await fileIo.chmod(path, 0o771);
    } catch (err) {
        console.log(`failed, err: ${JSON.stringify(err)}`)
    }
}

// Correct 2: chmod on regular files (not database paths)
async function changeModRegularFiles() {
    try {
        await fileIo.chmod('/home/user/documents/myfile.txt', 0o644);
        await fileIo.chmod('/tmp/temp_file.log', 0o755);
        await fileIo.chmod('/var/log/application.log', 0o600);
    } catch (err) {
        console.error("Regular file chmod failed:", err);
    }
}

// Correct 3: chmod on application data (non-database)
async function changeModAppData() {
    try {
        await fileIo.chmod('/data/storage/el1/files/config.json', 0o644);
        await fileIo.chmod('/data/storage/el2/cache/images/photo.jpg', 0o755);
        await fileIo.chmod('/data/storage/el3/temp/upload.tmp', 0o600);
    } catch (err) {
        console.error("App data chmod failed:", err);
    }
}

// Correct 4: chmodSync on regular paths
async function changeModSyncCorrect() {
    try {
        await fileIo.chmodSync('/home/user/scripts/backup.sh', 0o755);
        await fileIo.chmodSync('/etc/config/settings.conf', 0o644);
    } catch (err) {
        console.error("Sync chmod failed:", err);
    }
}

// Correct 5: Plain chmod on non-database paths
async function plainChmodCorrect() {
    try {
        chmod('/usr/local/bin/myapp', 0o755);
        chmod('/home/user/.bashrc', 0o644);
        chmod('/tmp/script.sh', 0o777);
    } catch (err) {
        console.error("Plain chmod failed:", err);
    }
}

// Correct 6: chmod on app files that are not in database directory
async function changeModAppFiles() {
    try {
        await fileIo.chmod('/data/app/el1/100/files/document.pdf', 0o644);
        await fileIo.chmod('/data/app/el2/100/cache/image.png', 0o644);
        await fileIo.chmod('/data/app/el3/100/temp/upload.zip', 0o600);
    } catch (err) {
        console.error("App files chmod failed:", err);
    }
}

// Correct 7: chmod on service files (not database)
async function changeModServiceFiles() {
    try {
        await fileIo.chmod('/data/service/el1/public/config/service.conf', 0o644);
        await fileIo.chmod('/data/service/el2/public/logs/service.log', 0o640);
        await fileIo.chmod('/data/service/el3/public/cache/temp.cache', 0o600);
    } catch (err) {
        console.error("Service files chmod failed:", err);
    }
}

// Correct 8: Guarded chmod operations
async function guardedChmodOperations(filePath) {
    // Multiple safety checks
    if (filePath.includes('/database/')) {
        console.log('Skipping database path:', filePath);
        return;
    }
    
    if (filePath.includes('context.databaseDir')) {
        console.log('Skipping database directory:', filePath);
        return;
    }
    
    try {
        await fileIo.chmod(filePath, 0o644);
        console.log('Successfully changed permissions for:', filePath);
    } catch (err) {
        console.error("Guarded chmod failed:", err);
    }
}

// Correct 9: Working with different file types (not databases)
async function changeModDifferentFileTypes() {
    const fileTypes = [
        '/data/storage/el1/documents/report.pdf',
        '/data/storage/el2/images/photo.jpg',
        '/data/storage/el3/audio/music.mp3',
        '/data/storage/el4/video/movie.mp4',
        '/data/storage/el5/archives/backup.tar.gz'
    ];
    
    for (const file of fileTypes) {
        try {
            await fileIo.chmod(file, 0o644);
        } catch (err) {
            console.error(`Failed to chmod ${file}:`, err);
        }
    }
}

// Correct 10: chmod with path validation
async function changeModWithValidation(targetPath) {
    // Validate that it's not a database path
    const forbiddenPaths = [
        '/database/',
        'databaseDir',
        '/data/storage/el1/database',
        '/data/storage/el2/database',
        '/data/storage/el3/database',
        '/data/storage/el4/database',
        '/data/storage/el5/database'
    ];
    
    const isForbidden = forbiddenPaths.some(forbidden => 
        targetPath.includes(forbidden)
    );
    
    if (isForbidden) {
        console.warn('Cannot change permissions on database path:', targetPath);
        return false;
    }
    
    try {
        await fileIo.chmod(targetPath, 0o755);
        return true;
    } catch (err) {
        console.error("Validated chmod failed:", err);
        return false;
    }
}

// Correct 11: chmod in conditional blocks (safe paths only)
async function conditionalChmodSafe(isProduction) {
    if (isProduction) {
        try {
            await fileIo.chmod('/var/log/production.log', 0o600);
            await fileIo.chmod('/etc/production/config.conf', 0o644);
        } catch (err) {
            console.error("Production chmod failed:", err);
        }
    } else {
        try {
            await fileIo.chmod('/tmp/debug.log', 0o666);
            await fileIo.chmod('/tmp/development.conf', 0o777);
        } catch (err) {
            console.error("Development chmod failed:", err);
        }
    }
}

// Correct 12: chmod on system paths
async function changeModSystemPaths() {
    try {
        await fileIo.chmod('/usr/local/lib/mylib.so', 0o755);
        await fileIo.chmod('/opt/myapp/bin/executable', 0o755);
        await fileIo.chmod('/var/cache/myapp/cache.dat', 0o644);
    } catch (err) {
        console.error("System paths chmod failed:", err);
    }
}

// Correct 13: chmod with dynamic paths (non-database)
async function changeModDynamicPaths(userId, appName) {
    const configPath = `/data/app/el1/${userId}/config/${appName}.json`;
    const cachePath = `/data/app/el2/${userId}/cache/${appName}/data.cache`;
    const logPath = `/data/app/el3/${userId}/logs/${appName}.log`;
    
    try {
        await fileIo.chmod(configPath, 0o644);
        await fileIo.chmod(cachePath, 0o644);
        await fileIo.chmod(logPath, 0o640);
    } catch (err) {
        console.error("Dynamic paths chmod failed:", err);
    }
}

// Correct 14: chmod operations in loops (safe paths)
async function changeModInLoopSafe() {
    const configFiles = [
        '/etc/myapp/main.conf',
        '/etc/myapp/network.conf',
        '/etc/myapp/logging.conf'
    ];
    
    for (const configFile of configFiles) {
        try {
            await fileIo.chmod(configFile, 0o644);
        } catch (err) {
            console.error(`Failed to chmod ${configFile}:`, err);
        }
    }
}

// Correct 15: chmod with error handling and path checking
async function safeChmodWithChecks(filePath, permissions) {
    try {
        // Safety check
        if (filePath.match(/\/database\/|databaseDir/)) {
            throw new Error('Database paths are not allowed');
        }
        
        await fileIo.chmod(filePath, permissions);
        console.log(`Successfully set permissions ${permissions} on ${filePath}`);
        
    } catch (err) {
        console.error("Safe chmod failed:", err);
        throw err;
    }
}

// Correct 16: chmod on backup paths (non-database)
async function changeModBackupPaths() {
    try {
        await fileIo.chmod('/data/backup/files/user_documents.tar.gz', 0o600);
        await fileIo.chmod('/data/backup/config/app_settings.json', 0o644);
        await fileIo.chmod('/data/backup/logs/system.log', 0o640);
    } catch (err) {
        console.error("Backup paths chmod failed:", err);
    }
}

// Correct 17: No chmod operations at all
async function noPermissionOperations() {
    try {
        // Just reading files, no permission changes
        const content = await fileIo.readText('/etc/config/app.conf');
        await fileIo.writeText('/tmp/output.txt', content);
        console.log('File operations completed without permission changes');
    } catch (err) {
        console.error("File operations failed:", err);
    }
}

// Correct 18: chmod with whitelist approach
async function changeModWhitelist(filePath) {
    const allowedPaths = [
        '/tmp/',
        '/var/log/',
        '/home/user/',
        '/opt/myapp/',
        '/usr/local/'
    ];
    
    const isAllowed = allowedPaths.some(allowed => 
        filePath.startsWith(allowed)
    );
    
    if (!isAllowed) {
        console.warn('Path not in whitelist:', filePath);
        return false;
    }
    
    try {
        await fileIo.chmod(filePath, 0o644);
        return true;
    } catch (err) {
        console.error("Whitelist chmod failed:", err);
        return false;
    }
}

// Correct 19: chmod operations with proper logging
async function changeModWithLogging(targetFile) {
    console.log(`Attempting to change permissions for: ${targetFile}`);
    
    // Ensure we're not operating on database paths
    if (targetFile.includes('/database/') || 
        targetFile.includes('databaseDir')) {
        console.error('Cannot change permissions on database files');
        return;
    }
    
    try {
        await fileIo.chmod(targetFile, 0o755);
        console.log(`Successfully changed permissions for: ${targetFile}`);
    } catch (err) {
        console.error(`Failed to change permissions for ${targetFile}:`, err);
    }
}

// Correct 20: Complex permission management (non-database)
async function complexPermissionManagement() {
    const filePermissions = {
        '/var/lib/myapp/data.json': 0o600,
        '/var/lib/myapp/config.json': 0o644,
        '/var/lib/myapp/public/readme.txt': 0o755,
        '/tmp/myapp/temp.log': 0o666
    };
    
    for (const [filePath, permission] of Object.entries(filePermissions)) {
        try {
            await fileIo.chmod(filePath, permission);
            console.log(`Set ${permission} on ${filePath}`);
        } catch (err) {
            console.error(`Failed to set permissions on ${filePath}:`, err);
        }
    }
}