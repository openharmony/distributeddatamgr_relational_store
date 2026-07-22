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
 
// Rule 14 Test File: Should NOT trigger database configuration consistency violations
// Consistent database configuration parameters across getRdbStore calls

// ========== These should NOT trigger Rule 14 warnings ==========

// Correct 1: Using shared configuration constant (from specification positive example)
const CONFIG = {
    "name": STORE_NAME,
    securityLevel: relationalStore.SecurityLevel.S1
}

async function CreateRdbStore(context) {
    var rdbStore = undefined;
    try {
        rdbStore = await relationalStore.getRdbStore(context, CONFIG);
    } catch (err) {
        console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
    }
    return rdbStore
}

async function GetActiveRdbStore(context) {
    var rdbStore = undefined;
    try {
        rdbStore = await relationalStore.getRdbStore(context, CONFIG);
    } catch (err) {
        console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
    }
    return rdbStore
}

// Correct 2: Identical inline configurations
async function createMainDatabase(context) {
    const config = {
        "name": "main_db",
        securityLevel: relationalStore.SecurityLevel.S1
    };
    return await relationalStore.getRdbStore(context, config);
}

async function getMainDatabase(context) {
    const config = {
        "name": "main_db",
        securityLevel: relationalStore.SecurityLevel.S1  // Identical configuration
    };
    return await relationalStore.getRdbStore(context, config);
}

// Correct 3: Consistent configuration with all parameters
async function createUserDatabase(context) {
    const config = {
        "name": "user_db",
        securityLevel: relationalStore.SecurityLevel.S2,
        encrypt: true,
        isReadOnly: false,
        customDir: "/data/user"
    };
    return await relationalStore.getRdbStore(context, config);
}

async function getUserDatabase(context) {
    const config = {
        "name": "user_db",
        securityLevel: relationalStore.SecurityLevel.S2,
        encrypt: true,
        isReadOnly: false,
        customDir: "/data/user"  // All parameters identical
    };
    return await relationalStore.getRdbStore(context, config);
}

// Correct 4: Shared configuration object
const LOG_DATABASE_CONFIG = {
    "name": "log_db",
    securityLevel: relationalStore.SecurityLevel.S1,
    encrypt: false,
    isReadOnly: true
};

async function createLogDatabase(context) {
    return await relationalStore.getRdbStore(context, LOG_DATABASE_CONFIG);
}

async function getLogDatabase(context) {
    return await relationalStore.getRdbStore(context, LOG_DATABASE_CONFIG);
}

async function connectLogDatabase(context) {
    return await relationalStore.getRdbStore(context, LOG_DATABASE_CONFIG);
}

// Correct 5: Multiple functions using same configuration
const BACKUP_CONFIG = {
    "name": "backup_db",
    securityLevel: relationalStore.SecurityLevel.S3,
    encrypt: true,
    customDir: "/data/backup"
};

async function createBackupDatabase(context) {
    return await relationalStore.getRdbStore(context, BACKUP_CONFIG);
}

async function getBackupDatabase(context) {
    return await relationalStore.getRdbStore(context, BACKUP_CONFIG);
}

async function initBackupDatabase(context) {
    return await relationalStore.getRdbStore(context, BACKUP_CONFIG);
}

async function connectBackupDatabase(context) {
    return await relationalStore.getRdbStore(context, BACKUP_CONFIG);
}

// Correct 6: Different database names with different configurations (no conflict)
async function createUsersDatabase(context) {
    const config = {
        "name": "users_db",
        securityLevel: relationalStore.SecurityLevel.S1
    };
    return await relationalStore.getRdbStore(context, config);
}

async function createSettingsDatabase(context) {
    const config = {
        "name": "settings_db",  // Different name, so different config is OK
        securityLevel: relationalStore.SecurityLevel.S3,
        encrypt: true
    };
    return await relationalStore.getRdbStore(context, config);
}

async function getUsersDatabase(context) {
    const config = {
        "name": "users_db",
        securityLevel: relationalStore.SecurityLevel.S1  // Same as create for users_db
    };
    return await relationalStore.getRdbStore(context, config);
}

async function getSettingsDatabase(context) {
    const config = {
        "name": "settings_db",
        securityLevel: relationalStore.SecurityLevel.S3,  // Same as create for settings_db
        encrypt: true
    };
    return await relationalStore.getRdbStore(context, config);
}

// Correct 7: Configuration factory function ensuring consistency
function createDatabaseConfig(name, secLevel, encrypted = false) {
    return {
        "name": name,
        securityLevel: secLevel,
        encrypt: encrypted
    };
}

async function createProductDatabase(context) {
    const config = createDatabaseConfig("product_db", relationalStore.SecurityLevel.S2, true);
    return await relationalStore.getRdbStore(context, config);
}

async function getProductDatabase(context) {
    const config = createDatabaseConfig("product_db", relationalStore.SecurityLevel.S2, true);
    return await relationalStore.getRdbStore(context, config);
}

// Correct 8: Class with consistent configuration
class DatabaseManager {
    constructor() {
        this.config = {
            "name": "manager_db",
            securityLevel: relationalStore.SecurityLevel.S2,
            encrypt: true,
            isReadOnly: false
        };
    }
    
    async createDatabase(context) {
        return await relationalStore.getRdbStore(context, this.config);
    }
    
    async getDatabase(context) {
        return await relationalStore.getRdbStore(context, this.config);
    }
    
    async connectDatabase(context) {
        return await relationalStore.getRdbStore(context, this.config);
    }
}

// Correct 9: Module-level configuration constants
const DB_CONFIGURATIONS = {
    CACHE: {
        "name": "cache_db",
        securityLevel: relationalStore.SecurityLevel.S1,
        isReadOnly: false
    },
    ANALYTICS: {
        "name": "analytics_db",
        securityLevel: relationalStore.SecurityLevel.S2,
        encrypt: true
    }
};

async function createCacheDatabase(context) {
    return await relationalStore.getRdbStore(context, DB_CONFIGURATIONS.CACHE);
}

async function getCacheDatabase(context) {
    return await relationalStore.getRdbStore(context, DB_CONFIGURATIONS.CACHE);
}

async function createAnalyticsDatabase(context) {
    return await relationalStore.getRdbStore(context, DB_CONFIGURATIONS.ANALYTICS);
}

async function getAnalyticsDatabase(context) {
    return await relationalStore.getRdbStore(context, DB_CONFIGURATIONS.ANALYTICS);
}

// Correct 10: Consistent configuration with error handling
const SECURE_CONFIG = {
    "name": "secure_db",
    securityLevel: relationalStore.SecurityLevel.S3,
    encrypt: true,
    isReadOnly: false
};

async function createSecureDatabase(context) {
    try {
        return await relationalStore.getRdbStore(context, SECURE_CONFIG);
    } catch (err) {
        console.error("Failed to create secure database:", err);
        throw err;
    }
}

async function getSecureDatabase(context) {
    try {
        return await relationalStore.getRdbStore(context, SECURE_CONFIG);
    } catch (err) {
        console.error("Failed to get secure database:", err);
        throw err;
    }
}

// Correct 11: Promise-based consistent usage
const PROMISE_CONFIG = {
    "name": "promise_db",
    securityLevel: relationalStore.SecurityLevel.S2
};

function createPromiseDatabase(context) {
    return relationalStore.getRdbStore(context, PROMISE_CONFIG);
}

function getPromiseDatabase(context) {
    return relationalStore.getRdbStore(context, PROMISE_CONFIG);
}

// Correct 12: Async/await with consistent configuration
async function databaseOperations(context) {
    const consistentConfig = {
        "name": "operations_db",
        securityLevel: relationalStore.SecurityLevel.S2,
        encrypt: false
    };
    
    // Multiple calls with same configuration in same function
    const store1 = await relationalStore.getRdbStore(context, consistentConfig);
    const store2 = await relationalStore.getRdbStore(context, consistentConfig);
    const store3 = await relationalStore.getRdbStore(context, consistentConfig);
    
    return { store1, store2, store3 };
}

// Correct 13: Configuration with computed values (but consistent)
const COMPUTED_SECURITY_LEVEL = relationalStore.SecurityLevel.S2;
const IS_ENCRYPTED = true;

const COMPUTED_CONFIG = {
    "name": "computed_db",
    securityLevel: COMPUTED_SECURITY_LEVEL,
    encrypt: IS_ENCRYPTED
};

async function createComputedDatabase(context) {
    return await relationalStore.getRdbStore(context, COMPUTED_CONFIG);
}

async function getComputedDatabase(context) {
    return await relationalStore.getRdbStore(context, COMPUTED_CONFIG);
}

// Correct 14: Single database call (no consistency issue)
async function singleDatabaseCall(context) {
    const config = {
        "name": "single_db",
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: true,
        isReadOnly: false,
        customDir: "/data/single"
    };
    return await relationalStore.getRdbStore(context, config);
}

// Correct 15: Different modules with same configuration approach
const MODULE_A_CONFIG = {
    "name": "module_a_db",
    securityLevel: relationalStore.SecurityLevel.S1
};

const MODULE_B_CONFIG = {
    "name": "module_b_db",  // Different name, different config is fine
    securityLevel: relationalStore.SecurityLevel.S3,
    encrypt: true
};

async function moduleACreate(context) {
    return await relationalStore.getRdbStore(context, MODULE_A_CONFIG);
}

async function moduleAGet(context) {
    return await relationalStore.getRdbStore(context, MODULE_A_CONFIG);
}

async function moduleBCreate(context) {
    return await relationalStore.getRdbStore(context, MODULE_B_CONFIG);
}

async function moduleBGet(context) {
    return await relationalStore.getRdbStore(context, MODULE_B_CONFIG);
}

// Correct 16: Utility functions with consistent configuration
const UTILITY_CONFIG = {
    "name": "utility_db",
    securityLevel: relationalStore.SecurityLevel.S2,
    encrypt: false,
    isReadOnly: true
};

async function initUtilityDatabase(context) {
    return await relationalStore.getRdbStore(context, UTILITY_CONFIG);
}

async function connectUtilityDatabase(context) {
    return await relationalStore.getRdbStore(context, UTILITY_CONFIG);
}

async function accessUtilityDatabase(context) {
    return await relationalStore.getRdbStore(context, UTILITY_CONFIG);
}

// Correct 17: Configuration validation with consistency
function validateAndCreateConfig(name, secLevel) {
    if (!name || !secLevel) {
        throw new Error("Invalid configuration parameters");
    }
    
    return {
        "name": name,
        securityLevel: secLevel,
        encrypt: true  // Consistent default
    };
}

async function createValidatedDatabase(context) {
    const config = validateAndCreateConfig("validated_db", relationalStore.SecurityLevel.S2);
    return await relationalStore.getRdbStore(context, config);
}

async function getValidatedDatabase(context) {
    const config = validateAndCreateConfig("validated_db", relationalStore.SecurityLevel.S2);
    return await relationalStore.getRdbStore(context, config);
}

// Correct 18: No database operations (should not trigger)
async function nonDatabaseOperations() {
    const data = await fetch('/api/data');
    const result = await data.json();
    
    localStorage.setItem('key', 'value');
    const stored = localStorage.getItem('key');
    
    return { result, stored };
}

// Correct 19: Mixed relationalStore and data_relationalStore with same config
const MIXED_CONFIG = {
    "name": "mixed_module_db",
    securityLevel: relationalStore.SecurityLevel.S2
};

async function createWithRelationalStore(context) {
    return await relationalStore.getRdbStore(context, MIXED_CONFIG);
}

async function getWithDataRelationalStore(context) {
    return await data_relationalStore.getRdbStore(context, MIXED_CONFIG);
}

// Correct 20: Deep copy ensuring exact consistency
const ORIGINAL_CONFIG = {
    "name": "deep_copy_db",
    securityLevel: relationalStore.SecurityLevel.S3,
    encrypt: true,
    isReadOnly: false
};

async function createWithOriginalConfig(context) {
    return await relationalStore.getRdbStore(context, ORIGINAL_CONFIG);
}

async function getWithDeepCopyConfig(context) {
    const configCopy = JSON.parse(JSON.stringify(ORIGINAL_CONFIG));
    return await relationalStore.getRdbStore(context, configCopy);
}