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
 
// Rule 14 Test File: Should trigger database configuration consistency violations
// Inconsistent database configuration parameters across getRdbStore calls

// ========== These should trigger Rule 14 warnings ==========

// Violation 1: Inconsistent encrypt and isReadOnly settings (from specification)
async function CreateRdbStore(context) {
    const config = {
        "name": STORE_NAME,
        securityLevel: relationalStore.SecurityLevel.S3
    }
    var rdbStore = undefined;
    try {
        rdbStore = await relationalStore.getRdbStore(context, config);
    } catch (err) {
        console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
    }
    return rdbStore
}

async function GetActiveRdbStore(context) {
    const config = {
        "name": STORE_NAME,
        securityLevel: relationalStore.SecurityLevel.S3,
        encrypt: true,
        isReadOnly: true
    }
    var rdbStore = undefined;
    try {
        rdbStore = await relationalStore.getRdbStore(context, config);
    } catch (err) {
        console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
    }
    return rdbStore
}

// Violation 2: Different securityLevel values
async function createMainDatabase(context) {
    const config = {
        "name": "main_db",
        securityLevel: relationalStore.SecurityLevel.S2
    };
    return await relationalStore.getRdbStore(context, config);
}

async function getMainDatabase(context) {
    const config = {
        "name": "main_db",
        securityLevel: relationalStore.SecurityLevel.S3  // Different security level
    };
    return await relationalStore.getRdbStore(context, config);
}

// Violation 3: Inconsistent encrypt settings
async function createUserDatabase(context) {
    const config = {
        "name": "user_db",
        securityLevel: relationalStore.SecurityLevel.S2,
        encrypt: false
    };
    return await relationalStore.getRdbStore(context, config);
}

async function getUserDatabase(context) {
    const config = {
        "name": "user_db",
        securityLevel: relationalStore.SecurityLevel.S2,
        encrypt: true  // Different encrypt setting
    };
    return await relationalStore.getRdbStore(context, config);
}

// Violation 4: Inconsistent isReadOnly settings
async function createLogDatabase(context) {
    const config = {
        "name": "log_db",
        securityLevel: relationalStore.SecurityLevel.S1,
        isReadOnly: false
    };
    return await relationalStore.getRdbStore(context, config);
}

async function getLogDatabase(context) {
    const config = {
        "name": "log_db",
        securityLevel: relationalStore.SecurityLevel.S1,
        isReadOnly: true  // Different read-only setting
    };
    return await relationalStore.getRdbStore(context, config);
}

// Violation 5: Different customDir settings
async function createBackupDatabase(context) {
    const config = {
        "name": "backup_db",
        securityLevel: relationalStore.SecurityLevel.S3,
        customDir: "/data/backup"
    };
    return await relationalStore.getRdbStore(context, config);
}

async function getBackupDatabase(context) {
    const config = {
        "name": "backup_db",
        securityLevel: relationalStore.SecurityLevel.S3,
        customDir: "/data/backup2"  // Different custom directory
    };
    return await relationalStore.getRdbStore(context, config);
}

// Violation 6: Multiple parameter inconsistencies
async function createComplexDatabase(context) {
    const config = {
        "name": "complex_db",
        securityLevel: relationalStore.SecurityLevel.S2,
        encrypt: false,
        isReadOnly: false
    };
    return await relationalStore.getRdbStore(context, config);
}

async function getComplexDatabase(context) {
    const config = {
        "name": "complex_db",
        securityLevel: relationalStore.SecurityLevel.S3,  // Different
        encrypt: true,                                    // Different
        isReadOnly: true                                  // Different
    };
    return await relationalStore.getRdbStore(context, config);
}

// Violation 7: Adding parameters in second call
async function createMinimalDatabase(context) {
    const config = {
        "name": "minimal_db",
        securityLevel: relationalStore.SecurityLevel.S1
    };
    return await relationalStore.getRdbStore(context, config);
}

async function getMinimalDatabaseWithExtra(context) {
    const config = {
        "name": "minimal_db",
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: true,        // Added parameter
        customDir: "/data/custom"  // Added parameter
    };
    return await relationalStore.getRdbStore(context, config);
}

// Violation 8: Removing parameters in second call
async function createFullDatabase(context) {
    const config = {
        "name": "full_db",
        securityLevel: relationalStore.SecurityLevel.S2,
        encrypt: true,
        isReadOnly: false,
        customDir: "/data/full"
    };
    return await relationalStore.getRdbStore(context, config);
}

async function getPartialDatabase(context) {
    const config = {
        "name": "full_db",
        securityLevel: relationalStore.SecurityLevel.S2
        // Missing encrypt, isReadOnly, customDir
    };
    return await relationalStore.getRdbStore(context, config);
}

// Violation 9: Multiple functions with same database but different configs
async function initDatabase(context) {
    return await relationalStore.getRdbStore(context, {
        "name": "multi_db",
        securityLevel: relationalStore.SecurityLevel.S1
    });
}

async function connectDatabase(context) {
    return await relationalStore.getRdbStore(context, {
        "name": "multi_db",
        securityLevel: relationalStore.SecurityLevel.S2  // Different
    });
}

async function accessDatabase(context) {
    return await relationalStore.getRdbStore(context, {
        "name": "multi_db",
        securityLevel: relationalStore.SecurityLevel.S3,  // Different
        encrypt: true  // Additional parameter
    });
}

// Violation 10: Different data_relationalStore calls
async function createWithDataModule(context) {
    const config = {
        "name": "data_module_db",
        securityLevel: data_relationalStore.SecurityLevel.S2
    };
    return await data_relationalStore.getRdbStore(context, config);
}

async function getWithRelationalStore(context) {
    const config = {
        "name": "data_module_db",
        securityLevel: relationalStore.SecurityLevel.S3  // Different security level
    };
    return await relationalStore.getRdbStore(context, config);
}

// Violation 11: Inline object differences
async function createInlineDatabase(context) {
    return await relationalStore.getRdbStore(context, {
        "name": "inline_db",
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: false
    });
}

async function getInlineDatabase(context) {
    return await relationalStore.getRdbStore(context, {
        "name": "inline_db",
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: true  // Different encrypt value
    });
}

// Violation 12: Variable vs inline configuration inconsistency
const staticConfig = {
    "name": "static_db",
    securityLevel: relationalStore.SecurityLevel.S2
};

async function createWithStaticConfig(context) {
    return await relationalStore.getRdbStore(context, staticConfig);
}

async function getWithInlineConfig(context) {
    return await relationalStore.getRdbStore(context, {
        "name": "static_db",
        securityLevel: relationalStore.SecurityLevel.S2,
        isReadOnly: true  // Additional parameter not in static config
    });
}

// Violation 13: Dynamic configuration with inconsistencies
async function createDynamicDatabase(context, encrypted) {
    const config = {
        "name": "dynamic_db",
        securityLevel: relationalStore.SecurityLevel.S2,
        encrypt: encrypted
    };
    return await relationalStore.getRdbStore(context, config);
}

async function getDynamicDatabase(context) {
    const config = {
        "name": "dynamic_db",
        securityLevel: relationalStore.SecurityLevel.S3,  // Different security
        encrypt: false  // Hardcoded different from dynamic
    };
    return await relationalStore.getRdbStore(context, config);
}

// Violation 14: Conditional configuration differences
async function createConditionalDatabase(context, isProduction) {
    const secLevel = isProduction ? 
        relationalStore.SecurityLevel.S3 : 
        relationalStore.SecurityLevel.S1;
        
    return await relationalStore.getRdbStore(context, {
        "name": "conditional_db",
        securityLevel: secLevel
    });
}

async function getConditionalDatabase(context) {
    return await relationalStore.getRdbStore(context, {
        "name": "conditional_db",
        securityLevel: relationalStore.SecurityLevel.S2  // Fixed level, inconsistent
    });
}

// Violation 15: Multiple calls in same function with inconsistencies
async function multipleCallsInconsistent(context) {
    const store1 = await relationalStore.getRdbStore(context, {
        "name": "same_function_db",
        securityLevel: relationalStore.SecurityLevel.S1
    });
    
    const store2 = await relationalStore.getRdbStore(context, {
        "name": "same_function_db",
        securityLevel: relationalStore.SecurityLevel.S2  // Different in same function
    });
    
    return { store1, store2 };
}

// Violation 16: Promise-based inconsistencies
function createPromiseDatabase(context) {
    return relationalStore.getRdbStore(context, {
        "name": "promise_db",
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: false
    });
}

function getPromiseDatabase(context) {
    return relationalStore.getRdbStore(context, {
        "name": "promise_db",
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: true  // Different encrypt setting
    });
}

// Violation 17: Callback style with inconsistencies (if supported)
function createCallbackDatabase(context, callback) {
    const config = {
        "name": "callback_db",
        securityLevel: relationalStore.SecurityLevel.S3,
        isReadOnly: false
    };
    
    relationalStore.getRdbStore(context, config)
        .then(callback)
        .catch(console.error);
}

function getCallbackDatabase(context, callback) {
    const config = {
        "name": "callback_db",
        securityLevel: relationalStore.SecurityLevel.S3,
        isReadOnly: true  // Different read-only setting
    };
    
    relationalStore.getRdbStore(context, config)
        .then(callback)
        .catch(console.error);
}

// Violation 18: Error handling with inconsistent configs
async function createWithErrorHandling(context) {
    try {
        return await relationalStore.getRdbStore(context, {
            "name": "error_db",
            securityLevel: relationalStore.SecurityLevel.S2
        });
    } catch (err) {
        console.error("Create failed:", err);
        throw err;
    }
}

async function getWithErrorHandling(context) {
    try {
        return await relationalStore.getRdbStore(context, {
            "name": "error_db",
            securityLevel: relationalStore.SecurityLevel.S1  // Different security level
        });
    } catch (err) {
        console.error("Get failed:", err);
        throw err;
    }
}

// Violation 19: Class method inconsistencies
class DatabaseManager {
    async createDatabase(context) {
        return await relationalStore.getRdbStore(context, {
            "name": "class_db",
            securityLevel: relationalStore.SecurityLevel.S2,
            encrypt: true
        });
    }
    
    async getDatabase(context) {
        return await relationalStore.getRdbStore(context, {
            "name": "class_db",
            securityLevel: relationalStore.SecurityLevel.S2,
            encrypt: false  // Different encrypt setting
        });
    }
}

// Violation 20: Mixed constant and variable usage
const BASE_CONFIG = {
    "name": "mixed_db",
    securityLevel: relationalStore.SecurityLevel.S1
};

async function createMixedDatabase(context) {
    return await relationalStore.getRdbStore(context, BASE_CONFIG);
}

async function getMixedDatabase(context) {
    const modifiedConfig = {
        ...BASE_CONFIG,
        encrypt: true  // Additional parameter, making it inconsistent
    };
    return await relationalStore.getRdbStore(context, modifiedConfig);
}