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
 
// Rule 12 Test File: Should trigger SQLite pragma restriction violations
// Prohibited PRAGMA operations that compromise database integrity

// ========== These should trigger Rule 12 warnings ==========

// Violation 1: PRAGMA journal_mode = OFF (from specification example 2)
async function CreateRdbStoreWithJournalOff(context) {
    const config = {
        "name": STORE_NAME,
        securityLevel: relationalStore.SecurityLevel.S3,
    }
    var rdbStore = undefined;
    try {
        rdbStore = await relationalStore.getRdbStore(context, config);
        await rdbStore?.execute('PRAGMA journal_mode = OFF');
    } catch (err) {
        console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
    }
    return rdbStore
}

// Violation 2: PRAGMA schema_version = xxxx (from specification example 2)
async function CreateRdbStoreWithSchemaVersion(context) {
    const config = {
        "name": STORE_NAME,
        securityLevel: relationalStore.SecurityLevel.S3,
    }
    var rdbStore = undefined;
    try {
        rdbStore = await relationalStore.getRdbStore(context, config);
        await rdbStore?.execute('PRAGMA schema_version = 100');
    } catch (err) {
        console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
    }
    return rdbStore
}

// Violation 3: PRAGMA synchronous = OFF (from specification example 2)
async function CreateRdbStoreWithSyncOff(context) {
    const config = {
        "name": STORE_NAME,
        securityLevel: relationalStore.SecurityLevel.S3,
    }
    var rdbStore = undefined;
    try {
        rdbStore = await relationalStore.getRdbStore(context, config);
        await rdbStore?.execute('PRAGMA synchronous=OFF');
    } catch (err) {
        console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
    }
    return rdbStore
}

// Violation 4: PRAGMA journal_mode = MEMORY (from specification example 2)
async function CreateRdbStoreWithJournalMemory(context) {
    const config = {
        "name": STORE_NAME,
        securityLevel: relationalStore.SecurityLevel.S3,
    }
    var rdbStore = undefined;
    try {
        rdbStore = await relationalStore.getRdbStore(context, config);
        await rdbStore?.execute('PRAGMA journal_mode = MEMORY');
    } catch (err) {
        console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
    }
    return rdbStore
}

// Violation 5: PRAGMA writable_schema = ON (from specification example 2)
async function CreateRdbStoreWithWritableSchema(context) {
    const config = {
        "name": STORE_NAME,
        securityLevel: relationalStore.SecurityLevel.S3,
    }
    var rdbStore = undefined;
    try {
        rdbStore = await relationalStore.getRdbStore(context, config);
        await rdbStore?.execute('PRAGMA writable_schema = ON');
    } catch (err) {
        console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
    }
    return rdbStore
}

// Violation 6: Multiple prohibited pragmas in one function
async function multiplePragmaViolations(context) {
    try {
        var rdbStore = await relationalStore.getRdbStore(context, config);
        await rdbStore?.execute('PRAGMA journal_mode = OFF');
        await rdbStore?.execute('PRAGMA synchronous = OFF');
        await rdbStore?.execute('PRAGMA writable_schema = ON');
        return rdbStore;
    } catch (err) {
        console.error("Multiple pragma violations:", err);
    }
}

// Violation 7: executeSql with prohibited pragma
async function executeSqlWithPragma() {
    try {
        await rdbStore?.executeSql('PRAGMA journal_mode = OFF');
    } catch (err) {
        console.error("ExecuteSql pragma failed:", err);
    }
}

// Violation 8: Variable containing prohibited pragma
async function variableWithPragma() {
    const dangerousQuery = 'PRAGMA synchronous = OFF';
    try {
        await rdbStore?.execute(dangerousQuery);
    } catch (err) {
        console.error("Variable pragma failed:", err);
    }
}

// Violation 9: Template literal with pragma
async function templateLiteralPragma(mode) {
    try {
        await rdbStore?.execute(`PRAGMA journal_mode = ${mode}`); // if mode is "OFF"
    } catch (err) {
        console.error("Template literal pragma failed:", err);
    }
}

// Violation 10: Pragma with different spacing
async function pragmaWithDifferentSpacing() {
    try {
        await rdbStore?.execute('PRAGMA    journal_mode    =    OFF');
        await rdbStore?.execute('PRAGMA synchronous=OFF'); // no spaces around =
        await rdbStore?.execute('PRAGMA  writable_schema   =  ON');
    } catch (err) {
        console.error("Spacing pragma failed:", err);
    }
}

// Violation 11: Case variations
async function pragmaCaseVariations() {
    try {
        await rdbStore?.execute('pragma journal_mode = off');
        await rdbStore?.execute('Pragma synchronous = Off');
        await rdbStore?.execute('PRAGMA WRITABLE_SCHEMA = on');
    } catch (err) {
        console.error("Case variation pragma failed:", err);
    }
}

// Violation 12: Pragma in different database calls
async function pragmaInDifferentCalls() {
    try {
        const store1 = await relationalStore.getRdbStore(context, config1);
        await store1.execute('PRAGMA journal_mode = OFF');
        
        const store2 = await relationalStore.getRdbStore(context, config2);
        await store2.executeSql('PRAGMA synchronous = OFF');
    } catch (err) {
        console.error("Different calls pragma failed:", err);
    }
}

// Violation 13: Pragma with schema version and specific value
async function schemaVersionWithValue() {
    try {
        await rdbStore?.execute('PRAGMA schema_version = 42');
        await rdbStore?.execute('PRAGMA schema_version = 100');
        await rdbStore?.execute('PRAGMA schema_version = 999');
    } catch (err) {
        console.error("Schema version pragma failed:", err);
    }
}

// Violation 14: Pragma in loop
async function pragmaInLoop() {
    const pragmas = [
        'PRAGMA journal_mode = OFF',
        'PRAGMA synchronous = OFF',
        'PRAGMA writable_schema = ON'
    ];
    
    for (const pragma of pragmas) {
        try {
            await rdbStore?.execute(pragma);
        } catch (err) {
            console.error(`Pragma ${pragma} failed:`, err);
        }
    }
}

// Violation 15: Conditional pragma execution
async function conditionalPragma(unsafe) {
    if (unsafe) {
        try {
            await rdbStore?.execute('PRAGMA journal_mode = OFF');
        } catch (err) {
            console.error("Conditional pragma failed:", err);
        }
    }
}

// Violation 16: Pragma with additional SQL
async function pragmaWithAdditionalSql() {
    try {
        await rdbStore?.execute('CREATE TABLE test (id INTEGER); PRAGMA journal_mode = OFF;');
    } catch (err) {
        console.error("Combined SQL with pragma failed:", err);
    }
}

// Violation 17: Dynamic pragma construction
async function dynamicPragmaConstruction() {
    const pragmaName = "journal_mode";
    const pragmaValue = "OFF";
    const query = `PRAGMA ${pragmaName} = ${pragmaValue}`;
    
    try {
        await rdbStore?.execute(query);
    } catch (err) {
        console.error("Dynamic pragma failed:", err);
    }
}

// Violation 18: Pragma in async operations
async function asyncPragmaOperations() {
    const pragmaOperations = [
        async () => await rdbStore?.execute('PRAGMA journal_mode = OFF'),
        async () => await rdbStore?.execute('PRAGMA synchronous = OFF'),
        async () => await rdbStore?.execute('PRAGMA writable_schema = ON')
    ];
    
    try {
        await Promise.all(pragmaOperations.map(op => op()));
    } catch (err) {
        console.error("Async pragma operations failed:", err);
    }
}

// Violation 19: Nested function with pragma
async function nestedFunctionWithPragma() {
    async function innerFunction() {
        await rdbStore?.execute('PRAGMA journal_mode = MEMORY');
    }
    
    try {
        await innerFunction();
    } catch (err) {
        console.error("Nested pragma failed:", err);
    }
}

// Violation 20: Pragma with error handling that still executes
async function pragmaWithErrorHandling() {
    try {
        await rdbStore?.execute('PRAGMA synchronous = OFF');
    } catch (err) {
        console.error("Pragma failed, but it was still attempted:", err);
        // The violation is attempting the pragma, not handling the error
    }
}