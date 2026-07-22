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
 
// Rule 9 Test File: Should trigger database error handling violations
// Missing proper error code handling for database operations

// ========== These should trigger Rule 9 warnings ==========

// Violation 1: Empty catch block for database operations (from specification)
async function retryForFull(cleaned) {
    try {
        const valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": new Uint8Array([1, 2, 3]),
        }
        await rdbStore?.insert("test", valueBucket);
    } catch (err) {
        // Empty catch - missing error code handling

    }
}

// Violation 2: Database query without error handling
async function queryWithoutErrorHandling() {
    try {
        let predicates = new data_relationalStore.RdbPredicates("test");
        predicates.equalTo("name", "zhangsan");
        let resultSet = await rdbStore.query(predicates);
        return resultSet;
    } catch (err) {
        console.log("Query failed");
        // Missing specific error code handling
    }
}

// Violation 3: Insert operation without retry logic
async function insertWithoutRetry() {
    try {
        const valueBucket = {
            "name": "lisi",
            "age": 25,
            "salary": 200.0,
        }
        await rdbStore?.insert("users", valueBucket);
    } catch (err) {
        console.error("Insert failed:", err);
        // Should handle 14800024, 14800025, 14800028 with retry
    }
}

// Violation 4: Update operation without proper error handling
async function updateWithoutErrorCodes() {
    try {
        const valueBucket = {
            "age": 26,
            "salary": 250.0,
        }
        let predicates = new data_relationalStore.RdbPredicates("users");
        predicates.equalTo("name", "lisi");
        await rdbStore?.update(valueBucket, predicates);
    } catch (err) {
        throw err; // Re-throwing without handling specific error codes
    }
}

// Violation 5: Delete operation with incomplete error handling
async function deleteWithIncompleteHandling() {
    try {
        let predicates = new data_relationalStore.RdbPredicates("users");
        predicates.equalTo("name", "zhangsan");
        await rdbStore?.delete(predicates);
    } catch (err) {
        if (err.code == 14800047) {
            console.log("Some error occurred");
            // Missing resultSet close and checkpoint
        }
        // Missing other error codes
    }
}

// Violation 6: Batch insert without comprehensive error handling
async function batchInsertWithoutErrorHandling() {
    try {
        const valueBuckets = [
            {"name": "user1", "age": 20},
            {"name": "user2", "age": 21},
            {"name": "user3", "age": 22}
        ];
        await rdbStore?.batchInsert("users", valueBuckets);
    } catch (err) {
        // Empty catch for batch operations
    }
}

// Violation 7: Execute SQL without error code handling
async function executeSqlWithoutHandling() {
    try {
        await rdbStore?.executeSql("UPDATE users SET age = age + 1");
    } catch (err) {
        console.log("SQL execution failed");
        // No specific error code handling
    }
}

// Violation 8: Transaction operations without error handling
async function transactionWithoutErrorHandling() {
    try {
        await rdbStore?.beginTransaction();
        const valueBucket = {"name": "transactional_user", "age": 30};
        await rdbStore?.insert("users", valueBucket);
        await rdbStore?.commit();
    } catch (err) {
        await rdbStore?.rollback();
        // Missing error code specific handling
    }
}

// Violation 9: Partial error code handling (missing some codes)
async function partialErrorHandling() {
    try {
        const valueBucket = {"name": "partial", "age": 35};
        await rdbStore?.insert("users", valueBucket);
    } catch (err) {
        if (err.code == 14800024) {
            console.log("Database busy");
            // Missing retry logic
        }
        // Missing 14800025, 14800028, 14800029, 14800047 handling
    }
}

// Violation 10: ResultSet operations without error handling
async function resultSetWithoutErrorHandling() {
    try {
        let predicates = new data_relationalStore.RdbPredicates("users");
        let resultSet = await rdbStore?.query(predicates);
        
        while (resultSet.goToNextRow()) {
            const name = resultSet.getString(0);
            const age = resultSet.getLong(1);
            console.log(`User: ${name}, Age: ${age}`);
        }
        resultSet.close();
    } catch (err) {
        // Empty catch for ResultSet operations
    }
}

// Violation 11: 14800047 handling without ResultSet cleanup
async function improper14800047Handling() {
    try {
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore?.query(predicates);
        await rdbStore?.insert("test", {"name": "test"});
    } catch (err) {
        if (err.code == 14800047) {
            console.log("Error 14800047 occurred");
            // Missing resultSet.close() and checkpoint
        }
    }
}

// Violation 12: 14800029 handling without disk cleanup
async function improper14800029Handling() {
    try {
        const largeBucket = {
            "name": "large_user",
            "data": new Uint8Array(1000000) // Large data
        };
        await rdbStore?.insert("users", largeBucket);
    } catch (err) {
        if (err.code == 14800029) {
            console.log("Disk full error");
            // Missing disk cleanup logic
        }
    }
}

// Violation 13: Busy error codes without retry and delay
async function busyErrorsWithoutRetry() {
    try {
        await rdbStore?.insert("users", {"name": "busy_test"});
    } catch (err) {
        if (err.code == 14800024 || err.code == 14800025 || err.code == 14800028) {
            console.log("Database busy");
            // Missing sleep/delay and retry logic
        }
    }
}

// Violation 14: Complex operations without any error handling
async function complexOperationsWithoutHandling() {
    try {
        // Multiple database operations
        let predicates1 = new data_relationalStore.RdbPredicates("users");
        let resultSet1 = await rdbStore?.query(predicates1);
        
        const valueBucket = {"name": "complex", "age": 40};
        await rdbStore?.insert("users", valueBucket);
        
        let predicates2 = new data_relationalStore.RdbPredicates("users");
        predicates2.equalTo("name", "complex");
        await rdbStore?.update({"age": 41}, predicates2);
        
        resultSet1.close();
    } catch (err) {
        console.error("Complex operation failed");
        // No specific error code handling for multiple operations
    }
}

// Violation 15: Async operations without proper error handling
async function asyncOperationsWithoutHandling() {
    try {
        const promises = [];
        for (let i = 0; i < 5; i++) {
            promises.push(rdbStore?.insert("users", {"name": `async_user_${i}`, "age": 20 + i}));
        }
        await Promise.all(promises);
    } catch (err) {
        // Missing error code handling for async operations
    }
}

// Violation 16: getRdbStore without error handling
async function getRdbStoreWithoutHandling() {
    try {
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.insert("test", {"name": "store_test"});
    } catch (err) {
        console.log("Failed to get RDB store");
        // Missing specific error code handling
    }
}

// Violation 17: Backup operations without error handling  
async function backupWithoutHandling() {
    try {
        await rdbStore?.backup("backup_file.db");
    } catch (err) {
        // Empty catch for backup operations
    }
}

// Violation 18: Restore operations without error handling
async function restoreWithoutHandling() {
    try {
        await rdbStore?.restore("backup_file.db");
    } catch (err) {
        console.log("Restore failed");
        // Missing error code handling
    }
}

// Violation 19: Query with predicates without error handling
async function queryPredicatesWithoutHandling() {
    try {
        let predicates = new data_relationalStore.RdbPredicates("users");
        predicates.like("name", "%test%");
        predicates.and().greaterThan("age", 18);
        let resultSet = await rdbStore?.query(predicates);
        return resultSet;
    } catch (err) {
        // No error handling
    }
}

// Violation 20: Nested try-catch with incomplete handling
async function nestedTryCatchIncomplete() {
    try {
        await rdbStore?.beginTransaction();
        try {
            await rdbStore?.insert("users", {"name": "nested"});
            await rdbStore?.commit();
        } catch (innerErr) {
            await rdbStore?.rollback();
            // Inner catch missing error code handling
        }
    } catch (outerErr) {
        console.error("Transaction failed");
        // Outer catch also missing error code handling
    }
}