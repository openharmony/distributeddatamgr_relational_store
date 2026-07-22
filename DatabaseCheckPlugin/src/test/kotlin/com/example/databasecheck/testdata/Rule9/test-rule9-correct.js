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
 
// Rule 9 Test File: Should NOT trigger database error handling violations
// Proper error code handling for database operations

// ========== These should NOT trigger Rule 9 warnings ==========

// Correct 1: Proper 14800047 handling with ResultSet cleanup and checkpoint (from specification)
async function checkpointWal() {
    let rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
    let predicates = new data_relationalStore.RdbPredicates("test");
    predicates.equalTo("name", "zhangsan");
    let resultSet = await rdbStore.query(predicates);
    
    try {
        const valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": new Uint8Array([1, 2, 3]),
        }
        await rdbStore?.insert("test", valueBucket);
    } catch (err) {
        if (err.code == 14800047) {
            resultSet?.close();
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        }
        console.info("Get RdbStore failed, err: " + err)
    }
}

// Correct 2: Proper retry logic for busy errors 14800024, 14800025, 14800028 (from specification)
async function retryForBusy(needRetry) {
    try {
        const valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": new Uint8Array([1, 2, 3]),
        }
        await rdbStore?.insert("test", valueBucket);
    } catch (err) {
        if ((err.code == 14800024 || err.code == 14800025 || err.code == 14800028) && needRetry) {
            sleep(1);
            await retryForBusy(false);
        }
    }
}

// Correct 3: Proper disk cleanup for 14800029 (from specification)
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
        if ((err.code == 14800029) && !cleaned) {
            // Clean up disk space
            await retryForFull(true);
        }
    }
}

// Correct 4: Comprehensive error handling for all required error codes
async function comprehensiveErrorHandling() {
    let resultSet = null;
    try {
        let predicates = new data_relationalStore.RdbPredicates("users");
        resultSet = await rdbStore?.query(predicates);
        
        const valueBucket = {
            "name": "comprehensive_user",
            "age": 25,
            "data": new Uint8Array([1, 2, 3, 4, 5])
        };
        await rdbStore?.insert("users", valueBucket);
        
    } catch (err) {
        if (err.code == 14800047) {
            // Close ResultSet and execute checkpoint
            resultSet?.close();
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if (err.code == 14800024 || err.code == 14800025 || err.code == 14800028) {
            // Retry with delay for busy database
            sleep(1);
            await comprehensiveErrorHandling();
        } else if (err.code == 14800029) {
            // Clean up disk space and retry
            console.log("Cleaning up disk space...");
            await comprehensiveErrorHandling();
        }
        console.error("Database operation failed:", err);
    }
}

// Correct 5: Query operations with proper error handling
async function queryWithProperErrorHandling() {
    let resultSet = null;
    try {
        let predicates = new data_relationalStore.RdbPredicates("users");
        predicates.like("name", "%test%");
        resultSet = await rdbStore?.query(predicates);
        
        const results = [];
        while (resultSet.goToNextRow()) {
            results.push({
                name: resultSet.getString(0),
                age: resultSet.getLong(1)
            });
        }
        return results;
        
    } catch (err) {
        if (err.code == 14800047) {
            resultSet?.close();
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if (err.code == 14800024 || err.code == 14800025 || err.code == 14800028) {
            sleep(1);
            return await queryWithProperErrorHandling();
        } else if (err.code == 14800029) {
            // Clean disk and retry
            return await queryWithProperErrorHandling();
        }
        throw err;
    } finally {
        resultSet?.close();
    }
}

// Correct 6: Update operations with retry logic
async function updateWithRetryLogic(needRetry = true) {
    try {
        const valueBucket = {"age": 30, "salary": 300.0};
        let predicates = new data_relationalStore.RdbPredicates("users");
        predicates.equalTo("name", "test_user");
        await rdbStore?.update(valueBucket, predicates);
        
    } catch (err) {
        if (err.code == 14800047) {
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if ((err.code == 14800024 || err.code == 14800025 || err.code == 14800028) && needRetry) {
            sleep(1);
            await updateWithRetryLogic(false);
        } else if (err.code == 14800029) {
            console.log("Disk cleanup needed");
            await updateWithRetryLogic(false);
        }
    }
}

// Correct 7: Delete operations with error handling
async function deleteWithErrorHandling() {
    let resultSet = null;
    try {
        let predicates = new data_relationalStore.RdbPredicates("users");
        predicates.equalTo("status", "deleted");
        await rdbStore?.delete(predicates);
        
    } catch (err) {
        if (err.code == 14800047) {
            resultSet?.close();
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if (err.code == 14800024 || err.code == 14800025 || err.code == 14800028) {
            sleep(1);
            await deleteWithErrorHandling();
        } else if (err.code == 14800029) {
            // Clean up and retry
            await deleteWithErrorHandling();
        }
    }
}

// Correct 8: Batch operations with comprehensive error handling
async function batchInsertWithErrorHandling(retryCount = 0) {
    const maxRetries = 3;
    try {
        const valueBuckets = [
            {"name": "batch_user1", "age": 20},
            {"name": "batch_user2", "age": 21},
            {"name": "batch_user3", "age": 22}
        ];
        await rdbStore?.batchInsert("users", valueBuckets);
        
    } catch (err) {
        if (err.code == 14800047) {
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if ((err.code == 14800024 || err.code == 14800025 || err.code == 14800028) && retryCount < maxRetries) {
            sleep(1);
            await batchInsertWithErrorHandling(retryCount + 1);
        } else if (err.code == 14800029 && retryCount < maxRetries) {
            console.log("Cleaning disk for batch operation");
            await batchInsertWithErrorHandling(retryCount + 1);
        }
    }
}

// Correct 9: Transaction with proper error handling
async function transactionWithErrorHandling() {
    let resultSet = null;
    try {
        await rdbStore?.beginTransaction();
        
        // Multiple operations in transaction
        const user1 = {"name": "trans_user1", "age": 25};
        await rdbStore?.insert("users", user1);
        
        let predicates = new data_relationalStore.RdbPredicates("users");
        predicates.equalTo("name", "trans_user1");
        await rdbStore?.update({"age": 26}, predicates);
        
        await rdbStore?.commit();
        
    } catch (err) {
        await rdbStore?.rollback();
        
        if (err.code == 14800047) {
            resultSet?.close();
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if (err.code == 14800024 || err.code == 14800025 || err.code == 14800028) {
            sleep(1);
            await transactionWithErrorHandling();
        } else if (err.code == 14800029) {
            // Clean up and retry transaction
            await transactionWithErrorHandling();
        }
    }
}

// Correct 10: SQL execution with error handling
async function executeSqlWithErrorHandling() {
    let resultSet = null;
    try {
        await rdbStore?.executeSql("CREATE TABLE IF NOT EXISTS temp_table (id INTEGER PRIMARY KEY, name TEXT)");
        
    } catch (err) {
        if (err.code == 14800047) {
            resultSet?.close();
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if (err.code == 14800024 || err.code == 14800025 || err.code == 14800028) {
            sleep(1);
            await executeSqlWithErrorHandling();
        } else if (err.code == 14800029) {
            console.log("Disk cleanup needed for SQL execution");
            await executeSqlWithErrorHandling();
        }
    }
}

// Correct 11: getRdbStore with error handling
async function getRdbStoreWithErrorHandling() {
    try {
        let store = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await store.insert("test", {"name": "store_test"});
        
    } catch (err) {
        if (err.code == 14800047) {
            await store?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if (err.code == 14800024 || err.code == 14800025 || err.code == 14800028) {
            sleep(1);
            await getRdbStoreWithErrorHandling();
        } else if (err.code == 14800029) {
            // Clean up disk space
            await getRdbStoreWithErrorHandling();
        }
    }
}

// Correct 12: Backup operations with error handling
async function backupWithErrorHandling(cleaned = false) {
    try {
        await rdbStore?.backup("backup_file.db");
        
    } catch (err) {
        if (err.code == 14800047) {
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if (err.code == 14800024 || err.code == 14800025 || err.code == 14800028) {
            sleep(1);
            await backupWithErrorHandling(cleaned);
        } else if (err.code == 14800029 && !cleaned) {
            console.log("Cleaning disk for backup operation");
            await backupWithErrorHandling(true);
        }
    }
}

// Correct 13: Restore operations with error handling
async function restoreWithErrorHandling() {
    let resultSet = null;
    try {
        await rdbStore?.restore("backup_file.db");
        
    } catch (err) {
        if (err.code == 14800047) {
            resultSet?.close();
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if (err.code == 14800024 || err.code == 14800025 || err.code == 14800028) {
            sleep(1);
            await restoreWithErrorHandling();
        } else if (err.code == 14800029) {
            // Clean up disk for restore
            await restoreWithErrorHandling();
        }
    }
}

// Correct 14: Complex nested operations with proper error handling
async function complexOperationsWithErrorHandling() {
    let resultSet1 = null;
    let resultSet2 = null;
    
    try {
        // First query
        let predicates1 = new data_relationalStore.RdbPredicates("users");
        resultSet1 = await rdbStore?.query(predicates1);
        
        // Insert operation
        const valueBucket = {"name": "complex_user", "age": 40};
        await rdbStore?.insert("users", valueBucket);
        
        // Second query
        let predicates2 = new data_relationalStore.RdbPredicates("users");
        predicates2.equalTo("name", "complex_user");
        resultSet2 = await rdbStore?.query(predicates2);
        
        // Update operation
        await rdbStore?.update({"age": 41}, predicates2);
        
    } catch (err) {
        if (err.code == 14800047) {
            resultSet1?.close();
            resultSet2?.close();
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if (err.code == 14800024 || err.code == 14800025 || err.code == 14800028) {
            sleep(1);
            await complexOperationsWithErrorHandling();
        } else if (err.code == 14800029) {
            console.log("Disk cleanup for complex operations");
            await complexOperationsWithErrorHandling();
        }
    } finally {
        resultSet1?.close();
        resultSet2?.close();
    }
}

// Correct 15: Async operations with proper error handling
async function asyncOperationsWithErrorHandling() {
    try {
        const promises = [];
        for (let i = 0; i < 5; i++) {
            promises.push(insertWithErrorHandling(`async_user_${i}`, 20 + i));
        }
        await Promise.all(promises);
        
    } catch (err) {
        if (err.code == 14800047) {
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if (err.code == 14800024 || err.code == 14800025 || err.code == 14800028) {
            sleep(1);
            await asyncOperationsWithErrorHandling();
        } else if (err.code == 14800029) {
            // Clean up disk for async operations
            await asyncOperationsWithErrorHandling();
        }
    }
}

// Helper function for async operations
async function insertWithErrorHandling(name, age) {
    let resultSet = null;
    try {
        await rdbStore?.insert("users", {"name": name, "age": age});
    } catch (err) {
        if (err.code == 14800047) {
            resultSet?.close();
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if (err.code == 14800024 || err.code == 14800025 || err.code == 14800028) {
            sleep(1);
            await insertWithErrorHandling(name, age);
        } else if (err.code == 14800029) {
            console.log(`Disk cleanup for user ${name}`);
            await insertWithErrorHandling(name, age);
        }
    }
}

// Correct 16: No database operations (should not trigger warnings)
async function nonDatabaseOperations() {
    try {
        const data = await fetch('/api/users');
        const users = await data.json();
        console.log('Users:', users);
    } catch (err) {
        console.error('API call failed:', err);
        // No need for database error codes
    }
}

// Correct 17: Database operations with specific error handling patterns
async function specificErrorPatterns() {
    let resultSet = null;
    try {
        let predicates = new data_relationalStore.RdbPredicates("test");
        resultSet = await rdbStore?.query(predicates);
        await rdbStore?.insert("test", {"name": "specific_test"});
        
    } catch (err) {
        // Specific handling for each error code
        switch (err.code) {
            case 14800047:
                resultSet?.close();
                await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
                break;
            case 14800024:
            case 14800025:
            case 14800028:
                sleep(1);
                await specificErrorPatterns();
                break;
            case 14800029:
                console.log("Cleaning disk space");
                await specificErrorPatterns();
                break;
            default:
                console.error("Unhandled database error:", err);
        }
    }
}

// Correct 18: Conditional retry logic
async function conditionalRetryLogic(retryEnabled = true, maxRetries = 3, currentRetry = 0) {
    try {
        const valueBucket = {"name": "conditional_user", "retry_count": currentRetry};
        await rdbStore?.insert("users", valueBucket);
        
    } catch (err) {
        if (err.code == 14800047) {
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if ((err.code == 14800024 || err.code == 14800025 || err.code == 14800028) && 
                   retryEnabled && currentRetry < maxRetries) {
            sleep(1);
            await conditionalRetryLogic(retryEnabled, maxRetries, currentRetry + 1);
        } else if (err.code == 14800029 && currentRetry < maxRetries) {
            // Disk cleanup with retry count
            await conditionalRetryLogic(retryEnabled, maxRetries, currentRetry + 1);
        }
    }
}

// Correct 19: Error handling with cleanup functions
async function errorHandlingWithCleanup() {
    let resultSet = null;
    
    const cleanup = () => {
        resultSet?.close();
    };
    
    try {
        let predicates = new data_relationalStore.RdbPredicates("cleanup_test");
        resultSet = await rdbStore?.query(predicates);
        await rdbStore?.insert("cleanup_test", {"name": "cleanup_user"});
        
    } catch (err) {
        if (err.code == 14800047) {
            cleanup();
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if (err.code == 14800024 || err.code == 14800025 || err.code == 14800028) {
            sleep(1);
            await errorHandlingWithCleanup();
        } else if (err.code == 14800029) {
            console.log("Cleaning disk and retrying");
            await errorHandlingWithCleanup();
        }
    } finally {
        cleanup();
    }
}

// Correct 20: Multiple try-catch blocks with proper error handling
async function multipleTryCatchBlocks() {
    // First try-catch for initial query
    let resultSet = null;
    try {
        let predicates = new data_relationalStore.RdbPredicates("multi_test");
        resultSet = await rdbStore?.query(predicates);
    } catch (err) {
        if (err.code == 14800047) {
            resultSet?.close();
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if (err.code == 14800024 || err.code == 14800025 || err.code == 14800028) {
            sleep(1);
            return await multipleTryCatchBlocks();
        }
    }
    
    // Second try-catch for insert operation
    try {
        await rdbStore?.insert("multi_test", {"name": "multi_user"});
    } catch (err) {
        if (err.code == 14800047) {
            resultSet?.close();
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        } else if (err.code == 14800029) {
            console.log("Disk cleanup for insert");
            return await multipleTryCatchBlocks();
        }
    } finally {
        resultSet?.close();
    }
}