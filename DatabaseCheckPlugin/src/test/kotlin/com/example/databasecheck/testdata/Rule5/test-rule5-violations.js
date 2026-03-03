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
 
// Rule 5 Test File: Should trigger transaction nesting and thread safety violations

// ========== These should trigger Rule 5 warnings ==========

// Violation 1: Using deprecated beginTransaction API (Example from specification)
async function deprecatedBeginTransactionExample() {
    var u8 = new Uint8Array([1, 2, 3])
    try {
        rdbStore.beginTransaction()  // Should trigger warning - deprecated API
        const valueBucket = {
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket)
        rdbStore.commit()  // Should trigger warning - deprecated API
    } catch (e) {
        rdbStore.rollback();  // Should trigger warning - deprecated API
    }
}

// Violation 2: Multiple deprecated API calls in same function
async function multipleDeprecatedAPIs() {
    try {
        rdbStore.beginTransaction();  // Should trigger warning
        
        await rdbStore.insert("users", {name: "John", age: 30});
        await rdbStore.update("users", {last_login: Date.now()}, "name = ?", ["John"]);
        
        rdbStore.commit();  // Should trigger warning
        
    } catch (err) {
        console.error("Transaction failed:", err);
        rdbStore.rollback();  // Should trigger warning
    }
}

// Violation 3: Deprecated beginTransaction with complex operations
async function complexDeprecatedTransaction() {
    let results = [];
    
    try {
        rdbStore.beginTransaction();  // Should trigger warning
        
        const users = await rdbStore.query("SELECT * FROM users WHERE active = ?", [true]);
        
        for (const user of users) {
            await rdbStore.update("users", 
                {last_processed: Date.now()}, 
                "id = ?", 
                [user.id]
            );
            results.push(user.id);
        }
        
        await rdbStore.insert("batch_logs", {
            operation: "bulk_update",
            affected_count: results.length,
            timestamp: Date.now()
        });
        
        rdbStore.commit();  // Should trigger warning
        return results;
        
    } catch (err) {
        console.error("Bulk operation failed:", err);
        rdbStore.rollback();  // Should trigger warning
        return [];
    }
}

// Violation 4: Nested deprecated transaction calls
async function nestedDeprecatedTransactions() {
    try {
        rdbStore.beginTransaction();  // Should trigger warning
        
        await rdbStore.insert("outer_table", {data: "outer"});
        
        try {
            // Inner operations
            await rdbStore.insert("inner_table", {data: "inner"});
            
            if (Math.random() > 0.5) {
                rdbStore.commit();  // Should trigger warning
            } else {
                rdbStore.rollback();  // Should trigger warning
            }
            
        } catch (innerErr) {
            console.error("Inner error:", innerErr);
            rdbStore.rollback();  // Should trigger warning
        }
        
    } catch (outerErr) {
        console.error("Outer error:", outerErr);
        rdbStore.rollback();  // Should trigger warning
    }
}

// Violation 5: Deprecated API with batch operations
async function batchOperationsDeprecated() {
    const products = [
        {name: "Product A", price: 100, category: "Electronics"},
        {name: "Product B", price: 200, category: "Electronics"},
        {name: "Product C", price: 150, category: "Books"}
    ];
    
    try {
        rdbStore.beginTransaction();  // Should trigger warning
        
        for (const product of products) {
            await rdbStore.insert("products", product);
        }
        
        // Update category statistics
        await rdbStore.execute(`
            UPDATE categories 
            SET product_count = product_count + ? 
            WHERE name = ?
        `, [2, "Electronics"]);
        
        await rdbStore.execute(`
            UPDATE categories 
            SET product_count = product_count + ? 
            WHERE name = ?
        `, [1, "Books"]);
        
        rdbStore.commit();  // Should trigger warning
        return products.length;
        
    } catch (err) {
        console.error("Batch insert failed:", err);
        rdbStore.rollback();  // Should trigger warning
        return 0;
    }
}

// Violation 6: Deprecated API with conditional logic
async function conditionalDeprecatedTransaction() {
    const shouldInsert = Math.random() > 0.5;
    
    try {
        rdbStore.beginTransaction();  // Should trigger warning
        
        if (shouldInsert) {
            await rdbStore.insert("conditional_table", {
                action: "insert",
                timestamp: Date.now(),
                random_value: Math.random()
            });
        } else {
            await rdbStore.update("conditional_table", 
                {last_updated: Date.now()}, 
                "id = ?", 
                [1]
            );
        }
        
        rdbStore.commit();  // Should trigger warning
        return "Operation completed";
        
    } catch (err) {
        console.error("Conditional operation failed:", err);
        rdbStore.rollback();  // Should trigger warning
        return "Operation failed";
    }
}

// Violation 7: Multiple sequential deprecated transactions
async function sequentialDeprecatedTransactions() {
    // First deprecated transaction
    try {
        rdbStore.beginTransaction();  // Should trigger warning
        await rdbStore.insert("sequence_table", {step: 1, timestamp: Date.now()});
        rdbStore.commit();  // Should trigger warning
    } catch (err) {
        console.error("First transaction failed:", err);
        rdbStore.rollback();  // Should trigger warning
    }
    
    // Second deprecated transaction
    try {
        rdbStore.beginTransaction();  // Should trigger warning
        await rdbStore.insert("sequence_table", {step: 2, timestamp: Date.now()});
        rdbStore.commit();  // Should trigger warning
    } catch (err) {
        console.error("Second transaction failed:", err);
        rdbStore.rollback();  // Should trigger warning
    }
    
    return "Sequential transactions completed";
}

// Violation 8: Deprecated API with async/await patterns
async function asyncDeprecatedTransaction() {
    const promises = [];
    
    try {
        rdbStore.beginTransaction();  // Should trigger warning
        
        // Create multiple async operations
        for (let i = 0; i < 5; i++) {
            const promise = rdbStore.insert("async_table", {
                id: i,
                data: `async_data_${i}`,
                timestamp: Date.now()
            });
            promises.push(promise);
        }
        
        // Wait for all operations to complete
        await Promise.all(promises);
        
        rdbStore.commit();  // Should trigger warning
        return "Async operations completed";
        
    } catch (err) {
        console.error("Async operations failed:", err);
        rdbStore.rollback();  // Should trigger warning
        return "Async operations failed";
    }
}

// Violation 9: Deprecated API in callback function
function callbackDeprecatedTransaction(callback) {
    try {
        rdbStore.beginTransaction();  // Should trigger warning
        
        rdbStore.insert("callback_table", {data: "callback_data"})
            .then(() => {
                rdbStore.commit();  // Should trigger warning
                if (callback) callback(null, "Success");
            })
            .catch(err => {
                console.error("Callback operation failed:", err);
                rdbStore.rollback();  // Should trigger warning
                if (callback) callback(err);
            });
            
    } catch (err) {
        console.error("Callback transaction setup failed:", err);
        rdbStore.rollback();  // Should trigger warning
        if (callback) callback(err);
    }
}

// Violation 10: Deprecated API with try-catch-finally
async function finallyDeprecatedTransaction() {
    let operationStarted = false;
    
    try {
        rdbStore.beginTransaction();  // Should trigger warning
        operationStarted = true;
        
        await rdbStore.insert("finally_table", {
            operation: "finally_test",
            timestamp: Date.now()
        });
        
        rdbStore.commit();  // Should trigger warning
        return "Finally operation completed";
        
    } catch (err) {
        console.error("Finally operation failed:", err);
        if (operationStarted) {
            rdbStore.rollback();  // Should trigger warning
        }
        throw err;
        
    } finally {
        console.log("Finally block executed");
        // Note: This is not a good practice, but testing detection
        if (operationStarted) {
            // Additional cleanup if needed
        }
    }
}