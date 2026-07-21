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
 
// Rule 4 Test File: Should NOT trigger transaction commit/rollback violations

// ========== These should NOT trigger Rule 4 warnings ==========

// Correct 1: Proper commit and rollback (Positive example from specification)
async function properCommitAndRollback() {
    let trans;
    try {
        trans = await rdbStore.createTransaction({
            transactionType: relationalStore.TransactionType.EXCLUSIVE
        });
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = new Array(100).fill(0).map(() => {
            return {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            };
        });
        const resultCount = await trans.batchInsert("test", valueBuckets);
        await trans.commit();
        return resultCount;
    } catch (err) {
        if (trans) {
            trans.rollback();
        }
        console.error(TAG + JSON.stringify(err));
        return err.code;
    }
}

// Correct 2: Simple transaction with proper cleanup
async function simpleTransactionProperCleanup() {
    let transaction;
    try {
        transaction = await rdbStore.createTransaction({
            transactionType: relationalStore.TransactionType.IMMEDIATE
        });
        
        await transaction.insert("users", {
            name: "Alice",
            email: "alice@example.com",
            created_at: Date.now()
        });
        
        await transaction.commit();
        return "User created successfully";
        
    } catch (err) {
        if (transaction) {
            transaction.rollback();
        }
        console.error("Transaction failed:", err);
        throw err;
    }
}

// Correct 3: Multiple operations with proper commit and rollback
async function multipleOperationsProperHandling() {
    let trans;
    try {
        trans = await rdbStore.createTransaction({});
        
        // Multiple related operations
        await trans.insert("orders", {
            id: 1001,
            customer_id: 123,
            total_amount: 299.99,
            order_date: Date.now()
        });
        
        await trans.insert("order_items", {
            order_id: 1001,
            product_id: 456,
            quantity: 2,
            price: 149.99
        });
        
        await trans.update("products", 
            {stock_quantity: "stock_quantity - 2"}, 
            "id = ?", 
            [456]
        );
        
        await trans.commit();
        return "Order processed successfully";
        
    } catch (err) {
        if (trans) {
            trans.rollback();
        }
        console.error("Order processing failed:", err);
        throw err;
    }
}

// Correct 4: Transaction with conditional operations and proper cleanup
async function conditionalOperationsProperCleanup() {
    let dbTransaction;
    try {
        dbTransaction = await rdbStore.createTransaction({
            transactionType: relationalStore.TransactionType.EXCLUSIVE
        });
        
        const user = await dbTransaction.query("SELECT * FROM users WHERE id = ?", [123]);
        
        if (user.length > 0) {
            await dbTransaction.update("users", 
                {last_login: Date.now(), login_count: "login_count + 1"}, 
                "id = ?", 
                [123]
            );
            
            await dbTransaction.insert("user_sessions", {
                user_id: 123,
                session_start: Date.now(),
                ip_address: "192.168.1.1"
            });
        } else {
            await dbTransaction.insert("users", {
                id: 123,
                name: "New User",
                created_at: Date.now(),
                login_count: 1
            });
        }
        
        await dbTransaction.commit();
        return "User session handled";
        
    } catch (err) {
        if (dbTransaction) {
            dbTransaction.rollback();
        }
        console.error("Session handling failed:", err);
        throw err;
    }
}

// Correct 5: Transaction with batch operations
async function batchOperationsCorrect() {
    let trans;
    try {
        trans = await rdbStore.createTransaction({
            transactionType: relationalStore.TransactionType.IMMEDIATE
        });
        
        const products = [
            {name: "Product A", price: 100, category: "Electronics"},
            {name: "Product B", price: 200, category: "Electronics"},
            {name: "Product C", price: 150, category: "Books"}
        ];
        
        await trans.batchInsert("products", products);
        
        // Update category statistics
        await trans.execute(`
            UPDATE categories 
            SET product_count = product_count + ? 
            WHERE name = ?
        `, [2, "Electronics"]);
        
        await trans.execute(`
            UPDATE categories 
            SET product_count = product_count + ? 
            WHERE name = ?
        `, [1, "Books"]);
        
        await trans.commit();
        return products.length;
        
    } catch (err) {
        if (trans) {
            trans.rollback();
        }
        console.error("Batch insert failed:", err);
        return 0;
    }
}

// Correct 6: Complex transaction with nested try-catch but proper rollback
async function nestedTryCatchCorrect() {
    let mainTransaction;
    try {
        mainTransaction = await rdbStore.createTransaction({});
        
        await mainTransaction.insert("operation_logs", {
            operation: "complex_update",
            started_at: Date.now()
        });
        
        try {
            const users = await mainTransaction.query("SELECT * FROM users WHERE active = ?", [true]);
            
            for (const user of users) {
                await mainTransaction.update("users", 
                    {last_processed: Date.now()}, 
                    "id = ?", 
                    [user.id]
                );
            }
            
            await mainTransaction.update("operation_logs", 
                {completed_at: Date.now(), status: "success"}, 
                "operation = ?", 
                ["complex_update"]
            );
            
            await mainTransaction.commit();
            return "Complex operation completed";
            
        } catch (innerErr) {
            console.error("Inner operation failed:", innerErr);
            throw innerErr; // Re-throw to outer catch
        }

        mainTransaction.commit();
        
    } catch (outerErr) {
        if (mainTransaction) {
            mainTransaction.rollback();
        }
        console.error("Complex operation failed:", outerErr);
        return "Operation failed";
    }
}

// Correct 7: Transaction with early success return but proper commit
async function earlyReturnWithCommit() {
    let trans;
    try {
        trans = await rdbStore.createTransaction({});
        
        const existingUser = await trans.query("SELECT * FROM users WHERE email = ?", ["test@example.com"]);
        
        if (existingUser.length > 0) {
            // Update existing user and commit before returning
            await trans.update("users", 
                {last_seen: Date.now()}, 
                "email = ?", 
                ["test@example.com"]
            );
            await trans.commit();
            return "User updated";
        }
        
        await trans.insert("users", {
            email: "test@example.com", 
            name: "Test User",
            created_at: Date.now()
        });
        await trans.commit();
        
        return "User created";
        
    } catch (err) {
        if (trans) {
            trans.rollback();
        }
        throw err;
    }
}

// Correct 8: Transaction with different variable names but proper handling
async function differentVariableNamesCorrect() {
    let myTransactionHandler;
    try {
        myTransactionHandler = await rdbStore.createTransaction({
            transactionType: relationalStore.TransactionType.EXCLUSIVE
        });
        
        await myTransactionHandler.execute("DELETE FROM temp_cache WHERE created_at < ?", [Date.now() - 86400000]);
        
        await myTransactionHandler.insert("cache_operations", {
            operation: "cleanup",
            timestamp: Date.now(),
            records_affected: 0 // This would be updated in real implementation
        });
        
        await myTransactionHandler.commit();
        return "Cache cleanup completed";
        
    } catch (err) {
        if (myTransactionHandler) {
            myTransactionHandler.rollback();
        }
        console.error("Cache cleanup failed:", err);
        throw err;
    }
}

// Correct 9: No transactions used - should not trigger any warnings
async function noTransactionUsed() {
    try {
        // Direct database operations without transactions
        const users = await rdbStore.query("SELECT * FROM users WHERE active = ?", [true]);
        
        for (const user of users) {
            await rdbStore.update("users", 
                {last_seen: Date.now()}, 
                "id = ?", 
                [user.id]
            );
        }
        
        await rdbStore.insert("operation_logs", {
            operation: "direct_update",
            timestamp: Date.now(),
            users_affected: users.length
        });
        
        return users.length;
        
    } catch (err) {
        console.error("Direct operations failed:", err);
        return 0;
    }
}

// Correct 10: Multiple transactions in sequence with proper handling
async function multipleTransactionsSequential() {
    // First transaction
    let trans1;
    try {
        trans1 = await rdbStore.createTransaction({});
        await trans1.insert("batch_jobs", {id: 1, status: "started", timestamp: Date.now()});
        await trans1.commit();
    } catch (err) {
        if (trans1) {
            trans1.rollback();
        }
        throw err;
    }
    
    // Second transaction
    let trans2;
    try {
        trans2 = await rdbStore.createTransaction({});
        await trans2.update("batch_jobs", {status: "completed", timestamp: Date.now()}, "id = ?", [1]);
        await trans2.commit();
        return "Batch job completed";
    } catch (err) {
        if (trans2) {
            trans2.rollback();
        }
        throw err;
    }
}