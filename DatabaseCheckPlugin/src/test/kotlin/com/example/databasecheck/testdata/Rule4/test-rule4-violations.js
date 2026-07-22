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
 
// Rule 4 Test File: Should trigger transaction commit/rollback violations

// ========== These should trigger Rule 4 warnings ==========

// Violation 1: Missing commit operation (Example 2 from specification)
async function missingCommitExample() {
    try {
        let trans = await rdbStore.createTransaction({
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
        // Should trigger warning - no commit operation
        const resultCount = await trans.batchInsert("test", valueBuckets);
        return resultCount;
    } catch (err) {
        console.error(TAG + JSON.stringify(err));
        return err.code;
    }
}

// Violation 2: Missing rollback in catch block (Example 1 from specification)
async function missingRollbackExample() {
    try {
        let trans = await rdbStore.createTransaction({
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
        // Should trigger warning - no rollback operation for transaction cleanup
        console.error(TAG + JSON.stringify(err));
        return err.code;
    }
}

// Violation 3: Transaction with operations but no commit
async function transactionWithoutCommit() {
    let transaction;
    try {
        transaction = await rdbStore.createTransaction({
            transactionType: relationalStore.TransactionType.IMMEDIATE
        });
        
        await transaction.insert("users", {name: "John", age: 30});
        await transaction.update("users", {last_login: Date.now()}, "name = ?", ["John"]);
        
        // Should trigger warning - missing commit
        return "Operations completed";
        
    } catch (err) {
        if (transaction) {
            transaction.rollback();
        }
        throw err;
    }
}

// Violation 4: Multiple operations, commit present, but missing rollback
async function missingRollbackMultipleOps() {
    try {
        let dbTransaction = await rdbStore.createTransaction({});
        
        await dbTransaction.insert("logs", {action: "start", timestamp: Date.now()});
        await dbTransaction.insert("logs", {action: "process", timestamp: Date.now()});
        await dbTransaction.insert("logs", {action: "end", timestamp: Date.now()});
        
        await dbTransaction.commit();
        return "Success";
        
    } catch (err) {
        // Should trigger warning - missing rollback for dbTransaction
        console.error("Transaction failed:", err);
        return "Failed";
    }
}

// Violation 5: Transaction created in try block, no commit or rollback
async function noCommitNoRollback() {
    try {
        let trans = await rdbStore.createTransaction({
            transactionType: relationalStore.TransactionType.EXCLUSIVE
        });
        
        await trans.execute("CREATE TABLE IF NOT EXISTS temp_table (id INTEGER, data TEXT)");
        await trans.insert("temp_table", {id: 1, data: "test"});
        
        // Should trigger warnings - both missing commit and missing rollback
        return "Table created";
        
    } catch (err) {
        console.error("Error:", err);
        return "Error occurred";
    }
}

// Violation 6: Different variable name, missing commit
async function differentVarNameMissingCommit() {
    let myTrans;
    try {
        myTrans = await rdbStore.createTransaction({
            transactionType: relationalStore.TransactionType.IMMEDIATE
        });
        
        await myTrans.batchInsert("products", [
            {name: "Product1", price: 100},
            {name: "Product2", price: 200}
        ]);
        
        // Should trigger warning - missing commit for myTrans
        return "Products inserted";
        
    } catch (err) {
        if (myTrans) {
            myTrans.rollback();
        }
        throw err;
    }
}

// Violation 7: Commit present but wrong rollback variable name
async function wrongRollbackVariable() {
    let transaction;
    try {
        transaction = await rdbStore.createTransaction({});
        
        await transaction.insert("orders", {id: 1, amount: 100});
        await transaction.commit();
        
        return "Order created";
        
    } catch (err) {
        // Should trigger warning - rollback uses wrong variable name
        if (trans) { // Wrong variable name - should be 'transaction'
            trans.rollback();
        }
        console.error("Error:", err);
        return "Failed";
    }
}

// Violation 8: Missing both commit and rollback with complex operations
async function complexOperationsMissingBoth() {
    try {
        let transactionHandler = await rdbStore.createTransaction({
            transactionType: relationalStore.TransactionType.EXCLUSIVE
        });
        
        // Complex operations
        const users = await transactionHandler.query("SELECT * FROM users WHERE active = ?", [true]);
        
        for (const user of users) {
            await transactionHandler.update("users", 
                {last_seen: Date.now()}, 
                "id = ?", 
                [user.id]
            );
        }
        
        await transactionHandler.insert("activity_logs", {
            action: "bulk_update",
            affected_users: users.length,
            timestamp: Date.now()
        });
        
        // Should trigger warnings - missing commit and missing rollback
        return users.length;
        
    } catch (err) {
        console.error("Bulk update failed:", err);
        return 0;
    }
}

// Violation 9: Nested try-catch with missing rollback
async function nestedTryCatchMissingRollback() {
    let outerTransaction;
    try {
        outerTransaction = await rdbStore.createTransaction({});
        
        await outerTransaction.insert("outer_table", {data: "outer"});
        
        try {
            // Inner operations
            await outerTransaction.insert("inner_table", {data: "inner"});
            await outerTransaction.commit();
            
            return "Success";
            
        } catch (innerErr) {
            console.error("Inner error:", innerErr);
            throw innerErr;
        }
        
    } catch (outerErr) {
        // Should trigger warning - missing rollback for outerTransaction
        console.error("Outer error:", outerErr);
        return "Failed";
    }
}

// Violation 10: Transaction with early return, missing commit
// This check is very hard, remain TODO
async function earlyReturnMissingCommit() {
    let trans;
    try {
        trans = await rdbStore.createTransaction({});
        
        const existingUser = await trans.query("SELECT * FROM users WHERE email = ?", ["test@example.com"]);
        
        if (existingUser.length > 0) {
            // Should trigger warning - early return without commit
            return "User already exists";
        }
        
        await trans.insert("users", {email: "test@example.com", name: "Test User"});
        await trans.commit();
        
        return "User created";
        
    } catch (err) {
        if (trans) {
            trans.rollback();
        }
        throw err;
    }
}