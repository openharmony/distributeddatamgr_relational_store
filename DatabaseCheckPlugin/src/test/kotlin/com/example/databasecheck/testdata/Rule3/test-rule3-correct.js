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

// Rule 3 Test File: Should NOT trigger transaction usage violations

// ========== These should NOT trigger Rule 3 warnings ==========

// Correct 1: Multiple CRUD operations in transaction (proper use)
async function properMultipleOperations() {
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
        
        // Multiple related CRUD operations - this is proper transaction use
        const resultCount1 = await trans.batchInsert("test", valueBuckets);
        const resultCount2 = await trans.batchInsert("test_backup", valueBuckets);
        
        await trans.commit();
        return resultCount1 + resultCount2;
        
    } catch (err) {
        if (trans) {
            trans.rollback();
        }
        console.error(TAG + JSON.stringify(err));
        return err.code;
    }
}

// Correct 2: No transaction for single operation
async function singleOperationWithoutTransaction() {
    try {
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBucket = {
            "name": "wang",
            "age": 25,
            "salary": 150.0,
            "blobType": u8,
        };
        
        // Single operation without transaction - this is correct
        const resultCount = await rdbStore.insert("users", valueBucket);
        return resultCount;
        
    } catch (err) {
        console.error("Insert failed: " + JSON.stringify(err));
        return err.code;
    }
}

// Correct 3: Transaction with only database CRUD operations
async function transactionWithOnlyDatabaseOps() {
    let transaction;
    try {
        transaction = await rdbStore.createTransaction({
            transactionType: relationalStore.TransactionType.IMMEDIATE
        });
        
        // All operations are database CRUD - this is correct
        const users = await transaction.query("SELECT * FROM users WHERE age > ?", [18]);
        
        for (const user of users) {
            await transaction.update("users", {last_login: Date.now()}, "id = ?", [user.id]);
        }
        
        await transaction.insert("login_logs", {
            user_count: users.length,
            timestamp: Date.now()
        });
        
        await transaction.commit();
        return users.length;
        
    } catch (err) {
        if (transaction) {
            await transaction.rollback();
        }
        throw err;
    }
}

// Correct 4: Time-consuming operations outside transaction
async function timeConsumingOpsOutsideTransaction() {
    try {
        // Time-consuming operations done outside transaction - this is correct
        const downloadedData = await download("https://example.com/userdata.json");
        const processedData = await processData(downloadedData);
        const uploadResult = await upload("https://backup.com/processed", processedData);
        
        // Only database operations in transaction
        let trans = await rdbStore.createTransaction({});
        
        await trans.insert("downloads", {
            source_url: "https://example.com/userdata.json",
            status: "completed",
            upload_id: uploadResult.id
        });
        
        await trans.insert("processing_logs", {
            download_id: uploadResult.id,
            processed_at: Date.now(),
            record_count: processedData.length
        });
        
        await trans.commit();
        
        return uploadResult.id;
        
    } catch (err) {
        console.error("Operation failed: " + JSON.stringify(err));
        throw err;
    }
}

// Correct 5: Multiple related database operations in transaction
async function batchUserOperations() {
    let trans;
    try {
        trans = await rdbStore.createTransaction({
            transactionType: relationalStore.TransactionType.EXCLUSIVE
        });
        
        // Multiple related operations that should be atomic
        const newUsers = [
            {name: "Alice", age: 30, department: "Engineering"},
            {name: "Bob", age: 25, department: "Engineering"},
            {name: "Carol", age: 28, department: "Engineering"}
        ];
        
        await trans.batchInsert("users", newUsers);
        
        // Update department statistics
        await trans.execute("UPDATE departments SET user_count = user_count + ? WHERE name = ?", 
                          [newUsers.length, "Engineering"]);
        
        // Log the batch operation
        await trans.insert("batch_operations", {
            operation_type: "bulk_user_insert",
            affected_count: newUsers.length,
            timestamp: Date.now()
        });
        
        await trans.commit();
        
    } catch (err) {
        if (trans) {
            await trans.rollback();
        }
        throw err;
    }
}

// Correct 6: Transaction with loops (no prohibited operations)
async function transactionWithLoops() {
    let transaction;
    try {
        transaction = await rdbStore.createTransaction({});
        
        const baseData = {
            category: "test",
            created_at: Date.now()
        };
        
        // Loop with only database operations - this is acceptable
        for (let i = 0; i < 5; i++) {
            await transaction.insert("test_records", {
                ...baseData,
                sequence: i,
                value: Math.random()
            });
        }
        
        // Another loop with database operations
        const recordIds = [];
        for (let j = 0; j < 3; j++) {
            const result = await transaction.insert("summary_records", {
                batch_id: j,
                total_records: 5,
                timestamp: Date.now()
            });
            recordIds.push(result.insertId);
        }
        
        await transaction.commit();
        return recordIds;
        
    } catch (err) {
        if (transaction) {
            await transaction.rollback();
        }
        throw err;
    }
}

// Correct 7: No transaction used (query operations only)
async function queryOperationsOnly() {
    try {
        // Query-only operations don't need transactions - this is correct
        const users = await rdbStore.query("SELECT * FROM users WHERE active = ?", [true]);
        const count = await rdbStore.query("SELECT COUNT(*) as total FROM users WHERE active = ?", [true]);
        
        return {
            users: users,
            total: count[0].total
        };
        
    } catch (err) {
        console.error("Query failed: " + JSON.stringify(err));
        throw err;
    }
}

// Correct 8: Proper transaction with data preprocessing done outside
async function preprocessingOutsideTransaction() {
    try {
        // Data preprocessing done outside transaction - this is correct
        const rawData = await fetchRawData();
        const processedUsers = rawData.map(item => ({
            name: item.full_name.trim(),
            email: item.email_address.toLowerCase(),
            age: parseInt(item.age_string),
            joined_date: new Date(item.join_timestamp)
        }));
        
        // Only atomic database operations in transaction
        let trans = await rdbStore.createTransaction({});
        
        await trans.batchInsert("users", processedUsers);
        await trans.execute("UPDATE statistics SET total_users = total_users + ?", [processedUsers.length]);
        
        await trans.commit();
        
        return processedUsers.length;
        
    } catch (err) {
        console.error("Batch insert failed: " + JSON.stringify(err));
        throw err;
    }
}

// Helper function - not using transactions
async function fetchRawData() {
    // This is outside any transaction - correct pattern
    return await fetch("https://api.example.com/raw-users").then(r => r.json());
}

async function processData(data) {
    // Data processing outside transaction - correct pattern
    return data.map(item => ({
        ...item,
        processed: true,
        processed_at: Date.now()
    }));
}