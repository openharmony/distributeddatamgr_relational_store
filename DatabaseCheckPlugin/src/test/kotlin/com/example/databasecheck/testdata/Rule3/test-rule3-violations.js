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
 
// Rule 3 Test File: Should trigger transaction usage violations

// ========== These should trigger Rule 3 warnings ==========

// Violation 1: Unnecessary transaction - single operation
async function unnecessaryTransactionSingle() {
    let trans;
    try {
        trans = await rdbStore.createTransaction({
            transactionType: relationalStore.TransactionType.EXCLUSIVE
        });
        const u8 = new Uint8Array([1, 2, 3]);
        const valueBuckets = [{
            "name": "lisi",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }];
        // Should trigger warning - only one CRUD operation in transaction
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

// Violation 2: Time-consuming operation - IPC call in transaction
async function transactionWithIpcCall() {
    let transaction;
    try {
        transaction = await rdbStore.createTransaction({
            transactionType: relationalStore.TransactionType.EXCLUSIVE
        });
        
        const valueBuckets = [{
            "name": "zhang",
            "age": 25,
            "salary": 200.0,
        }];
        
        await transaction.batchInsert("users", valueBuckets);
        
        // Should trigger warning - IPC call in transaction
        await ipc.sendMessage("processData", valueBuckets);
        
        await transaction.batchInsert("logs", [{action: "insert", timestamp: Date.now()}]);
        await transaction.commit();
        
    } catch (err) {
        if (transaction) {
            transaction.rollback();
        }
        throw err;
    }
}

// Violation 3: Time-consuming operation - download in transaction
async function transactionWithDownload() {
    let trans;
    try {
        trans = await rdbStore.createTransaction({});
        
        await trans.insert("downloads", {id: 1, status: "starting"});
        
        // Should trigger warning - download operation in transaction
        const fileData = await download("https://example.com/largefile.zip");
        
        await trans.update("downloads", {id: 1, status: "completed", data: fileData});
        await trans.commit();
        
    } catch (err) {
        if (trans) {
            await trans.rollback();
        }
        throw err;
    }
}

// Violation 4: Time-consuming operation - upload in transaction
async function transactionWithUpload() {
    let dbTransaction;
    try {
        dbTransaction = await rdbStore.createTransaction({
            transactionType: relationalStore.TransactionType.IMMEDIATE
        });
        
        const userData = await dbTransaction.query("SELECT * FROM users WHERE id = ?", [123]);
        
        // Should trigger warning - upload operation in transaction
        const uploadResult = await upload("https://api.example.com/data", userData);
        
        await dbTransaction.insert("upload_logs", {
            user_id: 123,
            upload_id: uploadResult.id,
            timestamp: Date.now()
        });
        
        await dbTransaction.commit();
        
    } catch (err) {
        if (dbTransaction) {
            await dbTransaction.rollback();
        }
        throw err;
    }
}

// Violation 5: Time-consuming operation - fetch/HTTP request in transaction
async function transactionWithFetch() {
    let trans;
    try {
        trans = await rdbStore.createTransaction({});
        
        await trans.insert("requests", {url: "https://api.example.com", status: "pending"});
        
        // Should trigger warning - fetch operation in transaction
        const response = await fetch("https://api.example.com/validate");
        const result = await response.json();
        
        await trans.update("requests", {status: "completed", result: JSON.stringify(result)});
        await trans.commit();
        
    } catch (err) {
        if (trans) {
            await trans.rollback();
        }
        throw err;
    }
}

// Violation 6: Time-consuming operation - socket operation in transaction
async function transactionWithSocket() {
    let transaction;
    try {
        transaction = await rdbStore.createTransaction({});
        
        await transaction.insert("connections", {type: "socket", status: "connecting"});
        
        // Should trigger warning - socket operation in transaction
        const socketConnection = await socket.connect("ws://example.com:8080");
        await socketConnection.send("Hello");
        
        await transaction.update("connections", {status: "connected"});
        await transaction.commit();
        
    } catch (err) {
        if (transaction) {
            await transaction.rollback();
        }
        throw err;
    }
}

// Violation 7: Time-consuming operation - RPC call in transaction
async function transactionWithRpc() {
    let trans;
    try {
        trans = await rdbStore.createTransaction({});
        
        await trans.insert("rpc_calls", {method: "getUserData", status: "calling"});
        
        // Should trigger warning - RPC operation in transaction
        const userData = await rpc.call("UserService", "getUserData", {userId: 456});
        
        await trans.insert("users", userData);
        await trans.commit();
        
    } catch (err) {
        if (trans) {
            await trans.rollback();
        }
        throw err;
    }
}

// Violation 8: Time-consuming operation - remote call in transaction
async function transactionWithRemoteCall() {
    let dbTrans;
    try {
        dbTrans = await rdbStore.createTransaction({});
        
        await dbTrans.insert("remote_calls", {target: "RemoteService", status: "calling"});
        
        // Should trigger warning - remote operation in transaction
        const remoteResult = await remote.invoke("RemoteService.processData", {data: "test"});
        
        await dbTrans.insert("results", remoteResult);
        await dbTrans.commit();
        
    } catch (err) {
        if (dbTrans) {
            await dbTrans.rollback();
        }
        throw err;
    }
}

// Violation 9: Multiple time-consuming operations in transaction
async function transactionWithMultipleTimeConsumingOps() {
    let trans;
    try {
        trans = await rdbStore.createTransaction({});
        
        await trans.insert("operations", {step: 1, status: "starting"});
        
        // Should trigger warning - multiple time-consuming operations
        const downloadResult = await download("https://example.com/data.json");
        const uploadResult = await upload("https://backup.com/data", downloadResult);
        const fetchResult = await fetch("https://api.com/notify");
        
        await trans.insert("operations", {step: 2, status: "completed"});
        await trans.commit();
        
    } catch (err) {
        if (trans) {
            await trans.rollback();
        }
        throw err;
    }
}

// Violation 10: Single operation with unnecessary transaction - different variable name
async function singleOperationDifferentVarName() {
    let myTransaction;
    try {
        myTransaction = await rdbStore.createTransaction({
            transactionType: relationalStore.TransactionType.EXCLUSIVE
        });
        
        // Should trigger warning - only one operation in transaction
        await myTransaction.delete("temp_data", "id = ?", ["temp123"]);

        
        await myTransaction.commit();
        
    } catch (err) {
        if (myTransaction) {
            myTransaction.rollback();
        }
        throw err;
    }
}