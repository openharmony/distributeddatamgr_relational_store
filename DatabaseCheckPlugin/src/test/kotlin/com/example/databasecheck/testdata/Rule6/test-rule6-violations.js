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
 
// Rule 6 Test File: Should trigger database deletion violations
// Simple rule: deleteRdbStore without rdbStore.close() before it

// ========== These should trigger Rule 6 warnings ==========

// Violation 1: Direct deleteRdbStore without rdbStore.close()
async function deleteWithoutClose1() {
    try {
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG); // Should trigger warning
    } catch (err) {
        console.error("Delete failed:", err);
    }
}

// Violation 2: deleteRdbStore without rdbStore.close() in same function
async function deleteWithoutClose2() {
    try {
        // Some other operations
        console.log("Preparing to delete database");
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG); // Should trigger warning
    } catch (err) {
        console.error("Delete failed:", err);
    }
}

// Violation 3: Multiple operations but no rdbStore.close()
async function deleteWithoutClose3() {
    try {
        let result = await someOtherOperation();
        console.log("Operation result:", result);
        
        // Still no rdbStore.close()
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG); // Should trigger warning
    } catch (err) {
        console.error("Delete failed:", err);
    }
}

// Violation 4: rdbStore.close() after deleteRdbStore (wrong order)
async function deleteWithWrongOrder() {
    try {
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG); // Should trigger warning
        await rdbStore?.close(); // Too late
    } catch (err) {
        console.error("Delete failed:", err);
    }
}

// Violation 5: Different variable name, no close
async function deleteWithDifferentVar() {
    let myStore = undefined;
    try {
        // No myStore.close() or rdbStore.close()
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG); // Should trigger warning
    } catch (err) {
        console.error("Delete failed:", err);
    }
}

// Violation 6: Comment mentions close but doesn't actually do it
async function deleteWithCommentOnly() {
    try {
        // TODO: should close rdbStore here
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG); // Should trigger warning
    } catch (err) {
        console.error("Delete failed:", err);
    }
}

// Violation 7: Close call in comment (not real code)
async function deleteWithCommentedClose() {
    try {
        // await rdbStore?.close();
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG); // Should trigger warning
    } catch (err) {
        console.error("Delete failed:", err);
    }
}

// Violation 8: Complex function without close
async function complexDeleteWithoutClose() {
    let success = false;
    try {
        if (Math.random() > 0.5) {
            console.log("Random condition met");
            success = await performComplexOperation();
        } else {
            console.log("Alternative path");
            success = await performAlternativeOperation();
        }
        
        if (success) {
            // Still no rdbStore.close()
            await data_relationalStore.deleteRdbStore(context, STORE_CONFIG); // Should trigger warning
        }
        
    } catch (err) {
        console.error("Complex delete failed:", err);
    }
}

// Violation 9: Async operations without close
async function asyncDeleteWithoutClose() {
    try {
        const promises = [
            asyncOperation1(),
            asyncOperation2(),
            asyncOperation3()
        ];
        
        await Promise.all(promises);
        
        // No rdbStore.close()
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG); // Should trigger warning
        
    } catch (err) {
        console.error("Async delete failed:", err);
    }
}

// Violation 10: Try-finally without close
async function tryFinallyWithoutClose() {
    try {
        await prepareDatabaseDeletion();
        
        // No rdbStore.close()
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG); // Should trigger warning
        
    } catch (err) {
        console.error("Delete preparation failed:", err);
        throw err;
    } finally {
        console.log("Cleanup completed");
    }
}