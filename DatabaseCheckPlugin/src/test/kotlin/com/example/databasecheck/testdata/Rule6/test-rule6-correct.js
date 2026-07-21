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
 
// Rule 6 Test File: Should NOT trigger database deletion violations
// Simple rule: deleteRdbStore WITH rdbStore.close() before it

// ========== These should NOT trigger Rule 6 warnings ==========

// Correct 1: Proper rdbStore.close() before deleteRdbStore
async function deleteWithProperClose1() {
    try {
        await rdbStore?.close();
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG);
    } catch (err) {
        console.error("Delete failed:", err);
    }
}

// Correct 2: Multiple operations with proper close
async function deleteWithProperClose2() {
    try {
        console.log("Preparing to delete database");
        await rdbStore?.close();
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG);
    } catch (err) {
        console.error("Delete failed:", err);
    }
}

// Correct 3: Complex operations with proper close
async function deleteWithComplexOperations() {
    try {
        let result = await someOtherOperation();
        console.log("Operation result:", result);
        
        // Proper close before deletion
        await rdbStore?.close();
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG);
    } catch (err) {
        console.error("Delete failed:", err);
    }
}

// Correct 4: Different variable name with close
async function deleteWithDifferentVarClose() {
    let myStore = undefined;
    try {
        await myStore?.close();
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG);
    } catch (err) {
        console.error("Delete failed:", err);
    }
}

// Correct 5: Multiple close calls (redundant but not wrong)
async function deleteWithMultipleClose() {
    try {
        await rdbStore?.close();
        await anotherStore?.close();
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG);
    } catch (err) {
        console.error("Delete failed:", err);
    }
}

// Correct 6: Close with error handling
async function deleteWithErrorHandling() {
    try {
        try {
            await rdbStore?.close();
        } catch (closeErr) {
            console.warn("Close failed, but continuing:", closeErr);
        }
        
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG);
    } catch (err) {
        console.error("Delete failed:", err);
    }
}

// Correct 7: Conditional close
async function deleteWithConditionalClose() {
    try {
        if (rdbStore) {
            await rdbStore.close();
        }
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG);
    } catch (err) {
        console.error("Delete failed:", err);
    }
}

// Correct 8: Close in finally block (unusual but valid)
async function deleteWithFinallyClose() {
    let shouldDelete = false;
    try {
        await prepareDatabase();
        shouldDelete = true;
    } catch (err) {
        console.error("Preparation failed:", err);
    } finally {
        if (rdbStore) {
            await rdbStore.close();
        }
        if (shouldDelete) {
            await data_relationalStore.deleteRdbStore(context, STORE_CONFIG);
        }
    }
}

// Correct 9: Async operations with proper close
async function deleteWithAsyncOperations() {
    try {
        const promises = [
            asyncOperation1(),
            asyncOperation2(),
            asyncOperation3()
        ];
        
        await Promise.all(promises);
        
        // Proper close before deletion
        await rdbStore?.close();
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG);
        
    } catch (err) {
        console.error("Async delete failed:", err);
    }
}

// Correct 10: Complex conditional logic with close
async function deleteWithComplexLogic() {
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
            await rdbStore?.close();
            await data_relationalStore.deleteRdbStore(context, STORE_CONFIG);
        }
        
    } catch (err) {
        console.error("Complex delete failed:", err);
    }
}

// Correct 11: No database operations at all (no need for close)
async function noDeleteOperation() {
    try {
        console.log("This function doesn't delete any database");
        await someOtherOperation();
        return "Success";
    } catch (err) {
        console.error("Operation failed:", err);
        return "Failed";
    }
}

// Correct 12: Multiple functions, each with proper close
async function firstDeleteFunction() {
    try {
        await rdbStore?.close();
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG_1);
    } catch (err) {
        console.error("First delete failed:", err);
    }
}

async function secondDeleteFunction() {
    try {
        await rdbStore?.close();
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG_2);
    } catch (err) {
        console.error("Second delete failed:", err);
    }
}