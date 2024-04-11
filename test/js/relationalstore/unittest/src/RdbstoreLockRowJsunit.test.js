/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import data_relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'
var context = ability_featureAbility.getContext()

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const TABLE = 'lockrowtest'
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS " + TABLE + " (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB, data1 asset, data2 assets )";
const LOG_TABLE = "naturalbase_rdb_aux_" + TABLE + "_log"

const CHECK_STATUS = "SELECT " + LOG_TABLE + ".status FROM " + LOG_TABLE + " INNER JOIN " + TABLE + " ON " +
    LOG_TABLE + ".data_key = " + TABLE + ".ROWID WHERE " + TABLE + ".name = '"
const STORE_CONFIG = {
    name: "LockRowTest.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}

const asset1 = {
    name: "name1",
    uri: "uri1",
    createTime: "createTime1",
    modifyTime: "modifyTime1",
    size: "size1",
    path: "path1",
    status: data_relationalStore.AssetStatus.ASSET_NORMAL,
}
const asset2 = {
    name: "name2",
    uri: "uri2",
    createTime: "createTime2",
    modifyTime: "modifyTime2",
    size: "size2",
    path: "path2",
    status: data_relationalStore.AssetStatus.ASSET_NORMAL,
}
const asset3 = {
    name: "name3",
    uri: "uri3",
    createTime: "createTime3",
    modifyTime: "modifyTime3",
    size: "size3",
    path: "path3",
    status: data_relationalStore.AssetStatus.ASSET_NORMAL,
}
const asset4 = {
    name: "name4",
    uri: "uri4",
    createTime: "createTime4",
    modifyTime: "modifyTime4",
    size: "size4",
    path: "path4",
    status: data_relationalStore.AssetStatus.ASSET_NORMAL,
}

var rdbStore = undefined;
var checkName = 'zhangsan';
var checkName2 = 'lisi';
const UNLOCK = 0;
const UNLOCKING = 1;
const LOCKED = 2;
const LOCK_CHANGE = 3;

describe('rdbStoreLockRowTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await rdbStore.executeSql(CREATE_TABLE_TEST, null);
        
        try {
            let tableArray = [TABLE];
            const setConfig = {
                autoSync: false,
            }
            await rdbStore.setDistributedTables(tableArray, data_relationalStore.DistributedType.DISTRIBUTED_CLOUD,
                setConfig);
            console.log(TAG + "set test to be distributed table success");
        } catch (err) {
            console.log(TAG + "set test to be distributed table failed");
            expect(null).assertFail();
        }
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
    })

    afterEach(function () {
        console.info(TAG + 'afterEach')
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        rdbStore = null
        await data_relationalStore.deleteRdbStore(context, "LockRowTest.db");
    })
    
    async function checkStatus(name, status) {
        try {
            let sql = CHECK_STATUS + name + "'";
            let resultSet = await rdbStore.querySql(sql);
            expect(true).assertEqual(resultSet.goToNextRow());
            expect(status).assertEqual(resultSet.getLong(0));
            console.log(TAG + `checkStatus success, status: `+ resultSet.getLong(0) + ', expert is ' + status)
            resultSet.close();
        } catch (err) {
            console.log(TAG + `checkStatus failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
    }

    async function queryLockedData(count, name) {
        console.log(TAG + `queryLockedData start`)
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", name)
            let resultSet = await rdbStore.queryLockedRow(predicates);
            expect(count).assertEqual(resultSet.rowCount);
            resultSet.close();
            console.log(TAG + `query all columns success`)
        } catch (err) {
            console.log(TAG + `query all columns failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", name)
            let resultSet = await rdbStore.queryLockedRow(predicates, ['name', 'age']);
            expect(count).assertEqual(resultSet.rowCount);
            resultSet.close();
            console.log(TAG + `query specified columns success`)
        } catch (err) {
            console.log(TAG + `query specified columns failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
        console.log(TAG + `queryLockedData end`)
    }

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_LockRow_0001
     * @tc.name Normal test case of original state
     * @tc.desc 1.Insert data, check status
     *          2.Update data, check status
     */
    it('testRdbStoreLockRow0001', 0, async function () {
        console.log(TAG + "************* testRdbStoreLockRow0001 start *************");
        var u8 = new Uint8Array([1, 2, 3]);
        const assets = [asset1, asset2];
        try {
            const valueBucket = {
                "name": checkName,
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
                "data1": asset3,
                "data2": assets
            }
            let ret = await rdbStore.insert(TABLE, valueBucket)
            console.log(TAG + `insert end: ` + ret)
            expect(1).assertEqual(ret);
            // check default status
            checkStatus(checkName, UNLOCK)
            console.log(TAG + `checkStatus end`)
        } catch (err) {
            console.log(TAG + `init failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
        queryLockedData(0, checkName)
        try {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "name": checkName,
                "age": 20,
                "salary": 200.5,
                "blobType": u8,
                "data1": asset3,
                "data2": assets
            }
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName)
            let ret = await rdbStore.update(valueBucket, predicates)
            await expect(1).assertEqual(ret);
            // check default status
            checkStatus(checkName, UNLOCK)
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
        queryLockedData(0, checkName)

        console.log(TAG + "************* testRdbStoreLockRow0001 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_LockRow_0002
     * @tc.name Abnormal test case of lock, if TABLE name or column invalid
     * @tc.desc 1.Configure predicates (TABLE name: "")
     *          2.Configure predicates (TABLE name: "wrongTable")
     *          3.Configure predicates (column: "aaa")
     *          4.Configure predicates (no data)
     */
    it('testRdbStoreLockRow0002', 0, async function () {
        console.log(TAG + "************* testRdbStoreLockRow0002 start *************");
        // lock
        try {
            let predicates = new data_relationalStore.RdbPredicates("")
            await rdbStore.lockRow(predicates) // table name should not empty
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect("401").assertEqual(err.code)
        }
        try {
            let predicates = new data_relationalStore.RdbPredicates("wrongTable")
            await rdbStore.lockRow(predicates) // wrongTable not exist
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `wrongTable failed, err: ${JSON.stringify(err)}`)
            expect(14800000).assertEqual(err.code)
        }
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("aaa", "null") // column aaa not exist
            await rdbStore.lockRow(predicates)
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `aaa failed, err: ${JSON.stringify(err)}`)
            expect(14800000).assertEqual(err.code)
        }
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName2)
            await rdbStore.lockRow(predicates)
            console.log(TAG + `lock success`)
        } catch (err) {
            console.log(TAG + `lock failed, no data is locked, err: ${JSON.stringify(err)}`)
            expect(14800018).assertEqual(err.code)
        }
        console.log(TAG + "************* testRdbStoreLockRow0002 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_LockRow_0003
     * @tc.name Abnormal test case of unlock, if TABLE name or column invalid
     * @tc.desc 1.Configure predicates (TABLE name: "")
     *          2.Configure predicates (TABLE name: "wrongTable")
     *          3.Configure predicates (column: "aaa")
     *          4.Configure predicates (no data)
     */
    it('testRdbStoreLockRow0003', 0, async function () {
        console.log(TAG + "************* testRdbStoreLockRow0003 start *************");
        // unlock
        try {
            let predicates = new data_relationalStore.RdbPredicates("")
            await rdbStore.unlockRow(predicates) // table name should not empty
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect("401").assertEqual(err.code)
        }
        try {
            let predicates = new data_relationalStore.RdbPredicates("wrongTable")
            await rdbStore.unlockRow(predicates) // wrongTable not exist
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `wrongTable failed, err: ${JSON.stringify(err)}`)
            expect(14800000).assertEqual(err.code)
        }
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("aaa", "null") // column aaa not exist
            await rdbStore.unlockRow(predicates)
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `aaa failed, err: ${JSON.stringify(err)}`)
            expect(14800000).assertEqual(err.code)
        }
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName2)
            await rdbStore.unlockRow(predicates)
            console.log(TAG + `lock success`)
        } catch (err) {
            console.log(TAG + `unlock failed, no data is unlocked, err: ${JSON.stringify(err)}`)
            expect(14800018).assertEqual(err.code)
        }
        console.log(TAG + "************* testRdbStoreLockRow0003 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_LockRow_0004
     * @tc.name Normal test case of lock/unlock
     * @tc.desc 1.unlock->locked
     *          2.locked->locked
     *          3.locked->unlock
     */
    it('testRdbStoreLockRow0004', 0, async function () {
        console.log(TAG + "************* testRdbStoreLockRow0004 start *************");
        // unlock->locked
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName)
            await rdbStore.lockRow(predicates)
            
            // check default status
            await checkStatus(checkName, LOCKED)
            console.log(TAG + `lock success`)
        } catch (err) {
            console.log(TAG + `lock failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(1, checkName)
        // locked->locked
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName)
            await rdbStore.lockRow(predicates)
            
            // check default status
            await checkStatus(checkName, LOCKED)
            console.log(TAG + `lock success`)
        } catch (err) {
            console.log(TAG + `lockRow failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(1, checkName)
        // locked->unlock
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName)
            await rdbStore.unlockRow(predicates)
            
            // check default status
            await checkStatus(checkName, UNLOCK)
            console.log(TAG + `unlock success`)
        } catch (err) {
            console.log(TAG + `unlock failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(0, checkName)
        console.log(TAG + "************* testRdbStoreLockRow0004 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_LockRow_0005
     * @tc.name Normal test case of lock/unlock
     * @tc.desc 1.unlock->unlock
     *          2.unlock->locked
     *          3.locked->lock_change
     */
    it('testRdbStoreLockRow0005', 0, async function () {
        console.log(TAG + "************* testRdbStoreLockRow0005 start *************");
        // unlock->unlock
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName)
            await rdbStore.unlockRow(predicates)
            
            // check default status
            await checkStatus(checkName, UNLOCK)
            console.log(TAG + `unlock success`)
        } catch (err) {
            console.log(TAG + `unlock failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(0, checkName)
        // unlock->locked
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName)
            await rdbStore.lockRow(predicates)
            
            // check default status
            await checkStatus(checkName, LOCKED)
            console.log(TAG + `lock success`)
        } catch (err) {
            console.log(TAG + `lock failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(1, checkName)
        // locked->lock_change
        try {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "name": checkName,
                "age": 20,
                "salary": 201.5,
                "blobType": u8,
            }
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName)
            let ret = await rdbStore.update(valueBucket, predicates)
            await expect(1).assertEqual(ret);
            console.log(TAG + "update done: " + ret);
            
            // check default status
            await checkStatus(checkName, LOCK_CHANGE)
            console.log(TAG + `lock change success`)
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
        await queryLockedData(1, checkName)
        console.log(TAG + "************* testRdbStoreLockRow0005 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_LockRow_0006
     * @tc.name Normal test case of lock/unlock
     * @tc.desc 1.lock_change->lock_change(lock)
     *          2.lock_change->lock_change(update data)
     *          3.lock_change->unlocking
     */
    it('testRdbStoreLockRow0006', 0, async function () {
        console.log(TAG + "************* testRdbStoreLockRow0006 start *************");
        // lock_change->lock_change
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName)
            await rdbStore.lockRow(predicates)
            
            // check default status
            await checkStatus(checkName, LOCK_CHANGE)
            console.log(TAG + `lock change success`)
        } catch (err) {
            console.log(TAG + `lock failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(1, checkName)
        // lock_change->lock_change
        try {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "name": checkName,
                "age": 21,
                "salary": 202.5,
                "blobType": u8,
            }
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName)
            let ret = await rdbStore.update(valueBucket, predicates)
            await expect(1).assertEqual(ret);
            await console.log(TAG + "update done: " + ret);
            
            // check default status
            await checkStatus(checkName, LOCK_CHANGE)
            console.log(TAG + `lock change success`)
        } catch (err) {
            console.log(TAG + `lock change failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
        await queryLockedData(1, checkName)
        // lock_change->unlocking
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName)
            await rdbStore.unlockRow(predicates)
            
            // check default status
            await checkStatus(checkName, UNLOCKING)
            console.log(TAG + `unlocking success`)
        } catch (err) {
            console.log(TAG + `unlocking failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(0, checkName)
        console.log(TAG + "************* testRdbStoreLockRow0006 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_LockRow_0007
     * @tc.name Normal test case of lock/unlock
     * @tc.desc 1.unlocking->unlocking
     *          2.unlocking->lock_change
     */
    it('testRdbStoreLockRow0007', 0, async function () {
        console.log(TAG + "************* testRdbStoreLockRow0007 start *************");
        // unlocking->unlocking
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName)
            await rdbStore.unlockRow(predicates)
            
            // check default status
            await checkStatus(checkName, UNLOCKING)
            console.log(TAG + `unlocking success`)
        } catch (err) {
            console.log(TAG + `unlocking failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(0, checkName)
        // unlocking->lock_change
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName)
            await rdbStore.lockRow(predicates)
            
            // check default status
            await checkStatus(checkName, LOCK_CHANGE)
            console.log(TAG + `lock change success`)
        } catch (err) {
            console.log(TAG + `lock change failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(1, checkName)
        console.log(TAG + "************* testRdbStoreLockRow0007 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_LockRow_0008
     * @tc.name Normal test case of lock/unlock(with Asset)
     * @tc.desc 1.Insert data, check status
     *          2.Update data, check status
     */
    it('testRdbStoreLockRow0008', 0, async function () {
        console.log(TAG + "************* testRdbStoreLockRow0008 start *************");
        const assets = [asset2, asset3];
        try {
            var u8 = new Uint8Array([1, 2, 3]);
            const valueBucket = {
                "name": checkName2,
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
                "data1": asset1,
                "data2": assets
            }
            let ret = await rdbStore.insert(TABLE, valueBucket)
            console.log(TAG + `ret :` + ret)
            expect(2).assertEqual(ret);
            // check default status
            await checkStatus(checkName2, UNLOCK)
            console.log(TAG + `init success`)
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
        await queryLockedData(0, checkName2)
        try {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "name": checkName2,
                "age": 20,
                "salary": 200.5,
                "blobType": u8,
                "data1": asset4,
                "data2": assets
            }
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName2)
            let ret = await rdbStore.update(valueBucket, predicates)
            await expect(1).assertEqual(ret);
            // check default status
            await checkStatus(checkName2, UNLOCK)
            console.log(TAG + `update success`)
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
        await queryLockedData(0, checkName2)
        console.log(TAG + "************* testRdbStoreLockRow0008 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_LockRow_0009
     * @tc.name Normal test case of update, value is long string and special characters
     * @tc.desc 1.unlock->locked
     *          2.locked->locked
     *          3.locked->unlock
     */
    it('testRdbStoreLockRow0009', 0, async function () {
        console.log(TAG + "************* testRdbStoreLockRow0009 start *************");
        const assets = [asset2, asset3];
        // unlock->locked
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName2)
            await rdbStore.lockRow(predicates)
            
            // check default status
            await checkStatus(checkName2, LOCKED)
            console.log(TAG + `lock success`)
        } catch (err) {
            console.log(TAG + `lock failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(1, checkName2)
        // locked->locked
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName2)
            await rdbStore.lockRow(predicates)
            
            // check default status
            await checkStatus(checkName2, LOCKED)
            console.log(TAG + `lock success`)
        } catch (err) {
            console.log(TAG + `lock failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(1, checkName2)
        // locked->unlock
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName2)
            await rdbStore.unlockRow(predicates)
            
            // check default status
            await checkStatus(checkName2, UNLOCK)
            console.log(TAG + `unlock success`)
        } catch (err) {
            console.log(TAG + `unlock failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(0, checkName2)
        console.log(TAG + "************* testRdbStoreLockRow0009 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_LockRow_0010
     * @tc.name Normal test case of lock/unlock
     * @tc.desc 1.unlock->unlock
     *          2.unlock->locked
     *          3.locked->lock_change
     */
    it('testRdbStoreLockRow0010', 0, async function () {
        console.log(TAG + "************* testRdbStoreLockRow0010 start *************");
        // unlock->unlock
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName2)
            await rdbStore.unlockRow(predicates)
            
            // check default status
            await checkStatus(checkName2, UNLOCK)
            console.log(TAG + `unlock success`)
        } catch (err) {
            console.log(TAG + `unlock failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(0, checkName2)
        // unlock->locked
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName2)
            await rdbStore.lockRow(predicates)
            
            // check default status
            await checkStatus(checkName2, LOCKED)
            console.log(TAG + `lock success`)
        } catch (err) {
            console.log(TAG + `lock failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(1, checkName2)
        // locked->lock_change
        try {
            var u8 = new Uint8Array([4, 5, 6])
            const assets = [asset2, asset3];
            const valueBucket = {
                "name": checkName2,
                "age": 20,
                "salary": 200.5,
                "blobType": u8,
                "data1": asset1,
                "data2": assets
            }
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName2)
            let ret = await rdbStore.update(valueBucket, predicates)
            await expect(1).assertEqual(ret);
            await console.log(TAG + "update done: " + ret);
            
            // check default status
            await checkStatus(checkName2, LOCK_CHANGE)
            console.log(TAG + `lock change success`)
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
        await queryLockedData(1, checkName2)
        console.log(TAG + "************* testRdbStoreLockRow0010 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_LockRow_0011
     * @tc.name Normal test case of lock/unlock
     * @tc.desc 1.lock_change->lock_change(lock)
     *          2.lock_change->lock_change(update data)
     *          3.lock_change->unlocking
     */
    it('testRdbStoreLockRow0011', 0, async function () {
        console.log(TAG + "************* testRdbStoreLockRow0011 start *************");
        // lock_change->lock_change
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName2)
            await rdbStore.lockRow(predicates)
            
            // check default status
            await checkStatus(checkName2, LOCK_CHANGE)
            console.log(TAG + `lock change success`)
        } catch (err) {
            console.log(TAG + `lock failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(1, checkName2)
        // lock_change->lock_change
        try {
            var u8 = new Uint8Array([4, 5, 6])
            const assets = [asset2, asset3];
            const valueBucket = {
                "name": checkName2,
                "age": 20,
                "salary": 200.5,
                "blobType": u8,
                "data1": asset4,
                "data2": assets
            }
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName2)
            let ret = await rdbStore.update(valueBucket, predicates)
            await expect(1).assertEqual(ret);
            await console.log(TAG + "update done: " + ret);
            
            // check default status
            await checkStatus(checkName2, LOCK_CHANGE)
            console.log(TAG + `lock change success`)
        } catch (err) {
            console.log(TAG + `lock change failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
        await queryLockedData(1, checkName2)
        // lock_change->unlocking
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName2)
            await rdbStore.unlockRow(predicates)
            
            // check default status
            await checkStatus(checkName2, UNLOCKING)
            console.log(TAG + `unlocking success`)
        } catch (err) {
            console.log(TAG + `unlocking failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(0, checkName2)
        console.log(TAG + "************* testRdbStoreLockRow0011 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_LockRow_0012
     * @tc.name Normal test case of lock/unlock
     * @tc.desc 1.unlocking->unlocking
     *          2.unlocking->lock_change
     */
    it('testRdbStoreLockRow0012', 0, async function () {
        console.log(TAG + "************* testRdbStoreLockRow0012 start *************");
        // unlocking->unlocking
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName2)
            await rdbStore.unlockRow(predicates)
            
            // check default status
            await checkStatus(checkName2, UNLOCKING)
            console.log(TAG + `unlocking success`)
        } catch (err) {
            console.log(TAG + `unlocking failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(0, checkName2)
        // unlocking->lock_change
        try {
            let predicates = new data_relationalStore.RdbPredicates(TABLE)
            predicates.equalTo("name", checkName2)
            await rdbStore.lockRow(predicates)
            
            // check default status
            await checkStatus(checkName2, LOCK_CHANGE)
            console.log(TAG + `lock change success`)
        } catch (err) {
            console.log(TAG + `lock change failed, err: ${JSON.stringify(err)}`)
            expect().assertFail();
        }
        await queryLockedData(1, checkName2)
        console.log(TAG + "************* testRdbStoreLockRow0012 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_LockRow_0013
     * @tc.name Abnormal test case of lock, if TABLE name or column invalid
     * @tc.desc 1.Parameter count is incorrect
     */
    it('testRdbStoreLockRow0013', 0, async function () {
        console.log(TAG + "************* testRdbStoreLockRow0013 start *************");
        try {
            await rdbStore.lockRow()
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect("401").assertEqual(err.code)
        }
        try {
            await rdbStore.lockRow()
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect("401").assertEqual(err.code)
        }
        try {
            await rdbStore.queryLockedRow()
            expect().assertFail()
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect("401").assertEqual(err.code)
        }
        console.log(TAG + "************* testRdbStoreLockRow0013 end   *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})
