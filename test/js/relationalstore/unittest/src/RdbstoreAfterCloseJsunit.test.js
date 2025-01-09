/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'
import relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]";
const STORE_NAME = "AfterCloseTest.db";
const context = ability_featureAbility.getContext();

async function createRdb() {
    const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
        "name TEXT UNIQUE, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";
    const STORE_CONFIG = {
        name: STORE_NAME,
        securityLevel: relationalStore.SecurityLevel.S1,
    };
    const rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
    await rdbStore.executeSql(CREATE_TABLE_TEST);
    var u8 = new Uint8Array([1, 2, 3]);
    const valueBucket = {
        "name": "zhangsan",
        "age": 18,
        "salary": 100.5,
        "blobType": u8,
    };
    await rdbStore.insert('test', valueBucket);
    return rdbStore;
}

describe('rdbStoreAfterCloseTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach');
    })

    afterEach(function () {
        console.info(TAG + 'afterEach');
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll');
    })

    /**
     * @tc.number testRdbAfterClose0001
     * @tc.name RDB Close test
     * @tc.desc execute after RDB closed
     */
    it('testRdbAfterClose0001', 0, async function () {
        console.log(TAG + "************* testRdbAfterClose0001 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            await rdbStore.execute('SELECT * FROM test LIMIT 100');
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testRdbAfterClose0001 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0002
     * @tc.name RDB Close test
     * @tc.desc executeSql after RDB closed
     */
    it('testRdbAfterClose0002', 0, async function () {
        console.log(TAG + "************* testRdbAfterClose0002 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            await rdbStore.executeSql('SELECT * FROM test LIMIT 100');
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testRdbAfterClose0002 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0003
     * @tc.name RDB Close test
     * @tc.desc query after RDB closed
     */
    it('testRdbAfterClose0003', 0, async function () {
        console.log(TAG + "************* testRdbAfterClose0003 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            let predicates = new relationalStore.RdbPredicates("test");
            predicates.equalTo('age', 18);
            await rdbStore.query(predicates);
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testRdbAfterClose0003 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0004
     * @tc.name RDB Close test
     * @tc.desc querySql after RDB closed
     */
    it('testRdbAfterClose0004', 0, async function () {
        console.log(TAG + "************* testRdbAfterClose0004 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }
        try {
            await rdbStore.querySql("SELECT * FROM test LIMIT 100");
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testRdbAfterClose0004 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0005
     * @tc.name RDB Close test
     * @tc.desc getModifyTime after RDB closed
     */
    it('testRdbAfterClose0005', 0, async function () {
        console.log(TAG + "************* testRdbAfterClose0005 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            await rdbStore.getModifyTime('test', 'name', [1]);
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testRdbAfterClose0005 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0006
     * @tc.name RDB Close test
     * @tc.desc getModifyTime after RDB closed
     */
    it('testRdbAfterClose0006', 0, async function (done) {
        console.log(TAG + "************* testRdbAfterClose0006 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            rdbStore.getModifyTime('test', 'name', [1], () => {});
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code);
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        done();
        console.log(TAG + "************* testRdbAfterClose0006 end *************");
    })


    /**
     * @tc.number testRdbAfterClose0007
     * @tc.name RDB Close test
     * @tc.desc insert after RDB closed
     */
    it('testRdbAfterClose0007', 0, async function (done) {
        console.log(TAG + "************* testRdbAfterClose0007 start *************");

        const rdbStore = await createRdb();
        var u8 = new Uint8Array([1, 2, 3])
        try {
            rdbStore.beginTransaction()
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)

        } catch (e) {
            console.log(TAG + e);
            expect(null).assertFail()
            console.log(TAG + "testRdbAfterClose0007 failed");
        }

        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
            expect(null).assertFail();
        }

        try {
            rdbStore.commit();
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }
        await relationalStore.deleteRdbStore(context, STORE_NAME);
        done();
        console.log(TAG + "************* testRdbAfterClose0007 end *************");
    })

    /**
     * @tc.number testRdbTransactionInsert0004
     * @tc.name RDB Close test
     * @tc.desc commit after RDB closed
     */
    it('testRdbAfterClose0008', 0, async function (done) {
        console.log(TAG + "************* testRdbAfterClose0008 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
            expect(null).assertFail();
        }

        try {
            await rdbStore.commit(1);
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }
        await relationalStore.deleteRdbStore(context, STORE_NAME);
        done();
        console.log(TAG + "************* testRdbAfterClose0008 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0009
     * @tc.name RDB Close test
     * @tc.desc rollBack after RDB closed
     */
    it('testRdbAfterClose0009', 0, async function (done) {
        console.log(TAG + "************* testRdbAfterClose0009 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
            expect(null).assertFail();
        }

        try {
            rdbStore.rollBack();
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }
        await relationalStore.deleteRdbStore(context, STORE_NAME);
        done();
        console.log(TAG + "************* testRdbAfterClose0009 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0010
     * @tc.name RDB Close test
     * @tc.desc rollBack after RDB closed
     */
    it('testRdbAfterClose0010', 0, async function (done) {
        console.log(TAG + "************* testRdbAfterClose0010 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
            expect(null).assertFail();
        }

        try {
            rdbStore.rollBack();
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        done()
        console.log(TAG + "************* testRdbAfterClose0010 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0011
     * @tc.name RDB Close test
     * @tc.desc beginTransaction after RDB closed
     */
    it('testRdbAfterClose0011', 0, async function () {
        console.log(TAG + "************* testRdbAfterClose0011 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            rdbStore.beginTransaction();
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }
        await relationalStore.deleteRdbStore(context, STORE_NAME);

        console.log(TAG + "************* testRdbAfterClose0011 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0012
     * @tc.name RDB Close test
     * @tc.desc beginTrans after RDB closed
     */
    it('testRdbAfterClose0012', 0, async function () {
        console.log(TAG + "************* testRdbAfterClose0012 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            await rdbStore.beginTrans();
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }
        await relationalStore.deleteRdbStore(context, STORE_NAME);

        console.log(TAG + "************* testRdbAfterClose0012 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0013
     * @tc.name RDB Close test
     * @tc.desc obtainDistributedTableName after RDB closed
     */
    it('testRdbAfterClose0013', 0, async function () {
        console.log(TAG + "************* testRdbAfterClose0013 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            await rdbStore.obtainDistributedTableName('573f', 'test');
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testRdbAfterClose0013 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0014
     * @tc.name RDB Close test
     * @tc.desc mount event after RDB closed
     */
    it('testRdbAfterClose0014', 0, async function () {
        console.log(TAG + "************* testRdbAfterClose0014 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            rdbStore.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_REMOTE, (deviceIds) => {
                console.log(TAG + 'deviceIds: ' + deviceIds);
            });
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testRdbAfterClose0014 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0015
     * @tc.name RDB Close test
     * @tc.desc unmount event after RDB closed
     */
    it('testRdbAfterClose0015', 0, async function () {
        console.log(TAG + "************* testRdbAfterClose0015 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            rdbStore.off('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_REMOTE, (deviceIds) => {
                console.log(TAG + 'deviceIds: ' + deviceIds);
            });
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testRdbAfterClose0015 end *************");
    })

    /**
     * @tc.number testRdbAfterClose00016
     * @tc.name RDB Close test
     * @tc.desc emit event after RDB closed
     */
    it('testRdbAfterClose0016', 0, async function () {
        console.log(TAG + "************* testRdbAfterClose00016 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            rdbStore.emit('testRdbAfterClose0016');
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testRdbAfterClose00016 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0017
     * @tc.name RDB Close test
     * @tc.desc cleanDirtyData after RDB closed
     */
    it('testRdbAfterClose0017', 0, async function () {
        console.log(TAG + "************* testRdbAfterClose0017 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            await rdbStore.cleanDirtyData('test')
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testRdbAfterClose0017 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0018
     * @tc.name RDB Close test
     * @tc.desc lockRow after RDB closed
     */
    it('testRdbAfterClose0018', 0, async function () {
        console.log(TAG + "************* testRdbAfterClose0018 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            let predicates = new relationalStore.RdbPredicates("test");
            predicates.equalTo('age', 18);
            await rdbStore.lockRow(predicates);
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testRdbAfterClose0018 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0019
     * @tc.name RDB Close test
     * @tc.desc queryLockedRow after RDB closed
     */
    it('testRdbAfterClose0019', 0, async function () {
        console.log(TAG + "************* testRdbAfterClose0019 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            let predicates = new relationalStore.RdbPredicates("test");
            predicates.equalTo('age', 18);
            const resutlSet = await rdbStore.queryLockedRow(predicates);
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testRdbAfterClose0019 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0020
     * @tc.name RDB Close test
     * @tc.desc unlockRow after RDB closed
     */
    it('testRdbAfterClose0020', 0, async function () {
        console.log(TAG + "************* testRdbAfterClose0020 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            let predicates = new relationalStore.RdbPredicates("test");
            predicates.equalTo('age', 18);
            await rdbStore.unlockRow(predicates);
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testRdbAfterClose0020 end *************");
    })

    /**
     * @tc.number testRdbAfterClose0021
     * @tc.name RDB Close test
     * @tc.desc attach after RDB closed
     */
    it('testRdbAfterClose0021', 0, async function () {
        console.log(TAG + "************* testRdbAfterClose0021 start *************");

        const rdbStore = await createRdb();
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            await rdbStore.attach('//test/path', 'test1')
            expect(null).assertFail();
        } catch (err) {
            console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await relationalStore.deleteRdbStore(context, STORE_NAME);
        console.log(TAG + "************* testRdbAfterClose0021 end *************");
    })
    console.log(TAG + "*************Unit Test End*************");
})