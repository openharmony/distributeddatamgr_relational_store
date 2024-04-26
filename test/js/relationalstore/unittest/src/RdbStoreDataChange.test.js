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
import relationalStore from '@ohos.data.relationalStore';
import ability_featureAbility from '@ohos.ability.featureAbility'

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const STORE_NAME = "data_change.db"
let rdbStore = undefined;
let context = ability_featureAbility.getContext()

describe('RdbStoreDataChangeTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        const config = {
            'name': STORE_NAME,
            securityLevel: relationalStore.SecurityLevel.S1,
        }
        try {
            await relationalStore.deleteRdbStore(context, STORE_NAME);
            rdbStore = await relationalStore.getRdbStore(context, config);

            const CREATE_TABLE_SQL = "CREATE TABLE IF NOT EXISTS test (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";
            await rdbStore.executeSql(CREATE_TABLE_SQL);

            const valueBucket1 = {
                'name': 'zhangsan',
                'age': 18,
                'salary': 25000,
                'blobType': new Uint8Array([1, 2, 3]),
            };

            let rowId = await rdbStore.insert('test', valueBucket1);
            expect(1).assertEqual(rowId);
        } catch (err) {
            console.error(TAG + `failed, code:${err.code}, message: ${err.message}`)
            expect().assertFail()
        }
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        try {
            rdbStore.off('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS)
        } catch (err) {
            console.error(TAG + `unRegister fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
        }
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        rdbStore = null
        await relationalStore.deleteRdbStore(context, STORE_NAME);
    })

    console.info(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name Normal case for inserting a data into local database
     * @tc.number testRdbStoreDataChange0001
     * @tc.desc 1. Register callback for local database
     *          2. Insert data
     *          3. UnRegister callback
     */
    it('testRdbStoreDataChange0001', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreDataChange0001 start *************");
        try {
            rdbStore.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, (ChangeInfos) => {
                for (let i = 0; i < ChangeInfos.length; i++) {
                    expect('test').assertEqual(ChangeInfos[i].table);
                    expect(0).assertEqual(ChangeInfos[i].type);
                    expect(2).assertEqual(ChangeInfos[i].inserted[0]);
                    expect(undefined).assertEqual(ChangeInfos[i].updated[0]);
                    expect(undefined).assertEqual(ChangeInfos[i].deleted[0]);
                }
                done();
            })
        } catch (err) {
            console.error(TAG + `on dataChange fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done();
        }

        try {
            const valueBucket1 = {
                'name': 'zhangsan',
                'age': 18,
                'salary': 25000,
                'blobType': new Uint8Array([1, 2, 3]),
            };

            let rowId = await rdbStore.insert('test', valueBucket1);
            expect(2).assertEqual(rowId);
        } catch (error) {
            console.error(TAG + `insert2 fail, code:${error.code}, message: ${error.message}`);
            expect().assertFail();
            done();
        }
        console.info(TAG + "************* testRdbStoreDataChange0001 end *************");
    })

    /**
     * @tc.name Normal case for updating a data
     * @tc.number testRdbStoreDataChange0001
     * @tc.desc 1. Register callback for local database
     *          2. Update data
     *          3. UnRegister callback
     */
    it('testRdbStoreDataChange0002', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreDataChange0002 start *************");
        try {
            rdbStore.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, (ChangeInfos) => {
                for (let i = 0; i < ChangeInfos.length; i++) {
                    expect('test').assertEqual(ChangeInfos[i].table);
                    expect(0).assertEqual(ChangeInfos[i].type);
                    expect(undefined).assertEqual(ChangeInfos[i].inserted[0]);
                    expect(1).assertEqual(ChangeInfos[i].updated[0]);
                    expect(undefined).assertEqual(ChangeInfos[i].deleted[0]);
                }
                done();
            })
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done();
        }

        try {
            const valueBucket = {
                'name': 'lisi',
                'age': 18,
                'salary': 30000,
                'blobType': new Uint8Array([1, 2, 3]),
            };
            let predicates = new relationalStore.RdbPredicates('test');
            predicates.equalTo('id', 1);
            let rowId = await rdbStore.update(valueBucket, predicates);
            expect(1).assertEqual(rowId);
        } catch (error) {
            console.error(TAG + `update fail, code:${error.code}, message: ${error.message}`);
            expect().assertFail();
            done();
        }
        console.info(TAG + "************* testRdbStoreDataChange0002 end *************");
    })

    /**
     * @tc.name Normal case for deleting datas
     * @tc.number testRdbStoreDataChange0003
     * @tc.desc 1. Register callback for local database
     *          2. Delete data
     *          3. UnRegister callback
     */
    it('testRdbStoreDataChange0003', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreDataChange0003 start *************");
        try {
            rdbStore.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, (ChangeInfos) => {
                for (let i = 0; i < ChangeInfos.length; i++) {
                    expect('test').assertEqual(ChangeInfos[i].table);
                    expect(0).assertEqual(ChangeInfos[i].type);
                    expect(undefined).assertEqual(ChangeInfos[i].inserted[0]);
                    expect(undefined).assertEqual(ChangeInfos[i].updated[0]);
                    expect(1).assertEqual(ChangeInfos[i].deleted[0]);
                    expect(2).assertEqual(ChangeInfos[i].deleted[1]);
                }
                done();
            })
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done();
        }

        try {
            let predicates = new relationalStore.RdbPredicates('test');
            let rowId = await rdbStore.delete(predicates);
            expect(2).assertEqual(rowId);
        } catch (error) {
            console.error(TAG + `delete fail, code:${error.code}, message: ${error.message}`);
            done();
            expect().assertFail();
        }
        console.info(TAG + "************* testRdbStoreDataChange0003 end *************");
    })

    /**
     * @tc.name Normal case for batch insert data into local database
     * @tc.number testRdbStoreDataChange0004
     * @tc.desc 1. Register callback for local database
     *          2. Batch insert data
     *          3. UnRegister callback
     */
    it('testRdbStoreDataChange0004', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreDataChange0004 start *************");
        try {
            rdbStore.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, (ChangeInfos) => {
                for (let i = 0; i < ChangeInfos.length; i++) {
                    expect('test').assertEqual(ChangeInfos[i].table);
                    expect(0).assertEqual(ChangeInfos[i].type);
                    expect(3).assertEqual(ChangeInfos[i].inserted[0]);
                    expect(4).assertEqual(ChangeInfos[i].inserted[1]);
                    expect(undefined).assertEqual(ChangeInfos[i].updated[0]);
                    expect(undefined).assertEqual(ChangeInfos[i].deleted[0]);
                }
                done();
            })
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done();
        }

        try {
            let u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let valueBucketArray = new Array();
            for (let i = 0; i < 2; i++) {
                valueBucketArray.push(valueBucket);
            }
            let rowId = await rdbStore.batchInsert("test", valueBucketArray);
            expect(2).assertEqual(rowId);
        } catch (error) {
            console.error(TAG + `insert fail, code:${error.code}, message: ${error.message}`);
            expect().assertFail();
            done();
        }
        console.info(TAG + "************* testRdbStoreDataChange0004 end *************");
    })

    /**
     * @tc.name Normal case for multi tables
     * @tc.number testRdbStoreDataChange0005
     * @tc.desc 1. Register callback for local database
     *          2. Create table test1
     *          3. Insert data into table test1
     *          4. UnRegister callback
     */
    it('testRdbStoreDataChange0005', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreDataChange0005 start *************");
        try {
            rdbStore.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, (ChangeInfos) => {
                for (let i = 0; i < ChangeInfos.length; i++) {
                    expect('test1').assertEqual(ChangeInfos[i].table);
                    expect(0).assertEqual(ChangeInfos[i].type);
                    expect(1).assertEqual(ChangeInfos[i].inserted[0]);
                    expect(undefined).assertEqual(ChangeInfos[i].updated[0]);
                    expect(undefined).assertEqual(ChangeInfos[i].deleted[0]);
                }
                done();
            })
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done();
        }

        try {
            const CREATE_TABLE_SQL = "CREATE TABLE IF NOT EXISTS test1 (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";
            await rdbStore.executeSql(CREATE_TABLE_SQL);

            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": new Uint8Array([1, 2, 3]),
            }
            let rowId = await rdbStore.insert("test1", valueBucket);
            expect(1).assertEqual(rowId);
        } catch (error) {
            console.error(TAG + `insert fail, code:${error.code}, message: ${error.message}`);
            expect().assertFail();
            done();
        }
        console.info(TAG + "************* testRdbStoreDataChange0005 end *************");
    })

    /**
     * @tc.name AbNormal case for failed to insert
     * @tc.number testRdbStoreDataChange0006
     * @tc.desc 1. Register callback for local database
     *          2. Failed to insert data into table test
     *          3. UnRegister callback
     */
    it('testRdbStoreDataChange0006', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreDataChange0006 start *************");
        try {
            rdbStore.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, (ChangeInfos) => {
                expect().assertFail();
                done();
            })
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done();
        }

        try {
            const valueBucket = {
                "age": 18,
                "salary": 100.5,
                "blobType": new Uint8Array([1, 2, 3]),
            }
            await rdbStore.insert("test", valueBucket);
            expect().assertFail();
            done();
        } catch (error) {
            expect(14800032).assertEqual(error.code);
            console.error(TAG + `insert fail, code:${error.code}, message: ${error.message}`);
            done();
        }
        console.info(TAG + "************* testRdbStoreDataChange0006 end *************");
    })

    /**
     * @tc.name AbNormal case for function on, if args is invalid
     * @tc.number testRdbStoreDataChange0007
     * @tc.desc 1.Register callback for local database, event is invalid
     *          2.Register callback for local database, SubscribeType is invalid
     */
    it('testRdbStoreDataChange0007', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreDataChange0007 start *************");
        try {
            rdbStore.on('', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, (ChangeInfos) => {})
            expect().assertFail();
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect('401').assertEqual(err.code);
        }

        try {
            // SubscribeType -2 is a invalid argument
            rdbStore.on('dataChange', -2, (ChangeInfos) => {})
            expect().assertFail();
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect('401').assertEqual(err.code);
        }
        done();
        console.info(TAG + "************* testRdbStoreDataChange0007 end *************");
    })

    /**
     * @tc.name AbNormal case for function off, if args is invalid
     * @tc.number testRdbStoreDataChange0008
     * @tc.desc 1.Register callback for local database, event is invalid
     *          2.Register callback for local database, SubscribeType is invalid
     */
    it('testRdbStoreDataChange0008', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreDataChange0008 start *************");
        try {
            rdbStore.off('', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, (ChangeInfos) => {})
            expect().assertFail();
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect('401').assertEqual(err.code);
        }

        try {
            // SubscribeType -2 is a invalid argument
            rdbStore.off('dataChange', -2, (ChangeInfos) => {})
            expect().assertFail();
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect('401').assertEqual(err.code);
        }
        done();
        console.info(TAG + "************* testRdbStoreDataChange0008 end *************");
    })

    /**
     * @tc.name Normal case for multi observer
     * @tc.number testRdbStoreDataChange0009
     * @tc.desc 1. Register observer1 and observer2 for local database
     *          2. Insert data into table test
     *          3. UnRegister observer1 and observer2
     */
    it('testRdbStoreDataChange0009', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreDataChange0009 start *************");
        function observer1(ChangeInfos) {
            console.info(TAG + "observer1");
            expect().assertFail();
            done();
        };

        function observer2(ChangeInfos) {
            console.info(TAG + "observer2");
            expect('test').assertEqual(ChangeInfos[0].table);
            done();
        };

        try {
            rdbStore.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, observer1);
            rdbStore.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, observer2);
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
        }

        try {
            rdbStore.off('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, observer1);
        } catch (err) {
            expect().assertFail();
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
        }

        try {
            const valueBucket = {
                'name': 'liSi',
                "age": 18,
                "salary": 100.5,
                "blobType": new Uint8Array([1, 2, 3]),
            }
            let rowId = await rdbStore.insert("test", valueBucket);
            expect(5).assertEqual(rowId);
        } catch (error) {
            expect().assertFail();
            console.error(TAG + `insert fail, code:${error.code}, message: ${error.message}`);
            done();
        }
        console.info(TAG + "************* testRdbStoreDataChange0009 end *************");
    })

    /**
     * @tc.name Normal case for multi observer
     * @tc.number testRdbStoreDataChange0010
     * @tc.desc 1. Register observer1 and observer2 for local database
     *          2. Insert data into table test
     *          3. UnRegister observer1 and observer2
     */
    it('testRdbStoreDataChange0010', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreDataChange0010 start *************");
        function observer1(ChangeInfos) {
            console.info(TAG + "observer1");
            expect('test').assertEqual(ChangeInfos[0].table);
        };

        function observer2(ChangeInfos) {
            console.info(TAG + "observer2");
            expect('test').assertEqual(ChangeInfos[0].table);
            done();
        };

        try {
            rdbStore.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, observer1);
            rdbStore.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, observer2);
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
        }

        try {
            const valueBucket = {
                'name': 'liSi',
                "age": 18,
                "salary": 100.5,
                "blobType": new Uint8Array([1, 2, 3]),
            }
            let rowId = await rdbStore.insert("test", valueBucket);
            expect(6).assertEqual(rowId);
        } catch (error) {
            expect().assertFail();
            console.error(TAG + `insert fail, code:${error.code}, message: ${error.message}`);
            done();
        }
        console.info(TAG + "************* testRdbStoreDataChange0010 end *************");
    })

    /**
     * @tc.name Normal case for multi observer
     * @tc.number testRdbStoreDataChange0011
     * @tc.desc 1. Register observer1 and observer2 for local database
     *          2. UnRegister observer1 and observer2
     *          3. Insert data into table test
     *
     */
    it('testRdbStoreDataChange0011', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreDataChange0011 start *************");
        function observer1(ChangeInfos) {
            console.info(TAG + "observer1");
            expect().assertFail();
            done();
        };

        function observer2(ChangeInfos) {
            console.info(TAG + "observer2");
            expect().assertFail();
            done();
        };

        try {
            rdbStore.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, observer1);
            rdbStore.on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, observer2);
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
        }

        try {
            rdbStore.off('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS);
        } catch (err) {
            expect().assertFail();
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
        }

        try {
            const valueBucket = {
                'name': 'liSi',
                "age": 18,
                "salary": 100.5,
                "blobType": new Uint8Array([1, 2, 3]),
            }
            let rowId = await rdbStore.insert("test", valueBucket);
            expect(7).assertEqual(rowId);
        } catch (error) {
            expect().assertFail();
            console.error(TAG + `insert fail, code:${error.code}, message: ${error.message}`);
        }
        done();
        console.info(TAG + "************* testRdbStoreDataChange0011 end *************");
    })

    console.info(TAG + "*************Unit Test End*************");
})
