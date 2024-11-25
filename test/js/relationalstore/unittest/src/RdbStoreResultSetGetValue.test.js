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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'
import relationalStore from '@ohos.data.relationalStore';
import ability_featureAbility from '@ohos.ability.featureAbility'

let context = ability_featureAbility.getContext()

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"

const STORE_CONFIG = {
    name: "getValue_test.db",
    securityLevel: relationalStore.SecurityLevel.S1,
}
let rdbStore;

describe('rdbStoreResultSetGetValueTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        await relationalStore.deleteRdbStore(context, "getValue_test.db");
        rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
        await rdbStore.executeSql("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "name TEXT, age INTEGER, salary REAL, blobType BLOB);");
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        await rdbStore.executeSql("DROP TABLE IF EXISTS test");
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        await relationalStore.deleteRdbStore(context, "getValue_test.db");
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name rdb store resultSet getValue test
     * @tc.number rdbStoreResultSetGetValueTest_0001
     * @tc.desc not insert blob
     */
    it('rdbStoreResultSetGetValueTest_0001', 0, async function () {
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0001 start *************");
        let valueBucket = {
            'name': 'lisi',
            'age': 18,
            'salary': 100.5,
        };
        try {
            let rowId = await rdbStore.insert("test", valueBucket);
            expect(1).assertEqual(rowId);
        } catch (err) {
            console.error(`### insert failed, code:${err.code}, message:${err.message}`)
        }

        try {
            let resultSet = await rdbStore.querySql('SELECT * FROM test')
            expect(true).assertEqual(resultSet.goToFirstRow());
            expect(null).assertEqual(resultSet.getValue(resultSet.getColumnIndex('blobType')));
        } catch (err) {
            console.error(`### query failed, code:${err.code}, message:${err.message}`)
        }
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0001 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getValue test
     * @tc.number rdbStoreResultSetGetValueTest_0002
     * @tc.desc insert blob: new Uint8Array()
     */
    it('rdbStoreResultSetGetValueTest_0002', 0, async function () {
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0002 start *************");
        let valueBucket = {
            'name': 'lisi',
            'age': 18,
            'salary': 100.5,
            'blobType': new Uint8Array()
        };
        try {
            let rowId = await rdbStore.insert("test", valueBucket);
            expect(1).assertEqual(rowId);
        } catch (err) {
            console.error(`### insert failed, code:${err.code}, message:${err.message}`)
        }

        try {
            let resultSet = await rdbStore.querySql('SELECT * FROM test')
            expect(true).assertEqual(resultSet.goToFirstRow());
            let blobValue = resultSet.getValue(resultSet.getColumnIndex('blobType'));
            expect(null).assertEqual(blobValue);
        } catch (err) {
            console.error(`### query failed, code:${err.code}, message:${err.message}`)
        }
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0002 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getValue test
     * @tc.number rdbStoreResultSetGetValueTest_0003
     * @tc.desc insert blob: ''
     */
    it('rdbStoreResultSetGetValueTest_0003', 0, async function () {
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0003 start *************");
        let valueBucket = {
            'name': 'lisi',
            'age': 18,
            'salary': 100.5,
            'blobType': ''
        };
        try {
            let rowId = await rdbStore.insert("test", valueBucket);
            expect(1).assertEqual(rowId);
        } catch (err) {
            console.error(`### insert failed, code:${err.code}, message:${err.message}`)
        }

        try {
            let resultSet = await rdbStore.querySql('SELECT * FROM test')
            expect(true).assertEqual(resultSet.goToFirstRow());
            expect('').assertEqual(resultSet.getValue(resultSet.getColumnIndex('blobType')));
        } catch (err) {
            console.error(`### query failed, code:${err.code}, message:${err.message}`)
        }
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0003 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getValue test
     * @tc.number rdbStoreResultSetGetValueTest_0004
     * @tc.desc insert blob: null
     */
    it('rdbStoreResultSetGetValueTest_0004', 0, async function () {
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0004 start *************");
        let valueBucket = {
            'name': 'lisi',
            'age': 18,
            'salary': 100.5,
            'blobType': null
        };
        try {
            let rowId = await rdbStore.insert("test", valueBucket);
            expect(1).assertEqual(rowId);
        } catch (err) {
            console.error(`### insert failed, code:${err.code}, message:${err.message}`)
        }

        try {
            let resultSet = await rdbStore.querySql('SELECT * FROM test')
            expect(true).assertEqual(resultSet.goToFirstRow());
            expect(null).assertEqual(resultSet.getValue(resultSet.getColumnIndex('blobType')));
        } catch (err) {
            console.error(`### query failed, code:${err.code}, message:${err.message}`)
        }
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0004 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getValue test
     * @tc.number rdbStoreResultSetGetValueTest_0005
     * @tc.desc insert string: ''
     */
    it('rdbStoreResultSetGetValueTest_0005', 0, async function () {
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0005 start *************");
        let valueBucket = {
            'name': '',
            'age': 18,
            'salary': 100.5,
            'blobType': new Uint8Array([1, 2, 3])
        };
        try {
            let rowId = await rdbStore.insert("test", valueBucket);
            expect(1).assertEqual(rowId);
        } catch (err) {
            console.error(`### insert failed, code:${err.code}, message:${err.message}`)
        }

        try {
            let resultSet = await rdbStore.querySql('SELECT * FROM test')
            expect(true).assertEqual(resultSet.goToFirstRow());
            expect('').assertEqual(resultSet.getValue(resultSet.getColumnIndex('name')));
        } catch (err) {
            console.error(`### query failed, code:${err.code}, message:${err.message}`)
        }
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0005 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getValue test
     * @tc.number rdbStoreResultSetGetValueTest_0006
     * @tc.desc insert string: null
     */
    it('rdbStoreResultSetGetValueTest_0006', 0, async function () {
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0006 start *************");
        let valueBucket = {
            'name': null,
            'age': 18,
            'salary': 100.5,
            'blobType': new Uint8Array([1, 2, 3])
        };
        try {
            let rowId = await rdbStore.insert("test", valueBucket);
            expect(1).assertEqual(rowId);
        } catch (err) {
            console.error(`### insert failed, code:${err.code}, message:${err.message}`)
        }

        try {
            let resultSet = await rdbStore.querySql('SELECT * FROM test')
            expect(true).assertEqual(resultSet.goToFirstRow());
            expect(null).assertEqual(resultSet.getValue(resultSet.getColumnIndex('name')));
        } catch (err) {
            console.error(`### query failed, code:${err.code}, message:${err.message}`)
        }
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0006 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getValue test
     * @tc.number rdbStoreResultSetGetValueTest_0007
     * @tc.desc not insert string
     */
    it('rdbStoreResultSetGetValueTest_0007', 0, async function () {
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0007 start *************");
        let valueBucket = {
            'age': 18,
            'salary': 100.5,
            'blobType': new Uint8Array([1, 2, 3])
        };
        try {
            let rowId = await rdbStore.insert("test", valueBucket);
            expect(1).assertEqual(rowId);
        } catch (err) {
            console.error(`### insert failed, code:${err.code}, message:${err.message}`)
        }

        try {
            let resultSet = await rdbStore.querySql('SELECT * FROM test')
            expect(true).assertEqual(resultSet.goToFirstRow());
            expect(null).assertEqual(resultSet.getValue(resultSet.getColumnIndex('name')));
        } catch (err) {
            console.error(`### query failed, code:${err.code}, message:${err.message}`)
        }
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0007 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getValue test
     * @tc.number rdbStoreResultSetGetValueTest_0008
     * @tc.desc insert number: ''
     */
    it('rdbStoreResultSetGetValueTest_0008', 0, async function () {
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0008 start *************");
        let valueBucket = {
            'name': 'lisi',
            'age': '',
            'salary': 100.5,
            'blobType': new Uint8Array([1, 2, 3])
        };
        try {
            let rowId = await rdbStore.insert("test", valueBucket);
            expect(1).assertEqual(rowId);
        } catch (err) {
            console.error(`### insert failed, code:${err.code}, message:${err.message}`)
        }

        try {
            let resultSet = await rdbStore.querySql('SELECT * FROM test')
            expect(true).assertEqual(resultSet.goToFirstRow());
            expect('').assertEqual(resultSet.getValue(resultSet.getColumnIndex('age')));
        } catch (err) {
            console.error(`### query failed, code:${err.code}, message:${err.message}`)
        }
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0008 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getValue test
     * @tc.number rdbStoreResultSetGetValueTest_0009
     * @tc.desc insert number: null
     */
    it('rdbStoreResultSetGetValueTest_0009', 0, async function () {
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0009 start *************");
        let valueBucket = {
            'name': 'lisi',
            'age': null,
            'salary': 100.5,
            'blobType': new Uint8Array([1, 2, 3])
        };
        try {
            let rowId = await rdbStore.insert("test", valueBucket);
            expect(1).assertEqual(rowId);
        } catch (err) {
            console.error(`### insert failed, code:${err.code}, message:${err.message}`)
        }

        try {
            let resultSet = await rdbStore.querySql('SELECT * FROM test')
            expect(true).assertEqual(resultSet.goToFirstRow());
            expect(null).assertEqual(resultSet.getValue(resultSet.getColumnIndex('age')));
        } catch (err) {
            console.error(`### query failed, code:${err.code}, message:${err.message}`)
        }
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0009 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getValue test
     * @tc.number rdbStoreResultSetGetValueTest_0010
     * @tc.desc not insert number
     */
    it('rdbStoreResultSetGetValueTest_0010', 0, async function () {
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0010 start *************");
        let valueBucket = {
            'name': 'lisi',
            'salary': 100.5,
            'blobType': new Uint8Array([1, 2, 3])
        };
        try {
            let rowId = await rdbStore.insert("test", valueBucket);
            expect(1).assertEqual(rowId);
        } catch (err) {
            console.error(`### insert failed, code:${err.code}, message:${err.message}`)
        }

        try {
            let resultSet = await rdbStore.querySql('SELECT * FROM test')
            expect(true).assertEqual(resultSet.goToFirstRow());
            expect(null).assertEqual(resultSet.getValue(resultSet.getColumnIndex('age')));
        } catch (err) {
            console.error(`### query failed, code:${err.code}, message:${err.message}`)
        }
        console.log(TAG + "************* rdbStoreResultSetGetValueTest_0010 end   *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})