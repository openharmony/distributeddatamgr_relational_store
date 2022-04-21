
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
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import dataRdb from '@ohos.data.rdb';
import featureAbility from '@ohos.ability.FeatureAbility';
import Ability from '@ohos.application.Ability'

const TAG = "[RDB_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " + "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";
const DATABASE_BACKUP_NAME = "backup001.db"
const DATABASE_RESTORE_NAME = "restore001.db"
const DATABASE_ROUTE = "/data/storage/el2/database/entry/db/"
const STORE_CONFIG = {
    name: "BackupRestoreTest.db",
}
var context = undefined
var rdbStore = undefined

describe('rdbStoreBackupRestoreWithFAContextTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        context = featureAbility.getContext()
        rdbStore = await dataRdb.getRdbStore(context, STORE_CONFIG, 1)
        await rdbStore.executeSql(CREATE_TABLE_TEST, null)
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 28,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            const valueBucket = {
                "name": "wangwu",
                "age": 38,
                "salary": 90.0,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }

    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        rdbStore = null
        await dataRdb.deleteRdbStore(context, DATABASE_RESTORE_NAME);
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name rdb backup test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Backup_0010
     * @tc.desc rdb backup test
     */
    it('testRdbStoreBackupRestoreWithFAContextTest0001', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreBackupRestore0001 start *************");
        try {
            await rdbStore.backup(DATABASE_ROUTE + DATABASE_BACKUP_NAME)
            console.log(TAG + "backup database success");
            expect(rdbStore).assertEqual(rdbStore)
        } catch (err) {
            console.log(TAG + "backup database failed");
            expect(null).assertFail();
        }
        done()
        console.log(TAG + "************* testRdbStoreBackupRestore0001 end *************");
    })

    /**
     * @tc.name rdb restore test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Restore_0020
     * @tc.desc rdb restore test
     */
    it('testRdbStoreBackupRestoreWithFAContextTest0002', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreBackupRestore0002 start *************");
        try {
            await rdbStore.restore(DATABASE_ROUTE + DATABASE_RESTORE_NAME, DATABASE_ROUTE + DATABASE_BACKUP_NAME)
            console.log(TAG + "restore database success");

        } catch (err) {
            console.log(TAG + "restore database failed");
            expect(null).assertFail();
        }

        done()
        console.log(TAG + "************* testRdbStoreBackupRestore0002 end *************");
    })

    /**
     * @tc.name rdb query test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Query_0030
     * @tc.desc rdb query test
     */
    it('testRdbStoreBackupRestoreWithFAContextTest0003', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreBackupRestore0003 start *************");
        let predicates = new dataRdb.RdbPredicates("test");
        predicates.equalTo("name", "zhangsan")
        let resultSet = await rdbStore.query(predicates)
        try {
            console.log(TAG + "After restore resultSet query done");
            expect(true).assertEqual(resultSet.goToFirstRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const name = resultSet.getString(resultSet.getColumnIndex("name"))
            const age = resultSet.getLong(resultSet.getColumnIndex("age"))
            const salary = resultSet.getDouble(resultSet.getColumnIndex("salary"))
            const blobType = resultSet.getBlob(resultSet.getColumnIndex("blobType"))
            console.log(TAG + "id=" + id + ", name=" + name + ", age=" + age + "," +
                " salary=" + salary + ", blobType=" + blobType);
            expect(1).assertEqual(id);
            expect("zhangsan").assertEqual(name)
            expect(18).assertEqual(age)
            expect(100.5).assertEqual(salary)
            expect(1).assertEqual(blobType[0])
            expect(2).assertEqual(blobType[1])
            expect(3).assertEqual(blobType[2])
        } catch (e) {
            console.log("After restore resultSet query error " + e);
        }
        resultSet = null
        done()
        console.log(TAG + "************* testRdbStoreBackupRestore0003 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})