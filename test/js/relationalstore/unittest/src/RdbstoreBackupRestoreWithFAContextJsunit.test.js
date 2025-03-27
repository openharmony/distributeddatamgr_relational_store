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
import data_relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'
import fileio from '@ohos.file.fs'

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    + "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)"
const DATABASE_DIR = "/data/storage/el2/database/entry/rdb/"
var rdbStore
var context = ability_featureAbility.getContext()
const STORE_CONFIG = {
    name: "BackupResotreTest.db",
    encrypt: true,
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
const DATABASE_BACKUP_NAME = "Backup.db"

async function CreatRdbStore(STORE_CONFIG) {
    let rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG)
    await rdbStore.executeSql(CREATE_TABLE_TEST, null)
    let u8 = new Uint8Array([1, 2, 3])
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
    return rdbStore
}

async function BackupTest(backupName) {
    try {
        let promiseRestore = rdbStore.backup(backupName)
        promiseRestore.then(() => {
            expect(false).assertTrue()
        }).catch((err) => {
            expect(true).assertTrue()
        })
        await promiseRestore
    } catch {
        expect(true).assertTrue()
    }

    rdbStore = null
}

async function RestoreTest(restoreName) {
    try {
        let promiseRestore = rdbStore.restore(restoreName)
        promiseRestore.then(() => {
            expect(false).assertTrue()
        }).catch((err) => {
            expect(true).assertTrue()
        })
        await promiseRestore
    } catch {
        expect(true).assertTrue()
    }

    rdbStore = null
}

describe('rdbStoreBackupRestoreWithFAContextTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
        rdbStore = await CreatRdbStore(STORE_CONFIG)
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        rdbStore = null
        await data_relationalStore.deleteRdbStore(context, STORE_CONFIG.name)
        await data_relationalStore.deleteRdbStore(context, DATABASE_BACKUP_NAME)
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************")

    /**
     * @tc.name RDB Backup Restore test
     * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0010
     * @tc.desc RDB backup and restore function test
     */
    it('RdbBackupRestoreTest_0010', 0, async function (done) {
        console.log(TAG + "************* RdbBackupRestoreTest_0010 start *************")

        try {
            await rdbStore.backup(DATABASE_BACKUP_NAME)
            // expect(true).assertEqual(fileio.accessSync(DATABASE_DIR + DATABASE_BACKUP_NAME))
            // expect(true).assertEqual(fileio.accessSync(DATABASE_DIR + STORE_CONFIG.name))

            await rdbStore.restore(DATABASE_BACKUP_NAME)
            // expect(true).assertEqual(fileio.accessSync(DATABASE_DIR + STORE_CONFIG.name))
        } catch (err) {
            expect().assertFail()
        }

        // RDB after restored, data query test
        let predicates = new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "zhangsan")
        let resultSet = await rdbStore.query(predicates)
        try {
            console.log(TAG + "After restore resultSet query done")
            expect(true).assertEqual(resultSet.goToFirstRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const name = resultSet.getString(resultSet.getColumnIndex("name"))
            const blobType = resultSet.getBlob(resultSet.getColumnIndex("blobType"))
            expect(1).assertEqual(id)
            expect("zhangsan").assertEqual(name)
            expect(1).assertEqual(blobType[0])
        } catch (err) {
            expect(false).assertTrue()
        }
        resultSet.close()
        resultSet = null
        done()
        console.log(TAG + "************* RdbBackupRestoreTest_0010 end *************")
    })

    /**
     * @tc.name RDB Backup test
     * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0020
     * @tc.desc RDB backup function test
     */
    it('RdbBackupRestoreTest_0020', 0, async function (done) {
        console.log(TAG + "************* RdbBackupRestoreTest_0020 start *************")
        // RDB backup function test, backup file name empty
        BackupTest("")

        // RDB backup function test, backup file name already exists
        BackupTest(STORE_CONFIG.name)

        done()
        console.log(TAG + "************* RdbBackupRestoreTest_0020 end *************")
    })

    /**
     * @tc.name RDB BackupRestore test
     * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0030
     * @tc.desc RDB restore function test
     */
    it('RdbBackupRestoreTest_0030', 0, async function (done) {
        console.log(TAG + "************* RdbBackupRestoreTest_0030 start *************")
        await rdbStore.backup(DATABASE_BACKUP_NAME)

        // RDB restore function test, backup file name empty
        RestoreTest("")

        // RDB restore function test, backup file is specified to database name
        RestoreTest(STORE_CONFIG.name)

        done()
        console.log(TAG + "************* RdbBackupRestoreTest_0030 end *************")
    })

    /**
     * @tc.name RDB BackupRestore test
     * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0040
     * @tc.desc RDB restore function test
     */
    it('RdbBackupRestoreTest_0040', 0, async function (done) {
        console.log(TAG + "************* RdbBackupRestoreTest_0040 start *************")
        let dbName = "notExistName.db"

        // RDB restore function test, backup file does not exists
        try {
            expect(false).assertEqual(fileio.accessSync(DATABASE_DIR + dbName))
        } catch (errCode) {
            expect(13900002).assertEqual(errCode.code)
        }
        RestoreTest(dbName)
        done()
        console.log(TAG + "************* RdbBackupRestoreTest_0040 end *************")
    })

    /**
     * @tc.name RDB BackupRestore test
     * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0050
     * @tc.desc RDB backup function test
     */
    it('RdbBackupRestoreBackupTest_0050', 0, async function (done) {
        console.log(TAG + "************* RdbBackupRestoreBackupTest_0050 start *************")

        const STORE_NAME = "AfterCloseTest.db";
        const rdbStore = await data_relationalStore.getRdbStore(
            context,
            {
                name: STORE_NAME,
                securityLevel: data_relationalStore.SecurityLevel.S1
            }
        )
        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            expect(null).assertFail();
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            let dbName = "QueryTest_bak.db"
            await rdbStore.backup(dbName)
        } catch (err) {
            console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await data_relationalStore.deleteRdbStore(context, STORE_NAME);
        done();
        console.log(TAG + "************* RdbBackupRestoreBackupTest_0050 end *************")
    })
    /**
     * @tc.name RDB BackupRestore test
     * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0060
     * @tc.desc RDB restore function test
     */
    it('RdbBackupRestoreBackupTest_0060', 0, async function (done) {
        console.log(TAG + "************* RdbBackupRestoreBackupTest_0060 start *************")

        const STORE_NAME = "AfterCloseTest.db";
        const rdbStore = await data_relationalStore.getRdbStore(
            context,
            {
                name: STORE_NAME,
                securityLevel: data_relationalStore.SecurityLevel.S1
            }
        )

        let dbName = "notExistName.db"
        BackupTest(dbName);

        try {
            await rdbStore.close();
            console.info(`${TAG} close succeeded`);
        } catch (err) {
            expect(null).assertFail();
            console.error(`${TAG} close failed, code is ${err.code},message is ${err.message}`);
        }

        try {
            await rdbStore.restore(dbName)
        } catch (err) {
            console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("14800014").assertEqual(err.code)
        }

        await data_relationalStore.deleteRdbStore(context, STORE_NAME);
        done();
        console.log(TAG + "************* RdbBackupRestoreBackupTest_0060 end *************")
    })
    /**
     * @tc.name RDB BackupRestore by sql test
     * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0062
     * @tc.desc sql func empty param test
     */
    it('RdbBackupRestoreBackupTest_0062', 0, async function (done) {
        console.log(TAG + "************* RdbBackupRestoreBackupTest_0062 start *************")

        const DEST_STORE_NAME = "Dest.db";
        const destDb = await data_relationalStore.getRdbStore(
            context,
            {
                name: DEST_STORE_NAME,
                securityLevel: data_relationalStore.SecurityLevel.S3
            }
        )

        try {
            await destDb.executeSql(`select import_db_from_path()`);
        } catch (error) {
            console.error("****** RdbBackupRestoreBackupTest_0062 ******" + JSON.stringify(error));
            expect(error.code).assertEqual(14800021);
        }
        
        expect('ok', await destDb.execute("pragma integrity_check"));
        await data_relationalStore.deleteRdbStore(context, DEST_STORE_NAME);
        done();
    })

    /**
     * @tc.name RDB BackupRestore by sql test
     * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0063
     * @tc.desc empty path test
     */
    it('RdbBackupRestoreBackupTest_0063', 0, async function (done) {
        console.log(TAG + "************* RdbBackupRestoreBackupTest_0063 start *************")

        const DEST_STORE_NAME = "Dest.db";
        const destDb = await data_relationalStore.getRdbStore(
            context,
            {
                name: DEST_STORE_NAME,
                securityLevel: data_relationalStore.SecurityLevel.S3
            }
        )

        try {
            await destDb.executeSql(`select import_db_from_path('')`);
        } catch (error) {
            console.error("****** RdbBackupRestoreBackupTest_0063 ******" + JSON.stringify(error));
            expect(error.code).assertEqual(14800030);
        }
        expect('ok', await destDb.execute("pragma integrity_check"));
        await data_relationalStore.deleteRdbStore(context, DEST_STORE_NAME);
        done();
    })

    /**
     * @tc.name RDB BackupRestore by sql test
     * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0064
     * @tc.desc souce db not exist test
     */
    it('RdbBackupRestoreBackupTest_0064', 0, async function (done) {
        console.log(TAG + "************* RdbBackupRestoreBackupTest_0064 start *************")

        const DEST_STORE_NAME = "Dest.db";
        const destDb = await data_relationalStore.getRdbStore(
            context,
            {
                name: DEST_STORE_NAME,
                securityLevel: data_relationalStore.SecurityLevel.S3
            }
        )

        try {
            await destDb.executeSql(`select import_db_from_path('/path/not_exist.db')`);
        } catch (error) {
            console.error("****** RdbBackupRestoreBackupTest_0064 ******" + JSON.stringify(error));
            expect(error.code).assertEqual(14800030);
        }
        expect('ok', await destDb.execute("pragma integrity_check"));
        await data_relationalStore.deleteRdbStore(context, DEST_STORE_NAME);
        done();
    })

    /**
     * @tc.name RDB BackupRestore by sql test
     * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0065
     * @tc.desc RDB dest store in transaction
     */
    it('RdbBackupRestoreBackupTest_0065', 0, async function (done) {
        console.log(TAG + "************* RdbBackupRestoreBackupTest_0065 start *************")

        const SOURCE_STORE_NAME = "Source.db";
        const SOURCE_STORE_PATH = "/data/storage/el2/database/entry/rdb/Source.db";
        
        const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "data1 text," + "data2 long, " + "data3 double," + "data4 blob)";
        const sourceDb = await data_relationalStore.getRdbStore(
            context,
            {
                name: SOURCE_STORE_NAME,
                securityLevel: data_relationalStore.SecurityLevel.S3
            }
        )

        await sourceDb.executeSql(CREATE_TABLE_TEST, null);  
        await sourceDb.close();

        const DEST_STORE_NAME = "Dest.db";
        const destDb = await data_relationalStore.getRdbStore(
            context,
            {
                name: DEST_STORE_NAME,
                securityLevel: data_relationalStore.SecurityLevel.S3
            }
        )

        destDb.beginTransaction();

        try {
            await destDb.executeSql(`select import_db_from_path('${SOURCE_STORE_PATH}')`);
        } catch (error) {
            console.error("****** RdbBackupRestoreBackupTest_0065 ******" + JSON.stringify(error));
            expect(error.code).assertEqual(14800024);
        }
        expect('ok', await destDb.execute("pragma integrity_check"));
        await data_relationalStore.deleteRdbStore(context, SOURCE_STORE_NAME);
        await data_relationalStore.deleteRdbStore(context, DEST_STORE_NAME);
        done();
    })

    /**
     * @tc.name RDB import_db_from_path sql func test
     * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0070
     * @tc.desc source store corrupted
     */
    it('RdbBackupRestoreBackupTest_0070', 0, async function (done) {
        console.log(TAG + "************* RdbBackupRestoreBackupTest_0070 start *************")

        const SOURCE_STORE_NAME = "Source.db";
        const SOURCE_STORE_PATH = "/data/storage/el2/database/entry/rdb/Source.db";
        
        const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "data1 text," + "data2 long, " + "data3 double," + "data4 blob)";
        const sourceDb = await data_relationalStore.getRdbStore(
            context,
            {
                name: SOURCE_STORE_NAME,
                securityLevel: data_relationalStore.SecurityLevel.S3
            }
        )

        await sourceDb.executeSql(CREATE_TABLE_TEST, null);  
        await sourceDb.close();

        const fileStream = await fileio.createStream(SOURCE_STORE_PATH, 'r+');
        const buffer = new ArrayBuffer(32);
        const uint8View = new Uint8Array(buffer);
        uint8View.forEach((val, index) => {
          uint8View[index] = 0xFF;
        });

        await fileStream.write(buffer, { offset: 0x0f40, length: uint8View.length });
        fileStream.closeSync();

        const DEST_STORE_NAME = "Dest.db";
        const destDb = await data_relationalStore.getRdbStore(
            context,
            {
                name: DEST_STORE_NAME,
                securityLevel: data_relationalStore.SecurityLevel.S3
            }
        )

        try {
            await destDb.executeSql(`select import_db_from_path('${SOURCE_STORE_PATH}')`);
        } catch (error) {
            console.error("****** RdbBackupRestoreBackupTest_0070 ******" + JSON.stringify(error));
            expect(error.code).assertEqual(14800011);
        }
        expect('ok', await destDb.execute("pragma integrity_check"));
        await data_relationalStore.deleteRdbStore(context, SOURCE_STORE_NAME);
        await data_relationalStore.deleteRdbStore(context, DEST_STORE_NAME);
        done();
    })

    /**
     * @tc.name RDB import_db_from_path sql func test
     * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0080
     * @tc.desc execute import check row count
     */
    it('RdbBackupRestoreBackupTest_0080', 0, async function (done) {
        console.log(TAG + "************* RdbBackupRestoreBackupTest_0080 start *************")

        const SOURCE_STORE_NAME = "Source.db";
        
        const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "data1 text," + "data2 long, " + "data3 double," + "data4 blob)";
        const sourceDb = await data_relationalStore.getRdbStore(
            context,
            {
                name: SOURCE_STORE_NAME,
                securityLevel: data_relationalStore.SecurityLevel.S3
            }
        )

        await sourceDb.executeSql(CREATE_TABLE_TEST, null);
        let times = 100;

        while (times--) {
          const valuesBuckets = new Array(100).fill(0).map((it, index) => {
            return {
                  "data1": "hello" + index,
                  "data2": 10,
                  "data3": 1.0,
                  "data4": new Uint8Array([1, 2, 3]),
            }
          });
          await sourceDb.batchInsert('test', valuesBuckets);
        }

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = sourceDb.querySync(predicates);
        console.log(TAG + "************* RdbBackupRestoreBackupTest_0080 start ************* rowCount: " + resultSet.rowCount);

        await resultSet.close();
        await sourceDb.close();


        const DEST_STORE_NAME = "Dest.db";
        const destDb = await data_relationalStore.getRdbStore(
            context,
            {
                name: DEST_STORE_NAME,
                securityLevel: data_relationalStore.SecurityLevel.S3
            }
        )

        try {
            await destDb.executeSql("select import_db_from_path('/data/storage/el2/database/entry/rdb/Source.db')");
            
            let predicates = await new data_relationalStore.RdbPredicates("test")
            let resultSet = destDb.querySync(predicates);
            expect(resultSet.rowCount).assertEqual(100 * 100);
        } catch (error) {
            console.error("****** RdbBackupRestoreBackupTest_0080 ******" + JSON.stringify(error));
            expect().assertFail();
        }
        expect('ok', await destDb.execute("pragma integrity_check"));
        await data_relationalStore.deleteRdbStore(context, SOURCE_STORE_NAME);
        await data_relationalStore.deleteRdbStore(context, DEST_STORE_NAME);
        done();
    })

    console.log(TAG + "*************Unit Test End*************")
}
)
