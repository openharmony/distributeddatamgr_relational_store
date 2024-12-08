/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
import data_relationalStore from '@ohos.data.relationalStore';
import ability_featureAbility from '@ohos.ability.featureAbility'

var context = ability_featureAbility.getContext()

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"

const STORE_CONFIG = {
    name: "stepResultSet_getRow_test.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
let rdbStore
describe('rdbStoreResultSetGetRowTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        await data_relationalStore.deleteRdbStore(context, "stepResultSet_getRow_test.db");
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
        await rdbStore.executeSql("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, " +
            "data2 INTEGER, data3 FLOAT, data4 BLOB, data5 BOOLEAN, data6 INTEGER);");
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        await rdbStore.executeSql("DROP TABLE IF EXISTS test");
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        await data_relationalStore.deleteRdbStore(context, "stepResultSet_getRow_test.db");
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRowTest0001
     * @tc.desc resultSet getRow test
     */
    it('rdbStoreResultSetGetRowTest0001', 0, async function (done) {
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0001 start *************");
        let valueBucket = {
            id: 1
        };
        let rowId = await rdbStore.insert("test", valueBucket);
        expect(1).assertEqual(rowId);

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates)
        expect(true).assertEqual(resultSet.goToFirstRow());

        let valueBucket_ret = resultSet.getRow();

        expect(1).assertEqual(valueBucket_ret["id"]);
        expect(null).assertEqual(valueBucket_ret["data1"]);
        expect(null).assertEqual(valueBucket_ret["data2"]);
        expect(null).assertEqual(valueBucket_ret["data3"]);
        expect(null).assertEqual(valueBucket_ret["data4"]);
        expect(null).assertEqual(valueBucket_ret["data5"]);

        done();
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0001 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRowTest0002
     * @tc.desc resultSet getRow test
     */
    it('rdbStoreResultSetGetRowTest0002', 0, async function (done) {
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0002 start *************");
        let valueBucket = {
            data1: null,
            data2: undefined,
            data4: undefined,
            data5: null
        };
        let rowId = await rdbStore.insert("test", valueBucket);
        expect(1).assertEqual(rowId);

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates)
        expect(true).assertEqual(resultSet.goToFirstRow());

        let valueBucket_ret = resultSet.getRow();

        expect(1).assertEqual(valueBucket_ret["id"]);
        expect(null).assertEqual(valueBucket_ret["data1"]);
        expect(null).assertEqual(valueBucket_ret["data2"]);
        expect(null).assertEqual(valueBucket_ret["data3"]);
        expect(null).assertEqual(valueBucket_ret["data4"]);
        expect(null).assertEqual(valueBucket_ret["data5"]);

        done();
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0002 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRowTest0003
     * @tc.desc resultSet getRow test
     */
    it('rdbStoreResultSetGetRowTest0003', 0, async function (done) {
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0003 start *************");
        let valueBucket = {
            data1: "hello",
            data2: 10,
            data3: 1.0,
            data4: new Uint8Array([1, 2, 3, 4]),
            data5: true,
        };
        let rowId = await rdbStore.insert("test", valueBucket);
        expect(1).assertEqual(rowId);

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates)
        expect(true).assertEqual(resultSet.goToFirstRow());

        let valueBucket_ret = resultSet.getRow();

        expect(1).assertEqual(valueBucket_ret.id);
        expect("hello").assertEqual(valueBucket_ret.data1);
        expect(10).assertEqual(valueBucket_ret.data2);
        expect(1.0).assertEqual(valueBucket_ret.data3);
        expect(4).assertEqual(valueBucket_ret.data4[3]);
        expect(1).assertEqual(valueBucket_ret.data5);

        done();
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0003 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRowTest0004
     * @tc.desc resultSet getRow test
     */
    it('rdbStoreResultSetGetRowTest0004', 0, async function (done) {
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0004 start *************");
        let valueBucket = {
            "data1": "",
            "data2": 10,
            "data3": 1.0,
            "data4": new Uint8Array([1, 2, 3, 4]),
            "data5": true,
        };
        let rowId = await rdbStore.insert("test", valueBucket);
        expect(1).assertEqual(rowId);

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates, ["data1", "data2"])
        expect(true).assertEqual(resultSet.goToFirstRow());

        let valueBucket_ret = resultSet.getRow();

        expect("").assertEqual(valueBucket_ret.data1);
        expect(undefined).assertEqual(valueBucket_ret.data3);
        expect(undefined).assertEqual(valueBucket_ret.data4);

        done();
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0004 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRowTest0005
     * @tc.desc insert blob: null
     */
    it('rdbStoreResultSetGetRowTest0005', 0, async function (done) {
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0005 start *************");
        let valueBucket = {
            "data1": "",
            "data2": 10,
            "data3": 1.0,
            "data4": null,
            "data5": true,
        };
        let rowId = await rdbStore.insert("test", valueBucket);
        expect(1).assertEqual(rowId);

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates, ["data4"])
        expect(true).assertEqual(resultSet.goToFirstRow());

        let valueBucket_ret = resultSet.getRow();
        expect(null).assertEqual(valueBucket_ret.data4);
        done();
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0005 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRowTest0006
     * @tc.desc insert blob: new Uint8Array()
     */
    it('rdbStoreResultSetGetRowTest0006', 0, async function (done) {
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0006 start *************");
        let valueBucket = {
            "data1": "",
            "data2": 10,
            "data3": 1.0,
            "data4": new Uint8Array(),
            "data5": true,
        };
        let rowId = await rdbStore.insert("test", valueBucket);
        expect(1).assertEqual(rowId);

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates, ["data4"])
        expect(true).assertEqual(resultSet.goToFirstRow());

        let valueBucket_ret = resultSet.getRow();
        expect(null).assertEqual(valueBucket_ret.data4);
        done();
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0006 end   *************");
    })

    /**
     * @tc.name rdb store resultSet insert undefined value and verify test
     * @tc.number rdbStoreResultSetGetRowTest0007
     * @tc.desc resultSet getRow test
     */
    it('rdbStoreInsertUndefinedValueTest0007', 0, async function (done) {
        console.log(TAG + "************* rdbStoreInsertUndefinedValueTest0007 start *************");
        let valueBucket = {
            data2: 10,
            data6: undefined
        };
        let rowId = await rdbStore.insert("test", valueBucket);
        expect(1).assertEqual(rowId);

        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates)
        expect(true).assertEqual(resultSet.goToFirstRow());

        let valueBucket_ret = resultSet.getRow();
        expect(10).assertEqual(valueBucket_ret["data2"]);
        done();
        console.log(TAG + "************* rdbStoreInsertUndefinedValueTest0007 end   *************");
    })

    /**
     * @tc.name rdb store resultSet insert undefined value and verify test
     * @tc.number rdbStoreResultSetGoToLastRow0008
     * @tc.desc resultSet goToFirstRow test
     */
    it('rdbStoreInsertUndefinedValueTest0008', 0, async function () {
        console.log(TAG + "************* rdbStoreInsertUndefinedValueTest0008 start *************");
        let predicates = await new data_relationalStore.RdbPredicates("test")
        let resultSet = await rdbStore.query(predicates)
        expect(false).assertEqual(resultSet.goToFirstRow());
        expect(false).assertEqual(resultSet.goToLastRow());
        console.log(TAG + "************* rdbStoreInsertUndefinedValueTest0008 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGoToLastRow0009
     * @tc.desc resultSet goToFirstRow test
     */
    it('rdbStoreResultSetGetRowTest0009', 0, async function () {
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0009 start *************");
        let querySql = "SELECT 1";
        let resultSet = await rdbStore.querySql(querySql);
        expect(true).assertEqual(resultSet.goToFirstRow());
        let valueBucket_ret = resultSet.getRow();
        expect(1).assertEqual(valueBucket_ret["1"]);
        console.log(TAG + "************* rdbStoreResultSetGetRowTest0009 end   *************");
    })

    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0001
     * @tc.desc resultSet getRows(maxCount) test: 100 rows of data, with empty arg
     */
    it('rdbStoreResultSetGetRowsTest0001', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0001 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let rows;
            let cnt = 0;
            while ((rows = await resultSet.getRows()).length != 0) {
                cnt++;
                console.info(JSON.stringify(rows[0]));
            }
            expect(0).assertEqual(cnt);
            resultSet.close();
            expect().assertFail();
        } catch (e) {
            resultSet.close();
            expect('401').assertEqual(e.code);
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0001 end   *************");
    });


    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0002
     * @tc.desc resultSet getRows(maxCount) test: 100 rows of data, with maxCount set to 100
     */
    it('rdbStoreResultSetGetRowsTest0002', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0002 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let rows;
            let cnt = 0;
            while ((rows = await resultSet.getRows(100)).length != 0) {
                expect(100).assertEqual(rows.length);
                for (let i = 0; i < rows.length; i++) {
                    expect('test' + (i + 1)).assertEqual(rows[i].data1);
                    expect(i + 1).assertEqual(rows[i].data6);
                }
                cnt++;
            }
            expect(1).assertEqual(cnt);
            resultSet.close();
        } catch (e) {
            resultSet.close();
            console.error(TAG + "rdbStoreResultSetGetRowsTest0002 failed, error" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0002 end   *************");
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0003
     * @tc.desc resultSet getRows(maxCount) test: 100 rows of data, with maxCount set to 50
     */
    it('rdbStoreResultSetGetRowsTest0003', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0003 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let rows;
            let cnt = 0;
            while ((rows = await resultSet.getRows(50)).length != 0) {
                expect(50).assertEqual(rows.length);
                for (let i = 0; i < rows.length; i++) {
                    expect('test' + (i + 1 + 50 * cnt)).assertEqual(rows[i].data1);
                    expect(i + 1 + 50 * cnt).assertEqual(rows[i].data6);
                }
                cnt++;
            }
            expect(2).assertEqual(cnt);
            resultSet.close();
        } catch (e) {
            resultSet.close();
            console.error(TAG + "rdbStoreResultSetGetRowsTest0003 failed, error" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0003 end   *************");
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0004
     * @tc.desc resultSet getRows(maxCount) test: 100 rows of data, with maxCount set to 60
     */
    it('rdbStoreResultSetGetRowsTest0004', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0004 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let rows;
            let cnt = 0;
            while ((rows = await resultSet.getRows(60)).length != 0) {
                if (cnt == 0) {
                    expect(60).assertEqual(rows.length);
                } else {
                    expect(40).assertEqual(rows.length);
                }
                for (let i = 0; i < rows.length; i++) {
                    expect('test' + (i + 1 + 60 * cnt)).assertEqual(rows[i].data1);
                    expect(i + 1 + 60 * cnt).assertEqual(rows[i].data6);
                }
                cnt++;
            }
            expect(2).assertEqual(cnt);
            resultSet.close();
        } catch (e) {
            resultSet.close();
            console.error(TAG + "rdbStoreResultSetGetRowsTest0004 failed, error" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0004 end   *************");
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0005
     * @tc.desc resultSet getRows(maxCount) test: 100 rows of data, with maxCount set to 200
     */
    it('rdbStoreResultSetGetRowsTest0005', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0005 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let rows;
            let cnt = 0;
            while ((rows = await resultSet.getRows(200)).length != 0) {
                expect(100).assertEqual(rows.length);
                for (let i = 0; i < rows.length; i++) {
                    expect('test' + (i + 1)).assertEqual(rows[i].data1);
                    expect(i + 1).assertEqual(rows[i].data6);
                }
                cnt++;
            }
            expect(1).assertEqual(cnt);
            resultSet.close();
        } catch (e) {
            resultSet.close();
            console.error(TAG + "rdbStoreResultSetGetRowsTest0005 failed, error" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0005 end   *************");
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0006
     * @tc.desc resultSet getRows(maxCount) test: 100 rows of data, with invalid maxCount 0
     */
    it('rdbStoreResultSetGetRowsTest0006', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0006 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let rows;
            let cnt = 0;
            while ((rows = await resultSet.getRows(0)).length != 0) {
                console.info(JSON.stringify(rows[0]))
                cnt++;
            }
            expect(0).assertEqual(cnt);
            resultSet.close();
            expect().assertFail();
        } catch (e) {
            expect('401').assertEqual(e.code);
            resultSet.close();
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0006 end   *************");
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0007
     * @tc.desc resultSet getRows(maxCount) test: 100 rows of data, with invalid maxCount -1
     */
    it('rdbStoreResultSetGetRowsTest0007', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0007 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
              data1: 'test' + i,
              data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let rows;
            let cnt = 0;
            while ((rows = await resultSet.getRows(-1)).length != 0) {
                cnt++;
            }
            expect(0).assertEqual(cnt);
            resultSet.close();
            expect().assertFail();
        } catch (e) {
            expect('401').assertEqual(e.code);
            resultSet.close();
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0007 end   *************");
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0008
     * @tc.desc resultSet getRows(maxCount, position) test: 100 rows of data, with (maxCount, position) set to (50, 0)
     */
    it('rdbStoreResultSetGetRowsTest0008', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0008 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let rows;
            let position = 0;
            let cnt = 0;
            while ((rows = await resultSet.getRows(50, position)).length != 0) {
                expect(50).assertEqual(rows.length);
                for (let i = 0; i < rows.length; i++) {
                    expect('test' + (i + 1 + 50 * cnt)).assertEqual(rows[i].data1);
                    expect(i + 1 + 50 * cnt).assertEqual(rows[i].data6);
                }
                position += rows.length;
                cnt++;
            }
            expect(100).assertEqual(position);
            expect(2).assertEqual(cnt);
            resultSet.close();
        } catch (e) {
            resultSet.close();
            console.error(TAG + "rdbStoreResultSetGetRowsTest0008 failed, error" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0008 end   *************");
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0009
     * @tc.desc resultSet getRows(maxCount, position) test: 100 rows of data, with (maxCount, position) set to (50, 70)
     */
    it('rdbStoreResultSetGetRowsTest0009', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0009 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let rows;
            let position = 70;
            let cnt = 0;
            while ((rows = await resultSet.getRows(50, position)).length != 0) {
                expect(30).assertEqual(rows.length);
                for (let i = 0; i < rows.length; i++) {
                    expect('test' + (i + 71)).assertEqual(rows[i].data1);
                    expect(i + 71).assertEqual(rows[i].data6);
                }
                position += rows.length;
                cnt++;
            }
            expect(100).assertEqual(position);
            expect(1).assertEqual(cnt);
            resultSet.close();
        } catch (e) {
            console.error(TAG + "rdbStoreResultSetGetRowsTest0009 failed, error" + JSON.stringify(e));
            resultSet.close();
            expect().assertFail();
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0009 end   *************");
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0010
     * @tc.desc resultSet getRows(maxCount, position) test: 100 rows of data, with (maxCount, position) set to (50, 50)
     */
    it('rdbStoreResultSetGetRowsTest0010', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0010 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
          rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let rows;
            let position = 50;
            let cnt = 0;
            while ((rows = await resultSet.getRows(50, position)).length != 0) {
                expect(50).assertEqual(rows.length);
                for (let i = 0; i < rows.length; i++) {
                    expect('test' + (i + 51)).assertEqual(rows[i].data1);
                    expect(i + 51).assertEqual(rows[i].data6);
                }
                position += rows.length;
                cnt++;
            }
            expect(100).assertEqual(position);
            expect(1).assertEqual(cnt);
            resultSet.close();
        } catch (e) {
            console.error(TAG + "rdbStoreResultSetGetRowsTest0010 failed, error" + JSON.stringify(e));
            resultSet.close();
            expect().assertFail();
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0010 end   *************");
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0011
     * @tc.desc resultSet getRows(maxCount, position) test: 100 rows of data, with (maxCount, position) set to (20, 50)
     */
    it('rdbStoreResultSetGetRowsTest0011', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0011 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let rows;
            let position = 50;
            let cnt = 0;
            while ((rows = await resultSet.getRows(20, position)).length != 0) {
                if (cnt != 2) {
                    expect(20).assertEqual(rows.length);
                    for (let i = 0; i < rows.length; i++) {
                        expect('test' + (i + 51 + 20 * cnt)).assertEqual(rows[i].data1);
                        expect(i + 51 + 20 * cnt).assertEqual(rows[i].data6);
                    }
                } else {
                    expect(10).assertEqual(rows.length);
                    for (let i = 0; i < rows.length; ++i) {
                        expect('test' + (i + 91)).assertEqual(rows[i].data1);
                        expect(i + 91).assertEqual(rows[i].data6);
                    }
                }
                position += rows.length;
                cnt++;
            }
            expect(100).assertEqual(position);
            expect(3).assertEqual(cnt);
            resultSet.close();
        } catch (e) {
            console.error(TAG + "rdbStoreResultSetGetRowsTest0011 failed, error" + JSON.stringify(e));
            resultSet.close();
            expect().assertFail();
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0011 end   *************");
    });

    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0012
     * @tc.desc resultSet getRows(maxCount, position) test: 100 rows of data and goToRow(50) before getrows,
     *     with (maxCount, position) set to (50, 0)
     */
    it('rdbStoreResultSetGetRowsTest0012', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0012 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        resultSet.goToRow(50);
        try {
            let rows;
            let position = 0;
            let cnt = 0;
            while ((rows = await resultSet.getRows(50, position)).length != 0) {
                expect(50).assertEqual(rows.length);
                for (let i = 0; i < rows.length; i++) {
                    expect('test' + (i + 1 + 50 * cnt)).assertEqual(rows[i].data1);
                    expect(i + 1 + 50 * cnt).assertEqual(rows[i].data6);
                }
                position += rows.length;
                cnt++;
            }
            expect(100).assertEqual(position);
            expect(2).assertEqual(cnt);
            resultSet.close();
        } catch (e) {
            console.error(TAG + "rdbStoreResultSetGetRowsTest0012 failed, error" + JSON.stringify(e));
            resultSet.close();
            expect().assertFail();
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0012 end   *************");
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0013
     * @tc.desc resultSet getRows(maxCount, position) test: 100 rows of data, with (maxCount, position) set to (20, 100)
     */
    it('rdbStoreResultSetGetRowsTest0013', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0013 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let rows;
            let position = 100;
            let cnt = 0;
            while ((rows = await resultSet.getRows(20, position)).length != 0) {
                position += rows.length;
                cnt++;
            }
            expect(0).assertEqual(position);
            expect(0).assertEqual(cnt);
            resultSet.close();
            expect().assertFail();
        } catch (e) {
            expect(14800012).assertEqual(e.code);
            resultSet.close();
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0013 end   *************");
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0014
     * @tc.desc resultSet getRows(maxCount, position) test: 100 rows of data, with invalid position -1
     */
    it('rdbStoreResultSetGetRowsTest0014', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0014 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let rows;
            let position = -1;
            let cnt = 0;
            while ((rows = await resultSet.getRows(20, position)).length != 0) {
                position += rows.length;
                cnt++;
            }
            expect(0).assertEqual(position);
            expect(0).assertEqual(cnt);
            resultSet.close();
            expect().assertFail();
        } catch (e) {
            expect('401').assertEqual(e.code);
            resultSet.close();
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0014 end   *************");
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0015
     * @tc.desc resultSet getRows(maxCount, position) test: resultSet closed before getRows
     */
    it('rdbStoreResultSetGetRowsTest0015', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0015 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let rows;
            let position = 50;
            let cnt = 0;
            resultSet.close();
            while ((rows = await resultSet.getRows(20, position)).length != 0) {
                position += rows.length;
                cnt++;
            }
            expect(0).assertEqual(position);
            expect(0).assertEqual(cnt);
            resultSet.close();
            expect().assertFail();
        } catch (e) {
            expect('14800014').assertEqual(e.code);
            resultSet.close();
            console.info(TAG + "rdbStoreResultSetGetRowsTest0015 success, err" + JSON.stringify(e));
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0015 end   *************");
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0016
     * @tc.desc resultSet getRows(maxCount, position) test: concurrent getRows and close on resultSet
     */
    it('rdbStoreResultSetGetRowsTest0016', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0016 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let position = 20
            const getRowsPromise = resultSet.getRows(100, position);
            getRowsPromise.then((rows) => {
                expect(80).assertEqual(rows.length);
                for (let i = 0; i < rows.length; i++) {
                    expect('test' + (i + 21)).assertEqual(rows[i].data1);
                    expect(i + 21).assertEqual(rows[i].data6);
                }
            console.info(TAG + "rdbStoreResultSetGetRowsTest0016 success");
            }).catch((e) =>{
                expect(14800014).assertEqual(e);
                console.info(TAG + "rdbStoreResultSetGetRowsTest0016 success, err" + JSON.stringify(e));
            }).finally(() =>{
                console.info(TAG + "************* rdbStoreResultSetGetRowsTest0016 end   *************");
            })
            resultSet.close();
        } catch (error) {
            resultSet.close();
            console.error(TAG + "rdbStoreResultSetGetRowsTest0016 failed, error" + JSON.stringify(error));
            console.info(TAG + "************* rdbStoreResultSetGetRowsTest0016 end   *************");
            expect().assertFail();
        }
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0017
     * @tc.desc resultSet getRows(maxCount, position) test: concurrent getRows and goTo on resultSet
     */
    it('rdbStoreResultSetGetRowsTest0017', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0017 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let position = 20;
            const getRowsPromise = resultSet.getRows(100, position);
            getRowsPromise.then((rows) => {
                console.info(TAG + "rows.length: " + JSON.stringify(rows.length));
                console.info(TAG + "data of rows[0]: " + JSON.stringify(rows[0]));
                console.info(TAG + "rdbStoreResultSetGetRowsTest0017 success");
            }).catch((e) =>{
                console.info(TAG + "rdbStoreResultSetGetRowsTest0017 success, err" + JSON.stringify(e));
            }).finally(() =>{
                console.info(TAG + "************* rdbStoreResultSetGetRowsTest0017 end   *************");
                resultSet.close();
            })
            resultSet.goTo(10);// goto: rowPos_ + 10
        } catch (error) {
            resultSet.close();
            console.error(TAG + "rdbStoreResultSetGetRowsTest0017 failed, error" + JSON.stringify(error));
            console.info(TAG + "************* rdbStoreResultSetGetRowsTest0017 end   *************");
            expect().assertFail();
        }
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0018
     * @tc.desc resultSet getRows(maxCount, position) test: concurrent getRows and goToRow on resultSet
     */
    it('rdbStoreResultSetGetRowsTest0018', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0018 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let position = 20;
            const getRowsPromise = resultSet.getRows(100, position);
            getRowsPromise.then((rows) => {
                console.info(TAG + "rows.length: " + JSON.stringify(rows.length));
                console.info(TAG + "data of rows[0]: " + JSON.stringify(rows[0]));
                console.info(TAG + "rdbStoreResultSetGetRowsTest0018 success");
            }).catch((e) =>{
                console.info(TAG + "rdbStoreResultSetGetRowsTest0018 success, err" + JSON.stringify(e));
            }).finally(() =>{
                resultSet.close();
                console.info(TAG + "************* rdbStoreResultSetGetRowsTest0018 end   *************");
            })
            resultSet.goToRow(1);
        } catch (error) {
            resultSet.close();
            console.error(TAG + "rdbStoreResultSetGetRowsTest0018 failed, error" + JSON.stringify(error));
            console.info(TAG + "************* rdbStoreResultSetGetRowsTest0018 end   *************");
            expect().assertFail();
        }
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0019
     * @tc.desc resultSet getRows(maxCount, position) test: concurrent getRows and goToFirstRow on resultSet
     */
    it('rdbStoreResultSetGetRowsTest0019', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0019 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let position = 20;
            const getRowsPromise = resultSet.getRows(100, position);
            getRowsPromise.then((rows) => {
                console.info(TAG + "rows.length: " + JSON.stringify(rows.length));
                console.info(TAG + "data of rows[0]: " + JSON.stringify(rows[0]));
                console.info(TAG + "rdbStoreResultSetGetRowsTest0019 success");
            }).catch((e) =>{
                console.info(TAG + "rdbStoreResultSetGetRowsTest0019 success, err" + JSON.stringify(e));
            }).finally(() =>{
                resultSet.close();
                console.info(TAG + "************* rdbStoreResultSetGetRowsTest0019 end   *************");
            })
            resultSet.goToFirstRow();
        } catch (error) {
            resultSet.close();
            console.error(TAG + "rdbStoreResultSetGetRowsTest0019 failed, error" + JSON.stringify(error));
            console.info(TAG + "************* rdbStoreResultSetGetRowsTest0019 end   *************");
            expect().assertFail();
        }
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0020
     * @tc.desc resultSet getRows(maxCount, position) test: concurrent getRows and goToLastRow on resultSet
     */
    it('rdbStoreResultSetGetRowsTest0020', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0020 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let position = 20;
            const getRowsPromise = resultSet.getRows(100, position);
            getRowsPromise.then((rows) => {
                console.info(TAG + "rows.length: " + JSON.stringify(rows.length));
                console.info(TAG + "data of rows[0]: " + JSON.stringify(rows[0]));
                console.info(TAG + "rdbStoreResultSetGetRowsTest0020 success");
            }).catch((e) =>{
                console.info(TAG + "rdbStoreResultSetGetRowsTest0020 success, err" + JSON.stringify(e));
            }).finally(() =>{
                resultSet.close();
                console.info(TAG + "************* rdbStoreResultSetGetRowsTest0020 end   *************");
            })
            resultSet.goToLastRow();
        } catch (error) {
            resultSet.close();
            console.error(TAG + "rdbStoreResultSetGetRowsTest0020 failed, error" + JSON.stringify(error));
            console.info(TAG + "************* rdbStoreResultSetGetRowsTest0020 end   *************");
            expect().assertFail();
        }
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0021
     * @tc.desc resultSet getRows(maxCount, position) test: concurrent getRows and goToNextRow on resultSet
     */
    it('rdbStoreResultSetGetRowsTest0021', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0021 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let position = 20;
            const getRowsPromise = resultSet.getRows(100, position);
            getRowsPromise.then((rows) => {
                console.info(TAG + "rows.length: " + JSON.stringify(rows.length));
                console.info(TAG + "data of rows[0]: " + JSON.stringify(rows[0]));
                console.info(TAG + "rdbStoreResultSetGetRowsTest0021 success");
            }).catch((e) =>{
                console.info(TAG + "rdbStoreResultSetGetRowsTest0021 success, err" + JSON.stringify(e));
            }).finally(() =>{
                resultSet.close();
                console.info(TAG + "************* rdbStoreResultSetGetRowsTest0021 end   *************");
            })
            resultSet.goToNextRow();
        } catch (error) {
            resultSet.close();
            console.error(TAG + "rdbStoreResultSetGetRowsTest0021 failed, Err" + JSON.stringify(error));
            console.info(TAG + "************* rdbStoreResultSetGetRowsTest0021 end   *************");
            expect().assertFail();
        }
    });
  
    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0022
     * @tc.desc resultSet getRows(maxCount, position) test: concurrent getRows and goToPreviousRow on resultSet
     */
    it('rdbStoreResultSetGetRowsTest0022', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0022 start *************");
        let rowId = 0;
        for (let i = 1; i <= 100; i++) {
            let valueBucket = {
                data1: 'test' + i,
                data6: i,
            };
            rowId = await rdbStore.insert("test", valueBucket);
        }
        expect(100).assertEqual(rowId);
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(100).assertEqual(resultSet.rowCount);
        try {
            let position = 20;
            const getRowsPromise = resultSet.getRows(100, position);
            getRowsPromise.then((rows) => {
                console.info(TAG + "rows.length: " + JSON.stringify(rows.length));
                console.info(TAG + "data of rows[0]: " + JSON.stringify(rows[0]));
                console.info(TAG + "rdbStoreResultSetGetRowsTest0022 success");
            }).catch((e) =>{
                console.info(TAG + "rdbStoreResultSetGetRowsTest0022 success, err" + JSON.stringify(e));
            }).finally(() =>{
                resultSet.close();
                console.info(TAG + "************* rdbStoreResultSetGetRowsTest0022 end   *************");
            })
            resultSet.goToPreviousRow();
        } catch (error) {
            resultSet.close();
            console.error(TAG + "rdbStoreResultSetGetRowsTest0022 failed, error" + JSON.stringify(error));
            console.info(TAG + "************* rdbStoreResultSetGetRowsTest0022 end   *************");
            expect().assertFail();
        }
    });

    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0023
     * @tc.desc resultSet getRows(maxCount) test: getRows(50) with empty resultSet
     */
    it('rdbStoreResultSetGetRowsTest0023', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0023 start *************");
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(0).assertEqual(resultSet.rowCount);
        try {
            let rows;
            let cnt = 0;
            while ((rows = await resultSet.getRows(50)).length != 0) {
                console.info(JSON.stringify(rows[0]));
                cnt++;
            }
            expect(0).assertEqual(cnt);
            expect(0).assertEqual(rows.length);
            resultSet.close();
        } catch (e) {
            resultSet.close();
            expect().assertFail();
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0023 end   *************");
    });

    /**
     * @tc.name rdb store resultSet getRow test
     * @tc.number rdbStoreResultSetGetRows0024
     * @tc.desc resultSet getRows(maxCount,position) test: getRows(50, 0) with empty resultSet
     */
    it('rdbStoreResultSetGetRowsTest0024', 0, async () => {
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0024 start *************");
        let predicates = new data_relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        expect(0).assertEqual(resultSet.rowCount);
        try {
            let rows;
            let cnt = 0;
            while ((rows = await resultSet.getRows(50, 0)).length != 0) {
                console.info(JSON.stringify(rows[0]));
                cnt++;
            }
            expect(0).assertEqual(cnt);
            expect(0).assertEqual(rows.length);
            resultSet.close();
            expect().assertFail();
        } catch (e) {
            resultSet.close();
            expect(14800012).assertEqual(e.code);
        }
        console.info(TAG + "************* rdbStoreResultSetGetRowsTest0024 end   *************");
    });
    console.log(TAG + "*************Unit Test End*************");
})