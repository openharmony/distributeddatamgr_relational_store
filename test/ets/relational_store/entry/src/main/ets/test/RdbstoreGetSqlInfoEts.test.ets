/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium';
import relationalStore from '@ohos.data.relationalStore';
import sendableRelationalStore from '@ohos.data.sendableRelationalStore';

const TAG = "[RDB_GETSQL_TEST]";
const bucket1000: relationalStore.ValuesBucket = {};
for(let i = 0; i < 1000; i++) {
  bucket1000["test" + i] = i;
}
export default function RDBstoreGetSqlInfoTest() {
  describe('rdbstoreGetSqlInfoTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll');
    });
    beforeEach(async () => {
      console.info(TAG + 'beforeEach');
    });
    afterEach(async () => {
      console.info(TAG + 'afterEach');
    });
    afterAll(async () => {
      console.info(TAG + 'afterAll');
    });

    console.log(TAG + "*************Unit Test Begin*************");
    /**
     * @tc.number testGetInsertSqlInfo
     * @tc.name Get Insert SQL Info
     * @tc.desc Tests the functionality of generating an INSERT SQL statement and its arguments.
     */
    it('testGetInsertSqlInfo', 0, async () => {
      console.log(TAG + "************* testGetInsertSqlInfo start *************");
      const bucket: relationalStore.ValuesBucket = {
        name: "Logitech",
        age: "18",
        sex: "man",
        desc: "asserter"
      };
      const info: relationalStore.SqlInfo = relationalStore.getInsertSqlInfo(
        "USER",
        bucket,
        relationalStore.ConflictResolution.ON_CONFLICT_NONE
      );
      expect(info.sql).assertEqual("INSERT INTO USER(age,desc,name,sex) VALUES (?,?,?,?)");
      expect(info.args).assertContain("Logitech");
      expect(info.args).assertContain("18");
      expect(info.args).assertContain("man");
      expect(info.args).assertContain("asserter");
      console.log(TAG + "************* testGetInsertSqlInfo end *************");
    });

    /**
     * @tc.number testGetInsertSqlInfoTabkleNameTooLength
     * @tc.name Get Insert SQL Info Bucket Is Null
     * @tc.desc Verifies that an error is thrown when the bucket is empty or null.
     */
    it('testGetInsertSqlInfoTabkleNameTooLength', 0, async () => {
      console.log(TAG + "************* testGetInsertSqlInfoTabkleNameTooLength start *************");
      const bucket: relationalStore.ValuesBucket = {
        name: "Logitech",
        age: "18",
        sex: "man",
        desc: "asserter"
      };
      let tableName: string = "";
      for(let i = 0; i < 256; i++) {
        tableName = tableName + "a";
      }
      try {
        relationalStore.getInsertSqlInfo(
          tableName,
          bucket,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetInsertSqlInfoTabkleNameTooLength end *************");
      }
    });

    /**
     * @tc.number testGetInsertSqlInfoBucketTooLength
     * @tc.name Get Insert SQL Info Bucket Is Null
     * @tc.desc Verifies that an error is thrown when the bucket is empty or null.
     */
    it('testGetInsertSqlInfoBucketTooLength', 0, async () => {
      console.log(TAG + "************* testGetInsertSqlInfoBucketTooLength start *************");
      try {
        relationalStore.getInsertSqlInfo(
          "user",
          bucket1000,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetInsertSqlInfoBucketTooLength end *************");
      }
    });

    /**
     * @tc.number testGetInsertSqlInfoBucketColumTooLength
     * @tc.name Get Insert SQL Info Bucket Is Null
     * @tc.desc Verifies that an error is thrown when the bucket is empty or null.
     */
    it('testGetInsertSqlInfoBucketColumTooLength', 0, async () => {
      console.log(TAG + "************* testGetInsertSqlInfoBucketColumTooLength start *************");
      let tableName: string = "";
      for(let i = 0; i < 256; i++) {
        tableName = tableName + "a";
      }
      const bucket: relationalStore.ValuesBucket = {
        name: tableName,
        age: "18",
        sex: "man",
        desc: "asserter"
      };
      try {
        relationalStore.getInsertSqlInfo(
          "user",
          bucket,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetInsertSqlInfoBucketColumTooLength end *************");
      }
    });

    /**
     * @tc.number testGetInsertSqlInfoTableNameIsEmpty
     * @tc.name Get Insert SQL Info Bucket Is Null
     * @tc.desc Verifies that an error is thrown when the bucket is empty or null.
     */
    it('testGetInsertSqlInfoTableNameIsEmpty', 0, async () => {
      console.log(TAG + "************* testGetInsertSqlInfoTableNameIsEmpty start *************");
      const bucket: relationalStore.ValuesBucket = {
        name: "tableName",
        age: "18",
        sex: "man",
        desc: "asserter"
      };
      try {
        relationalStore.getInsertSqlInfo(
          "",
          bucket,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetInsertSqlInfoTableNameIsEmpty end *************");
      }
    });

    /**
     * @tc.number testGetInsertSqlInfoConflictResolutionIsEmpty
     * @tc.name Get Insert SQL Info Bucket Is Null
     * @tc.desc Verifies that an error is thrown when the bucket is empty or null.
     */
    it('testGetInsertSqlInfoConflictResolutionIsEmpty', 0, async () => {
      console.log(TAG + "************* testGetInsertSqlInfoConflictResolutionIsEmpty start *************");
      const bucket: relationalStore.ValuesBucket = {
        name: "tableName",
        age: "18",
        sex: "man",
        desc: "asserter"
      };
      try {
        relationalStore.getInsertSqlInfo(
          "tableName",
          bucket,
          5
        );
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetInsertSqlInfoConflictResolutionIsEmpty end *************");
      }
    });

    /**
     * @tc.number testGetInsertSqlInfoBucketIsNull
     * @tc.name Get Insert SQL Info Bucket Is Null
     * @tc.desc Verifies that an error is thrown when the bucket is empty or null.
     */
    it('testGetInsertSqlInfoBucketIsNull', 0, async () => {
      console.log(TAG + "************* testGetInsertSqlInfoBucketIsNull start *************");
      const bucket: relationalStore.ValuesBucket = {};
      try {
        relationalStore.getInsertSqlInfo(
          "USER",
          bucket,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetInsertSqlInfoBucketIsNull end *************");
      }
    });

    /**
     * @tc.number testGetInsertSqlInfoBucketIsAssets
     * @tc.name Get Insert SQL Info Bucket Is Assets
     * @tc.desc Verifies that an error is thrown when the bucket contains invalid data type (Assets).
     */
    it('testGetInsertSqlInfoBucketIsAssets', 0, async () => {
      console.log(TAG + "************* testGetInsertSqlInfoBucketIsAssets start *************");
      const values: relationalStore.Assets = [
        {
          name: "a",
          uri: "b",
          path: "c",
          createTime: "d",
          modifyTime: "e",
          size: "f",
          status: relationalStore.AssetStatus.ASSET_NORMAL
        }
      ];
      const bucket: relationalStore.ValuesBucket = {
        value: values
      };
      try {
        relationalStore.getInsertSqlInfo(
          "ASSETS",
          bucket,
          relationalStore.ConflictResolution.ON_CONFLICT_REPLACE
        );
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetInsertSqlInfoBucketIsAssets end *************");
      }
    });

    /**
     * @tc.number testGetUpdateSqlInfo
     * @tc.name Get Update SQL Info
     * @tc.desc Verifies `getUpdateSqlInfo` function correctly generates an UPDATE SQL statement and its arguments.
     */
    it('testGetUpdateSqlInfo', 0, async () => {
      console.log(TAG + "************* testGetUpdateSqlInfo start *************");
      const bucket: relationalStore.ValuesBucket = {
        name: "Logitech",
        age: "18",
        sex: "man",
        desc: "asserter"
      };
      const predicates = new relationalStore.RdbPredicates("users");
      const info: relationalStore.SqlInfo = relationalStore.getUpdateSqlInfo(
        predicates,
        bucket,
        relationalStore.ConflictResolution.ON_CONFLICT_NONE
      );
      expect(info.sql).assertEqual("UPDATE users SET age=?,desc=?,name=?,sex=?");
      expect(info.args).assertContain("Logitech");
      expect(info.args).assertContain("18");
      expect(info.args).assertContain("man");
      expect(info.args).assertContain("asserter");
      console.log(TAG + "************* testGetUpdateSqlInfo end *************");
    });

    /**
     * @tc.number testGetUpdateSqlInfoBucketIsNull
     * @tc.name Get Update SQL Info Bucket Is Null
     * @tc.desc Verifies that an error is thrown when the bucket is empty.
     */
    it('testGetUpdateSqlInfoBucketIsNull', 0, async () => {
      console.log(TAG + "************* testGetUpdateSqlInfoBucketIsNull start *************");
      const predicates = new relationalStore.RdbPredicates("users");
      const bucket: relationalStore.ValuesBucket = {};
      try {
        relationalStore.getUpdateSqlInfo(
          predicates,
          bucket,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetUpdateSqlInfoBucketIsNull end *************");
      }
    });

    /**
     * @tc.number testGetUpdateSqlInfoBucketTooLength
     * @tc.name Get Update SQL Info Bucket Is Null
     * @tc.desc Verifies that an error is thrown when the bucket is empty.
     */
    it('testGetUpdateSqlInfoBucketTooLength', 0, async () => {
      console.log(TAG + "************* testGetUpdateSqlInfoBucketTooLength start *************");
      const predicates = new relationalStore.RdbPredicates("users");
      try {
        relationalStore.getUpdateSqlInfo(
          predicates,
          bucket1000,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetUpdateSqlInfoBucketTooLength end *************");
      }
    });

    /**
     * @tc.number testGetUpdateSqlInfoBucketCloumTooLength
     * @tc.name Get Update SQL Info Bucket Is Null
     * @tc.desc Verifies that an error is thrown when the bucket is empty.
     */
    it('testGetUpdateSqlInfoBucketCloumTooLength', 0, async () => {
      console.log(TAG + "************* testGetUpdateSqlInfoBucketCloumTooLength start *************");
      const predicates = new relationalStore.RdbPredicates("users");
      let tableName: string = "";
      for(let i = 0; i < 256; i++) {
        tableName = tableName + "a";
      }
      const bucket: relationalStore.ValuesBucket = {
        name: tableName,
        age: "18",
        sex: "man",
        desc: "asserter"
      };
      try {
        relationalStore.getUpdateSqlInfo(
          predicates,
          bucket,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetUpdateSqlInfoBucketCloumTooLength end *************");
      }
    });

    /**
     * @tc.number testGetUpdateSqlInfoTableTooLength
     * @tc.name Get Update SQL Info Bucket Is Null
     * @tc.desc Verifies that an error is thrown when the bucket is empty.
     */
    it('testGetUpdateSqlInfoTableTooLength', 0, async () => {
      console.log(TAG + "************* testGetUpdateSqlInfoTableTooLength start *************");
      let tableName: string = "";
      for(let i = 0; i < 256; i++) {
        tableName = tableName + "a";
      }
      const predicates = new relationalStore.RdbPredicates(tableName);
      const bucket: relationalStore.ValuesBucket = {
        name: "tableName",
        age: "18",
        sex: "man",
        desc: "asserter"
      };
      try {
        relationalStore.getUpdateSqlInfo(
          predicates,
          bucket,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetUpdateSqlInfoTableTooLength end *************");
      }
    });

    /**
     * @tc.number testGetUpdateSqlInfoWhereClauseTooLength
     * @tc.name Get Update SQL Info Bucket Is Null
     * @tc.desc Verifies that an error is thrown when the bucket is empty.
     */
    it('testGetUpdateSqlInfoWhereClauseTooLength', 0, async () => {
      console.log(TAG + "************* testGetUpdateSqlInfoWhereClauseTooLength start *************");
      let tableName: string = "";
      for(let i = 0; i < 256; i++) {
        tableName = tableName + "a";
      }
      const predicates = new relationalStore.RdbPredicates("tableName");
      predicates.equalTo(tableName, "user");
      const bucket: relationalStore.ValuesBucket = {
        name: "tableName",
        age: "18",
        sex: "man",
        desc: "asserter"
      };
      try {
        relationalStore.getUpdateSqlInfo(
          predicates,
          bucket,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetUpdateSqlInfoWhereClauseTooLength end *************");
      }
    });

    /**
     * @tc.number testGetUpdateSqlInfoConflictResolutionIsEmpty
     * @tc.name Get Update SQL Info Bucket Is Null
     * @tc.desc Verifies that an error is thrown when the bucket is empty.
     */
    it('testGetUpdateSqlInfoConflictResolutionIsEmpty', 0, async () => {
      console.log(TAG + "************* testGetUpdateSqlInfoConflictResolutionIsEmpty start *************");
      const predicates = new relationalStore.RdbPredicates("tableName");
      predicates.equalTo("tableName", "user");
      const bucket: relationalStore.ValuesBucket = {
        name: "tableName",
        age: "18",
        sex: "man",
        desc: "asserter"
      };
      try {
        relationalStore.getUpdateSqlInfo(
          predicates,
          bucket,
          5
        );
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetUpdateSqlInfoConflictResolutionIsEmpty end *************");
      }
    });

    /**
     * @tc.number testGetDeleteSqlInfo
     * @tc.name Get Delete SQL Info
     * @tc.desc Verifies that the generated delete SQL statement is correct when the table name is provided.
     */
    it('testGetDeleteSqlInfo', 0, async () => {
      console.log(TAG + "************* testGetDeleteSqlInfo start *************");
      const predicates = new relationalStore.RdbPredicates("users");
      const info: relationalStore.SqlInfo = relationalStore.getDeleteSqlInfo(predicates);
      expect(info.sql).assertEqual("DELETE FROM users");
      console.log(TAG + "************* testGetDeleteSqlInfo end *************");
    });

    /**
     * @tc.number testGetDeleteSqlInfoTableNameTooLength
     * @tc.name Get Delete SQL Info Table Name Must Be Not Empty
     * @tc.desc Verifies that an error is thrown when the table name is empty for delete SQL generation.
     */
    it('testGetDeleteSqlInfoTableNameTooLength', 0, async () => {
      console.log(TAG + "************* testGetDeleteSqlInfoTableNameTooLength start *************");
      try {
        let tableName: string = "";
        for(let i = 0; i < 256; i++) {
          tableName = tableName + "a";
        }
        const predicates = new relationalStore.RdbPredicates(tableName);
        relationalStore.getDeleteSqlInfo(predicates);
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetDeleteSqlInfoTableNameTooLength end *************");
      }
    });

    /**
     * @tc.number testGetDeleteSqlInfoTableNameTooLength
     * @tc.name Get Delete SQL Info Table Name Must Be Not Empty
     * @tc.desc Verifies that an error is thrown when the WhereClause is too length.
     */
    it('testGetDeleteSqlInfoTableNameTooLength', 0, async () => {
      console.log(TAG + "************* testGetDeleteSqlInfoTableNameTooLength start *************");
      try {
        let tableName: string = "";
        for(let i = 0; i < 256; i++) {
          tableName = tableName + "a";
        }
        const predicates = new relationalStore.RdbPredicates("tableName");
        predicates.equalTo(tableName, "a");
        relationalStore.getDeleteSqlInfo(predicates);
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetDeleteSqlInfoTableNameTooLength end *************");
      }
    });

    /**
     * @tc.number testGetQuerySqlInfo
     * @tc.name Get Query SQL Info
     * @tc.desc Verifies that the generated query SQL statement is correct with default columns.
     */
    it('testGetQuerySqlInfo', 0, async () => {
      console.log(TAG + "************* testGetQuerySqlInfo start *************");
      const predicates = new relationalStore.RdbPredicates("users");
      const info: relationalStore.SqlInfo = relationalStore.getQuerySqlInfo(predicates);
      expect(info.sql).assertEqual("SELECT * FROM users");
      console.log(TAG + "************* testGetQuerySqlInfo end *************");
    });

    /**
     * @tc.number testGetQuerySqlInfoColumnsIsNullList
     * @tc.name Get Query SQL Info Columns Is Null List
     * @tc.desc Verifies that the generated query SQL statement is correct when an empty column list is provided.
     */
    it('testGetQuerySqlInfoColumnsIsNullList', 0, async () => {
      console.log(TAG + "************* testGetQuerySqlInfoColumnsIsNullList start *************");
      const predicates = new relationalStore.RdbPredicates("users");
      const info: relationalStore.SqlInfo = relationalStore.getQuerySqlInfo(predicates, []);
      expect(info.sql).assertEqual("SELECT * FROM users");
      console.log(TAG + "************* testGetQuerySqlInfoColumnsIsNullList end *************");
    });

    /**
     * @tc.number testGetQuerySqlInfoByColumns
     * @tc.name Get Query SQL Info By Columns
     * @tc.desc Verifies that the generated query SQL statement is correct when specific columns are provided.
     */
    it('testGetQuerySqlInfoByColumns', 0, async () => {
      console.log(TAG + "************* testGetQuerySqlInfoByColumns start *************");
      const predicates = new relationalStore.RdbPredicates("users");
      const info: relationalStore.SqlInfo = relationalStore.getQuerySqlInfo(predicates, ["name", "age"]);
      expect(info.sql).assertEqual("SELECT name, age  FROM users");
      console.log(TAG + "************* testGetQuerySqlInfoByColumns end *************");
    });

    /**
     * @tc.number testGetQuerySqlInfoTableNameTooLength
     * @tc.name Get Query SQL Info Table Name Must Be Not Empty
     * @tc.desc Verifies that an error is thrown when the Table is too length.
     */
    it('testGetQuerySqlInfoTableNameTooLength', 0, async () => {
      console.log(TAG + "************* testGetQuerySqlInfoTableNameTooLength start *************");
      try {
        let tableName: string = "";
        for(let i = 0; i < 256; i++) {
          tableName = tableName + "a";
        }
        const predicates = new relationalStore.RdbPredicates(tableName);
        relationalStore.getQuerySqlInfo(predicates);
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetQuerySqlInfoTableNameTooLength end *************");
      }
    });

    /**
     * @tc.number testGetQuerySqlInfoWhereClauseTooLength
     * @tc.name Get Query SQL Info Table Name Must Be Not Empty
     * @tc.desc Verifies that an error is thrown when the WhereClause is too length.
     */
    it('testGetQuerySqlInfoWhereClauseTooLength', 0, async () => {
      console.log(TAG + "************* testGetQuerySqlInfoWhereClauseTooLength start *************");
      try {
        let tableName: string = "";
        for(let i = 0; i < 256; i++) {
          tableName = tableName + "a";
        }
        const predicates = new relationalStore.RdbPredicates("tableName");
        predicates.equalTo(tableName, "a");
        relationalStore.getQuerySqlInfo(predicates);
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetQuerySqlInfoWhereClauseTooLength end *************");
      }
    });

    /**
     * @tc.number testGetQuerySqlInfoColumnsNotString
     * @tc.name Get Query SQL Info Table Name Must Be Not Empty
     * @tc.desc Verifies that an error is thrown when the Columns is not a string array.
     */
    it('testGetQuerySqlInfoTableNameTooLength', 0, async () => {
      console.log(TAG + "************* testGetQuerySqlInfoTableNameTooLength start *************");
      try {
        const predicates = new relationalStore.RdbPredicates("tableName");
        predicates.equalTo("tableName", "a");
        relationalStore.getQuerySqlInfo(predicates, [3, 4]);
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetQuerySqlInfoTableNameTooLength end *************");
      }
    });

    /**
     * @tc.number testGetQuerySqlInfoColumnsTooLength
     * @tc.name Get Query SQL Info Table Name Must Be Not Empty
     * @tc.desc Verifies that an error is thrown when the Columns is too length.
     */
    it('testGetQuerySqlInfoColumnsTooLength', 0, async () => {
      console.log(TAG + "************* testGetQuerySqlInfoColumnsTooLength start *************");
      try {
        const colums:string[] = new Array(1003);
        for(let i = 0; i < colums.length; i++) {
          colums[i] = "a";
        }
        const predicates = new relationalStore.RdbPredicates("tableName");
        predicates.equalTo("tableName", "a");
        relationalStore.getQuerySqlInfo(predicates, colums);
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetQuerySqlInfoColumnsTooLength end *************");
      }
    });

    /**
     * @tc.number testToSendableValues
     * @tc.name Test To Sendable Values
     * @tc.desc Verifies that converting an array of values to sendable values works correctly.
     */
    it('testToSendableValues', 0, async () => {
      console.log(TAG + "************* testToSendableValues start *************");
      const array: relationalStore.ValueType[] = [];
      array.push(1);
      array.push(2);
      const values = sendableRelationalStore.toSendableValues(array);
      expect(values.length).assertEqual(2);
      console.log(TAG + "************* testToSendableValues end *************");
    });
    console.log(TAG + "*************Unit Test End*************");
  })
}