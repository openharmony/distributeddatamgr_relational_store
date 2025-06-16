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
for(let i = 0; i < 1001; i++) {
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
      try {
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
        expect(info.args[0]).assertEqual("18");
        expect(info.args[1]).assertEqual("asserter");
        expect(info.args[2]).assertEqual("Logitech");
        expect(info.args[3]).assertEqual("man");
        console.log(TAG + "************* testGetInsertSqlInfo end *************");
      } catch (e){
        expect(null).assertFail();
        console.log(TAG + "************* testGetInsertSqlInfo end *************");
      }
    });

    /**
     * @tc.number testGetInsertSqlInfoTabkleNameTooLong
     * @tc.name Get Insert SQL Info tablename length must less then 256
     * @tc.desc Verifies that an error is thrown when the tablename is too long.
     */
    it('testGetInsertSqlInfoTabkleNameTooLong', 0, async () => {
      console.log(TAG + "************* testGetInsertSqlInfoTabkleNameTooLong start *************");
      const bucket: relationalStore.ValuesBucket = {
        name: "Logitech",
        age: "18",
        sex: "man",
        desc: "asserter"
      };
      let tableName: string = "x".repeat(257);
      try {
        relationalStore.getInsertSqlInfo(
          tableName,
          bucket,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
        expect(null).assertFail();
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetInsertSqlInfoTabkleNameTooLong end *************");
      }
    });

    /**
     * @tc.number testGetInsertSqlInfoBucketTooLong
     * @tc.name Get Insert SQL Info Bucket length must less then 1000
     * @tc.desc Verifies that an error is thrown when the bucket is too long.
     */
    it('testGetInsertSqlInfoBucketTooLong', 0, async () => {
      console.log(TAG + "************* testGetInsertSqlInfoBucketTooLong start *************");
      try {
        relationalStore.getInsertSqlInfo(
          "user",
          bucket1000,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
        expect(null).assertFail();
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetInsertSqlInfoBucketTooLong end *************");
      }
    });

    /**
     * @tc.number testGetInsertSqlInfoBucketColumnTooLong
     * @tc.name Get Insert SQL Info bucket key length must less then 256
     * @tc.desc Verifies that an error is thrown when the bucket Column is too long.
     */
    it('testGetInsertSqlInfoBucketColumnTooLong', 0, async () => {
      console.log(TAG + "************* testGetInsertSqlInfoBucketColumnTooLong start *************");
      let tableName: string = "a".repeat(257);
      const bucket: relationalStore.ValuesBucket = {
        name: tableName,
        age: "18",
        sex: "man",
        desc: "asserter"
      };
      bucket[tableName] = "tableName"
      try {
        relationalStore.getInsertSqlInfo(
          "user",
          bucket,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
        expect(null).assertFail();
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetInsertSqlInfoBucketColumnTooLong end *************");
      }
    });

    /**
     * @tc.number testGetInsertSqlInfoTableNameIsEmpty
     * @tc.name Get Insert SQL Info table Is empty
     * @tc.desc Verifies that an error is thrown when the table is empty or null.
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
        expect(null).assertFail();
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetInsertSqlInfoTableNameIsEmpty end *************");
      }
    });

    /**
     * @tc.number testGetInsertSqlInfoConflictResolutionIsNotEmpty
     * @tc.name Get Insert SQL Info
     * @tc.desc Verifies that an error is thrown when the ConflictResolution is not empty.
     */
    it('testGetInsertSqlInfoConflictResolutionIsNotEmpty', 0, async () => {
      console.log(TAG + "************* testGetInsertSqlInfoConflictResolutionIsNotEmpty start *************");
      try {
        const bucket: relationalStore.ValuesBucket = {
          name: "tableName",
          age: "18",
          sex: "man",
          desc: "asserter"
        };
        const info: relationalStore.SqlInfo = relationalStore.getInsertSqlInfo(
          "tableName",
          bucket,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
        expect(info.sql).assertEqual("INSERT INTO tableName(age,desc,name,sex) VALUES (?,?,?,?)");
        console.log(TAG + "************* testGetInsertSqlInfoConflictResolutionIsNotEmpty end *************");
      } catch (e) {
        expect(null).assertFail();
        console.log(TAG + "************* testGetInsertSqlInfoConflictResolutionIsNotEmpty end *************");
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
        expect(null).assertFail();
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetInsertSqlInfoBucketIsNull end *************");
      }
    });

    /**
     * @tc.number testGetInsertSqlInfoBucketIsAssets
     * @tc.name Get Insert SQL Info Bucket contains Assets
     * @tc.desc Verifies that an error is thrown when the bucket contains Assets & ON_CONFLICT_REPLACE.
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
          status: relationalStore.AssetStatus.ASSET_INSERT
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
        expect(null).assertFail();
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetInsertSqlInfoBucketIsAssets end *************");
      }
    });

    /**
     * @tc.number testGetInsertSqlInfoBucketIsAssets2
     * @tc.name Get Insert SQL Info Bucket contains Assets
     * @tc.desc Verifies that an error is thrown when the bucket contains Assets & ON_CONFLICT_IGNORE.
     */
    it('testGetInsertSqlInfoBucketIsAssets2', 0, async () => {
      console.log(TAG + "************* testGetInsertSqlInfoBucketIsAssets start *************");
      try {
        const values: relationalStore.Assets = [
          {
            name: "a",
            uri: "b",
            path: "c",
            createTime: "d",
            modifyTime: "e",
            size: "f",
            status: relationalStore.AssetStatus.ASSET_INSERT
          }
        ];
        const bucket: relationalStore.ValuesBucket = {
          value: values
        };
        const info: relationalStore.SqlInfo = relationalStore.getInsertSqlInfo(
          "USER",
          bucket,
          relationalStore.ConflictResolution.ON_CONFLICT_IGNORE
        );
        const assets = info.args[0] as relationalStore.Assets;
        expect(info.sql).assertEqual("INSERT OR IGNORE INTO USER(value) VALUES (?)");
        expect(assets.length).assertEqual(values.length);
        expect(assets[0].name).assertEqual(values[0].name);
        expect(assets[0].uri).assertEqual(values[0].uri);
        expect(assets[0].path).assertEqual(values[0].path);
        expect(assets[0].createTime).assertEqual(values[0].createTime);
        expect(assets[0].modifyTime).assertEqual(values[0].modifyTime);
        expect(assets[0].size).assertEqual(values[0].size);
        expect(assets[0].status).assertEqual(values[0].status);
        console.log(TAG + "************* testGetInsertSqlInfo end *************");
      } catch (e) {
        expect(null).assertFail();
        console.log(TAG + "************* testGetInsertSqlInfo end *************");
      }
    });

    /**
     * @tc.number testGetUpdateSqlInfo
     * @tc.name Get Update SQL Info
     * @tc.desc Verifies `getUpdateSqlInfo` function correctly generates an UPDATE SQL statement and its arguments.
     */
    it('testGetUpdateSqlInfo', 0, async () => {
      console.log(TAG + "************* testGetUpdateSqlInfo start *************");
      try {
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
        expect(info.args[0]).assertEqual("18");
        expect(info.args[1]).assertEqual("asserter");
        expect(info.args[2]).assertEqual("Logitech");
        expect(info.args[3]).assertEqual("man");
        console.log(TAG + "************* testGetUpdateSqlInfo end *************");
      } catch (e) {
        expect(null).assertFail();
        console.log(TAG + "************* testGetUpdateSqlInfo end *************");
      }
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
        expect(null).assertFail();
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetUpdateSqlInfoBucketIsNull end *************");
      }
    });

    /**
     * @tc.number testGetUpdateSqlInfoBucketTooLong
     * @tc.name Get Update SQL Info Bucket length must less then 1000
     * @tc.desc Verifies that an error is thrown when the bucket is too long.
     */
    it('testGetUpdateSqlInfoBucketTooLong', 0, async () => {
      console.log(TAG + "************* testGetUpdateSqlInfoBucketTooLong start *************");
      const predicates = new relationalStore.RdbPredicates("users");
      try {
        relationalStore.getUpdateSqlInfo(
          predicates,
          bucket1000,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
        expect(null).assertFail();
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetUpdateSqlInfoBucketTooLong end *************");
      }
    });

    /**
     * @tc.number testGetUpdateSqlInfoBucketCloumnTooLong
     * @tc.name Get Update SQL Info the column in bucket length must less then 256
     * @tc.desc Verifies that an error is thrown when the column in bucket is too long.
     */
    it('testGetUpdateSqlInfoBucketCloumnTooLong', 0, async () => {
      console.log(TAG + "************* testGetUpdateSqlInfoBucketCloumnTooLong start *************");
      const predicates = new relationalStore.RdbPredicates("users");
      let tableName: string = "a".repeat(257);
      const bucket: relationalStore.ValuesBucket = {
        age: "18",
        sex: "man",
        desc: "asserter"
      };
      bucket[tableName] = "tableName";
      try {
        relationalStore.getUpdateSqlInfo(
          predicates,
          bucket,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
        expect(null).assertFail();
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetUpdateSqlInfoBucketCloumnTooLong end *************");
      }
    });

    /**
     * @tc.number testGetUpdateSqlInfoTableTooLong
     * @tc.name Get Update SQL Info Bucket Is Null
     * @tc.desc Verifies that an error is thrown when the tablename is too long.
     */
    it('testGetUpdateSqlInfoTableTooLong', 0, async () => {
      console.log(TAG + "************* testGetUpdateSqlInfoTableTooLong start *************");
      let tableName: string = "a".repeat(257);
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
        expect(null).assertFail();
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetUpdateSqlInfoTableTooLong end *************");
      }
    });

    /**
     * @tc.number testGetUpdateSqlInfoWhereClauseTooLong
     * @tc.name Get Update SQL Info Bucket Is Null
     * @tc.desc Verifies that an error is thrown when the WhereClause is too long.
     */
    it('testGetUpdateSqlInfoWhereClauseTooLong', 0, async () => {
      console.log(TAG + "************* testGetUpdateSqlInfoWhereClauseTooLong start *************");
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
        expect(null).assertFail();
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetUpdateSqlInfoWhereClauseTooLong end *************");
      }
    });

    /**
     * @tc.number testGetUpdateSqlInfoConflictResolutionIsNotEmpty
     * @tc.name Get Update SQL Info Bucket Is Null
     * @tc.desc Verifies that an error is thrown when the Conflict is not empty.
     */
    it('testGetUpdateSqlInfoConflictResolutionIsNotEmpty', 0, async () => {
      console.log(TAG + "************* testGetUpdateSqlInfoConflictResolutionIsNotEmpty start *************");
      try {
        const predicates = new relationalStore.RdbPredicates("tableName");
        predicates.equalTo("tableName", "user");
        const bucket: relationalStore.ValuesBucket = {
          name: "tableName",
          age: "18",
          sex: "man",
          desc: "asserter"
        };
        const info: relationalStore.SqlInfo = relationalStore.getUpdateSqlInfo(
          predicates,
          bucket,
          relationalStore.ConflictResolution.ON_CONFLICT_NONE
        );
        expect(info.sql).assertEqual("UPDATE tableName SET age=?,desc=?,name=?,sex=? WHERE tableName = ? ");
      } catch (e) {
        expect(null).assertFail();
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
      try {
        const predicates = new relationalStore.RdbPredicates("users");
        const info: relationalStore.SqlInfo = relationalStore.getDeleteSqlInfo(predicates);
        expect(info.sql).assertEqual("DELETE FROM users");
        console.log(TAG + "************* testGetDeleteSqlInfo end *************");
      } catch (e) {
        expect(null).assertFail();
        console.log(TAG + "************* testGetDeleteSqlInfo end *************");
      }
    });

    /**
     * @tc.number testGetDeleteSqlInfo2
     * @tc.name Get Delete SQL Info Table Name Must Be Not Empty
     * @tc.desc Verifies that the generated delete SQL statement is correct when the table name is provided.
     */
    it('testGetDeleteSqlInfo2', 0, async () => {
      console.log(TAG + "************* testGetDeleteSqlInfo2 start *************");
      try {
        const predicates = new relationalStore.RdbPredicates("users");
        predicates.equalTo("tableName", "a");
        predicates.notEqualTo("age", 18)
        const info: relationalStore.SqlInfo = relationalStore.getDeleteSqlInfo(predicates);
        expect(info.sql).assertEqual("DELETE FROM users WHERE tableName = ?  AND age <> ? ");
        expect(info.args[0]).assertEqual("a");
        expect(info.args[1]).assertEqual(18);
        console.log(TAG + "************* testGetDeleteSqlInfo2 end *************");
      } catch (e) {
        expect(null).assertFail();
        console.log(TAG + "************* testGetQuerySqlInfo end *************");
      }
    });

    /**
     * @tc.number testGetDeleteSqlInfoTableNameTooLong
     * @tc.name Get Delete SQL Info Table Name length Must less then 256
     * @tc.desc Verifies that an error is thrown when the table name is too long.
     */
    it('testGetDeleteSqlInfoTableNameTooLong', 0, async () => {
      console.log(TAG + "************* testGetDeleteSqlInfoTableNameTooLong start *************");
      try {
        let tableName: string = "a".repeat(257);
        const predicates = new relationalStore.RdbPredicates(tableName);
        relationalStore.getDeleteSqlInfo(predicates);
        expect(null).assertFail();
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetDeleteSqlInfoTableNameTooLong end *************");
      }
    });

    /**
     * @tc.number testGetDeleteSqlInfoValueTooLong
     * @tc.name Get Delete SQL Info value Must less then 256
     * @tc.desc Verifies that an error is thrown when the value is too long.
     */
    it('testGetDeleteSqlInfoValueTooLong', 0, async () => {
      console.log(TAG + "************* testGetDeleteSqlInfoValueTooLong start *************");
      try {
        let tableName: string = "a".repeat(257);
        const predicates = new relationalStore.RdbPredicates("tableName");
        predicates.equalTo(tableName, "a");
        relationalStore.getDeleteSqlInfo(predicates);
        expect(null).assertFail();
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetDeleteSqlInfoValueTooLong end *************");
      }
    });

    /**
     * @tc.number testGetQuerySqlInfo
     * @tc.name Get Query SQL Info
     * @tc.desc Verifies that the generated query SQL statement is correct with default columns.
     */
    it('testGetQuerySqlInfo', 0, async () => {
      console.log(TAG + "************* testGetQuerySqlInfo start *************");
      try {
        const predicates = new relationalStore.RdbPredicates("users");
        const info: relationalStore.SqlInfo = relationalStore.getQuerySqlInfo(predicates);
        expect(info.sql).assertEqual("SELECT * FROM users");
        console.log(TAG + "************* testGetQuerySqlInfo end *************");
      } catch (e) {
        expect(null).assertFail();
        console.log(TAG + "************* testGetQuerySqlInfo end *************");
      }
    });

    /**
     * @tc.number testGetQuerySqlInfoColumnsIsNullList
     * @tc.name Get Query SQL Info Columns Is Null List
     * @tc.desc Verifies that the generated query SQL statement is correct when an empty column list is provided.
     */
    it('testGetQuerySqlInfoColumnsIsNullList', 0, async () => {
      console.log(TAG + "************* testGetQuerySqlInfoColumnsIsNullList start *************");
      try {
        const predicates = new relationalStore.RdbPredicates("users");
        const info: relationalStore.SqlInfo = relationalStore.getQuerySqlInfo(predicates, []);
        expect(info.sql).assertEqual("SELECT * FROM users");
        console.log(TAG + "************* testGetQuerySqlInfoColumnsIsNullList end *************");
      } catch (e) {
        expect(null).assertFail();
        console.log(TAG + "************* testGetQuerySqlInfoColumnsIsNullList end *************");
      }
    });

    /**
     * @tc.number testGetQuerySqlInfoByColumns
     * @tc.name Get Query SQL Info By Columns
     * @tc.desc Verifies that the generated query SQL statement is correct when specific columns are provided.
     */
    it('testGetQuerySqlInfoByColumns', 0, async () => {
      console.log(TAG + "************* testGetQuerySqlInfoByColumns start *************");
      try {
        const predicates = new relationalStore.RdbPredicates("users");
        const info: relationalStore.SqlInfo = relationalStore.getQuerySqlInfo(predicates, ["name", "age"]);
        expect(info.sql).assertEqual("SELECT name, age  FROM users");
        console.log(TAG + "************* testGetQuerySqlInfoByColumns end *************");
      } catch (e) {
        expect(null).assertFail();
        console.log(TAG + "************* testGetQuerySqlInfoByColumns end *************");
      }
    });

    /**
     * @tc.number testGetQuerySqlInfoTableNameTooLong
     * @tc.name Get Query SQL Info Table Name length must less then 256
     * @tc.desc Verifies that an error is thrown when the Table is too Long.
     */
    it('testGetQuerySqlInfoTableNameTooLong', 0, async () => {
      console.log(TAG + "************* testGetQuerySqlInfoTableNameTooLong start *************");
      try {
        let tableName: string = "a".repeat(257);
        const predicates = new relationalStore.RdbPredicates(tableName);
        relationalStore.getQuerySqlInfo(predicates);
        expect(null).assertFail();
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetQuerySqlInfoTableNameTooLong end *************");
      }
    });

    /**
     * @tc.number testGetQuerySqlInfoWhereClauseTooLong
     * @tc.name Get Query SQL Info WhereClause length is less then 256
     * @tc.desc Verifies that an error is thrown when the WhereClause is too long.
     */
    it('testGetQuerySqlInfoWhereClauseTooLong', 0, async () => {
      console.log(TAG + "************* testGetQuerySqlInfoWhereClauseTooLong start *************");
      try {
        let tableName: string = "a".repeat(257);
        const predicates = new relationalStore.RdbPredicates("tableName");
        predicates.equalTo(tableName, "a");
        relationalStore.getQuerySqlInfo(predicates);
        expect(null).assertFail();
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetQuerySqlInfoWhereClauseTooLong end *************");
      }
    });

    /**
     * @tc.number testGetQuerySqlInfoColumnsNotstringarray
     * @tc.name Get Query SQL Info Columns must be a string array
     * @tc.desc Verifies that an error is thrown when the Columns is not a string array.
     */
    it('testGetQuerySqlInfoColumnsNotstringarray', 0, async () => {
      console.log(TAG + "************* testGetQuerySqlInfoColumnsNotstringarray start *************");
      try {
        const predicates = new relationalStore.RdbPredicates("tableName");
        predicates.equalTo("tableName", "a");
        const info: relationalStore.SqlInfo =  relationalStore.getQuerySqlInfo(predicates, ["3", "4"]);
        expect(info.sql).assertEqual("SELECT 3, 4  FROM tableName WHERE tableName = ? ");
        expect(info.args[0]).assertEqual('a');
        console.log(TAG + "************* testGetQuerySqlInfoColumnsNotstringarray end *************");
      } catch (e) {
        expect(null).assertFail();
        console.log(TAG + "************* testGetQuerySqlInfoColumnsNotstringarray end *************");
      }
    });

    /**
     * @tc.number testGetQuerySqlInfoColumnsTooLong
     * @tc.name Get Query SQL Info Columns length Must less then 1000
     * @tc.desc Verifies that an error is thrown when the Columns is too length.
     */
    it('testGetQuerySqlInfoColumnsTooLong', 0, async () => {
      console.log(TAG + "************* testGetQuerySqlInfoColumnsTooLong start *************");
      try {
        const colums:string[] = new Array(1003);
        for(let i = 0; i < colums.length; i++) {
          colums[i] = "a";
        }
        const predicates = new relationalStore.RdbPredicates("tableName");
        predicates.equalTo("tableName", "a");
        relationalStore.getQuerySqlInfo(predicates, colums);
        expect(null).assertFail();
      } catch (e) {
        expect(e.code).assertEqual("14800001");
        console.log(TAG + "************* testGetQuerySqlInfoColumnsTooLong end *************");
      }
    });

    /**
     * @tc.number testToSendableValues
     * @tc.name Test To Sendable Values
     * @tc.desc Verifies that converting an array of values to sendable values works correctly.
     */
    it('testToSendableValues', 0, async () => {
      console.log(TAG + "************* testToSendableValues start *************");
      try {
        const array: relationalStore.ValueType[] = [];
        array.push(1);
        array.push(2);
        array.push("aaaaaaa");
        const values = sendableRelationalStore.toSendableValues(array);
        expect(values.length).assertEqual(3);
        expect(values[0]).assertEqual(1);
        expect(values[1]).assertEqual(2);
        expect(values[2]).assertEqual("aaaaaaa");
        console.log(TAG + "************* testToSendableValues end *************");
      } catch (e) {
        expect(null).assertFail();
        console.log(TAG + "************* testToSendableValues end *************");
      }
    });
    console.log(TAG + "*************Unit Test End*************");
  })
}