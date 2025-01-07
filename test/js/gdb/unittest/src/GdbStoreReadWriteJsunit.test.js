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
import graphStore from '@ohos.data.graphStore'
import ability_featureAbility from '@ohos.ability.featureAbility'

const TAG = "[GRAPH_STORE_JSKITS_TEST]";
const context = ability_featureAbility.getContext();
const CREATE_GRAPH_TEST = "CREATE GRAPH test {(person:Person {name STRING, age INT}), (person) -[:Friend]-> (person)};"
const STORE_CONFIG = {
    name: "readwritegraph",
    securityLevel: graphStore.SecurityLevel.S1,
};

describe('graphStoreReadWriteTest', () => {
    let store;
    beforeAll(async () => {
        console.info(TAG + 'beforeAll');
        await graphStore.deleteStore(context, STORE_CONFIG);
        await graphStore.getStore(context, STORE_CONFIG);
    })

    beforeEach(async () => {
        console.info(TAG + 'beforeEach');
        await store.write(CREATE_GRAPH_TEST);
    })

    afterEach(async () => {
        console.info(TAG + 'afterEach');
        await store.write("DROP GRAPH test");
    })

    afterAll(async () => {
        console.info(TAG + 'afterAll');
        await store.close();
        await graphStore.deleteStore(context, STORE_CONFIG);
    })

    console.info(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name graph store close test
     * @tc.number GdbStoreCloseTest0001
     * @tc.desc graph store close test
     */
    it('testGraphStoreClose0001', 0, async () => {
        console.info(TAG + "************* testGraphStoreClose0001 start *************");
        let storeConfig = {
            name: "closeStore",
            securityLevel: graphStore.SecurityLevel.S1,
        };
        let closestore = await graphStore.getStore(context, storeConfig);
        await closestore.write(CREATE_GRAPH_TEST);
        await closestore.write("INSERT (:Person {name: 'name_1', age: 11});");
        await closestore.write("DROP GRAPH test");
        try {
            await closestore.close();
        } catch (e) {
            console.error(TAG + "close test failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        await graphStore.deleteStore(context, storeConfig);
        console.info(TAG + "************* testGraphStoreClose0001 end *************");
    })

    /**
     * @tc.name graph store write test
     * @tc.number GdbStoreWriteTest0001
     * @tc.desc graph store write insert
     */
    it('testGraphStoreWrite0001', 0, async () => {
        console.info(TAG + "************* testGraphStoreWrite0001 start *************");
        try {
            await store.write("INSERT (:Person {name: 'name_1', age: 11});");
            await store.write("INSERT (:Person {name: 'name_2', age: 22});");
            await store.write(
                "MATCH (p1:Person {name: 'name_1'}), (p2:Person {name: 'name_2'}) INSERT (p1) -[:Friend]-> (p2);"
            );
            let result = await store.read("MATCH (p:Person) where p.age < 30 RETURN p")
            if (result.records) {
                expect(2).assertEqual(result.records.length);
            } else {
                console.error(TAG + "write test1 INSERT vertex failed.");
                expect().assertFail();
            }
            let path = await store.read(
                "MATCH path = (p1:Person {name: 'name_1'})-[]-(p2:Person {name: 'name_2'}) RETURN path;"
            );
            if (path.records) {
                expect(1).assertEqual(path.records.length);
            } else {
                console.error(TAG + "write test1 INSERT edge failed.");
                expect().assertFail();
            }
        } catch (e) {
            console.error(TAG + "write test1 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStoreWrite0001 end *************");
    })

    /**
     * @tc.name graph store write test
     * @tc.number GdbStoreWriteTest0002
     * @tc.desc graph store write update
     */
    it('testGraphStoreWrite0002', 0, async () => {
        console.info(TAG + "************* testGraphStoreWrite0002 start *************");
        try {
            await store.write("INSERT (:Person {name: 'name_1', age: 11});");
            await store.write("INSERT (:Person {name: 'name_2', age: 22});");
            await store.write(
                "MATCH (p1:Person {name: 'name_1'}), (p2:Person {name: 'name_2'}) INSERT (p1) -[:Friend]-> (p2);"
            );
            await store.write("MATCH (p1:Person {name: 'name_1'}) SET p1.age = 21;");
            await store.write("MATCH (p2:Person {name: 'name_2'}) SET p2.name = 'Aname';");
            await store.write("MATCH (n:Person {name: 'name_1'})-[r:Friend]->(m:Person) SET m.age = 32");

            let p1 = await store.read("MATCH (p1:Person) where p1.name = 'name_1' RETURN p1;");
            if (p1.records) {
                expect(1).assertEqual(p1.records.length);
                let temp = p1.records[0];
                let vertex = temp["p1"];
                expect('1').assertEqual(vertex.vid);
                let proper = vertex.properties;
                expect(21).assertEqual(proper["AGE"]);
                expect('name_1').assertEqual(proper["NAME"]);
            } else {
                console.error(TAG + "write test2 read data1 failed.");
                expect().assertFail();
            }

            let p2 = await store.read("MATCH (p2:Person) where p2.name = 'name_2' RETURN p2;");
            if (p2.records) {
                expect(0).assertEqual(p2.records.length);
            } else {
                console.error(TAG + "write test2 read data2 failed.");
                expect().assertFail();
            }

            let p3 = await store.read("MATCH (p3:Person) where p3.name = 'Aname' RETURN p3;");
            if (p3.records) {
                expect(1).assertEqual(p3.records.length);
                let temp = p3.records[0];
                let vertex = temp["p3"];
                expect('2').assertEqual(vertex.vid);
                let proper = vertex.properties;
                expect(32).assertEqual(proper["AGE"]);
                expect('Aname').assertEqual(proper["NAME"]);
            } else {
                console.error(TAG + "write test2 read data3 failed.");
                expect().assertFail();
            }
        } catch (e) {
            console.error(TAG + "write test2 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStoreWrite0002 end *************");
    })

    /**
     * @tc.name graph store write test
     * @tc.number GdbStoreWriteTest0003
     * @tc.desc graph store write delete
     */
    it('testGraphStoreWrite0003', 0, async () => {
        console.info(TAG + "************* testGraphStoreWrite0003 start *************");
        try {
            await store.write("INSERT (:Person {name: 'name_1', age: 11});");
            await store.write("INSERT (:Person {name: 'name_2', age: 22});");
            await store.write(
                "MATCH (p1:Person {name: 'name_1'}), (p2:Person {name: 'name_2'}) INSERT (p1) -[:Friend]-> (p2);"
            );
            await store.write("MATCH (p:Person {name: 'name_1'}) DETACH DELETE p;");
            // read
            let p = await store.read("MATCH (p:Person) where p.age < 30 RETURN p");
            if (p.records) {
                expect(1).assertEqual(p.records.length);
            } else {
                console.error(TAG + "write test3 read data1 failed.");
                expect().assertFail();
            }

            let path = await store.read(
                "MATCH path = (p1:Person {name: 'name_1'})-[]-(p2:Person {name: 'name_2'}) RETURN path;"
            )
            if (path.records) {
                expect(0).assertEqual(path.records.length);
            } else {
                console.error(TAG + "write test3 read data2 failed.");
                expect().assertFail();
            }
        } catch (e) {
            console.error(TAG + "write test3 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStoreWrite0003 end *************");
    })

    /**
     * @tc.name graph store write test
     * @tc.number GdbStoreWriteTest0004
     * @tc.desc graph store write with 2 params
     */
    it('testGraphStoreWrite0004', 0, async () => {
        console.info(TAG + "************* testGraphStoreWrite0004 start *************");
        try {
            await store.write("INSERT (:Person {name: 'name_1', age: 11});");
            await store.write("INSERT (:Person {name: 'name_2', age: 22});");
            let INSERT1 = "INSERT (:Person {name: 'name_3', age: 33});"
            let INSERT2 = "INSERT (:Person {name: 'name_4', age: 44});"
            await store.write(INSERT1, INSERT2);
            expect().assertFail();
        } catch (e) {
            expect(401).assertEqual(e.code);
            // read
            let p = await store.read("MATCH (p:Person) where p.age < 50 RETURN p");
            if (p.records) {
                expect(2).assertEqual(p.records.length);
            } else {
                console.error(TAG + "write test4 read data failed.");
                expect().assertFail();
            }
        }
        console.info(TAG + "************* testGraphStoreWrite0004 end *************");
    })

    /**
     * @tc.name graph store write test
     * @tc.number GdbStoreWriteTest0005
     * @tc.desc graph store close before write
     */
    it('testGraphStoreWrite0005', 0, async () => {
        console.info(TAG + "************* testGraphStoreWrite0005 start *************");
        let storeConfig = {
            name: "closeStore",
            securityLevel: graphStore.SecurityLevel.S1,
        };
        let closestore = await graphStore.getStore(context, storeConfig);
        await closestore.write(CREATE_GRAPH_TEST);
        try {
            await closestore.write("INSERT (:Person {name: 'name_1', age: 11});");
            let p = await closestore.read("MATCH (p:Person) where p.age < 30 RETURN p");
            if (p.records) {
                expect(1).assertEqual(p.records.length);
            } else {
                console.error(TAG + "write test5 read data failed.");
                expect().assertFail();
            }
            await closestore.close();
            await closestore.write("INSERT (:Person {name: 'name_2', age: 22});");
            expect().assertFail();
        } catch (e) {
            expect('31300002').assertEqual(e.code);
        }
        await graphStore.deleteStore(context, storeConfig);
        console.info(TAG + "************* testGraphStoreWrite0005 end *************");
    })

    /**
     * @tc.name graph store write test
     * @tc.number GdbStoreWriteTest0006
     * @tc.desc graph store write with duplicate type
     */
    it('testGraphStoreWrite0006', 0, async () => {
        console.info(TAG + "************* testGraphStoreWrite0006 start *************")
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        let INSERT = "INSERT (:Person {name: 'name_3', name: 'name_4', age: 33});"
        try {
            //insert sucess
            await store.write(INSERT);
            let result = await store.write("MATCH (p:Person) where p.age = 33 RETURN p;");
            if (result.records) {
                expect(0).assertEqual(result.records.length);
            }
        } catch (e) {
            console.error(TAG + "write test6 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStoreWrite0006 end *************");
    })

    /**
     * @tc.name graph store write test
     * @tc.number GdbStoreWriteTest0007
     * @tc.desc graph store write with undefined type
     */
    it('testGraphStoreWrite0007', 0, async () => {
        console.info(TAG + "************* testGraphStoreWrite0007 start *************");
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        let UPDATE = "MATCH (p:Person {name: 'name_1'}) DETACH DELETE p_error"
        try {
            await store.write(UPDATE);
            expect().assertFail();
        } catch (e) {
            expect(31300007).assertEqual(e.code);
            // read
            let p = await store.read("MATCH (p:Person) where p.age < 50 RETURN p");
            if (p.records) {
                expect(2).assertEqual(p.records.length);
            } else {
                console.error(TAG + "write test7 read data failed.");
                expect().assertFail();
            }
        }
        console.info(TAG + "************* testGraphStoreWrite0007 end *************");
    })

    /**
     * @tc.name graph store write test
     * @tc.number GdbStoreWriteTest0008
     * @tc.desc graph store write with GQL statement syntax error
     */
    it('testGraphStoreWrite0008', 0, async () => {
        console.info(TAG + "************* testGraphStoreWrite0008 start *************");
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        let INSERT = "INSERT (:ZOO {name: 'name_3', age: 33);"
        try {
           await store.write(INSERT);
            expect().assertFail();
        } catch (e) {
            expect(31300009).assertEqual(e.code);
            // read
            let p = await store.read("MATCH (p:Person) where p.age < 50 RETURN p");
            if (p.records) {
                expect(2).assertEqual(p.records.length);
            } else {
                console.error(TAG + "write test8 read data failed.");
                expect().assertFail();
            }
        }
        console.info(TAG + "************* testGraphStoreWrite0008 end *************");
    })

    /**
     * @tc.name graph store write test
     * @tc.number GdbStoreWriteTest0009
     * @tc.desc graph store write with GQL statement semantic error
     */
    it('testGraphStoreWrite0009', 0, async () => {
        console.info(TAG + "************* testGraphStoreWrite0009 start *************");
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        let UPDATE = "MATCH (p1:Person {name: 'name_1'}) SET p1.age = 'six';"
        try {
            await store.write(UPDATE);
            expect().assertFail();
        } catch (e) {
            expect(31300010).assertEqual(e.code);
            // read
            let p = await store.read("MATCH (p:Person) where p.age < 50 RETURN p");
            if (p.records) {
                expect(2).assertEqual(p.records.length);
                let temp = p.records[0];
                expect('p').assertEqual(temp[0]);
                expect('name_1').assertEqual(temp[1].name);
                expect(11).assertEqual(temp[1].age);
            } else {
                console.error(TAG + "write test9 read data failed.");
                expect().assertFail();
            }
        }
        console.info(TAG + "************* testGraphStoreWrite0009 end *************");
    })

    /**
     * @tc.name graph store write test
     * @tc.number GdbStoreWriteTest0010
     * @tc.desc graph store write and update null data
     */
    it('testGraphStoreWrite0010', 0, async () => {
        console.info(TAG + "************* testGraphStoreWrite0010 start *************");
        await store.write("INSERT (:Person {name: 'name_1'});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        let data = await store.read("MATCH (p:Person) where p.age < 50 RETURN p");
        if (data.records) {
            expect(2).assertEqual(data.records.length);
            let temp = data.records[0];
            let vertex = temp["p"];
            expect('2').assertEqual(vertex.vid);
            let proper = vertex.properties;
            expect(22).assertEqual(proper["AGE"]);
        } else {
            console.error(TAG + "write test9 INSERT data failed.");
            expect().assertFail();
        }
        let UPDATE1 = "MATCH (p1:Person {name: 'name_1'}) SET p1.age = 16;"
        let UPDATE2 = "MATCH (p2:Person {name: 'name_2'}) SET p2.age = 16, p2.name = null;"
        try {
            await store.write(UPDATE1);
            await store.write(UPDATE2);
            data = await store.read("MATCH (p:Person) where p.age < 50 RETURN p");
            if (data.records) {
                expect(2).assertEqual(data.records.length);
                let temp = data.records[0];
                let vertex = temp["p"];
                expect('1').assertEqual(vertex.vid);
                let proper = vertex.properties;
                expect('name_1').assertEqual(proper["NAME"]);
                expect(16).assertEqual(proper["AGE"]);

                temp = data.records[1];
                vertex = temp["p"];
                expect('2').assertEqual(vertex.vid);
                proper = vertex.properties;
                // name undefined
                expect(16).assertEqual(proper["AGE"]);
            } else {
                console.error(TAG + "write test10 read data failed.");
                expect().assertFail();
            }
        } catch (e) {
            console.error(TAG + "write test10 update null data failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStoreWrite0010 end *************");
    })

    /**
     * @tc.name graph store write test
     * @tc.number GdbStoreWriteTest0011
     * @tc.desc graph store write create too many graphs
     */
    it('testGraphStoreWrite0011', 0, async () => {
        console.info(TAG + "************* testGraphStoreWrite0011 start *************");
        try {
            await store.write("CREATE GRAPH test1 {(company:Company {rowid INT, name STRING}) };");
            expect().assertFail();
        } catch (e) {
            expect(31300012).assertEqual(e.code);
        }
        console.info(TAG + "************* testGraphStoreWrite0011 end *************");
    })

    /**
     * @tc.name graph store write test
     * @tc.number GdbStoreWriteTest0012
     * @tc.desc graph store write delete the vertexs of a relation
     */
    it('testGraphStoreWrite0012', 0, async () => {
        console.info(TAG + "************* testGraphStoreWrite0012 start *************");
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        await store.write("INSERT (:Person {name: 'name_3', age: 33});");
        await store.write(
            "MATCH (p1:Person {name: 'name_1'}), (p3:Person {name: 'name_3'}) INSERT (p1) -[:Friend]-> (p3);"
        );
        let data = await store.read("MATCH (p:Person) where p.age < 50 RETURN p");
        if (data.records) {
            expect(3).assertEqual(data.records.length);
        } else {
            console.error(TAG + "write test12 INSERT data failed.");
            expect().assertFail();
        }
        let DELETE = "MATCH (p:Person)-[:Friend]->(relatedP:Person) DETACH DELETE p, relatedP;"
        try {
            await store.write(DELETE);
            data = await store.read("MATCH (p:Person) where p.age < 50 RETURN p");
            // read data
            if (data.records) {
                expect(1).assertEqual(data.records.length);
                let temp = data.records[0];
                let vertex = temp["p"];
                expect('2').assertEqual(vertex.vid);
                let proper = vertex.properties;
                expect('name_2').assertEqual(proper["NAME"]);
                expect(22).assertEqual(proper["AGE"]);
            } else {
                console.error(TAG + "write test12 read data failed.");
                expect().assertFail();
            }
        } catch (e) {
            console.error(TAG + "write test12 delete failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStoreWrite0012 end *************");
    })

    /**
     * @tc.name graph store read test
     * @tc.number GdbStoreReadTest0001
     * @tc.desc graph store read query vertex test
     */
    it('testGraphStoreRead0001', 0, async () => {
        console.info(TAG + "************* testGraphStoreRead0001 start *************");
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        await store.write("INSERT (:Person {name: 'name_3', age: 22});");
        try {
            let p = await store.read("MATCH (p:Person {age: 22}) RETURN p;");
            if (p.records) {
                expect(2).assertEqual(p.records.length);
                let temp = p.records[0];
                let vertex = temp["p"];
                expect('2').assertEqual(vertex.vid);
                let proper = vertex.properties;
                expect('name_2').assertEqual(proper["NAME"]);
                expect(22).assertEqual(proper["AGE"]);

                temp = p.records[1];
                vertex = temp["p"];
                expect('3').assertEqual(vertex.vid);
                proper = vertex.properties;
                expect('name_3').assertEqual(proper["NAME"]);
                expect(22).assertEqual(proper["AGE"]);
            } else {
                console.error(TAG + "read test1 query failed.");
                expect().assertFail();
            }
        } catch (e) {
            console.error(TAG + "read test1 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStoreRead0001 end *************");
    })

    /**
     * @tc.name graph store read test
     * @tc.number GdbStoreReadTest0002
     * @tc.desc graph store read query null data test
     */
    it('testGraphStoreRead0002', 0, async () => {
        console.info(TAG + "************* testGraphStoreRead0002 start *************");
        await store.write("INSERT (:Person {age: 11});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        await store.write("INSERT (:Person {name: 'name_3', age: 22});");
        try {
            let p = await store.read("MATCH (p:Person {age: 11}) RETURN p;");
            if (p.records) {
                expect(1).assertEqual(p.records.length);
                let temp = p.records[0];
                let vertex = temp["p"];
                expect('1').assertEqual(vertex.vid);
                let proper = vertex.properties;
                // name undefined
                expect(11).assertEqual(proper["AGE"]);
            } else {
                console.error(TAG + "read test2 query null data failed.");
                expect().assertFail();
            }

            p = await store.read("MATCH (p:Person {age: 22}) RETURN p;");
            if (p.records) {
                expect(2).assertEqual(p.records.length);
                let temp = p.records[0];
                let vertex = temp["p"];
                expect('2').assertEqual(vertex.vid);
                let proper = vertex.properties;
                expect('name_2').assertEqual(proper["NAME"]);
                expect(22).assertEqual(proper["AGE"]);

                temp = p.records[1];
                vertex = temp["p"];
                proper = vertex.properties;
                expect('name_3').assertEqual(proper["NAME"]);
            } else {
                console.error(TAG + "read test2 query null data failed.");
                expect().assertFail();
            }
        } catch (e) {
            console.error(TAG + "read test2 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStoreRead0002 end *************");
    })

    /**
     * @tc.name graph store read test
     * @tc.number GdbStoreReadTest0003
     * @tc.desc graph store read by relation
     */
    it('testGraphStoreRead0003', 0, async () => {
        console.info(TAG + "************* testGraphStoreRead0003 start *************");
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        await store.write("INSERT (:Person {name: 'name_3', age: 22});");
        await store.write(
            "MATCH (p1:Person {name: 'name_1'}), (p2:Person {name: 'name_2'}) INSERT (p1)-[:Friend]->(p2);"
        )
        try {
            let data = await store.read(
                "MATCH (p1:Person {age: 11})-[r:Friend]->(p2:Person {name :'name_2'}) RETURN p1, r, p2;"
            );
            if (data.records) {
                expect(1).assertEqual(data.records.length);
                let temp = data.records[0];
                let vertex = temp["p1"];
                expect('1').assertEqual(vertex.vid);
                let proper = vertex.properties;
                expect('name_1').assertEqual(proper["NAME"]);
                expect(11).assertEqual(proper["AGE"]);

                let edge = temp["r"];
                expect('4').assertEqual(edge.eid);
                expect('1').assertEqual(edge.startVid);
                expect('2').assertEqual(edge.endVid);

                vertex = temp["p2"];
                expect('2').assertEqual(vertex.vid);
                expect('p2'.assertEqual(temp[0]));
                proper = vertex.properties;
                expect(22).assertEqual(proper["AGE"]);
            } else {
                console.error(TAG + "read test3 query relation failed.");
                expect().assertFail();
            }
        } catch (e) {
            console.error(TAG + "read test3 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStoreRead0003 end *************");
    })

    /**
     * @tc.name graph store read test
     * @tc.number GdbStoreReadTest0004
     * @tc.desc graph store read by where statement
     */
    it('testGraphStoreRead0004', 0, async () => {
        console.info(TAG + "************* testGraphStoreRead0004 start *************");
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        await store.write("INSERT (:Person {name: 'name_3', age: 22});");
        try {
            let data = await store.read("MATCH (p:Person) where p.age >= 22 RETURN p;");
            if (data.records) {
                expect(2).assertEqual(data.records.length);
                let temp = data.records[0];
                let vertex = temp["p"];
                expect('2').assertEqual(vertex.vid);
                let proper = vertex.properties;
                expect('name_2').assertEqual(proper["NAME"]);
                expect(22).assertEqual(proper["AGE"]);

                temp = data.records[1];
                vertex = temp["p"];
                expect('3').assertEqual(vertex.vid);
                proper = vertex.properties;
                expect('name_3').assertEqual(proper["NAME"]);
            } else {
                console.error(TAG + "read test4 query by where failed.");
                expect().assertFail();
            }
        } catch (e) {
            console.error(TAG + "read test4 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStoreRead0004 end *************");
    })

    /**
     * @tc.name graph store read test
     * @tc.number GdbStoreReadTest0005
     * @tc.desc graph store read by where statement
     */
    it('testGraphStoreRead0005', 0, async () => {
        console.info(TAG + "************* testGraphStoreRead0005 start *************");
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        await store.write("INSERT (:Person {name: 'name_3', age: 22});");
        try {
            let data = await store.read("MATCH (p:Person) where p.age < 22 RETURN p;");
            if (data.records) {
                expect(1).assertEqual(data.records.length);
                let temp = data.records[0];
                let vertex = temp["p"];
                expect('1').assertEqual(vertex.vid);
                let proper = vertex.properties;
                expect('name_1').assertEqual(proper["NAME"]);
                expect(11).assertEqual(proper["AGE"]);
            } else {
                console.error(TAG + "read test5 query by where failed.");
                expect().assertFail();
            }
        } catch (e) {
            console.error(TAG + "read test5 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStoreRead0005 end *************");
    })

    /**
     * @tc.name graph store read test
     * @tc.number GdbStoreReadTest0006
     * @tc.desc graph store read by where statement
     */
    it('testGraphStoreRead0006', 0, async () => {
        console.info(TAG + "************* testGraphStoreRead0006 start *************");
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        await store.write("INSERT (:Person {name: 'name_3', age: 33});");
        try {
            let data = await store.read("MATCH (p:Person) where p.age <> 22 RETURN p;");
            if (data.records) {
                expect(2).assertEqual(data.records.length);
                let temp = data.records[0];
                let vertex = temp["p"];
                expect('1').assertEqual(vertex.vid);
                let proper = vertex.properties;
                expect('name_1').assertEqual(proper["NAME"]);
                expect(11).assertEqual(proper["AGE"]);

                temp = data.records[1];
                vertex = temp["p"];
                expect('3').assertEqual(vertex.vid);
                proper = vertex.properties;
                expect('name_3').assertEqual(proper["NAME"]);
                expect(33).assertEqual(proper["AGE"]);
            } else {
                console.error(TAG + "read test6 query by where failed.");
                expect().assertFail();
            }
        } catch (e) {
            console.error(TAG + "read test6 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStoreRead0006 end *************");
    })

    /**
     * @tc.name graph store read test
     * @tc.number GdbStoreReadTest0007
     * @tc.desc graph store read by like statement
     */
    it('testGraphStoreRead0007', 0, async () => {
        console.info(TAG + "************* testGraphStoreRead0007 start *************");
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        await store.write("INSERT (:Person {name: 'name_3', age: 33});");
        try {
            let data = await store.read("MATCH (p:Person) where p.name like 'name_%' RETURN p;");
            if (data.records) {
                expect(3).assertEqual(data.records.length);
                let temp = data.records[0];
                let vertex = temp["p"];
                expect('1').assertEqual(vertex.vid);
                let proper = vertex.properties;
                expect('name_1').assertEqual(proper["NAME"]);
                expect(11).assertEqual(proper["AGE"]);

                temp = data.records[1];
                vertex = temp["p"];
                expect('2').assertEqual(vertex.vid);
                proper = vertex.properties;
                expect('name_2').assertEqual(proper["NAME"]);
                expect(22).assertEqual(proper["AGE"]);

                temp = data.records[2];
                vertex = temp["p"];
                expect('3').assertEqual(vertex.vid);
                proper = vertex.properties;
                expect('name_3').assertEqual(proper["NAME"]);
                expect(33).assertEqual(proper["AGE"]);
            } else {
                console.error(TAG + "read test7 query by like failed.");
                expect().assertFail();
            }
        } catch (e) {
            console.error(TAG + "read test7 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStoreRead0007 end *************");
    })

    /**
     * @tc.name graph store read test
     * @tc.number GdbStoreReadTest0008
     * @tc.desc graph store read path
     */
    it('testGraphStoreRead0008', 0, async () => {
        console.info(TAG + "************* testGraphStoreRead0008 start *************");
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        await store.write("INSERT (:Person {name: 'name_3', age: 33});");
        await store.write(
            "MATCH (p1:Person {name: 'name_1'}), (p2:Person {name: 'name_2'}) INSERT (p1) -[:Friend]-> (p2);"
        );
        await store.write(
            "MATCH (p2:Person {name: 'name_2'}), (p3:Person {name: 'name_3'}) INSERT (p2) -[:Friend]-> (p3);"
        );
        try {
            let data = await store.read(
                "MATCH path = (a:Person {name: 'name_1'})-[]->{2,2}(b:Person {name: 'name_3'}) RETURN a, b, path;"
            );
            if (data.records) {
                expect(1).assertEqual(data.records.length);
                let temp = data.records[0];

                let vertex1 = temp["a"];
                expect('1').assertEqual(vertex1.vid);
                let proper = vertex1.properties;
                expect('name_1').assertEqual(proper["NAME"]);
                expect(11).assertEqual(proper["AGE"]);
                
                let vertex2 = temp["b"];
                expect('3').assertEqual(vertex1.vid);
                proper = vertex1.properties;
                expect('name_3').assertEqual(proper["NAME"]);
                expect(33).assertEqual(proper["AGE"]);

                let path = temp["path"];
                expect(2).assertEqual(path.length);
                let segments = path.segments;
                expect(JSON.stringify(vertex1)).assertEqual(JSON.stringify(segments[0].start));
                expect(JSON.stringify(vertex2)).assertEqual(JSON.stringify(segments[1].end));

                let edge = segments[1].edge;
                expect('5').assertEqual(edge.eid);
                expect('2').assertEqual(edge.startVid);
                expect('3').assertEqual(edge.endVid);
            } else {
                console.error(TAG + "read test8 query path failed.");
                expect().assertFail();
            }
        } catch (e) {
            console.error(TAG + "read test8 failed, error:" + JSON.stringify(e));
            expect().assertFail();
        }
        console.info(TAG + "************* testGraphStoreRead0008 end *************");
    })

    /**
     * @tc.name graph store read test
     * @tc.number GdbStoreReadTest0009
     * @tc.desc graph store read with 2 params
     */
    it('testGraphStoreRead0009', 0, async () => {
        console.info(TAG + "************* testGraphStoreRead0009 start *************");
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        await store.write(
            "MATCH (p1:Person {name: 'name_1'}), (p2:Person {name: 'name_2'}) INSERT (p1) -[:Friend]-> (p2);"
        );

        let MATCH1 = "MATCH (p1:Person {name: 'name_1'}) RETURN p1;"
        let MATCH2 = "MATCH (p2:Person {name: 'name_2'}) RETURN p2;"
        try {
            let result = await store.read(MATCH1, MATCH2);
            expect().assertFail();
        } catch (e) {
            expect(401).assertEqual(e.code);
        }
        console.info(TAG + "************* testGraphStoreRead0009 end *************");
    })

    /**
     * @tc.name graph store read test
     * @tc.number GdbStoreReadTest0010
     * @tc.desc graph store close before read
     */
    it('testGraphStoreRead0010', 0, async () => {
        console.info(TAG + "************* testGraphStoreRead0010 start *************");
        let storeConfig = {
            name: "closeStore",
            securityLevel: graphStore.SecurityLevel.S1,
        };
        let closestore = await graphStore.getStore(context, storeConfig);
        await closestore.write(CREATE_GRAPH_TEST);
        await closestore.write("INSERT (:Person {name: 'name_1', age: 11});");
        await closestore.write("INSERT (:Person {name: 'name_2', age: 22});");
        await closestore.write(
            "MATCH (p1:Person {name: 'name_1'}), (p2:Person {name: 'name_2'}) INSERT (p1) -[:Friend]-> (p2);"
        );
        await closestore.close();
        let MATCH = "MATCH (p1:Person {name: 'name_1'}) RETURN p1;"
        try {
            let result = await closestore.read(MATCH);
            expect().assertFail();
        } catch (e) {
            expect('31300002').assertEqual(e.code);
        }
        await graphStore.deleteStore(context, storeConfig);
        console.info(TAG + "************* testGraphStoreRead0010 end *************");
    })

    /**
     * @tc.name graph store read test
     * @tc.number GdbStoreReadTest0011
     * @tc.desc graph store read with undefined type
     */
    it('testGraphStoreRead0011', 0, async () => {
        console.info(TAG + "************* testGraphStoreRead0011 start *************");
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        await store.write(
            "MATCH (p1:Person {name: 'name_1'}), (p2:Person {name: 'name_2'}) INSERT (p1) -[:Friend]-> (p2);"
        );
        let MATCH = "MATCH path = (p1:ZOO {name: 'name_1'})-[]-(p2:Person {name: 'name_2'}) RETURN path;"
        try {
            let result = await store.read(MATCH);
            expect().assertFail();
        } catch (e) {
            expect(31300007).assertEqual(e.code);
        }
        console.info(TAG + "************* testGraphStoreRead0011 end *************");
    })

    /**
     * @tc.name graph store read test
     * @tc.number GdbStoreReadTest0012
     * @tc.desc graph store read with GQL statement syntax error
     */
    it('testGraphStoreRead0012', 0, async () => {
        console.info(TAG + "************* testGraphStoreRead0012 start *************");
        await store.write("INSERT (:Person {name: 'name_1', age: 11});");
        await store.write("INSERT (:Person {name: 'name_2', age: 22});");
        await store.write(
            "MATCH (p1:Person {name: 'name_1'}), (p2:Person {name: 'name_2'}) INSERT (p1) -[:Friend]-> (p2);"
        );
        try {
            let result = await store.read("MATCH (p:Person {name: 'name_1}) RETURN p");
            expect().assertFail();
        } catch (e) {
            expect(31300009).assertEqual(e.code);
        }
        console.info(TAG + "************* testGraphStoreRead0012 end *************");
    })
    console.info(TAG + "*************Unit Test End*************");
})