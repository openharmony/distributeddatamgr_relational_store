// @ts-nocheck
/*
* Copyright (c) 2022 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an 'AS IS' BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import storage from '@system.storage';

const TAG = '[SYSTEM_STORAGE_JSKITS_TEST]'
describe('systemStorageTest', function () {
    beforeAll(function () {
        console.info(TAG + 'beforeAll')
    })

    afterEach(function () {
        console.info(TAG + 'afterEach')
        storage.clear({
            success: function () {
                console.info(TAG + 'afterEach clear success')
            },
            fail: function (data, errCode) {
                console.info(TAG + 'afterEach clear fail, data = ' + data + ', errCode = ' + errCode)
            }
        })
    })

    /**
     * @tc.name testSet001
     * @tc.number SUB_DDM_AppDataFWK_SystemStorage_Set_0001
     * @tc.desc set and can get correct value in success callback, finally get complete callback
     */
    it('testSet001', 0, async function (done) {
        console.log(TAG + '************* testSet001 start *************');
        let completeRet = false;
        let successRet = false;
        let getValue = undefined;
        await storage.set({
            key: 'storageKey',
            value: 'testValue',
            success() {
                successRet = true;
            },
            complete() {
                completeRet = true;
            }
        });
        await storage.get({
            key: 'storageKey',
            async success(data) {
                getValue = data;
                await expect(getValue).assertEqual('testValue');
            }
        })
        expect(successRet).assertTrue();
        expect(completeRet).assertTrue();
        done();

        console.log(TAG + '************* testSet001 end *************');
    })

    /**
     * @tc.name testSet002
     * @tc.number SUB_DDM_AppDataFWK_SystemStorage_Set_0002
     * @tc.desc set null key can receive fail callback
     */
    it('testSet002', 0, async function (done) {
        console.log(TAG + '************* testSet002 start *************');
        var testData = undefined;
        var testErrCode = undefined;
        await storage.set({
            key: '',
            value: 'testValue',
            success: function () {
                expect(false).assertTrue();
            },
            fail: function (data, errCode) {
                testData = data;
                testErrCode = errCode;
            }
        })
        expect("The key string is null or empty.").assertEqual(testData);
        expect(-1006).assertEqual(testErrCode);

        done();

        console.log(TAG + '************* testSet002 end *************');
    })

    /**
     * @tc.name testSet003
     * @tc.number SUB_DDM_AppDataFWK_SystemStorage_Set_0003
     * @tc.desc set key which size over 32 bytes and can receive fail callback
     */
    it('testSet003', 0, async function (done) {
        console.log(TAG + '************* testSet003 start *************');
        var testData = undefined;
        var testErrCode = undefined;
        await storage.set({
            key: 'x'.repeat(33),
            value: 'testValue',
            success: function () {
                expect(false).assertTrue();
            },
            fail: function (data, errCode) {
                testData = data;
                testErrCode = errCode;
            }
        })
        expect("The key string length should shorter than 32.").assertEqual(testData);
        expect(-1016).assertEqual(testErrCode);

        done();

        console.log(TAG + '************* testSet003 end *************');
    })


    /**
     * @tc.name testSet004
     * @tc.number SUB_DDM_AppDataFWK_SystemStorage_Set_0004
     * @tc.desc set value which size over 128 bytes and can receive fail callback
     */
    it('testSet004', 0, async function (done) {
        console.log(TAG + '************* testSet004 start *************');
        var testData = undefined;
        var testErrCode = undefined;
        await storage.set({
            key: 'testKey',
            value: 'x'.repeat(129),
            success: function () {
                expect(false).assertTrue();
            },
            fail: function (data, errCode) {
                testData = data;
                testErrCode = errCode;
            }
        })
        expect("The value string length should shorter than 128.").assertEqual(testData);
        expect(-1017).assertEqual(testErrCode);

        done();

        console.log(TAG + '************* testSet004 end *************');
    })

    /**
     * @tc.name testGet001
     * @tc.number SUB_DDM_AppDataFWK_SystemStorage_Get_0001
     * @tc.desc set and can get correct value in success callback, finally receive a get complete callback
     */
    it('testGet001', 0, async function (done) {
        console.log(TAG + '************* testGet001 start *************');
        var testVal = undefined;
        var completeRet = false;
        await storage.set({
            key: 'storageKey',
            value: 'storageVal',
        })
        await storage.get({
            key: 'storageKey',
            success: function (data) {
                testVal = data;
            },
            complete: function () {
                completeRet = true;
            }
        })
        expect('storageVal').assertEqual(testVal);
        expect(completeRet).assertTrue();

        done();

        console.log(TAG + '************* testGet001 end *************');
    })

    /*
     * @tc.name testGet002
     * @tc.number SUB_DDM_AppDataFWK_SystemStorage_Get_0002
     * @tc.desc get value without set any value and can get default in success callback
     */
    it('testGet002', 0, async function (done) {
        console.log(TAG + '************* testGet002 start *************');
        var completeRet = false;
        await storage.get({
            key: 'storageKey',
            default: '123',
            success: function (data) {
                expect('123').assertEqual(data);
            },
            complete: function () {
                completeRet = true;
            }
        })
        expect(completeRet).assertTrue();

        done();

        console.log(TAG + '************* testGet002 end *************');
    })


    /*
     * @tc.name testGet003
     * @tc.number SUB_DDM_AppDataFWK_SystemStorage_Get_0003
     * @tc.desc get default size over 128 and can receive fail callback
     */
    it('testGet003', 0, async function (done) {
        console.log(TAG + '************* testGet003 start *************');
        var testVal = undefined;
        var testData = undefined;
        var testErrCode = undefined;
        var completeRet = false;
        var failRet = false;
        await storage.get({
            key: 'storageKey',
            default: 'x'.repeat(129),
            success: function (data) {
                testVal = data;
            },
            fail: function (data, errCode) {
                testErrCode = errCode;
                testData = data;
                failRet = true;
            },
            complete: function () {
                completeRet = true;
            }
        })
        expect(failRet).assertTrue();
        expect(completeRet).assertTrue();
        expect(-1018).assertEqual(testErrCode);
        expect('The default string length should shorter than 128.').assertEqual(testData);
        expect(testVal == undefined).assertTrue();

        done();

        console.log(TAG + '************* testGet003 end *************');
    })

    /*
     * @tc.name testGet004
     * @tc.number SUB_DDM_AppDataFWK_SystemStorage_Get_0004
     * @tc.desc get null key and can return default value
     */
    it('testGet004', 0, async function (done) {
        console.log(TAG + '************* testGet004 start *************');
        var testVal = undefined;
        var completeRet = false;
        await storage.get({
            key: '',
            default: 'storageVal',
            success: function (data) {
                testVal = data;
            },
            fail: function (errCode, data) {
                expect(false).assertTrue();
            },
            complete: function () {
                completeRet = true;
            }
        })
        expect(testVal).assertEqual('storageVal');
        expect(completeRet).assertTrue();

        done();

        console.log(TAG + '************* testGet004 end *************');
    })

    /*
     * @tc.name testDelete001
     * @tc.number SUB_DDM_AppDataFWK_SystemStorage_Delete_0001
     * @tc.desc delete value and can not get value
     */
    it('testDelete001', 0, async function (done) {
        console.log(TAG + '************* testDelete001 start *************');
        var testData = undefined;
        var completeRet = false;
        var successRet = false;
        await storage.set({
            key: 'storageKey',
            value: 'storageVal'
        })
        await storage.delete({
            key: "storageKey",
            success: function () {
                successRet = true;
            },
            complete: function () {
                completeRet = true;
            }
        });
        await storage.get({
            key: 'storageKey',
            default: 'testVal',
            success: function (data) {
                testData = data;
            }
        })
        expect(completeRet).assertTrue();
        expect(successRet).assertTrue();
        expect(testData).assertEqual('testVal');

        done();

        console.log(TAG + '************* testDelete001 end *************');
    })

    /*
     * @tc.name testDelete002
     * @tc.number SUB_DDM_AppDataFWK_SystemStorage_Delete_0002
     * @tc.desc delete null key and can get fail callback
     */
    it('testDelete002', 0, async function (done) {
        console.log(TAG + '************* testDelete002 start *************');
        var testData = undefined;
        var testErrCode = undefined;
        var completeRet = false;
        var failRet = false;
        await storage.set({
            key: 'storageKey',
            value: 'storageVal'
        })
        await storage.delete({
            key: '',
            success: function () {
                expect(false).assertTrue();
            },
            fail: function (data, err) {
                testErrCode = err;
                testData = data;
                failRet = true;
            },
            complete: function () {
                completeRet = true;
            }
        })
        expect(completeRet).assertTrue();
        expect("The key string is null or empty.").assertEqual(testData);
        expect(-1006).assertEqual(testErrCode);
        expect(failRet).assertTrue();

        done();

        console.log(TAG + '************* testDelete002 end *************');
    })

    /*
     * @tc.name testDelete003
     * @tc.number SUB_DDM_AppDataFWK_SystemStorage_Delete_0003
     * @tc.desc delete incorrect key and can get success callback
     */
    it('testDelete003', 0, async function (done) {
        console.log(TAG + '************* testDelete003 start *************');
        var testVal = undefined;
        var completeRet = false;
        storage.set({
            key: 'storageKey',
            value: 'storageVal'
        });
        await storage.delete({
            key: '123',
            success: function () {
            },
            fail: function (err, data) {
                expect(false).assertTrue();
            },
            complete: function () {
                completeRet = true;
            }
        });
        await storage.get({
            key: 'storageKey',
            default: 'testVal',
            success: function (data) {
                testVal = data;
            }
        })
        expect(completeRet).assertTrue();
        expect(testVal).assertEqual('storageVal');

        done();

        console.log(TAG + '************* testDelete003 end *************');
    })

    /*
     * @tc.name testClear001
     * @tc.number SUB_DDM_AppDataFWK_SystemStorage_Clear_0001
     * @tc.desc clear and can receive success callback
     */
    it('testClear001', 0, async function (done) {
        console.log(TAG + '************* testClear001 start *************');
        var successRet = false;
        await storage.set({
            key: 'storageKey1',
            value: 'storageVal1'
        });
        await storage.set({
            key: 'storageKey2',
            value: 'storageVal2'
        });
        await storage.clear({
            success(){
                successRet = true;
            },
            fail(){
                expect(false).assertTrue();
            }
        });
        expect(successRet).assertTrue();

        done();

        console.log(TAG + '************* testClear001 end *************');
    })


})