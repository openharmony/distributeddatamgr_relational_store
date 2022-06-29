/*
* Copyright (c) 2021 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import data_preferences from '@ohos.data.preferences'
import featureAbility from '@ohos.ability.featureAbility';

const NAME = 'test_preferences';
const KEY_TEST_INT_ELEMENT = 'key_test_int';
const KEY_TEST_LONG_ELEMENT = 'key_test_long';
const KEY_TEST_FLOAT_ELEMENT = 'key_test_float';
const KEY_TEST_BOOLEAN_ELEMENT = 'key_test_boolean';
const KEY_TEST_STRING_ELEMENT = 'key_test_string';
const KEY_TEST_NUMBER_ARRAY_ELEMENT = 'key_test_number_array';
const KEY_TEST_STRING_ARRAY_ELEMENT = 'key_test_string_array';
const KEY_TEST_BOOL_ARRAY_ELEMENT = 'key_test_bool_array';
var mPreferences;
var context;

const TAG = '[PREFERENCES_CALLBACK_JSUNIT_TEST]'

describe('preferencesTest', function () {
    beforeAll(async function () {
        console.info('beforeAll')
        context = featureAbility.getContext()
        mPreferences = await data_preferences.getPreferences(context, NAME);
    })

    afterAll(async function () {
        console.info('afterAll')
        await data_preferences.deletePreferences(context, NAME);
    })

    /**
     * @tc.name clear callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0010
     * @tc.desc clear callback interface test
     */
    it('testPreferencesClear0012', 0, async function (done) {
        await mPreferences.put(KEY_TEST_STRING_ELEMENT, "test");
        await mPreferences.flush();
        await mPreferences.clear(async function (err, ret) {
            let pre = await mPreferences.get(KEY_TEST_STRING_ELEMENT, "defaultvalue")
            expect("defaultvalue").assertEqual(pre);
            done();
        });
    })

    /**
     * @tc.name has string callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0020
     * @tc.desc has string callback interface test
     */
    it('testPreferencesHasKey0032', 0, async function (done) {
        await mPreferences.put(KEY_TEST_STRING_ELEMENT, "test");
        await mPreferences.has(KEY_TEST_STRING_ELEMENT, function (err, ret) {
            expect(true).assertEqual(ret);
            done();
        })
    })

    /**
     * @tc.name has int callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0130
     * @tc.desc has int callback interface test
     */
    it('testPreferencesHasKey0033', 0, async function (done) {
        await mPreferences.put(KEY_TEST_INT_ELEMENT, 1);
        await mPreferences.has(KEY_TEST_INT_ELEMENT, function (err, ret) {
            expect(true).assertEqual(ret);
            done();
        })
    })

    /**
     * @tc.name has float callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0140
     * @tc.desc has float callback interface test
     */
    it('testPreferencesHasKey0034', 0, async function (done) {
        await mPreferences.put(KEY_TEST_FLOAT_ELEMENT, 1.1);
        await mPreferences.has(KEY_TEST_FLOAT_ELEMENT, function (err, ret) {
            expect(true).assertEqual(ret);
            done();
        })
    })

    /**
     * @tc.name has long callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0150
     * @tc.desc has long callback interface test
     */
    it('testPreferencesHasKey0035', 0, async function (done) {
        await mPreferences.put(KEY_TEST_LONG_ELEMENT, 0);
        await mPreferences.has(KEY_TEST_LONG_ELEMENT, function (err, ret) {
            expect(true).assertEqual(ret);
            done();
        })
    })

    /**
     * @tc.name has boolean callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0160
     * @tc.desc has boolean callback interface test
     */
    it('testPreferencesHasKey0036', 0, async function (done) {
        await mPreferences.put(KEY_TEST_BOOLEAN_ELEMENT, false);
        await mPreferences.has(KEY_TEST_BOOLEAN_ELEMENT, function (err, ret) {
            expect(true).assertEqual(ret);
            done();
        })
    })

    /**
     * @tc.name get defaultValue callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0030
     * @tc.desc get defaultValue callback interface test
     */
    it('testPreferencesGetDefValue0062', 0, async function (done) {
        await mPreferences.clear();
        await mPreferences.get(KEY_TEST_STRING_ELEMENT, "defaultValue", function (err, ret) {
            expect('defaultValue').assertEqual(ret);
            done();
        })
    })

    /**
     * @tc.name get float callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0040
     * @tc.desc get float callback interface test
     */
    it('testPreferencesGetFloat0072', 0, async function (done) {
        await mPreferences.clear();
        await mPreferences.put(KEY_TEST_FLOAT_ELEMENT, 3.0);
        await mPreferences.get(KEY_TEST_FLOAT_ELEMENT, 0.0, function (err, ret) {
            expect(3.0).assertEqual(ret);
            done();
        })
    })

    /**
     * @tc.name get int callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0050
     * @tc.desc get int callback interface test
     */
    it('testPreferencesGetInt0082', 0, async function (done) {
        await mPreferences.clear();
        await mPreferences.put(KEY_TEST_INT_ELEMENT, 3);
        await mPreferences.get(KEY_TEST_INT_ELEMENT, 0.0, function (err, ret) {
            expect(3).assertEqual(ret);
            done();
        })
    })

    /**
     * @tc.name get long callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0060
     * @tc.desc get long callback interface test
     */
    it('testPreferencesGetLong0092', 0, async function (done) {
        await mPreferences.clear();
        await mPreferences.put(KEY_TEST_LONG_ELEMENT, 3);
        let pref = await mPreferences.get(KEY_TEST_LONG_ELEMENT, 0)
        expect(3).assertEqual(pref);
        await mPreferences.get(KEY_TEST_LONG_ELEMENT, 0, function (err, ret) {
            expect(3).assertEqual(ret);
            done();
        });
    })

    /**
     * @tc.name get String callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0070
     * @tc.desc get String callback interface test
     */
    it('testPreferencesGetString102', 0, async function (done) {
        await mPreferences.clear();
        await mPreferences.put(KEY_TEST_STRING_ELEMENT, "test");
        await mPreferences.flush();
        await mPreferences.get(KEY_TEST_STRING_ELEMENT, "defaultvalue", function (err, ret) {
            expect('test').assertEqual(ret);
            done();
        });
    })

    /**
     * @tc.name put boolean callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0080
     * @tc.desc put boolean callback interface test
     */
    it('testPreferencesPutBoolean0122', 0, async function (done) {
        await mPreferences.clear();
        await mPreferences.put(KEY_TEST_BOOLEAN_ELEMENT, true, async function (err, ret) {
            let pre = await mPreferences.get(KEY_TEST_BOOLEAN_ELEMENT, false);
            expect(true).assertEqual(pre);
            await mPreferences.flush();
            let pre2 = await mPreferences.get(KEY_TEST_BOOLEAN_ELEMENT, false)
            expect(true).assertEqual(pre2);
            done();
        });
    })

    /**
     * @tc.name put float callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0090
     * @tc.desc put float callback interface test
     */
    it('testPreferencesPutFloat0132', 0, async function (done) {
        await mPreferences.clear();
        await mPreferences.put(KEY_TEST_FLOAT_ELEMENT, 4.0, async function (err, ret) {
            let pre = await mPreferences.get(KEY_TEST_FLOAT_ELEMENT, 0.0);
            expect(4.0).assertEqual(pre);
            await mPreferences.flush();
            let pre2 = await mPreferences.get(KEY_TEST_FLOAT_ELEMENT, 0.0);
            expect(4.0).assertEqual(pre2);
            done();
        });
    })

    /**
     * @tc.name put int callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0100
     * @tc.desc put int callback interface test
     */
    it('testPreferencesPutInt0142', 0, async function (done) {
        await mPreferences.clear();
        await mPreferences.put(KEY_TEST_INT_ELEMENT, 4, async function (err, ret) {
            let pre = await mPreferences.get(KEY_TEST_INT_ELEMENT, 0);
            expect(4).assertEqual(pre);
            await mPreferences.flush();
            let pre2 = await mPreferences.get(KEY_TEST_INT_ELEMENT, 0);
            expect(4).assertEqual(pre2);
            done();
        });
    })

    /**
     * @tc.name put long callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0110
     * @tc.desc put long callback interface test
     */
    it('testPreferencesPutLong0152', 0, async function (done) {
        await mPreferences.clear();
        await mPreferences.put(KEY_TEST_LONG_ELEMENT, 4);
        await mPreferences.put(KEY_TEST_LONG_ELEMENT, 4, async function (err, ret) {
            let pre = await mPreferences.get(KEY_TEST_LONG_ELEMENT, 0);
            expect(4).assertEqual(pre);
            await mPreferences.flush();
            let pre2 = await mPreferences.get(KEY_TEST_LONG_ELEMENT, 0);
            expect(4).assertEqual(pre2);
            done();
        });
    })

    /**
     * @tc.name put String callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0120
     * @tc.desc put String callback interface test
     */
    it('testPreferencesPutString0162', 0, async function (done) {
        await mPreferences.clear();
        await mPreferences.put(KEY_TEST_STRING_ELEMENT, '', async function (err, ret) {
            let pre = await mPreferences.get(KEY_TEST_STRING_ELEMENT, "defaultvalue")
            expect('').assertEqual(pre);
            await mPreferences.flush();
            let pre2 = await mPreferences.get(KEY_TEST_STRING_ELEMENT, "defaultvalue")
            expect('').assertEqual(pre2);
            done();
        });
    })

    /**
     * @tc.name clear、put、get、flush String callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0120
     * @tc.desc flush String callback interface test
     */
     it('testPreferencesCallback0172', 0, function (done) {
        console.log(TAG + "testPreferencesCallback0172 begin.");
        mPreferences.clear(function (err, val) {
            if(err){
                expect(null).assertEqual();
            }
            mPreferences.put(KEY_TEST_STRING_ELEMENT, '', function (err, ret) {
                if(err){
                    expect(null).assertEqual();
                }
                mPreferences.get(KEY_TEST_STRING_ELEMENT, "defaultvalue", function (err, pre) {
                    if(err){
                        expect(null).assertEqual();
                    }
                    expect('').assertEqual(pre);
                    mPreferences.flush(function (err, val) {
                        if(err){
                            expect(null).assertEqual();
                        }
                        mPreferences.get(KEY_TEST_STRING_ELEMENT, "defaultvalue", function (err, pre2) {
                            if(err){
                                expect(null).assertEqual();
                            }
                            expect('').assertEqual(pre2);
                            done();
                            console.log(TAG + "testPreferencesCallback0172 end.");
                        })
                    });
                })
            });
        });
    })

    /**
     * @tc.name put StringArray callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0001
     * @tc.desc put String callback interface test
     */
    it('testPreferencesPutStringArray0001', 0, async function (done) {
        await mPreferences.clear();
        var stringArr = ['11', '22', '33']
        await mPreferences.put(KEY_TEST_STRING_ARRAY_ELEMENT, stringArr, async function (err, ret) {
            let pre = await mPreferences.get(KEY_TEST_STRING_ARRAY_ELEMENT, ['123', '321'])
            for (let i = 0; i < stringArr.length; i++) {
                expect(stringArr[i]).assertEqual(pre[i]);
            }

            done();
        });
    })

    /**
     * @tc.name put NumberArray callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0002
     * @tc.desc put String callback interface test
     */
    it('testPreferencesPutNumArray0001', 0, async function (done) {
        await mPreferences.clear();
        var doubleArr = [11, 22, 33]
        await mPreferences.put(KEY_TEST_NUMBER_ARRAY_ELEMENT, doubleArr, async function (err, ret) {
            let pre = await mPreferences.get(KEY_TEST_NUMBER_ARRAY_ELEMENT, [123, 321])
            for (let i = 0; i < doubleArr.length; i++) {
                expect(doubleArr[i]).assertEqual(pre[i]);
            }

            done();
        });
    })

    /**
     * @tc.name put BoolArray callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0003
     * @tc.desc put String callback interface test
     */
    it('testPreferencesPutBoolArray0001', 0, async function (done) {
        await mPreferences.clear();
        let boolArr = [true, false, false, true]
        await mPreferences.put(KEY_TEST_BOOL_ARRAY_ELEMENT, boolArr, async function (err, ret) {
            let pre = await mPreferences.get(KEY_TEST_BOOL_ARRAY_ELEMENT, [true, false])
            for (let i = 0; i < boolArr.length; i++) {
                expect(boolArr[i]).assertEqual(pre[i]);
            }

            done();
        });
    })

    /**
     * @tc.name getAll callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0004
     * @tc.desc getAll callback interface test
     */
    it('testPreferencesGetAll0001', 0, async function (done) {
        await mPreferences.clear();
        let doubleArr = [11, 22, 33]
        let stringArr = ['11', '22', '33']
        let boolArr = [true, false, false, true]
        await mPreferences.put(KEY_TEST_STRING_ARRAY_ELEMENT, stringArr)
        await mPreferences.put(KEY_TEST_BOOL_ARRAY_ELEMENT, boolArr)
        await mPreferences.put(KEY_TEST_NUMBER_ARRAY_ELEMENT, doubleArr)
        await mPreferences.put(KEY_TEST_BOOLEAN_ELEMENT, false)
        await mPreferences.put(KEY_TEST_STRING_ELEMENT, "123")
        await mPreferences.put(KEY_TEST_FLOAT_ELEMENT, 123.1)

        await mPreferences.flush()

        await mPreferences.getAll(function (err, obj) {
            expect(false).assertEqual(obj.key_test_boolean)
            expect("123").assertEqual(obj.key_test_string)
            expect(123.1).assertEqual(obj.key_test_float)
            let sArr = obj.key_test_string_array
            for (let i = 0; i < sArr.length; i++) {
                expect(sArr[i]).assertEqual(stringArr[i]);
            }

            let bArr = obj.key_test_bool_array
            for (let i = 0; i < bArr.length; i++) {
                expect(bArr[i]).assertEqual(boolArr[i]);
            }

            let nArr = obj.key_test_number_array
            for (let i = 0; i < nArr.length; i++) {
                expect(nArr[i]).assertEqual(doubleArr[i]);
            }

            done()
        })
    })
})