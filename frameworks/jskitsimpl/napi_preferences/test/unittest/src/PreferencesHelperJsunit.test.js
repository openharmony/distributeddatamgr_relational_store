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
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import data_preferences from '@ohos.data.preferences'
import featureAbility from '@ohos.ability.FeatureAbility';

const NAME = 'test_preferences';
const KEY_TEST_STRING_ELEMENT = 'key_test_string';
var mPreferences;
var context;
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
     * @tc.name getPreferencesSync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0010
     * @tc.desc getPreferencesSync interface test
     */
    it('testGetPreferencesHelper001', 0, async function () {
        mPreferences = await data_preferences.getPreferences(context, NAME);
        await mPreferences.put('test', 2);
        await mPreferences.flush();
        var value = await mPreferences.get('test', 0);
        expect(value).assertEqual(2);
    })

    /**
     * @tc.name getPreferences interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0020
     * @tc.desc getPreferences interface test
     */
    it('testGetPreferencesHelper002', 0, async function (done) {
        const promise = data_preferences.getPreferences(context, NAME);
        promise.then(async (pref) => {
            await pref.put('test', 2);
            await pref.flush();
            var value = await mPreferences.get('test', 0);
            expect(value).assertEqual(2);
        }).catch((err) => {
            expect(null).assertFail();
        });
        await promise;
        done();
    })

    /**
     * @tc.name removePreferencesFromCache interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0030
     * @tc.desc removePreferencesFromCache interface test
     */
    it('testRemovePreferencesFromCache001', 0, async function (done) {
        let perf = await data_preferences.getPreferences(context, NAME);
        perf = null;
        const promise = data_preferences.removePreferencesFromCache(context, NAME);
        promise.then((pref) => {
        }).catch((err) => {
            expect(null).assertFail();
        });
        await promise;
        done();
    })

    /**
     * @tc.name deletePreferences interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0060
     * @tc.desc deletePreferences interface test
     */
    it('testDeletePreferencesHelper002', 0, async function (done) {
        let perf = await data_preferences.getPreferences(context, NAME);
        perf = null;
        const promise = data_preferences.deletePreferences(context, NAME);
        promise.then((pref) => {
        }).catch((err) => {
            expect(null).assertFail();
        });
        await promise;
        done();
    })

    /**
     * @tc.name put interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_0140
     * @tc.desc put interface test
     */
    it('testPreferencesRegisterObserver001', 0, async function () {
        await mPreferences.clear();
        var observer = function (key) {
            console.info('testPreferencesRegisterObserver001 key' + key);
            expect('abcd').assertEqual(key);
        };
        await mPreferences.on('change', observer);
        await mPreferences.put(KEY_TEST_STRING_ELEMENT, "abcd");
    })

    /**
     * @tc.name repeat on interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_0150
     * @tc.desc repeat on interface test
     */
    it('testPreferencesRegisterObserver002', 0, async function () {
        await mPreferences.clear();
        var observer = function (key) {
            console.info('testPreferencesRegisterObserver002 key' + key);
            expect('abc').assertEqual(key);
        };
        await mPreferences.on('change', observer);
        await mPreferences.on('change', observer);
        await mPreferences.put(KEY_TEST_STRING_ELEMENT, "abc");
    })

    /**
     * @tc.name off interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_0160
     * @tc.desc off interface test
     */
    it('testPreferencesUnRegisterObserver001', 0, async function () {
        var observer = function (key) {
            console.info('testPreferencesUnRegisterObserver001 key' + key);
            expect('').assertEqual(key);
        };
        await mPreferences.on('change', observer);
        await mPreferences.off('change', observer);
        await mPreferences.put(KEY_TEST_STRING_ELEMENT, "abc");
    })
})