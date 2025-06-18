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

import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import relationalStore from '@ohos.data.relationalStore';
import ability_featureAbility from '@ohos.ability.featureAbility'


const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const SELECT_VEC =
    "'[0.0034683854319155216,0.03641285002231598,-0.07023966312408447,0.044056713581085205,0.0012323030969128013," +
    "0.0668216347694397,-0.051434680819511414,-0.08662710338830948,-0.05796094238758087,0.0445525236427784," +
    "0.06823701411485672,0.15785539150238037,0.008310764096677303,0.0031550948042422533,0.059119582176208496," +
    "0.16296637058258057,-0.16677643358707428,0.028591593727469444,-0.0774831622838974,0.13105066120624542," +
    "-0.06658935546875,-0.17502543330192566,0.0004895461024716496,-0.039065588265657425,-0.021489106118679047," +
    "0.08095866441726685,0.1294800341129303,0.0903729498386383,0.03329519182443619,0.047984130680561066," +
    "-0.0037370261270552874,-0.038509905338287354,0.0800866112112999,-0.027948979288339615,0.04174582660198212," +
    "0.13182558119297028,-0.059934262186288834,-0.08387927711009979,0.113731250166893,-0.026094511151313782," +
    "-0.1130823865532875,0.039138030260801315,0.007647618185728788,-0.0945548489689827,0.12383178621530533," +
    "0.09071730822324753,-0.023663459345698357,-0.05253434553742409,-0.040944185107946396,0.10114503651857376," +
    "-0.051067765802145004,0.034750234335660934,0.10236344486474991,-0.08334743976593018,-0.05340084061026573," +
    "-0.12497875094413757,-0.004996792413294315,0.025939637795090675,0.056392405182123184,-0.09303992241621017," +
    "0.04230094328522682,-0.033300627022981644,0.06190573796629906,-0.10170590877532959,0.033479053527116776," +
    "0.11075326800346375,0.02244972623884678,-0.14792247116565704,-0.14567142724990845,-0.018098996952176094," +
    "0.05258564278483391,0.0011908907908946276,0.1809721440076828,-0.022740621119737625,0.10480812191963196," +
    "-0.10338152199983597,-0.030866824090480804,0.04990679770708084,-0.005369830410927534,0.025820014998316765," +
    "0.08079411834478378,-0.18422630429267883,0.07818714529275894,0.09904448688030243,0.19703106582164764," +
    "-0.11577515304088593,0.1655191332101822,-0.25517070293426514,0.20069096982479095,0.0844234824180603," +
    "-0.12411679327487946,-0.019857294857501984,0.09271357953548431,-0.0442894883453846,0.059886328876018524," +
    "0.002025386318564415,0.022315988317131996,-0.019258759915828705,-0.03424579277634621,-0.07038101553916931," +
    "-0.02083408646285534,0.11584726721048355,0.04192301630973816,0.12722893059253693,-0.1408625841140747," +
    "-0.02967262640595436,-0.014546873979270458,0.06512382626533508,-0.04907092824578285,-0.05675692856311798," +
    "-0.026348542422056198,0.07538445293903351,0.08171205967664719,-0.06878633797168732,-0.130681112408638," +
    "0.005745945032685995,-0.10949227958917618,0.13608132302761078,0.04036335274577141,-0.09908778220415115," +
    "-0.025767125189304352,-0.05611008033156395,-0.06343607604503632,-0.03752011060714722,0.15635617077350616," +
    "0.0960443913936615,0.03842826932668686,-0.12800946831703186]'";
const vec1 = '[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,' +
    '38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,' +
    '75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,' +
    '109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128]';
const vec2 = '[2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,' +
    '38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,' +
    '75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,' +
    '109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129]';
const vec3 = '[3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,' +
    '38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,' +
    '75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,' +
    '109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130]';
const vec4 = '[4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,' +
    '39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,' +
    '76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,' +
    '109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131]';
const vec5 = '[5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,' +
    '39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,' +
    '75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,' +
    '108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132]';
const vec6 = '[6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,' +
    '40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,' +
    '76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,' +
    '109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133]';
const vec7 = '[7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,' +
    '40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,' +
    '75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,' +
    '107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134]';
const vec8 = '[8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,' +
    '41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,' +
    '77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,' +
    '110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135]';
const vec9 = '[9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,' +
    '42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,' +
    '78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,' +
    '111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136]';
const vec10 = '[10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,' +
    '42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,' +
    '78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,' +
    '110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137]';

const clstVec0 = '[0.12,-0.05,0.23,-0.17,0.08,0.31,-0.02,0.14,-0.11,0.25,0.03,-0.19,0.07,0.29,-0.08,0.16,0.21,-0.03,' +
    '0.09,-0.14,0.27,0.05,-0.22,0.11,0.18,-0.07,0.13,-0.09,0.24,0.01,-0.16,0.04,0.12,-0.05,0.23,-0.17,0.08,0.31,-0.02,' +
    '0.14,-0.11,0.25,0.03,-0.19,0.07,0.29,-0.08,0.16,0.21,-0.03,0.09,-0.14,0.27,0.05,-0.22,0.11,0.18,-0.07,0.13,-0.09,' +
    '0.24,0.01,-0.16,0.04,0.12,-0.05,0.23,-0.17,0.08,0.31,-0.02,0.14,-0.11,0.25,0.03,-0.19,0.07,0.29,-0.08,0.16,0.21,' +
    '-0.03,0.09,-0.14,0.27,0.05,-0.22,0.11,0.18,-0.07,0.13,-0.09,0.24,0.01,-0.16,0.04,0.12,-0.05,0.23,-0.17,0.08,0.31,' +
    '-0.02,0.14,-0.11,0.25,0.03,-0.19,0.07,0.29,-0.08,0.16,0.21,-0.03,0.09,-0.14,0.27,0.05,-0.22,0.11,0.18,-0.07,0.13,' +
    '-0.09,0.24,0.01,-0.16,0.04,0.12,-0.05,0.23,-0.17,0.08,0.31,-0.02,0.14,-0.11,0.25,0.03,-0.19,0.07,0.29,-0.08,0.16,' +
    '0.21,-0.03,0.09,-0.14,0.27,0.05,-0.22,0.11,0.18,-0.07,0.13,-0.09,0.24,0.01,-0.16,0.04,0.12,-0.05,0.23,-0.17,0.08,' +
    '0.31,-0.02,0.14,-0.11,0.25,0.03,-0.19,0.07,0.29,-0.08,0.16,0.21,-0.03,0.09,-0.14,0.27,0.05,-0.22,0.11,0.18,-0.07,' +
    '0.13,-0.09,0.24,0.01,-0.16,0.04,0.12,-0.05,0.23,-0.17,0.08,0.31,-0.02,0.14,-0.11,0.25,0.03,-0.19,0.07,0.29,-0.08,' +
    '0.16,0.21,-0.03,0.09,-0.14,0.27,0.05,-0.22,0.11,0.18,-0.07,0.13,-0.09,0.24,0.01,-0.16,0.04,0.12,-0.05,0.23,-0.17,' +
    '0.08,0.31,-0.02,0.14,-0.11,0.25,0.03,-0.19,0.07,0.29,-0.08,0.16,0.21,-0.03,0.09,-0.14,0.27,0.05,-0.22,0.11,0.18,' +
    '-0.07,0.13,-0.09,0.24,0.01,-0.16,0.04]';
const clstVec1 = '[-0.08,0.15,-0.22,0.07,0.19,-0.03,0.11,-0.14,0.26,0.02,-0.18,0.09,0.13,-0.06,0.21,-0.11,0.04,0.17,' +
    '-0.09,0.23,-0.15,0.08,0.12,-0.07,0.24,0.01,-0.19,0.05,0.16,-0.04,0.14,-0.12,-0.08,0.15,-0.22,0.07,0.19,-0.03,' +
    '0.11,-0.14,0.26,0.02,-0.18,0.09,0.13,-0.06,0.21,-0.11,0.04,0.17,-0.09,0.23,-0.15,0.08,0.12,-0.07,0.24,0.01,-0.19,' +
    '0.05,0.16,-0.04,0.14,-0.12,-0.08,0.15,-0.22,0.07,0.19,-0.03,0.11,-0.14,0.26,0.02,-0.18,0.09,0.13,-0.06,0.21,-0.11,' +
    '0.04,0.17,-0.09,0.23,-0.15,0.08,0.12,-0.07,0.24,0.01,-0.19,0.05,0.16,-0.04,0.14,-0.12,-0.08,0.15,-0.22,0.07,0.19,' +
    '-0.03,0.11,-0.14,0.26,0.02,-0.18,0.09,0.13,-0.06,0.21,-0.11,0.04,0.17,-0.09,0.23,-0.15,0.08,0.12,-0.07,0.24,0.01,' +
    '-0.19,0.05,0.16,-0.04,0.14,-0.12,-0.08,0.15,-0.22,0.07,0.19,-0.03,0.11,-0.14,0.26,0.02,-0.18,0.09,0.13,-0.06,0.21,' +
    '-0.11,0.04,0.17,-0.09,0.23,-0.15,0.08,0.12,-0.07,0.24,0.01,-0.19,0.05,0.16,-0.04,0.14,-0.12,-0.08,0.15,-0.22,0.07,' +
    '0.19,-0.03,0.11,-0.14,0.26,0.02,-0.18,0.09,0.13,-0.06,0.21,-0.11,0.04,0.17,-0.09,0.23,-0.15,0.08,0.12,-0.07,0.24,' +
    '0.01,-0.19,0.05,0.16,-0.04,0.14,-0.12,-0.08,0.15,-0.22,0.07,0.19,-0.03,0.11,-0.14,0.26,0.02,-0.18,0.09,0.13,-0.06,' +
    '0.21,-0.11,0.04,0.17,-0.09,0.23,-0.15,0.08,0.12,-0.07,0.24,0.01,-0.19,0.05,0.16,-0.04,0.14,-0.12,-0.08,0.15,-0.22,' +
    '0.07,0.19,-0.03,0.11,-0.14,0.26,0.02,-0.18,0.09,0.13,-0.06,0.21,-0.11,0.04,0.17,-0.09,0.23,-0.15,0.08,0.12,-0.07,' +
    '0.24,0.01,-0.19,0.05,0.16,-0.04,0.14,-0.12]';
const clstVec2 = '[0.15,-0.12,0.18,-0.09,0.22,0.04,-0.17,0.11,0.07,-0.14,0.23,-0.06,0.19,0.02,-0.21,0.08,0.13,-0.11,' +
    '0.16,-0.07,0.24,0.03,-0.18,0.09,0.12,-0.13,0.17,-0.05,0.25,0.01,-0.19,0.07,0.15,-0.12,0.18,-0.09,0.22,0.04,-0.17,' +
    '0.11,0.07,-0.14,0.23,-0.06,0.19,0.02,-0.21,0.08,0.13,-0.11,0.16,-0.07,0.24,0.03,-0.18,0.09,0.12,-0.13,0.17,-0.05,' +
    '0.25,0.01,-0.19,0.07,0.15,-0.12,0.18,-0.09,0.22,0.04,-0.17,0.11,0.07,-0.14,0.23,-0.06,0.19,0.02,-0.21,0.08,0.13,' +
    '-0.11,0.16,-0.07,0.24,0.03,-0.18,0.09,0.12,-0.13,0.17,-0.05,0.25,0.01,-0.19,0.07,0.15,-0.12,0.18,-0.09,0.22,0.04,' +
    '-0.17,0.11,0.07,-0.14,0.23,-0.06,0.19,0.02,-0.21,0.08,0.13,-0.11,0.16,-0.07,0.24,0.03,-0.18,0.09,0.12,-0.13,0.17,' +
    '-0.05,0.25,0.01,-0.19,0.07,0.15,-0.12,0.18,-0.09,0.22,0.04,-0.17,0.11,0.07,-0.14,0.23,-0.06,0.19,0.02,-0.21,0.08,' +
    '0.13,-0.11,0.16,-0.07,0.24,0.03,-0.18,0.09,0.12,-0.13,0.17,-0.05,0.25,0.01,-0.19,0.07,0.15,-0.12,0.18,-0.09,0.22,' +
    '0.04,-0.17,0.11,0.07,-0.14,0.23,-0.06,0.19,0.02,-0.21,0.08,0.13,-0.11,0.16,-0.07,0.24,0.03,-0.18,0.09,0.12,-0.13,' +
    '0.17,-0.05,0.25,0.01,-0.19,0.07,0.15,-0.12,0.18,-0.09,0.22,0.04,-0.17,0.11,0.07,-0.14,0.23,-0.06,0.19,0.02,-0.21,' +
    '0.08,0.13,-0.11,0.16,-0.07,0.24,0.03,-0.18,0.09,0.12,-0.13,0.17,-0.05,0.25,0.01,-0.19,0.07,0.15,-0.12,0.18,-0.09,' +
    '0.22,0.04,-0.17,0.11,0.07,-0.14,0.23,-0.06,0.19,0.02,-0.21,0.08,0.13,-0.11,0.16,-0.07,0.24,0.03,-0.18,0.09,0.12,' +
    '-0.13,0.17,-0.05,0.25,0.01,-0.19,0.07]';
const clstVec3 = '[-0.21,0.08,0.14,-0.19,0.05,0.17,-0.12,0.23,-0.07,0.11,0.16,-0.14,0.09,0.22,-0.04,0.18,-0.11,0.13,' +
    '0.15,-0.16,0.07,0.24,-0.02,0.19,-0.09,0.12,0.17,-0.13,0.08,0.21,-0.05,0.15,-0.21,0.08,0.14,-0.19,0.05,0.17,-0.12,' +
    '0.23,-0.07,0.11,0.16,-0.14,0.09,0.22,-0.04,0.18,-0.11,0.13,0.15,-0.16,0.07,0.24,-0.02,0.19,-0.09,0.12,0.17,-0.13,' +
    '0.08,0.21,-0.05,0.15,-0.21,0.08,0.14,-0.19,0.05,0.17,-0.12,0.23,-0.07,0.11,0.16,-0.14,0.09,0.22,-0.04,0.18,-0.11,' +
    '0.13,0.15,-0.16,0.07,0.24,-0.02,0.19,-0.09,0.12,0.17,-0.13,0.08,0.21,-0.05,0.15,-0.21,0.08,0.14,-0.19,0.05,0.17,' +
    '-0.12,0.23,-0.07,0.11,0.16,-0.14,0.09,0.22,-0.04,0.18,-0.11,0.13,0.15,-0.16,0.07,0.24,-0.02,0.19,-0.09,0.12,0.17,' +
    '-0.13,0.08,0.21,-0.05,0.15,-0.21,0.08,0.14,-0.19,0.05,0.17,-0.12,0.23,-0.07,0.11,0.16,-0.14,0.09,0.22,-0.04,0.18,' +
    '-0.11,0.13,0.15,-0.16,0.07,0.24,-0.02,0.19,-0.09,0.12,0.17,-0.13,0.08,0.21,-0.05,0.15,-0.21,0.08,0.14,-0.19,0.05,' +
    '0.17,-0.12,0.23,-0.07,0.11,0.16,-0.14,0.09,0.22,-0.04,0.18,-0.11,0.13,0.15,-0.16,0.07,0.24,-0.02,0.19,-0.09,0.12,' +
    '0.17,-0.13,0.08,0.21,-0.05,0.15,-0.21,0.08,0.14,-0.19,0.05,0.17,-0.12,0.23,-0.07,0.11,0.16,-0.14,0.09,0.22,-0.04,' +
    '0.18,-0.11,0.13,0.15,-0.16,0.07,0.24,-0.02,0.19,-0.09,0.12,0.17,-0.13,0.08,0.21,-0.05,0.15,-0.21,0.08,0.14,-0.19,' +
    '0.05,0.17,-0.12,0.23,-0.07,0.11,0.16,-0.14,0.09,0.22,-0.04,0.18,-0.11,0.13,0.15,-0.16,0.07,0.24,-0.02,0.19,-0.09,' +
    '0.12,0.17,-0.13,0.08,0.21,-0.05,0.15]';
const clstVec4 = '[0.07,-0.18,0.12,0.15,-0.09,0.21,-0.14,0.06,0.17,-0.11,0.19,-0.07,0.13,0.16,-0.12,0.08,0.22,' +
    '-0.05,0.14,-0.17,0.09,0.18,-0.13,0.11,0.15,-0.08,0.2,-0.04,0.16,-0.14,0.1,0.19,0.07,-0.18,0.12,0.15,-0.09,' +
    '0.21,-0.14,0.06,0.17,-0.11,0.19,-0.07,0.13,0.16,-0.12,0.08,0.22,-0.05,0.14,-0.17,0.09,0.18,-0.13,0.11,0.15,' +
    '-0.08,0.2,-0.04,0.16,-0.14,0.1,0.19,0.07,-0.18,0.12,0.15,-0.09,0.21,-0.14,0.06,0.17,-0.11,0.19,-0.07,0.13,' +
    '0.16,-0.12,0.08,0.22,-0.05,0.14,-0.17,0.09,0.18,-0.13,0.11,0.15,-0.08,0.2,-0.04,0.16,-0.14,0.1,0.19,0.07,' +
    '-0.18,0.12,0.15,-0.09,0.21,-0.14,0.06,0.17,-0.11,0.19,-0.07,0.13,0.16,-0.12,0.08,0.22,-0.05,0.14,-0.17,0.09,' +
    '0.18,-0.13,0.11,0.15,-0.08,0.2,-0.04,0.16,-0.14,0.1,0.19,0.07,-0.18,0.12,0.15,-0.09,0.21,-0.14,0.06,0.17,' +
    '-0.11,0.19,-0.07,0.13,0.16,-0.12,0.08,0.22,-0.05,0.14,-0.17,0.09,0.18,-0.13,0.11,0.15,-0.08,0.2,-0.04,0.16,' +
    '-0.14,0.1,0.19,0.07,-0.18,0.12,0.15,-0.09,0.21,-0.14,0.06,0.17,-0.11,0.19,-0.07,0.13,0.16,-0.12,0.08,0.22,' +
    '-0.05,0.14,-0.17,0.09,0.18,-0.13,0.11,0.15,-0.08,0.2,-0.04,0.16,-0.14,0.1,0.19,0.07,-0.18,0.12,0.15,-0.09,' +
    '0.21,-0.14,0.06,0.17,-0.11,0.19,-0.07,0.13,0.16,-0.12,0.08,0.22,-0.05,0.14,-0.17,0.09,0.18,-0.13,0.11,0.15,' +
    '-0.08,0.2,-0.04,0.16,-0.14,0.1,0.19,0.07,-0.18,0.12,0.15,-0.09,0.21,-0.14,0.06,0.17,-0.11,0.19,-0.07,0.13,' +
    '0.16,-0.12,0.08,0.22,-0.05,0.14,-0.17,0.09,0.18,-0.13,0.11,0.15,-0.08,0.2,-0.04,0.16,-0.14,0.1,0.19]';

let isSupportVector = false;
let store;
let context = ability_featureAbility.getContext()
const STORE_CONFIG = {
    name: "vector_database_test.db",
    securityLevel: relationalStore.SecurityLevel.S1,
    vector: true,
};
describe('rdbStoreRdExecuteTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        isSupportVector = relationalStore.isVectorSupported();
        console.info(TAG + 'isSupportVector: ' + isSupportVector);
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
        if (!isSupportVector) {
            console.error(TAG + 'not support vector.');
            return;
        }
        try {
            store?.close();
            await relationalStore.deleteRdbStore(context, STORE_CONFIG);
            store = await relationalStore.getRdbStore(context, STORE_CONFIG)
            await store?.execute("CREATE TABLE IF NOT EXISTS title_vector_20" +
                "(docId text primary key, dir text, fileExt text, appSource text, " +
                "createdDate bigint, isDeleted bool);");
            await store?.execute("CREATE TABLE IF NOT EXISTS content_vector_20" +
                "(uid bigint primary key, docId text, chunkId int, contentRepr floatvector(128) NOT COPY);");
            await store?.execute("CREATE INDEX idx ON content_vector_20 USING GSDISKANN(contentRepr COSINE) " +
                "WITH (out_degree=46,enable_lvq=true,lvq_quant_bit=8,reserve_dist=false,accelerate_prune=true);");
            await store?.execute(
                "INSERT INTO title_vector_20 VALUES ('1', 'opt/test/app00/', 'pptx', 'app00', 1685421482, true);");
            await store?.execute(
                "INSERT INTO title_vector_20 VALUES ('2', 'opt/test/app11/', 'pptx', 'app11', 1685421483, true);");
            await store?.execute(
                "INSERT INTO title_vector_20 VALUES ('3', 'opt/test/app22/', 'pptx', 'app22', 1685421484, true);");
            await store?.execute(
                "INSERT INTO title_vector_20 VALUES ('4', 'opt/test/app33/', 'docx', 'app33', 1685421485, true);");
            await store?.execute(
                "INSERT INTO title_vector_20 VALUES ('5', 'opt/test/app44/', 'docx', 'app44', 1685421486, true);");
            await store?.execute(
                "INSERT INTO title_vector_20 VALUES ('6', 'opt/test/app55/', 'json', 'app55', 1685421487, true);");
            await store?.execute(
                "INSERT INTO title_vector_20 VALUES ('7', 'opt/test/app66/', 'json', 'app66', 1685421488, true);");
            await store?.execute(
                "INSERT INTO title_vector_20 VALUES ('8', 'opt/test/app77/', 'json', 'app77', 1685421489, true);");
            await store?.execute(
                "INSERT INTO title_vector_20 VALUES ('9', 'opt/test/app88/', 'json', 'app88', 1685421489, true);");
            await store?.execute(
                "INSERT INTO title_vector_20 VALUES ('10', 'opt/test/app99/', 'json', 'app99', 1685421499, true);");
            await store?.execute(`INSERT INTO content_vector_20 VALUES (1, '1', 1, '${vec1}');`);
            await store?.execute(`INSERT INTO content_vector_20 VALUES (2, '2', 2, '${vec2}');`);
            await store?.execute(`INSERT INTO content_vector_20 VALUES (3, '3', 3, '${vec3}');`);
            await store?.execute(`INSERT INTO content_vector_20 VALUES (4, '4', 4, '${vec4}');`);
            await store?.execute(`INSERT INTO content_vector_20 VALUES (5, '5', 5, '${vec5}');`);
            await store?.execute(`INSERT INTO content_vector_20 VALUES (6, '6', 6, '${vec6}');`);
            await store?.execute(`INSERT INTO content_vector_20 VALUES (7, '7', 7, '${vec7}');`);
            await store?.execute(`INSERT INTO content_vector_20 VALUES (8, '8', 8, '${vec8}');`);
            await store?.execute(`INSERT INTO content_vector_20 VALUES (9, '9', 9, '${vec9}');`);
            await store?.execute(`INSERT INTO content_vector_20 VALUES (10, '10', 10, '${vec10}');`);
        } catch (e) {
            console.error(TAG + `beforeEach init data failed. errcode: ${e.code}`);
        }
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        try {
            await store?.close();
            store = null;
            await relationalStore.deleteRdbStore(context, STORE_CONFIG);
        } catch (e) {
            console.error(TAG + `clear data failed. errcode: ${e.code}`);
        }
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name testVectorSubSelectSuccess0001
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_SubSelect_success_0001
     * @tc.desc sub select in select where success
     */
    it('testVectorSubSelectSuccess0001', 0, async function () {
        console.log(TAG + "************* testVectorSubSelectSuccess0001 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }
        try {
            const selectSql = `SELECT docId, chunkId, contentRepr, contentRepr <=> ${SELECT_VEC} as vc
                               FROM content_vector_20
                               WHERE contentRepr <=> ${SELECT_VEC}
                                   < 1
                                 AND docId IN (
                                   SELECT docId from title_vector_20 WHERE (createdDate
                                   > 1685421481
                                 and createdDate
                                   < 1685507881)
                                 AND (dir = 'opt/test/app00/'
                                  or dir = 'opt/test/app22/'
                                  or dir = 'opt/test/app44/')
                                 AND isDeleted = true
                                   )
                               ORDER BY contentRepr <=> ${SELECT_VEC} LIMIT 20;`;
            const result = await store?.querySql(selectSql);
            expect(result?.rowCount).assertEqual(3);
            result?.close();
        } catch (e) {
            console.error(TAG + `testVectorSubSelectSuccess0001 failed. err: ${JSON.stringify(e)}`);
            expect().assertFail();
        }
        console.log(TAG + "************* testVectorSubSelectSuccess0001 end   *************");
    });

    /**
     * @tc.name testVectorSubSelectFailed0001
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_SubSelect_failed_0001
     * @tc.desc sub select in select where failed, syntax error
     */
    it('testVectorSubSelectFailed0001', 0, async function () {
        console.log(TAG + "************* testVectorSubSelectFailed0001 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }
        try {
            const selectSql = `SELECT docId, chunkId, contentRepr, contentRepr <=> ${SELECT_VEC} as vc
                               FROM content_vector_20
                               WHERE contentRepr <=> ${SELECT_VEC}
                                   < 1
                                 AND docId IN (
                                   SELECT docId from title_vector_201 WHERE (createdDate
                                   > 1685421481
                                 and createdDate
                                   < 1685507881)
                                 AND (dir = 'opt/test/app00/'
                                  or dir = 'opt/test/app22/'
                                  or dir = 'opt/test/app44/')
                                 AND isDeleted = true
                                   )
                               ORDER BY contentRepr <=> ${SELECT_VEC} LIMIT 20;`;
            const result = await store?.querySql(selectSql);
            expect(result?.rowCount).assertEqual(-1);
            expect(result?.goToNextRow()).assertFalse();
            result?.close();
        } catch (e) {
            console.error(TAG + `testVectorSubSelectFailed0001 failed. err: ${JSON.stringify(e)}`);
            expect().assertFail();
        }
        console.log(TAG + "************* testVectorSubSelectFailed0001 end   *************");
    });

    /**
     * @tc.name testVectorSubSelectFailed0002
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_SubSelect_failed_0002
     * @tc.desc sub select in select where failed, result empty
     */
    it('testVectorSubSelectFailed0002', 0, async function () {
        console.log(TAG + "************* testVectorSubSelectFailed0002 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }
        try {
            const selectSql = `SELECT docId, chunkId, contentRepr, contentRepr <=> ${SELECT_VEC} as vc
                               FROM content_vector_20
                               WHERE contentRepr <=> ${SELECT_VEC}
                                   < 1
                                 AND docId IN (
                                   SELECT docId from title_vector_20 WHERE (createdDate
                                   > 1685421481
                                 and createdDate
                                   < 1685507881)
                                 AND (dir = 'opt/test/app00/1'
                                  or dir = 'opt/test/app22/1'
                                  or dir = 'opt/test/app44/1')
                                 AND isDeleted = true
                                   )
                               ORDER BY contentRepr <=> ${SELECT_VEC} LIMIT 20;`;
            const result = await store?.querySql(selectSql);
            expect(result?.rowCount).assertEqual(0);
            expect(result?.goToNextRow()).assertFalse();
            result?.close();
        } catch (e) {
            console.error(TAG + `testVectorSubSelectFailed0002 failed. err: ${JSON.stringify(e)}`);
            expect().assertFail();
        }
        console.log(TAG + "************* testVectorSubSelectFailed0002 end   *************");
    });

    /**
     * @tc.name testVectorSubSelectSuccess0002
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_SubSelect_success_0002
     * @tc.desc sub select in select from success
     */
    it('testVectorSubSelectSuccess0002', 0, async function () {
        console.log(TAG + "************* testVectorSubSelectSuccess0002 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }
        try {
            const selectSql = `select *
                               from (SELECT docId
                                     from title_vector_20
                                     WHERE (createdDate > 1685421481 and createdDate < 1685507881)
                                       AND (dir = 'opt/test/app00/' or dir = 'opt/test/app22/' or
                                            dir = 'opt/test/app44/')
                                       AND isDeleted = true) as docId;`;
            const result = await store?.querySql(selectSql);
            expect(result?.rowCount).assertEqual(3);
            result?.close();
        } catch (e) {
            console.error(TAG + `testVectorSubSelectSuccess0002 failed. err: ${JSON.stringify(e)}`);
            expect().assertFail();
        }
        console.log(TAG + "************* testVectorSubSelectSuccess0002 end   *************");
    });

    /**
     * @tc.name testVectorSubSelectSuccess0003
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_SubSelect_success_0003
     * @tc.desc sub select in select target success
     */
    it('testVectorSubSelectSuccess0003', 0, async function () {
        console.log(TAG + "************* testVectorSubSelectSuccess0003 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }
        try {
            const selectSql = `select (SELECT contentRepr <=> ${SELECT_VEC} as vc
                               FROM content_vector_20
                               WHERE contentRepr <=> ${SELECT_VEC} < 1) as myVc
                               from title_vector_20`;
            const result = await store?.querySql(selectSql);
            expect(result?.rowCount).assertEqual(10);
            result?.close();
        } catch (e) {
            console.error(TAG + `testVectorSubSelectSuccess0004 failed. err: ${JSON.stringify(e)}`);
            expect().assertFail();
        }
        console.log(TAG + "************* testVectorSubSelectSuccess0003 end   *************");
    });

    /**
     * @tc.name testVectorSubSelectSuccess0004
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_SubSelect_success_0004
     * @tc.desc sub select in insert success
     */
    it('testVectorSubSelectSuccess0004', 0, async function () {
        console.log(TAG + "************* testVectorSubSelectSuccess0004 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }
        try {
            const createTable2 = `CREATE TABLE IF NOT EXISTS title_vector_21
                                  (
                                      docId text primary key,
                                      dir text,
                                      fileExt text,
                                      appSource text,
                                      createdDate bigint,
                                      isDeleted bool
                                  );`;
            await store?.execute(createTable2);

            const insert = `insert into title_vector_21 select * from title_vector_20;`;
            await store?.execute(insert);

            const result = await store?.querySql(`select * from title_vector_21`);
            expect(result?.rowCount).assertEqual(10);
            result?.close();
        } catch (e) {
            console.error(TAG + `testVectorSubSelectSuccess0004 failed. err: ${JSON.stringify(e)}`);
            expect().assertFail();
        }
        console.log(TAG + "************* testVectorSubSelectSuccess0004 end   *************");
    });

    /**
     * @tc.name testVectorSubSelectFailed0003
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_SubSelect_failed_0003
     * @tc.desc sub select in insert failed, sub select empty
     */
    it('testVectorSubSelectFailed0003', 0, async function () {
        console.log(TAG + "************* testVectorSubSelectFailed0003 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }
        const createTable2 = `CREATE TABLE IF NOT EXISTS title_vector_21
                              (
                                  docId text primary key,
                                  dir text,
                                  fileExt text,
                                  appSource text,
                                  createdDate bigint,
                                  isDeleted bool
                              );`;
        await store?.execute(createTable2);
        try {
            const insert = `insert into title_vector_20 select * from title_vector_21;`;
            await store?.execute(insert);

            const result = await store?.querySql(`select * from title_vector_20`);
            expect(result?.rowCount).assertEqual(10);
            result?.close();
        } catch (e) {
            console.error(TAG + `testVectorSubSelectFailed0003 failed. err: ${JSON.stringify(e)}`);
            expect().assertFail();
        }
        console.log(TAG + "************* testVectorSubSelectFailed0003 end   *************");
    });

    /**
     * @tc.name testVectorSubSelectFailed0004
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_SubSelect_failed_0004
     * @tc.desc sub select in insert failed, syntax error
     */
    it('testVectorSubSelectFailed0004', 0, async function () {
        console.log(TAG + "************* testVectorSubSelectFailed0004 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }
        const createTable2 = `CREATE TABLE IF NOT EXISTS title_vector_21
                              (
                                  docId text primary key,
                                  dir text,
                                  fileExt text,
                                  appSource text,
                                  createdDate bigint,
                                  isDeleted bool
                              );`;
        await store?.execute(createTable2);
        try {
            const insert = `insert into title_vector_21 select * from title_vector_22;`;
            await store?.execute(insert);
        } catch (e) {
            console.error(TAG + `testVectorSubSelectFailed0004 failed. err: ${JSON.stringify(e)}`);
            expect(e.code).assertEqual(14800021);
        }
        console.log(TAG + "************* testVectorSubSelectFailed0004 end   *************");
    });

    /**
     * @tc.name testVectorSubSelectSuccess0005
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_SubSelect_success_0005
     * @tc.desc sub select in delete success
     */
    it('testVectorSubSelectSuccess0005', 0, async function () {
        console.log(TAG + "************* testVectorSubSelectSuccess0005 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }
        try {
            const deleteSql = `delete
                               from content_vector_20
                               where docId IN (SELECT docId
                                               from title_vector_20
                                               WHERE (createdDate > 1685421481 and createdDate < 1685507881)
                                                 AND (dir = 'opt/test/app00/' or dir = 'opt/test/app22/' or
                                                      dir = 'opt/test/app44/')
                                                 AND isDeleted = true);`;
            await store?.execute(deleteSql);

            const result = await store?.querySql(`select * from content_vector_20`);
            expect(result?.rowCount).assertEqual(7);
            result?.close();
        } catch (e) {
            console.error(TAG + `testVectorSubSelectSuccess0005 failed. err: ${JSON.stringify(e)}`);
            expect().assertFail();
        }
        console.log(TAG + "************* testVectorSubSelectSuccess0005 end   *************");
    });

    /**
     * @tc.name testVectorSubSelectFailed0005
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_SubSelect_failed_0005
     * @tc.desc sub select in delete failed, syntax error
     */
    it('testVectorSubSelectFailed0005', 0, async function () {
        console.log(TAG + "************* testVectorSubSelectSuccess0005 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }
        try {
            const deleteSql = `delete
                               from content_vector_20
                               where docId IN (SELECT docIds
                                               from title_vector_20
                                               WHERE (createdDate > 1685421481 and createdDate < 1685507881)
                                                 AND (dir = 'opt/test/app00/' or dir = 'opt/test/app22/' or
                                                      dir = 'opt/test/app44/')
                                                 AND isDeleted = true);`;
            await store?.execute(deleteSql);
        } catch (e) {
            console.error(TAG + `testVectorSubSelectFailed0005 failed. err: ${JSON.stringify(e)}`);
            expect(e.code).assertEqual(14800021);
        }
        console.log(TAG + "************* testVectorSubSelectFailed0005 end   *************");
    });

    /**
     * @tc.name testVectorSubSelectFailed0006
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_SubSelect_failed_0006
     * @tc.desc sub select in delete failed, sub select empty
     */
    it('testVectorSubSelectFailed0006', 0, async function () {
        console.log(TAG + "************* testVectorSubSelectFailed0006 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }
        try {
            const deleteSql = `delete
                               from content_vector_20
                               where docId IN (SELECT docId
                                               from title_vector_20
                                               WHERE (createdDate > 1685421481 and createdDate < 1685507881)
                                                 AND (dir = 'opt/test/app00/111' or dir = 'opt/test/app22/111' or
                                                      dir = 'opt/test/app44/111')
                                                 AND isDeleted = true);`;
            await store?.execute(deleteSql);

            const result = await store?.querySql(`select * from content_vector_20`);
            expect(result?.rowCount).assertEqual(10);
            result?.close();
        } catch (e) {
            console.error(TAG + `testVectorSubSelectFailed0006 failed. err: ${JSON.stringify(e)}`);
            expect().assertFail();
        }
        console.log(TAG + "************* testVectorSubSelectFailed0006 end   *************");
    });

    /**
     * @tc.name testVectorSubSelectSuccess0006
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_SubSelect_success_0006
     * @tc.desc sub select in update where success
     */
    it('testVectorSubSelectSuccess0006', 0, async function () {
        console.log(TAG + "************* testVectorSubSelectSuccess0006 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }
        const where = `WHERE contentRepr <=> ${SELECT_VEC} < 1 AND docId IN (
          SELECT docId from title_vector_20 WHERE (createdDate > 1685421481 and createdDate < 1685507881)
          AND (dir = 'opt/test/app00/' or dir = 'opt/test/app22/' or dir = 'opt/test/app44/')
          AND isDeleted = true
        );`;
        const selectSql = `select docId, chunkId from content_vector_20 ${where}`;

        try {
            const result = await store?.querySql(selectSql);
            while (result?.goToNextRow()) {
                let value1 = result?.getValue(0);
                let value2 = result?.getValue(1);
                console.log(TAG + "before docId: " + value1?.toString() + ", chunkId: " + value2?.toString());
            }
            expect(result?.rowCount).assertEqual(3);
            result?.close();
            const expectChunkId = 111;
            const updateSql = `update content_vector_20 set chunkId = ${expectChunkId} ${where}`;
            await store?.execute(updateSql);

            const result2 = await store?.querySql(selectSql);
            while (result2?.goToNextRow()) {
                let value1 = result2?.getValue(0);
                let value2 = result2?.getValue(1);
                expect(expectChunkId == value2).assertTrue();
                console.log(TAG + "after docId: " + value1?.toString() + ", chunkId: " + value2?.toString());
            }
            expect(result2?.rowCount).assertEqual(3);
            result2?.close();
        } catch (e) {
            console.error(TAG + `testVectorSubSelectSuccess0006 failed. err: ${JSON.stringify(e)}`);
            expect().assertFail();
        }
        console.log(TAG + "************* testVectorSubSelectSuccess0006 end   *************");
    });

    /**
     * @tc.name testVectorSubSelectFailed0007
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_SubSelect_failed_0007
     * @tc.desc sub select in update where, sub select empty
     */
    it('testVectorSubSelectFailed0007', 0, async function () {
        console.log(TAG + "************* testVectorSubSelectFailed0007 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }
        const selectSql = `select chunkId
                           from content_vector_20
                           WHERE contentRepr <=> ${SELECT_VEC}
                               < 1
                             AND docId IN (
                               SELECT docId from title_vector_20 WHERE (createdDate
                               > 1685421481
                             and createdDate
                               < 1685507881)
                             AND (dir = 'opt/test/app00/'
                              or dir = 'opt/test/app22/'
                              or dir = 'opt/test/app44/')
                             AND isDeleted = true
                               );`;

        try {
            const result = await store?.querySql(selectSql);
            while (result?.goToNextRow()) {
                let value = result?.getValue(0);
                console.log(TAG + "value: " + value?.toString());
            }
            expect(result?.rowCount).assertEqual(3);
            result?.close();

            const updateSql = `update content_vector_20
                               set chunkId = 111
                               WHERE contentRepr <=> ${SELECT_VEC}
                                   < 1
                                 AND docId IN (
                                   SELECT docId from title_vector_20 WHERE (createdDate
                                   > 1685421481
                                 and createdDate
                                   < 1685507881)
                                 AND (dir = 'opt/test/app00/111'
                                  or dir = 'opt/test/app22/111'
                                  or dir = 'opt/test/app44/111')
                                 AND isDeleted = true
                                   );`;
            await store?.execute(updateSql);

            const result2 = await store?.querySql(selectSql);
            while (result2?.goToNextRow()) {
                let value = result2?.getValue(0);
                console.log(TAG + "value: " + value?.toString());
            }
            expect(result2?.rowCount).assertEqual(3);
            result2?.close();
        } catch (e) {
            console.error(TAG + `testVectorSubSelectFailed0007 failed. err: ${JSON.stringify(e)}`);
            expect().assertFail();
        }
        console.log(TAG + "************* testVectorSubSelectFailed0007 end   *************");
    });

    /**
     * @tc.name testVectorSubSelectSuccess0007
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_SubSelect_success_0007
     * @tc.desc sub select in update set success
     */
    it('testVectorSubSelectSuccess0007', 0, async function () {
        console.log(TAG + "************* testVectorSubSelectSuccess0007 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }
        const selectSql = `select chunkId
                           from content_vector_20
                           WHERE contentRepr <=> ${SELECT_VEC}
                               < 1
                             AND docId IN (
                               SELECT docId from title_vector_20 WHERE (createdDate
                               > 1685421481
                             and createdDate
                               < 1685507881)
                             AND (dir = 'opt/test/app00/'
                              or dir = 'opt/test/app22/'
                              or dir = 'opt/test/app44/')
                             AND isDeleted = true
                               );`;

        try {
            const result = await store?.querySql(selectSql);
            while (result?.goToNextRow()) {
                let value = result?.getValue(0);
                console.log(TAG + "value: " + value?.toString());
            }
            expect(result?.rowCount).assertEqual(3);
            result?.close();

            const updateSql = `update content_vector_20
                               set chunkId = (select sum(chunkId) from content_vector_20)
                               WHERE contentRepr <=> ${SELECT_VEC}
                                   < 1
                                 AND docId IN (
                                   SELECT docId from title_vector_20 WHERE (createdDate
                                   > 1685421481
                                 and createdDate
                                   < 1685507881)
                                 AND (dir = 'opt/test/app00/'
                                  or dir = 'opt/test/app22/'
                                  or dir = 'opt/test/app44/')
                                 AND isDeleted = true
                                   );`;
            await store?.execute(updateSql);

            const result2 = await store?.querySql(selectSql);
            const expectChunkId = 55;
            while (result2?.goToNextRow()) {
                let value = result2?.getValue(0);
                expect(expectChunkId == value).assertTrue();
                console.log(TAG + "value: " + value?.toString());
            }
            expect(result2?.rowCount).assertEqual(3);
            result2?.close();
        } catch (e) {
            console.error(TAG + `testVectorSubSelectSuccess0007 failed. err: ${JSON.stringify(e)}`);
            expect().assertFail();
        }
        console.log(TAG + "************* testVectorSubSelectSuccess0007 end   *************");
    });

    /**
     * @tc.name testVectorSubSelectFailed0008
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_SubSelect_failed_0008
     * @tc.desc sub select in update set, sub select empty
     */
    it('testVectorSubSelectFailed0008', 0, async function () {
        console.log(TAG + "************* testVectorSubSelectFailed0008 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }
        const selectSql = `select chunkId
                           from content_vector_20
                           WHERE contentRepr <=> ${SELECT_VEC}
                               < 1
                             AND docId IN (
                               SELECT docId from title_vector_20 WHERE (createdDate
                               > 1685421481
                             and createdDate
                               < 1685507881)
                             AND (dir = 'opt/test/app00/'
                              or dir = 'opt/test/app22/'
                              or dir = 'opt/test/app44/')
                             AND isDeleted = true
                               );`;

        try {
            const result = await store?.querySql(selectSql);
            while (result?.goToNextRow()) {
                let value = result?.getValue(0);
                console.log(TAG + "value: " + value?.toString());
            }
            expect(result?.rowCount).assertEqual(3);
            result?.close();

            const updateSql = `update content_vector_20
                               set chunkId = (select sum(chunkId) from content_vector_20 where chunkId = 111)
                               WHERE contentRepr <=> ${SELECT_VEC}
                                   < 1
                                 AND docId IN (
                                   SELECT docId from title_vector_20 WHERE (createdDate
                                   > 1685421481
                                 and createdDate
                                   < 1685507881)
                                 AND (dir = 'opt/test/app00/'
                                  or dir = 'opt/test/app22/'
                                  or dir = 'opt/test/app44/')
                                 AND isDeleted = true
                                   );`;
            await store?.execute(updateSql);

            const result2 = await store?.querySql(selectSql);
            while (result2?.goToNextRow()) {
                let value = result2?.getValue(0);
                console.log(TAG + "value: " + value?.toString());
            }
            expect(result2?.rowCount).assertEqual(3);
            result2?.close();
        } catch (e) {
            console.error(TAG + `testVectorSubSelectFailed0008 failed. err: ${JSON.stringify(e)}`);
            expect().assertFail();
        }
        console.log(TAG + "************* testVectorSubSelectFailed0008 end   *************");
    });

    /**
     * @tc.name testVectorSubSelectFailed0009
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_SubSelect_failed_0009
     * @tc.desc sub select in update set, sub select result out of range.
     */
    it('testVectorSubSelectFailed0009', 0, async function () {
        console.log(TAG + "************* testVectorSubSelectFailed0009 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }
        const selectSql = `select chunkId from content_vector_20
        WHERE contentRepr <=> ${SELECT_VEC} < 1 AND docId IN (
          SELECT docId from title_vector_20 WHERE (createdDate > 1685421481 and createdDate < 1685507881)
          AND (dir = 'opt/test/app00/' or dir = 'opt/test/app22/' or dir = 'opt/test/app44/')
          AND isDeleted = true group by docId
        );`;

        const result = await store?.querySql(selectSql);

        try {
            while (result?.goToNextRow()) {
                let value = result.getValue(0);
                console.log(TAG + "value: " + value?.toString());
            }
            result?.getValue(10);
            expect().assertFail();
            result?.close();
        } catch (e) {
            console.error(TAG + `testVectorSubSelectFailed0009 failed. err: ${JSON.stringify(e)}`);
            result?.close();
            expect(14800012 == e.code).assertTrue();
        }
        console.log(TAG + "************* testVectorSubSelectFailed0009 end   *************");
    });

    /**
     * @tc.name testVectorClusterIndexSuccess0001
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_ClusterIndex_success_0001
     * @tc.desc create cluster index and insert 10 vec, then query from table and check.
     */
    it('testVectorClusterInsertSuccess0001', 0, async function () {
        console.log(TAG + "************* testVectorClusterInsertSuccess0001 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }

        try {
            await store?.execute("create table cluster_vec_10 (id int PRIMARY KEY, repr floatvector(256));");
        } catch (e) {
            console.error(TAG + `create table cluster_vec_10 failed. errcode: ${e.code}`);
        }

        try {
            await store?.execute("create index cluster_index on cluster_vec_10 using IVFCLUSTER(repr COSINE);");
        } catch (e) {
            console.error(TAG + `create cluster index failed. errcode: ${e.code}`);
        }

        try {
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (0, '${clstVec0}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (1, '${clstVec1}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (2, '${clstVec2}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (3, '${clstVec3}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (4, '${clstVec4}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (5, '${clstVec0}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (6, '${clstVec1}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (7, '${clstVec2}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (8, '${clstVec3}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (9, '${clstVec4}');`);
        } catch (e) {
            console.error(TAG + `insert face vector in table failed. errcode: ${e.code}`);
        }

        const selectSql = `select id, repr, CLUSTER_ID(repr) from cluster_vec_10;`;
        const result = await store?.querySql(selectSql);
        expect(result?.rowCount).assertEqual(10);
        try {
            while (result?.goToNextRow()) {
                let id = result.getValue(0);
                let tmpVec = result.getValue(1);
                let clstId = result.getValue(2);
                console.log(TAG + "id: " + id?.toString() + "clstId: " + clstId?.toString());
            }
            result?.getValue(10);
            expect().assertFail();
            result?.close();
        } catch (e) {
            console.error(TAG + `testVectorClusterInsertSuccess0001 failed. err: ${JSON.stringify(e)}`);
            result?.close();
            expect(14800012 == e.code).assertTrue();
        }
        console.log(TAG + "************* testVectorClusterInsertSuccess0001 end   *************");
    });

    /**
     * @tc.name testVectorClusterIndexSuccess0002
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_ClusterIndex_success_0002
     * @tc.desc insert 10 vec, run cluster, then query from table and check.
     */
    it('testVectorClusterIndexSuccess0002', 0, async function () {
        console.log(TAG + "************* testVectorClusterIndexSuccess0002 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }

        try {
            await store?.execute("create table cluster_vec_10 (id int PRIMARY KEY, repr floatvector(256));");
        } catch (e) {
            console.error(TAG + `create table cluster_vec_10 failed. errcode: ${e.code}`);
        }

        try {
            await store?.execute("create index cluster_index on cluster_vec_10 using IVFCLUSTER(repr COSINE);");
        } catch (e) {
            console.error(TAG + `create cluster index failed. errcode: ${e.code}`);
        }

        try {
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (0, '${clstVec0}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (1, '${clstVec1}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (2, '${clstVec2}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (3, '${clstVec3}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (4, '${clstVec4}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (5, '${clstVec0}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (6, '${clstVec1}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (7, '${clstVec2}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (8, '${clstVec3}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (9, '${clstVec4}');`);
        } catch (e) {
            console.error(TAG + `insert face vector in table failed. errcode: ${e.code}`);
        }

        try {
            await store?.execute("PRAGMA CLUSTER_RUN cluster_vec_10.cluster_index;");
            await new Promise(resolve => setTimeout(resolve, 50)); // wait 50ms for cluster build exec
        } catch (e) {
            console.error(TAG + `run cluster build failed. errcode: ${e.code}`);
        }

        const selectSql = `select id, repr, CLUSTER_ID(repr) from cluster_vec_10;`;
        const result = await store?.querySql(selectSql);
        expect(result?.rowCount).assertEqual(10);
        try {
            while (result?.goToNextRow()) {
                let id = result.getValue(0);
                let tmpVec = result.getValue(1);
                let clstId = result.getValue(2);
                console.log(TAG + "id: " + id?.toString() + "clstId: " + clstId?.toString());
            }
            result?.getValue(10);
            expect().assertFail();
            result?.close();
        } catch (e) {
            console.error(TAG + `testVectorClusterIndexSuccess0002 failed. err: ${JSON.stringify(e)}`);
            result?.close();
            expect(14800012 == e.code).assertTrue();
        }
        console.log(TAG + "************* testVectorClusterIndexSuccess0002 end   *************");
    });

    /**
     * @tc.name testVectorClusterIndexSuccess0003
     * @tc.number SUB_DISTRIBUTEDDATAMGR_RDB_JSVectorStore_ClusterIndex_success_0003
     * @tc.desc insert 5 vec, run cluster, then insert 5 vec, run cluster again.
     */
    it('testVectorClusterIndexSuccess0003', 0, async function () {
        console.log(TAG + "************* testVectorClusterIndexSuccess0003 start *************");
        if (!isSupportVector) {
            expect(isSupportVector).assertFalse();
            return;
        }

        try {
            await store?.execute("create table cluster_vec_10 (id int PRIMARY KEY, repr floatvector(256));");
        } catch (e) {
            console.error(TAG + `create table cluster_vec_10 failed. errcode: ${e.code}`);
        }

        try {
            await store?.execute("create index cluster_index on using IVFCLUSTER(repr COSINE);");
        } catch (e) {
            console.error(TAG + `create cluster index failed. errcode: ${e.code}`);
        }

        try {
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (0, '${clstVec0}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (1, '${clstVec1}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (2, '${clstVec2}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (3, '${clstVec3}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (4, '${clstVec4}');`);
        } catch (e) {
            console.error(TAG + `insert face vector in table failed. errcode: ${e.code}`);
        }

        try {
            await store?.execute("PRAGMA CLUSTER_RUN cluster_vec_10.cluster_index;");
            await new Promise(resolve => setTimeout(resolve, 50)); // wait 50ms for cluster build exec
        } catch (e) {
            console.error(TAG + `run cluster build failed. errcode: ${e.code}`);
        }

        try {
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (5, '${clstVec0}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (6, '${clstVec1}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (7, '${clstVec2}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (8, '${clstVec3}');`);
            await store?.execute(`INSERT INTO cluster_vec_10 VALUES (9, '${clstVec4}');`);
        } catch (e) {
            console.error(TAG + `insert face vector in table failed. errcode: ${e.code}`);
        }

        try {
            await store?.execute("PRAGMA CLUSTER_RUN cluster_vec_10.cluster_index;");
            await new Promise(resolve => setTimeout(resolve, 50)); // wait 50ms for cluster build exec
        } catch (e) {
            console.error(TAG + `run cluster build failed. errcode: ${e.code}`);
        }

        const selectSql = `select id, repr, CLUSTER_ID(repr) from cluster_vec_10;`;
        const result = await store?.querySql(selectSql);
        expect(result?.rowCount).assertEqual(10);
        try {
            while (result?.goToNextRow()) {
                let id = result.getValue(0);
                let tmpVec = result.getValue(1);
                let clstId = result.getValue(2);
                console.log(TAG + "id: " + id?.toString() + "clstId: " + clstId?.toString());
            }
            result?.getValue(10);
            expect().assertFail();
            result?.close();
        } catch (e) {
            console.error(TAG + `testVectorClusterIndexSuccess0003 failed. err: ${JSON.stringify(e)}`);
            result?.close();
            expect(14800012 == e.code).assertTrue();
        }
        console.log(TAG + "************* testVectorClusterIndexSuccess0003 end   *************");
    });

    console.log(TAG + "*************Unit Test End*************");
})