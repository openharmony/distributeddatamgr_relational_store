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
import { expect } from "@ohos/hypium";
import fs from '@ohos.file.fs'
import relationalStore from '@ohos.data.relationalStore';
import common from '@ohos.app.ability.common';
async function corruptDatabaseFile(fileName: string)
{
  let stat = await fs.stat(fileName);
  let file = await fs.open(fileName, fs.OpenMode.READ_WRITE);
  fs.lseek(file.fd, 0, fs.WhenceType.SEEK_SET);
  let bufferSize = stat.size;
  let buffer = new ArrayBuffer(bufferSize);
  let uint8Array = new Uint8Array(buffer);
  let fChar = 'F'.charCodeAt(0);
  uint8Array.fill(fChar);
  await fs.write(file.fd, buffer, { offset: 0, length: bufferSize });
}

export async function createCorruptDb(context:common.ApplicationContext, config:relationalStore.StoreConfig)
{
  let dbPath = context.databaseDir + "/rdb/" + config.name;
  let dbPathWal = dbPath + "-wal";
  let dbPathShm = dbPath + "-shm";
  await corruptDatabaseFile(dbPath);
  await corruptDatabaseFile(dbPathWal);
  await corruptDatabaseFile(dbPathShm);
}

export function getRowCount(resultSet:relationalStore.LiteResultSet|undefined):number {
  let count = 0;
  while(resultSet?.goToNextRow()) {
    count++;
  }
  return count;
}

export async function callAndCodeCheck(code:number|string, funName:string, fun:Function)
{
  console.log(`*************${funName} start*************`);
  try {
    await fun();
    expect(true).assertFail();
  } catch (e) {
    console.error(`${funName} failed. code is ${e.code}, message is ${e.message}`);
    expect(e.code).assertEqual(code);
  }
  console.log(`*************${funName} end***************`);
}

export async function call(funName:string, fun:Function)
{
  console.log(`*************${funName} start*************`);
  try {
    await fun();
  } catch (e) {
    console.error(`${funName} failed. code is ${e.code}, message is ${e.message}`);
    expect(true).assertFail();
  }
  console.log(`*************${funName} end***************`);
}