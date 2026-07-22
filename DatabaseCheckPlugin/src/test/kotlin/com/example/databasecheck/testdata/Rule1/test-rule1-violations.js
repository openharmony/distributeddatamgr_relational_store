/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

// Rule 1 Test File: Should trigger database rule violations

// ========== These should trigger Rule 1 warnings ==========

async function testViolation1(context, path) {
    // Should trigger warning - fileIo.open on context.databaseDir
    var fdhaha = await fileIo.open(context.databaseDir + path, 0, 0o2770);
    
    // Should trigger warning - fileIo.close
    await fileIo.close(fdhaha);
}

async function testViolation2(context, path) {
    // Should trigger warning - fileIo.open on static database path
    var fd22 = await fileIo.open('/data/storage/el1/database/' + path, 0, 0o2770);
    
    // Should trigger warning - fileIo.open on el2 database path with hap name
    var fd3 = await fileIo.open('/data/storage/el2/database/' + context.currentHapModuleInfo.name + '/' + path, 0, 0o2770);
    
    await fileIo.close(fd22);
    await fileIo.close(fd3);
}

function testViolation3() {
    // Should trigger warnings - other prohibited operations on database paths
    fopen('/data/storage/el3/database/test.db', 'r');
    open('/data/service/el1/public/database/service.db', 'w');
    fcntl('/data/app/el2/user123/database/com.example.app/data.db');
    flock('/data/service/el4/userId/database/serviceability-xxx/config.db');
}

function testViolation4() {
    // Should trigger warnings - more database paths
    var fd = fileIo.open('/data/storage/el4/database/important.db', 0, 0o644);
    fileIo.close(fd);
    
    var fd2333 = fileIo.openSync('/data/storage/el5/database/sync.db', 0, 0o644);
    fileIo.closeSync(fd2333);
}