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

#ifndef OHOS_DISTRIBUTED_DATA_DATABASE_UTILS_ACL_H
#define OHOS_DISTRIBUTED_DATA_DATABASE_UTILS_ACL_H

#include <stdint.h>

#include <string>
namespace OHOS {
namespace DATABASE_UTILS {
/*
 * ACL tag values
 */
enum class ACL_TAG : uint16_t {
    UNDEFINED = 0x00,
    USER_OBJ = 0x01,
    USER = 0x02,
    GROUP_OBJ = 0x04,
    GROUP = 0x08,
    MASK = 0x10,
    OTHER = 0x20,
};

/*
 * ACL perm values
 */
class ACL_PERM {
public:
    uint16_t value_ = 0;
    enum Value : uint16_t {
        READ = 0x04,
        WRITE = 0x02,
        EXECUTE = 0x01,
    };

public:
    ACL_PERM() = default;
    ACL_PERM(const uint16_t x)
    {
        value_ = (x & READ) | (x & WRITE) | (x & EXECUTE);
    }
};

struct AclXattrEntry {
    static constexpr uint32_t ACL_UNDEFINED_ID = static_cast<uint32_t>(-1);
    ACL_TAG tag_ = ACL_TAG::UNDEFINED;
    ACL_PERM perm_ = {};
    uint32_t id_ = ACL_UNDEFINED_ID;

    AclXattrEntry(const ACL_TAG tag, const uint32_t id, const ACL_PERM mode) : tag_(tag), perm_(mode), id_(id)
    {
    }
};
class Acl {
public:
    /*
     * ACL extended attributes (xattr) names
    */
    static constexpr const char *ACL_XATTR_DEFAULT = "system.posix_acl_default";
    static constexpr const char *ACL_XATTR_ACCESS = "system.posix_acl_access";
    static constexpr uint16_t R_RIGHT = 4;
    static constexpr uint16_t W_RIGHT = 2;
    static constexpr uint16_t E_RIGHT = 1;
    Acl(const std::string &path, const std::string &aclAttrName)
    {
    }

    int32_t SetAcl(const AclXattrEntry &entry)
    {
        return 0;
    }

    bool HasAcl(const AclXattrEntry &entry)
    {
        return 0;
    }
};
} // namespace DATABASE_UTILS
} // namespace OHOS

#endif // OHOS_DISTRIBUTED_DATA_DATABASE_UTILS_ACL_H