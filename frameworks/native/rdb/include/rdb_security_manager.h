/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef NATIVE_RDB_RDB_SECURITY_MANAGER_H
#define NATIVE_RDB_RDB_SECURITY_MANAGER_H

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <climits>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <unordered_map>
#include <shared_mutex>
#include <string>
#include <vector>

namespace OHOS::NativeRdb {
class RDBCrypto;
struct RdbSecretKeyData {
    static constexpr uint8_t CURRENT_VERSION = 2;
    uint8_t version = CURRENT_VERSION;
    time_t timeValue{};
    std::vector<uint8_t> secretKey{};
    RdbSecretKeyData() = default;
    ~RdbSecretKeyData()
    {
        version = 0;
        timeValue = time_t();
        secretKey.assign(secretKey.size(), 0);
    }
};
struct RdbSecretContent {
    static constexpr uint32_t MAGIC_NUMBER = 0x6B6B6B6B;
    static constexpr uint32_t NONCE_VALUE_SIZE = 12;
    static constexpr uint8_t CURRENT_VERSION = 2;
    uint32_t magicNum = MAGIC_NUMBER;
    uint8_t version = CURRENT_VERSION;
    std::vector<uint8_t> nonce_{};
    std::vector<uint8_t> encrypt_{};
    RdbSecretContent() = default;
    ~RdbSecretContent()
    {
        nonce_.assign(nonce_.size(), 0);
        encrypt_.assign(encrypt_.size(), 0);
    }
};

class RdbPassword final {
public:
    RdbPassword();
    ~RdbPassword();

    bool operator==(const RdbPassword &input) const;
    bool operator!=(const RdbPassword &input) const;

    size_t GetSize() const;
    const uint8_t *GetData() const;
    int SetValue(const uint8_t *inputData, size_t inputSize);
    int Clear();
    bool IsValid() const;

private:
    static constexpr size_t MAX_PASSWORD_SIZE = 128;
    uint8_t data_[MAX_PASSWORD_SIZE] = { UCHAR_MAX };
    size_t size_ = 0;
};

class RdbSecurityManager {
public:
    enum HksErrCode {
        HKS_SUCCESS = 0,
        HKS_FAILURE = -1,
        HKS_ERROR_NOT_EXIST = -13,
    };

    enum KeyFileType : int32_t {
        PUB_KEY_FILE = 0,
        PUB_KEY_FILE_NEW_KEY,
        PUB_KEY_FILE_BUTT
    };

    class KeyFiles {
    public:
        KeyFiles(const std::string &dbPath, bool openFile = true);
        ~KeyFiles();
        const std::string GetKeyFile(KeyFileType type);
        int32_t InitKeyPath();
        int32_t DestroyLock();
        int32_t Lock(bool isBlock = true);
        int32_t Unlock();

    private:
        bool InitLockPath();
        int32_t lockFd_ = -1;
        std::string lock_;
        std::string keys_[PUB_KEY_FILE_BUTT];
    };
    static RdbSecurityManager &GetInstance();
    int32_t Init(const std::string &bundleName);

    RdbPassword GetRdbPassword(const std::string &dbPath, KeyFileType keyFileType);
    void DelAllKeyFiles(const std::string &dbPath);
    void DelKeyFile(const std::string &dbPath, KeyFileType keyFileType);
    void ChangeKeyFile(const std::string &dbPath);
    int32_t RestoreKeyFile(const std::string &dbPath, const std::vector<uint8_t> &key);
    bool IsNewKeyFilesExists(const std::string &dbPath);

private:
    RdbSecurityManager();
    ~RdbSecurityManager();

    void* GetHandle();
    void SetBundleName(const std::string &bundleName);
    std::set<std::string> GetBundleNames();
    std::shared_ptr<RDBCrypto> GetDelegate();
    void UpgradeKey(const std::string &keyPath, const std::string &dbPath, KeyFileType keyFileType);
    std::vector<char> GenerateHMAC(std::vector<char> &data, const std::string &key);
    std::pair<bool, RdbSecretKeyData> LoadSecretKeyFromDiskV0(const std::string &keyPath);
    std::pair<bool, RdbSecretKeyData> LoadSecretKeyFromDiskV1(const std::string &keyPath);
    std::pair<bool, RdbSecretContent> UnpackV0(const std::vector<char> &content);
    std::pair<bool, RdbSecretContent> UnpackV1(const std::vector<char> &content);
    std::pair<bool, RdbSecretKeyData> DecryptV0(const RdbSecretContent &content);
    std::pair<bool, RdbSecretKeyData> DecryptV1(const RdbSecretContent &content);
    std::pair<bool, RdbSecretContent> EncryptWorkKey(const std::vector<uint8_t> &key);
    std::vector<uint8_t> DecryptWorkKey(const std::vector<uint8_t> &key, const std::vector<uint8_t> &nonce);
    void ReportCryptFault(int32_t code, const std::string &message);
    static bool CreateDir(const std::string &fileDir);
    std::vector<uint8_t> GenerateRandomNum(uint32_t len);
    std::shared_ptr<RDBCrypto> CreateDelegate(const std::vector<uint8_t> &rootKeyAlias);
    bool SaveSecretKeyToFile(const std::string &keyFile, const std::vector<uint8_t> &workKey = {});
    bool SaveSecretKeyToDisk(const std::string &keyPath, const RdbSecretContent &secretContent);
    std::string GetBundleName();
    RdbPassword LoadSecretKeyFromFile(const std::string &keyPath);
    std::pair<bool, RdbSecretKeyData> LoadSecretKeyFromDisk(const std::string &keyPath);
    std::pair<bool, RdbSecretContent> Unpack(const std::vector<char> &content);
    std::pair<bool, RdbSecretKeyData> Decrypt(const RdbSecretContent &content);
    using LoadKeyHandler = std::pair<bool, RdbSecretKeyData> (RdbSecurityManager::*)(const std::string &keyPath);
    static constexpr LoadKeyHandler LOAD_KEY_HANDLERS[PUB_KEY_FILE_BUTT] = {
        &RdbSecurityManager::LoadSecretKeyFromDiskV0,
        &RdbSecurityManager::LoadSecretKeyFromDiskV1
    };

    static constexpr const char *PUB_KEY_SUFFIXES[] = {
        ".pub_key_v2",
        ".pub_key_v2.new",
    };
    static constexpr const char *OLD_PUB_KEY_SUFFIXES[] = {
        ".pub_key",
        ".pub_key_v1",
    };
    static constexpr const char *OLD_PUB_NEW_KEY_SUFFIXES[] = {
        ".pub_key.new",
        ".pub_key.new",
    };
    static constexpr char const *SUFFIX_KEY_LOCK = ".key_lock";
    static constexpr const char *RDB_HKS_BLOB_TYPE_NONCE = "Z5s0Bo571Koq";
    static constexpr const char *RDB_ROOT_KEY_ALIAS = "DistributedDataRdb";
    static constexpr uint8_t AEAD_LEN = 16;
    static constexpr uint32_t RDB_KEY_SIZE = 32;
    static constexpr uint32_t UPGRADE_TIMES = 2;
    static constexpr uint32_t HEX_FIELD_WIDTH = 2;
    static constexpr uint8_t VERSION_V0 = 1;
    static constexpr uint8_t VERSION_V1 = 2;
    static constexpr uint8_t HMAC_SIZE = 8;

    const std::vector<uint8_t> rootAlias_;
    std::mutex mutex_;
    std::mutex cryptoMutex_;
    std::shared_ptr<RDBCrypto> rdbCrypto_;
    std::mutex bundleNameMutex_;
    std::set<std::string> bundleNames_;
    std::mutex handleMutex_;
    void *handle_;
};

} // namespace OHOS::NativeRdb
#endif
