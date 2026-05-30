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

#include "rdb_cache_manager.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>
#include <random>
#include <regex>
#include <sstream>

namespace OHOS {
namespace Rdb {

namespace {
constexpr int CACHE_ERR_NOT_INITIALIZED = -1;
constexpr int CACHE_ERR_CALLBACK_NOT_FOUND = -3;
constexpr int CACHE_ERR_INVALID_PARAM = -8;
constexpr int CACHE_ERR_VALUE_TOO_LARGE = -9;
constexpr int CACHE_ERR_KEY_NOT_FOUND = -10;
constexpr int CACHE_ERR_ENTRY_EXPIRED = -11;
constexpr int CACHE_ERR_ENTRY_INVALID = -12;
constexpr int CACHE_ERR_LOADER_EMPTY = -13;
constexpr int CACHE_ERR_CACHE_EMPTY = -14;
constexpr int CACHE_ERR_KEY_EMPTY = -15;
constexpr int CACHE_ERR_KEY_TOO_LONG = -16;

constexpr size_t COMPRESSION_THRESHOLD_BYTES = 1024;
constexpr size_t MAX_KEY_LENGTH = 256;
constexpr int DEFAULT_COMPACTION_INTERVAL_MS = 300000;
constexpr int TTL_EVICT_MAX_HOURS = 24;
constexpr size_t METADATA_ENTRY_SIZE_ESTIMATE = 64;
constexpr int DEFAULT_COMPRESSION_LEVEL = 6;
constexpr double PERCENT_FACTOR = 100.0;
constexpr int DEFAULT_ENTRY_VERSION = 1;
} // namespace

CacheManager &CacheManager::GetInstance()
{
    static CacheManager instance;
    return instance;
}

CacheManager::CacheManager() : initialized_(false), stopThreads_(false), callbackIdCounter_(0)
{
}

CacheManager::~CacheManager()
{
    Shutdown();
}

int CacheManager::Initialize(const CacheConfig &config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) {
        return CACHE_ERR_NOT_INITIALIZED;
    }

    config_ = config;
    cache_.clear();
    lruList_.clear();
    lruMap_.clear();
    tableEntryCount_.clear();
    stats_ = CacheStatistics();
    initialized_ = true;
    stopThreads_ = false;

    cleanupThread_ = std::thread(&CacheManager::CleanupThread, this);
    compactionThread_ = std::thread(&CacheManager::CompactionThread, this);

    return 0;
}

void CacheManager::Shutdown()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) {
            return;
        }
        stopThreads_ = true;
        initialized_ = false;
    }

    if (cleanupThread_.joinable()) {
        cleanupThread_.join();
    }
    if (compactionThread_.joinable()) {
        compactionThread_.join();
    }

    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
    lruList_.clear();
    lruMap_.clear();
    tableEntryCount_.clear();
    callbacks_.clear();
}

bool CacheManager::IsInitialized() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return initialized_;
}

CacheEntry CacheManager::BuildCacheEntry(
    const std::string &key, const std::vector<uint8_t> &value, int ttl, int priority)
{
    CacheEntry entry;
    entry.key = key;
    entry.value = value;
    entry.status = CacheEntryStatus::STATUS_VALID;
    entry.createdAt = std::chrono::system_clock::now();
    entry.lastAccessedAt = entry.createdAt;
    entry.expiresAt = entry.createdAt + std::chrono::milliseconds(ttl > 0 ? ttl : config_.defaultTTL);
    entry.accessCount = 0;
    entry.hitCount = 0;
    entry.missCount = 0;
    entry.size = value.size();
    entry.priority = priority;
    entry.version = DEFAULT_ENTRY_VERSION;

    if (config_.enableCompression && value.size() > COMPRESSION_THRESHOLD_BYTES) {
        std::vector<uint8_t> compressed;
        if (CompressValue(value, compressed) == 0 && compressed.size() < value.size()) {
            entry.value = compressed;
            entry.size = compressed.size();
            stats_.compressionCount++;
        }
    }

    return entry;
}

void CacheManager::InsertOrUpdateEntry(const std::string &key, const CacheEntry &entry)
{
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        stats_.totalSize -= it->second.size;
        stats_.updateCount++;

        auto lruIt = lruMap_.find(key);
        if (lruIt != lruMap_.end()) {
            lruList_.erase(lruIt->second);
            lruMap_.erase(lruIt);
        }
    } else {
        stats_.insertionCount++;
    }

    cache_[key] = entry;
    lruList_.push_front(key);
    lruMap_[key] = lruList_.begin();
    stats_.totalSize += entry.size;
    stats_.totalEntries = static_cast<int>(cache_.size());
}

int CacheManager::Put(const std::string &key, const std::vector<uint8_t> &value, int ttl, int priority)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return CACHE_ERR_NOT_INITIALIZED;
    }

    int ret = ValidateKey(key);
    if (ret != 0) {
        return ret;
    }

    ret = ValidateValue(value);
    if (ret != 0) {
        return ret;
    }

    auto startTime = std::chrono::steady_clock::now();

    size_t entrySize = value.size();
    if (entrySize > config_.maxEntrySize) {
        return CACHE_ERR_VALUE_TOO_LARGE;
    }

    while (stats_.totalSize + entrySize > config_.maxSize || static_cast<int>(cache_.size()) >= config_.maxEntries) {
        ret = EvictEntry();
        if (ret != 0) {
            break;
        }
    }

    CacheEntry entry = BuildCacheEntry(key, value, ttl, priority);
    InsertOrUpdateEntry(key, entry);

    auto endTime = std::chrono::steady_clock::now();
    UpdateStatistics("put", std::chrono::duration<double, std::milli>(endTime - startTime).count());

    return 0;
}

int CacheManager::PutWithTable(
    const std::string &key, const std::vector<uint8_t> &value, const std::string &tableName, int ttl)
{
    int ret = Put(key, value, ttl);
    if (ret == 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            it->second.tableName = tableName;
            tableEntryCount_[tableName]++;
        }
    }
    return ret;
}

void CacheManager::RefreshLRU(const std::string &key)
{
    auto lruIt = lruMap_.find(key);
    if (lruIt != lruMap_.end()) {
        lruList_.erase(lruIt->second);
        lruList_.push_front(key);
        lruMap_[key] = lruList_.begin();
    }
}

void CacheManager::DecompressIfNeeded(const CacheEntry &entry, std::vector<uint8_t> &value)
{
    if (!config_.enableCompression) {
        return;
    }
    std::vector<uint8_t> decompressed;
    if (DecompressValue(entry.value, decompressed) == 0) {
        value = decompressed;
        stats_.decompressionCount++;
    }
}

int CacheManager::Get(const std::string &key, std::vector<uint8_t> &value)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return CACHE_ERR_NOT_INITIALIZED;
    }

    auto startTime = std::chrono::steady_clock::now();

    auto it = cache_.find(key);
    if (it == cache_.end()) {
        stats_.missCount++;
        stats_.missRate = static_cast<double>(stats_.missCount) / (stats_.hitCount + stats_.missCount);
        return CACHE_ERR_KEY_NOT_FOUND;
    }

    CacheEntry &entry = it->second;

    if (IsExpired(entry)) {
        entry.status = CacheEntryStatus::STATUS_EXPIRED;
        stats_.expirationCount++;
        stats_.missCount++;
        return CACHE_ERR_ENTRY_EXPIRED;
    }

    if (entry.status == CacheEntryStatus::STATUS_INVALID) {
        stats_.missCount++;
        return CACHE_ERR_ENTRY_INVALID;
    }

    UpdateAccessInfo(entry);
    value = entry.value;
    DecompressIfNeeded(entry, value);

    entry.hitCount++;
    stats_.hitCount++;
    stats_.hitRate = static_cast<double>(stats_.hitCount) / (stats_.hitCount + stats_.missCount);

    RefreshLRU(key);

    auto endTime = std::chrono::steady_clock::now();
    UpdateStatistics("get", std::chrono::duration<double, std::milli>(endTime - startTime).count());

    return 0;
}

int CacheManager::GetWithMetadata(
    const std::string &key, std::vector<uint8_t> &value, std::map<std::string, std::string> &metadata)
{
    int ret = Get(key, value);
    if (ret == 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            metadata = it->second.metadata;
        }
    }
    return ret;
}

bool CacheManager::Contains(const std::string &key) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return false;
    }
    return !IsExpired(it->second) && it->second.status == CacheEntryStatus::STATUS_VALID;
}

size_t CacheManager::RemoveEntryFromCache(const std::string &key, bool notifyCallbacks)
{
    size_t entrySize = 0;
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return 0;
    }

    entrySize = it->second.size;

    auto lruIt = lruMap_.find(key);
    if (lruIt != lruMap_.end()) {
        lruList_.erase(lruIt->second);
        lruMap_.erase(lruIt);
    }

    if (notifyCallbacks) {
        NotifyCallbacks(key, CacheEntryStatus::STATUS_EVICTED);
    }
    cache_.erase(it);
    stats_.totalEntries = static_cast<int>(cache_.size());

    return entrySize;
}

int CacheManager::Remove(const std::string &key)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return CACHE_ERR_NOT_INITIALIZED;
    }

    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return CACHE_ERR_KEY_NOT_FOUND;
    }

    if (!it->second.tableName.empty()) {
        auto tableIt = tableEntryCount_.find(it->second.tableName);
        if (tableIt != tableEntryCount_.end() && tableIt->second > 0) {
            tableIt->second--;
        }
    }

    size_t removedSize = RemoveEntryFromCache(key);
    if (removedSize > 0) {
        stats_.totalSize -= removedSize;
        stats_.deletionCount++;
    }

    return 0;
}

int CacheManager::RemoveByTable(const std::string &tableName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return CACHE_ERR_NOT_INITIALIZED;
    }

    std::vector<std::string> keysToRemove;
    for (const auto &pair : cache_) {
        if (pair.second.tableName == tableName) {
            keysToRemove.push_back(pair.first);
        }
    }

    for (const auto &key : keysToRemove) {
        size_t removedSize = RemoveEntryFromCache(key);
        if (removedSize > 0) {
            stats_.totalSize -= removedSize;
            stats_.deletionCount++;
        }
    }

    tableEntryCount_.erase(tableName);
    return static_cast<int>(keysToRemove.size());
}

int CacheManager::RemoveByPattern(const std::string &pattern)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return CACHE_ERR_NOT_INITIALIZED;
    }

    std::vector<std::string> keysToRemove;
    std::regex patternRegex(pattern);
    for (const auto &pair : cache_) {
        if (std::regex_match(pair.first, patternRegex)) {
            keysToRemove.push_back(pair.first);
        }
    }

    for (const auto &key : keysToRemove) {
        size_t removedSize = RemoveEntryFromCache(key);
        if (removedSize > 0) {
            stats_.totalSize -= removedSize;
            stats_.deletionCount++;
        }
    }

    return static_cast<int>(keysToRemove.size());
}

int CacheManager::RemoveExpired()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return CACHE_ERR_NOT_INITIALIZED;
    }

    std::vector<std::string> expiredKeys;
    for (const auto &pair : cache_) {
        if (IsExpired(pair.second)) {
            expiredKeys.push_back(pair.first);
        }
    }

    for (const auto &key : expiredKeys) {
        size_t removedSize = RemoveEntryFromCache(key);
        if (removedSize > 0) {
            stats_.totalSize -= removedSize;
            stats_.expirationCount++;
        }
    }

    return static_cast<int>(expiredKeys.size());
}

int CacheManager::Clear()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return CACHE_ERR_NOT_INITIALIZED;
    }

    cache_.clear();
    lruList_.clear();
    lruMap_.clear();
    tableEntryCount_.clear();
    stats_.totalEntries = 0;
    stats_.totalSize = 0;

    return 0;
}

size_t CacheManager::GetSize(const std::string &key) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return 0;
    }
    return it->second.size;
}

CacheEntryStatus CacheManager::GetStatus(const std::string &key) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return CacheEntryStatus::STATUS_INVALID;
    }
    if (IsExpired(it->second)) {
        return CacheEntryStatus::STATUS_EXPIRED;
    }
    return it->second.status;
}

std::chrono::system_clock::time_point CacheManager::GetCreatedAt(const std::string &key) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return {};
    }
    return it->second.createdAt;
}

std::chrono::system_clock::time_point CacheManager::GetLastAccessedAt(const std::string &key) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return {};
    }
    return it->second.lastAccessedAt;
}

int CacheManager::GetAccessCount(const std::string &key) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return 0;
    }
    return it->second.accessCount;
}

int CacheManager::GetVersion(const std::string &key) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return 0;
    }
    return it->second.version;
}

int CacheManager::SetTTL(const std::string &key, int ttl)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return CACHE_ERR_KEY_NOT_FOUND;
    }
    it->second.expiresAt = std::chrono::system_clock::now() + std::chrono::milliseconds(ttl);
    return 0;
}

int CacheManager::GetTTL(const std::string &key) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return CACHE_ERR_KEY_NOT_FOUND;
    }
    auto now = std::chrono::system_clock::now();
    auto ttl = std::chrono::duration_cast<std::chrono::milliseconds>(it->second.expiresAt - now).count();
    return ttl > 0 ? static_cast<int>(ttl) : 0;
}

int CacheManager::SetPriority(const std::string &key, int priority)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return CACHE_ERR_KEY_NOT_FOUND;
    }
    it->second.priority = priority;
    return 0;
}

int CacheManager::GetPriority(const std::string &key) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return 0;
    }
    return it->second.priority;
}

int CacheManager::Update(const std::string &key, const std::vector<uint8_t> &value)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return CACHE_ERR_KEY_NOT_FOUND;
    }

    stats_.totalSize -= it->second.size;
    it->second.value = value;
    it->second.size = value.size();
    it->second.version++;
    it->second.lastAccessedAt = std::chrono::system_clock::now();
    stats_.totalSize += it->second.size;
    stats_.updateCount++;

    return 0;
}

int CacheManager::UpdateIfPresent(const std::string &key, const std::vector<uint8_t> &value)
{
    return Update(key, value);
}

int CacheManager::UpdateMetadata(const std::string &key, const std::map<std::string, std::string> &metadata)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return CACHE_ERR_KEY_NOT_FOUND;
    }
    it->second.metadata = metadata;
    return 0;
}

int CacheManager::GetOrLoad(
    const std::string &key, std::vector<uint8_t> &value, std::function<std::vector<uint8_t>()> loader, int ttl)
{
    int ret = Get(key, value);
    if (ret == 0) {
        return 0;
    }

    value = loader();
    if (value.empty()) {
        return CACHE_ERR_LOADER_EMPTY;
    }

    return Put(key, value, ttl);
}

int CacheManager::PutBatch(const std::map<std::string, std::vector<uint8_t>> &entries, int ttl)
{
    int count = 0;
    for (const auto &pair : entries) {
        if (Put(pair.first, pair.second, ttl) == 0) {
            count++;
        }
    }
    return count;
}

int CacheManager::GetBatch(const std::vector<std::string> &keys, std::map<std::string, std::vector<uint8_t>> &values)
{
    int count = 0;
    for (const auto &key : keys) {
        std::vector<uint8_t> value;
        if (Get(key, value) == 0) {
            values[key] = value;
            count++;
        }
    }
    return count;
}

int CacheManager::RemoveBatch(const std::vector<std::string> &keys)
{
    int count = 0;
    for (const auto &key : keys) {
        if (Remove(key) == 0) {
            count++;
        }
    }
    return count;
}

int CacheManager::InvalidateByTable(const std::string &tableName)
{
    return RemoveByTable(tableName);
}

int CacheManager::InvalidateByQuery(const std::string &queryHash)
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> keysToRemove;
    for (const auto &pair : cache_) {
        if (pair.second.queryHash == queryHash) {
            keysToRemove.push_back(pair.first);
        }
    }

    for (const auto &key : keysToRemove) {
        size_t removedSize = RemoveEntryFromCache(key, false);
        if (removedSize > 0) {
            stats_.totalSize -= removedSize;
        }
    }

    stats_.totalEntries = static_cast<int>(cache_.size());
    return static_cast<int>(keysToRemove.size());
}

int CacheManager::InvalidateAll()
{
    return Clear();
}

CacheStatistics CacheManager::GetStatistics() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

std::map<std::string, std::any> CacheManager::GetDetailedStatistics() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, std::any> detailed;
    detailed["totalEntries"] = stats_.totalEntries;
    detailed["totalSize"] = stats_.totalSize;
    detailed["hitCount"] = stats_.hitCount;
    detailed["missCount"] = stats_.missCount;
    detailed["hitRate"] = stats_.hitRate;
    detailed["missRate"] = stats_.missRate;
    detailed["evictionCount"] = stats_.evictionCount;
    detailed["expirationCount"] = stats_.expirationCount;
    detailed["insertionCount"] = stats_.insertionCount;
    detailed["updateCount"] = stats_.updateCount;
    detailed["deletionCount"] = stats_.deletionCount;
    detailed["averageAccessTime"] = stats_.averageAccessTime;
    detailed["averageEntrySize"] = stats_.averageEntrySize;
    detailed["compressionCount"] = stats_.compressionCount;
    detailed["decompressionCount"] = stats_.decompressionCount;
    detailed["compressionRatio"] = stats_.compressionRatio;
    detailed["maxSize"] = config_.maxSize;
    detailed["maxEntries"] = config_.maxEntries;
    detailed["memoryUtilization"] = GetMemoryUtilization();
    return detailed;
}

int CacheManager::ResetStatistics()
{
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.hitCount = 0;
    stats_.missCount = 0;
    stats_.evictionCount = 0;
    stats_.expirationCount = 0;
    stats_.insertionCount = 0;
    stats_.updateCount = 0;
    stats_.deletionCount = 0;
    stats_.hitRate = 0.0;
    stats_.missRate = 0.0;
    stats_.averageAccessTime = 0.0;
    stats_.compressionCount = 0;
    stats_.decompressionCount = 0;
    stats_.persistenceCount = 0;
    stats_.warmupCount = 0;
    return 0;
}

int CacheManager::SetMaxSize(size_t maxSize)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (maxSize == 0) {
        return CACHE_ERR_INVALID_PARAM;
    }
    config_.maxSize = maxSize;
    return 0;
}

size_t CacheManager::GetMaxSize() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.maxSize;
}

int CacheManager::SetMaxEntries(int maxEntries)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (maxEntries <= 0) {
        return CACHE_ERR_INVALID_PARAM;
    }
    config_.maxEntries = maxEntries;
    return 0;
}

int CacheManager::GetMaxEntries() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.maxEntries;
}

int CacheManager::SetDefaultTTL(int ttl)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (ttl <= 0) {
        return CACHE_ERR_INVALID_PARAM;
    }
    config_.defaultTTL = ttl;
    return 0;
}

int CacheManager::GetDefaultTTL() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.defaultTTL;
}

int CacheManager::SetEvictionPolicy(CacheEvictionPolicy policy)
{
    std::lock_guard<std::mutex> lock(mutex_);
    config_.evictionPolicy = policy;
    return 0;
}

CacheEvictionPolicy CacheManager::GetEvictionPolicy() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.evictionPolicy;
}

int CacheManager::EnableCompression(bool enable)
{
    std::lock_guard<std::mutex> lock(mutex_);
    config_.enableCompression = enable;
    return 0;
}

bool CacheManager::IsCompressionEnabled() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.enableCompression;
}

int CacheManager::EnableEncryption(bool enable)
{
    std::lock_guard<std::mutex> lock(mutex_);
    config_.enableEncryption = enable;
    return 0;
}

bool CacheManager::IsEncryptionEnabled() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.enableEncryption;
}

int CacheManager::EnableStats(bool enable)
{
    std::lock_guard<std::mutex> lock(mutex_);
    config_.enableStats = enable;
    return 0;
}

bool CacheManager::IsStatsEnabled() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.enableStats;
}

int CacheManager::OptimizeCache()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return CACHE_ERR_NOT_INITIALIZED;
    }

    RemoveExpiredInternal();
    CompactCacheInternal();

    stats_.lastCompactionAt = std::chrono::system_clock::now();
    return 0;
}

int CacheManager::CompactCache()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return CACHE_ERR_NOT_INITIALIZED;
    }
    CompactCacheInternal();
    return 0;
}

int CacheManager::DefragmentCache()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return CACHE_ERR_NOT_INITIALIZED;
    }
    return 0;
}

int CacheManager::ShrinkCache(size_t targetSize)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return CACHE_ERR_NOT_INITIALIZED;
    }

    int count = 0;
    while (stats_.totalSize > targetSize && !cache_.empty()) {
        if (EvictEntry() != 0) {
            break;
        }
        count++;
    }
    return count;
}

int CacheManager::WarmupCache(const std::vector<std::string> &keys)
{
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.warmupCount += static_cast<int>(keys.size());
    return 0;
}

int CacheManager::PreloadTable(const std::string &tableName)
{
    (void)tableName;
    return 0;
}

int CacheManager::PreloadQuery(const std::string &queryHash)
{
    (void)queryHash;
    return 0;
}

int CacheManager::SaveToDisk(const std::string &path)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return CACHE_ERR_NOT_INITIALIZED;
    }
    (void)path;
    stats_.persistenceCount++;
    return 0;
}

int CacheManager::LoadFromDisk(const std::string &path)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return CACHE_ERR_NOT_INITIALIZED;
    }
    (void)path;
    return 0;
}

int CacheManager::EnablePersistence(bool enable, const std::string &path)
{
    std::lock_guard<std::mutex> lock(mutex_);
    config_.enablePersistence = enable;
    if (!path.empty()) {
        config_.persistencePath = path;
    }
    return 0;
}

bool CacheManager::IsPersistenceEnabled() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.enablePersistence;
}

int CacheManager::SetHighWaterMark(double mark)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (mark <= 0.0 || mark > 1.0) {
        return CACHE_ERR_INVALID_PARAM;
    }
    config_.highWaterMark = mark;
    return 0;
}

double CacheManager::GetHighWaterMark() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.highWaterMark;
}

int CacheManager::SetLowWaterMark(double mark)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (mark <= 0.0 || mark > 1.0) {
        return CACHE_ERR_INVALID_PARAM;
    }
    config_.lowWaterMark = mark;
    return 0;
}

double CacheManager::GetLowWaterMark() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.lowWaterMark;
}

size_t CacheManager::GetMemoryUsage() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_.totalSize;
}

double CacheManager::GetMemoryUtilization() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (config_.maxSize == 0) {
        return 0.0;
    }
    return static_cast<double>(stats_.totalSize) / config_.maxSize * PERCENT_FACTOR;
}

size_t CacheManager::GetAvailableMemory() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (stats_.totalSize >= config_.maxSize) {
        return 0;
    }
    return config_.maxSize - stats_.totalSize;
}

std::vector<std::string> CacheManager::GetKeys() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> keys;
    keys.reserve(cache_.size());
    for (const auto &pair : cache_) {
        keys.push_back(pair.first);
    }
    return keys;
}

std::vector<std::string> CacheManager::GetKeysByTable(const std::string &tableName) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> keys;
    for (const auto &pair : cache_) {
        if (pair.second.tableName == tableName) {
            keys.push_back(pair.first);
        }
    }
    return keys;
}

std::vector<std::string> CacheManager::GetKeysByPattern(const std::string &pattern) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> keys;
    std::regex patternRegex(pattern);
    for (const auto &pair : cache_) {
        if (std::regex_match(pair.first, patternRegex)) {
            keys.push_back(pair.first);
        }
    }
    return keys;
}

int CacheManager::GetEntryCount() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<int>(cache_.size());
}

int CacheManager::GetEntryCountByTable(const std::string &tableName) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tableEntryCount_.find(tableName);
    if (it == tableEntryCount_.end()) {
        return 0;
    }
    return it->second;
}

int CacheManager::RegisterCacheCallback(
    const std::string &eventType, std::function<void(const std::string &, CacheEntryStatus)> callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    (void)eventType;
    int callbackId = ++callbackIdCounter_;
    callbacks_[callbackId] = std::move(callback);
    return callbackId;
}

int CacheManager::UnregisterCacheCallback(int callbackId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = callbacks_.find(callbackId);
    if (it == callbacks_.end()) {
        return CACHE_ERR_CALLBACK_NOT_FOUND;
    }
    callbacks_.erase(it);
    return 0;
}

int CacheManager::SetCleanupInterval(int intervalMs)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (intervalMs <= 0) {
        return CACHE_ERR_INVALID_PARAM;
    }
    config_.cleanupInterval = intervalMs;
    return 0;
}

int CacheManager::GetCleanupInterval() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.cleanupInterval;
}

int CacheManager::TriggerCleanup()
{
    return RemoveExpired();
}

int CacheManager::SetCompressionLevel(int level)
{
    (void)level;
    return 0;
}

int CacheManager::GetCompressionLevel() const
{
    return DEFAULT_COMPRESSION_LEVEL;
}

double CacheManager::GetCompressionRatio() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_.compressionRatio;
}

int CacheManager::SetEncryptionKey(const std::string &key)
{
    std::lock_guard<std::mutex> lock(mutex_);
    encryptionKeyHash_ = "hash_" + std::to_string(key.length());
    return 0;
}

std::string CacheManager::GetEncryptionKeyHash() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return encryptionKeyHash_;
}

int CacheManager::Prefetch(const std::string &key, std::function<std::vector<uint8_t>()> loader)
{
    if (Contains(key)) {
        return 0;
    }
    auto value = loader();
    if (value.empty()) {
        return CACHE_ERR_LOADER_EMPTY;
    }
    return Put(key, value);
}

int CacheManager::PrefetchBatch(
    const std::vector<std::string> &keys, std::function<std::vector<uint8_t>(const std::string &)> loader)
{
    int count = 0;
    for (const auto &key : keys) {
        if (Prefetch(key, [&loader, &key]() { return loader(key); }) == 0) {
            count++;
        }
    }
    return count;
}

int CacheManager::SetCacheable(const std::string &key, bool cacheable)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return CACHE_ERR_KEY_NOT_FOUND;
    }
    if (!cacheable) {
        it->second.status = CacheEntryStatus::STATUS_INVALID;
    } else {
        it->second.status = CacheEntryStatus::STATUS_VALID;
    }
    return 0;
}

bool CacheManager::IsCacheable(const std::string &key) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return false;
    }
    return it->second.status != CacheEntryStatus::STATUS_INVALID;
}

int CacheManager::Touch(const std::string &key)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return CACHE_ERR_KEY_NOT_FOUND;
    }
    UpdateAccessInfo(it->second);
    return 0;
}

int CacheManager::Promote(const std::string &key)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return CACHE_ERR_KEY_NOT_FOUND;
    }
    it->second.priority++;
    return 0;
}

int CacheManager::Demote(const std::string &key)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return CACHE_ERR_KEY_NOT_FOUND;
    }
    if (it->second.priority > 0) {
        it->second.priority--;
    }
    return 0;
}

int CacheManager::SetMetadata(const std::string &key, const std::string &metaKey, const std::string &metaValue)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return CACHE_ERR_KEY_NOT_FOUND;
    }
    it->second.metadata[metaKey] = metaValue;
    return 0;
}

std::string CacheManager::GetMetadata(const std::string &key, const std::string &metaKey) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return "";
    }
    auto metaIt = it->second.metadata.find(metaKey);
    if (metaIt == it->second.metadata.end()) {
        return "";
    }
    return metaIt->second;
}

std::map<std::string, std::string> CacheManager::GetAllMetadata(const std::string &key) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return {};
    }
    return it->second.metadata;
}

int CacheManager::SetVersion(const std::string &key, int version)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return CACHE_ERR_KEY_NOT_FOUND;
    }
    it->second.version = version;
    return 0;
}

int CacheManager::IncrementVersion(const std::string &key)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return CACHE_ERR_KEY_NOT_FOUND;
    }
    it->second.version++;
    return it->second.version;
}

bool CacheManager::IsVersionValid(const std::string &key, int expectedVersion) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return false;
    }
    return it->second.version == expectedVersion;
}

int CacheManager::SetETag(const std::string &key, const std::string &etag)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return CACHE_ERR_KEY_NOT_FOUND;
    }
    it->second.etag = etag;
    return 0;
}

std::string CacheManager::GetETag(const std::string &key) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return "";
    }
    return it->second.etag;
}

bool CacheManager::IsETagValid(const std::string &key, const std::string &expectedETag) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return false;
    }
    return it->second.etag == expectedETag;
}

int CacheManager::SetCacheableTable(const std::string &tableName, bool cacheable)
{
    std::lock_guard<std::mutex> lock(mutex_);
    tableCacheable_[tableName] = cacheable;
    return 0;
}

bool CacheManager::IsCacheableTable(const std::string &tableName) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tableCacheable_.find(tableName);
    if (it == tableCacheable_.end()) {
        return true;
    }
    return it->second;
}

std::vector<std::string> CacheManager::GetCacheableTables() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> tables;
    for (const auto &pair : tableCacheable_) {
        if (pair.second) {
            tables.push_back(pair.first);
        }
    }
    return tables;
}

int CacheManager::SetTableTTL(const std::string &tableName, int ttl)
{
    std::lock_guard<std::mutex> lock(mutex_);
    tableTTL_[tableName] = ttl;
    return 0;
}

int CacheManager::GetTableTTL(const std::string &tableName) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tableTTL_.find(tableName);
    if (it == tableTTL_.end()) {
        return config_.defaultTTL;
    }
    return it->second;
}

int CacheManager::SetTablePriority(const std::string &tableName, int priority)
{
    std::lock_guard<std::mutex> lock(mutex_);
    tablePriority_[tableName] = priority;
    return 0;
}

int CacheManager::GetTablePriority(const std::string &tableName) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tablePriority_.find(tableName);
    if (it == tablePriority_.end()) {
        return 0;
    }
    return it->second;
}

int CacheManager::SetTableMaxEntries(const std::string &tableName, int maxEntries)
{
    std::lock_guard<std::mutex> lock(mutex_);
    tableMaxEntries_[tableName] = maxEntries;
    return 0;
}

int CacheManager::GetTableMaxEntries(const std::string &tableName) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tableMaxEntries_.find(tableName);
    if (it == tableMaxEntries_.end()) {
        return config_.maxEntries;
    }
    return it->second;
}

int CacheManager::SetTableEvictionPolicy(const std::string &tableName, CacheEvictionPolicy policy)
{
    std::lock_guard<std::mutex> lock(mutex_);
    tableEvictionPolicy_[tableName] = policy;
    return 0;
}

CacheEvictionPolicy CacheManager::GetTableEvictionPolicy(const std::string &tableName) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tableEvictionPolicy_.find(tableName);
    if (it == tableEvictionPolicy_.end()) {
        return config_.evictionPolicy;
    }
    return it->second;
}

int CacheManager::DumpCacheInfo(std::string &info) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream oss;
    oss << "Cache Info:\n";
    oss << "  Total Entries: " << stats_.totalEntries << "\n";
    oss << "  Total Size: " << stats_.totalSize << " bytes\n";
    oss << "  Max Size: " << config_.maxSize << " bytes\n";
    oss << "  Max Entries: " << config_.maxEntries << "\n";
    oss << "  Hit Rate: " << (stats_.hitRate * PERCENT_FACTOR) << "%\n";
    oss << "  Hit Count: " << stats_.hitCount << "\n";
    oss << "  Miss Count: " << stats_.missCount << "\n";
    oss << "  Eviction Count: " << stats_.evictionCount << "\n";
    oss << "  Expiration Count: " << stats_.expirationCount << "\n";
    info = oss.str();
    return 0;
}

int CacheManager::DumpCacheEntries(std::vector<CacheEntry> &entries) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    entries.clear();
    entries.reserve(cache_.size());
    for (const auto &pair : cache_) {
        entries.push_back(pair.second);
    }
    return 0;
}

int CacheManager::DumpTableInfo(const std::string &tableName, std::string &info) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream oss;
    oss << "Table Cache Info: " << tableName << "\n";

    auto it = tableEntryCount_.find(tableName);
    oss << "  Entry Count: " << (it != tableEntryCount_.end() ? it->second : 0) << "\n";

    auto ttlIt = tableTTL_.find(tableName);
    oss << "  TTL: " << (ttlIt != tableTTL_.end() ? ttlIt->second : config_.defaultTTL) << "ms\n";

    auto prioIt = tablePriority_.find(tableName);
    oss << "  Priority: " << (prioIt != tablePriority_.end() ? prioIt->second : 0) << "\n";

    info = oss.str();
    return 0;
}

int CacheManager::EvictEntry()
{
    switch (config_.evictionPolicy) {
        case CacheEvictionPolicy::POLICY_LRU:
            return EvictByLRU();
        case CacheEvictionPolicy::POLICY_LFU:
            return EvictByLFU();
        case CacheEvictionPolicy::POLICY_FIFO:
            return EvictByFIFO();
        case CacheEvictionPolicy::POLICY_RANDOM:
            return EvictByRandom();
        case CacheEvictionPolicy::POLICY_TTL:
            return EvictByTTL();
        case CacheEvictionPolicy::POLICY_ADAPTIVE:
            return EvictByAdaptive();
        case CacheEvictionPolicy::POLICY_WEIGHTED:
            return EvictByWeighted();
        default:
            return EvictByLRU();
    }
}

int CacheManager::EvictByLRU()
{
    if (lruList_.empty()) {
        return CACHE_ERR_CACHE_EMPTY;
    }

    std::string key = lruList_.back();
    size_t removedSize = RemoveEntryFromCache(key);
    if (removedSize > 0) {
        stats_.totalSize -= removedSize;
        stats_.evictionCount++;
    }

    return 0;
}

int CacheManager::EvictByLFU()
{
    if (cache_.empty()) {
        return CACHE_ERR_CACHE_EMPTY;
    }

    std::string minKey;
    int minAccess = std::numeric_limits<int>::max();

    for (const auto &pair : cache_) {
        if (pair.second.accessCount < minAccess) {
            minAccess = pair.second.accessCount;
            minKey = pair.first;
        }
    }

    if (!minKey.empty()) {
        size_t removedSize = RemoveEntryFromCache(minKey);
        if (removedSize > 0) {
            stats_.totalSize -= removedSize;
            stats_.evictionCount++;
        }
    }

    return 0;
}

int CacheManager::EvictByFIFO()
{
    if (lruList_.empty()) {
        return CACHE_ERR_CACHE_EMPTY;
    }

    std::string key = lruList_.back();
    size_t removedSize = RemoveEntryFromCache(key);
    if (removedSize > 0) {
        stats_.totalSize -= removedSize;
        stats_.evictionCount++;
    }

    return 0;
}

int CacheManager::EvictByRandom()
{
    if (cache_.empty()) {
        return CACHE_ERR_CACHE_EMPTY;
    }

    auto it = cache_.begin();
    std::advance(it, std::rand() % cache_.size());

    std::string key = it->first;
    size_t removedSize = RemoveEntryFromCache(key);
    if (removedSize > 0) {
        stats_.totalSize -= removedSize;
        stats_.evictionCount++;
    }

    return 0;
}

int CacheManager::EvictByTTL()
{
    if (cache_.empty()) {
        return CACHE_ERR_CACHE_EMPTY;
    }

    auto now = std::chrono::system_clock::now();
    std::string minKey;
    auto minExpiry = now + std::chrono::hours(TTL_EVICT_MAX_HOURS);

    for (const auto &pair : cache_) {
        if (pair.second.expiresAt < minExpiry) {
            minExpiry = pair.second.expiresAt;
            minKey = pair.first;
        }
    }

    if (!minKey.empty()) {
        size_t removedSize = RemoveEntryFromCache(minKey);
        if (removedSize > 0) {
            stats_.totalSize -= removedSize;
            stats_.evictionCount++;
        }
    }

    return 0;
}

int CacheManager::EvictByAdaptive()
{
    double utilization = GetMemoryUtilization();
    if (utilization > config_.highWaterMark * PERCENT_FACTOR) {
        return EvictByLRU();
    }
    return EvictByLFU();
}

int CacheManager::EvictByWeighted()
{
    if (cache_.empty()) {
        return CACHE_ERR_CACHE_EMPTY;
    }

    std::string minKey;
    double minScore = std::numeric_limits<double>::max();

    auto now = std::chrono::system_clock::now();
    for (const auto &pair : cache_) {
        double age = std::chrono::duration<double>(now - pair.second.lastAccessedAt).count();
        double score =
            static_cast<double>(pair.second.accessCount) / (age > 0 ? age : 1.0) * (pair.second.priority + 1);

        if (score < minScore) {
            minScore = score;
            minKey = pair.first;
        }
    }

    if (!minKey.empty()) {
        size_t removedSize = RemoveEntryFromCache(minKey);
        if (removedSize > 0) {
            stats_.totalSize -= removedSize;
            stats_.evictionCount++;
        }
    }

    return 0;
}

int CacheManager::CompressValue(const std::vector<uint8_t> &input, std::vector<uint8_t> &output)
{
    output = input;
    return 0;
}

int CacheManager::DecompressValue(const std::vector<uint8_t> &input, std::vector<uint8_t> &output)
{
    output = input;
    return 0;
}

int CacheManager::EncryptValue(const std::vector<uint8_t> &input, std::vector<uint8_t> &output)
{
    output = input;
    return 0;
}

int CacheManager::DecryptValue(const std::vector<uint8_t> &input, std::vector<uint8_t> &output)
{
    output = input;
    return 0;
}

bool CacheManager::IsExpired(const CacheEntry &entry) const
{
    return std::chrono::system_clock::now() > entry.expiresAt;
}

void CacheManager::UpdateAccessInfo(CacheEntry &entry)
{
    entry.accessCount++;
    entry.lastAccessedAt = std::chrono::system_clock::now();
}

void CacheManager::UpdateStatistics(const std::string &operation, double duration)
{
    if (!config_.enableStats) {
        return;
    }

    if (operation == "get") {
        int totalAccess = stats_.hitCount + stats_.missCount;
        stats_.averageAccessTime = (stats_.averageAccessTime * (totalAccess - 1) + duration) / totalAccess;
    }

    if (stats_.totalEntries > 0) {
        stats_.averageEntrySize = static_cast<double>(stats_.totalSize) / stats_.totalEntries;
    }

    if (stats_.compressionCount > 0) {
        stats_.compressionRatio = 1.0;
    }
}

void CacheManager::NotifyCallbacks(const std::string &key, CacheEntryStatus status)
{
    for (const auto &pair : callbacks_) {
        if (pair.second) {
            pair.second(key, status);
        }
    }
}

int CacheManager::ValidateKey(const std::string &key) const
{
    if (key.empty()) {
        return CACHE_ERR_KEY_EMPTY;
    }
    if (key.length() > MAX_KEY_LENGTH) {
        return CACHE_ERR_KEY_TOO_LONG;
    }
    return 0;
}

int CacheManager::ValidateValue(const std::vector<uint8_t> &value) const
{
    if (value.size() > config_.maxEntrySize) {
        return CACHE_ERR_VALUE_TOO_LARGE;
    }
    return 0;
}

size_t CacheManager::CalculateEntrySize(const CacheEntry &entry) const
{
    return entry.key.size() + entry.value.size() + entry.tableName.size() + entry.queryHash.size() +
           entry.etag.size() + sizeof(CacheEntry) + entry.metadata.size() * METADATA_ENTRY_SIZE_ESTIMATE;
}

void CacheManager::CleanupThread()
{
    while (!stopThreads_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.cleanupInterval));

        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) {
            continue;
        }

        RemoveExpiredInternal();

        stats_.lastCleanupAt = std::chrono::system_clock::now();
    }
}

void CacheManager::CompactionThread()
{
    while (!stopThreads_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(DEFAULT_COMPACTION_INTERVAL_MS));

        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) {
            continue;
        }

        CompactCacheInternal();
        stats_.lastCompactionAt = std::chrono::system_clock::now();
    }
}

void CacheManager::RemoveExpiredInternal()
{
    std::vector<std::string> expiredKeys;
    for (const auto &pair : cache_) {
        if (IsExpired(pair.second)) {
            expiredKeys.push_back(pair.first);
        }
    }

    for (const auto &key : expiredKeys) {
        size_t removedSize = RemoveEntryFromCache(key);
        if (removedSize > 0) {
            stats_.totalSize -= removedSize;
            stats_.expirationCount++;
        }
    }

    stats_.totalEntries = static_cast<int>(cache_.size());
}

void CacheManager::CompactCacheInternal()
{
    stats_.memorySaved = 0;
}

} // namespace Rdb
} // namespace OHOS