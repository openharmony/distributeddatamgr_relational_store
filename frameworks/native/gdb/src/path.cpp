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
#define LOG_TAG "GdbPath"
#include "path.h"

#include "gdb_errors.h"
#include "path_segment.h"
#include "grd_error.h"
#include "logger.h"

namespace OHOS::DistributedDataAip {
Path::Path(std::shared_ptr<Vertex> start, std::shared_ptr<Vertex> end) : start_(start), end_(end)
{
    pathLen_ = 0;
}

Path::Path(std::shared_ptr<Vertex> start, std::shared_ptr<Vertex> end, uint32_t pathLen,
    std::vector<std::shared_ptr<PathSegment>> segments)
    : pathLen_(pathLen), start_(start),  end_(end), segments_(std::move(segments))
{
}

Path::Path() : pathLen_(0), start_(nullptr), end_(nullptr), segments_()
{
}

uint32_t Path::GetPathLength() const
{
    return pathLen_;
}

void Path::SetPathLength(uint32_t pathLen)
{
    this->pathLen_ = pathLen;
}

std::shared_ptr<Vertex> Path::GetStart() const
{
    return start_;
}

void Path::SetStart(std::shared_ptr<Vertex> start)
{
    this->start_ = start;
}

std::shared_ptr<Vertex> Path::GetEnd() const
{
    return end_;
}

void Path::SetEnd(std::shared_ptr<Vertex> end)
{
    this->end_ = end;
}

const std::vector<std::shared_ptr<PathSegment>> &Path::GetSegments() const
{
    return segments_;
}

bool Path::Marshal(json &node) const
{
    return false;
}

bool Path::Unmarshal(const json &node)
{
    bool isUnmarshalSuccess = true;
    isUnmarshalSuccess = GetValue(node, PATHLEN, pathLen_) && isUnmarshalSuccess;
    if (start_ == nullptr) {
        start_ = std::make_shared<Vertex>();
    }
    isUnmarshalSuccess = GetValue(node, START, start_) && isUnmarshalSuccess;
    if (end_ == nullptr) {
        end_ = std::make_shared<Vertex>();
    }
    isUnmarshalSuccess = GetValue(node, END, end_) && isUnmarshalSuccess;

    isUnmarshalSuccess = GetValue(node, SEGMENTS, segments_) && isUnmarshalSuccess;
    return isUnmarshalSuccess;
}

std::shared_ptr<Path> Path::Parse(const std::string &jsonStr, int32_t &errCode)
{
    Path path;
    if (!Serializable::Unmarshall(jsonStr, path)) {
        LOG_WARN("Parse path failed.");
        errCode = E_PARSE_JSON_FAILED;
        return nullptr;
    }
    errCode = E_OK;
    return std::make_shared<Path>(path);
}
} // namespace OHOS::DistributedDataAip
