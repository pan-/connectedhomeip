/*
 *
 *    Copyright (c) 2021 Project CHIP Authors
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#pragma once

#include <app/common/gen/af-structs.h>

#include <core/CHIPError.h>
#include <string>
#include <vector>

class MediaInputManager
{
public:
    CHIP_ERROR Init();
    std::vector<EmberAfMediaInputInfo> proxyGetInputList();
    bool proxySelectInputRequest(uint8_t input);
    bool proxyShowInputStatusRequest();
    bool proxyHideInputStatusRequest();
    bool proxyRenameInputRequest(uint8_t input, std::string name);
};