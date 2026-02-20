/**
 * Copyright © 2026
 *
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
#include "config.h"

#include "paths.hpp"

#include <filesystem>
#include <string>

#include <gtest/gtest.h>

namespace fs = std::filesystem;

/**
 * Test the error() function returns expected path
 */
TEST(PathsTest, ErrorPathReturnsCorrectPath)
{
    auto errorPath = phosphor::logging::paths::error();

    // The path should be PERSIST_PATH_ROOT + "/errors"
    std::string expectedPath = std::string(PERSIST_PATH_ROOT) + "/errors";

    EXPECT_EQ(errorPath.string(), expectedPath);
}

/**
 * Test the extension() function returns expected path
 */
TEST(PathsTest, ExtensionPathReturnsCorrectPath)
{
    auto extensionPath = phosphor::logging::paths::extension();

    // The path should be PERSIST_PATH_ROOT + "/extensions"
    std::string expectedPath = std::string(PERSIST_PATH_ROOT) + "/extensions";

    EXPECT_EQ(extensionPath.string(), expectedPath);
}

/**
 * Test that paths are not empty
 */
TEST(PathsTest, PathsAreNotEmpty)
{
    auto errorPath = phosphor::logging::paths::error();
    auto extensionPath = phosphor::logging::paths::extension();

    EXPECT_FALSE(errorPath.empty());
    EXPECT_FALSE(extensionPath.empty());
}

/**
 * Test that paths are absolute (assuming PERSIST_PATH_ROOT is absolute)
 */
TEST(PathsTest, PathsAreValid)
{
    auto errorPath = phosphor::logging::paths::error();
    auto extensionPath = phosphor::logging::paths::extension();

    // Paths should have the root component
    EXPECT_TRUE(errorPath.has_root_path());
    EXPECT_TRUE(extensionPath.has_root_path());
}

/**
 * Test that error and extension paths are different
 */
TEST(PathsTest, ErrorAndExtensionPathsAreDifferent)
{
    auto errorPath = phosphor::logging::paths::error();
    auto extensionPath = phosphor::logging::paths::extension();

    EXPECT_NE(errorPath, extensionPath);
}
