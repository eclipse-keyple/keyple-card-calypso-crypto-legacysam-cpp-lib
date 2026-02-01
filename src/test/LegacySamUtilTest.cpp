/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the MIT License which is available at                             *
 * https://opensource.org/licenses/MIT.                                       *
 *                                                                            *
 * SPDX-License-Identifier: MIT                                               *
 ******************************************************************************/

#include <regex>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "keyple/card/calypso/crypto/legacysam/LegacySamUtil.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keypop/calypso/crypto/legacysam/sam/LegacySam.hpp"

using keyple::card::calypso::crypto::legacysam::LegacySamUtil;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keypop::calypso::crypto::legacysam::sam::LegacySam;

TEST(LegacySamUtilTest, buildPowerOnDataFilter_whenSamC1_shouldBuildRightRegex)
{
    const std::string actual = LegacySamUtil::buildPowerOnDataFilter(
        LegacySam::ProductType::SAM_C1, "12345678");
    const std::string expected = "3B(.{6}|.{10})805A..80C1.{6}12345678829000";

    ASSERT_EQ(actual, expected);
}

TEST(LegacySamUtilTest, buildPowerOnDataFilter_whenHsmC1_shouldBuildRightRegex)
{
    const std::string actual = LegacySamUtil::buildPowerOnDataFilter(
        LegacySam::ProductType::HSM_C1, "87654321");
    const std::string expected = "3B(.{6}|.{10})805A..80C1.{6}87654321829000";

    ASSERT_EQ(actual, expected);
}

TEST(
    LegacySamUtilTest, buildPowerOnDataFilter_whenSamS1DX_shouldBuildRightRegex)
{
    const std::string actual = LegacySamUtil::buildPowerOnDataFilter(
        LegacySam::ProductType::SAM_S1DX, "ABCDEFGH");
    const std::string expected = "3B(.{6}|.{10})805A..80D?.{6}ABCDEFGH829000";

    ASSERT_EQ(actual, expected);
}

TEST(
    LegacySamUtilTest, buildPowerOnDataFilter_whenSamS1E1_shouldBuildRightRegex)
{
    const std::string actual = LegacySamUtil::buildPowerOnDataFilter(
        LegacySam::ProductType::SAM_S1E1, "HGFEDCBA");
    const std::string expected = "3B(.{6}|.{10})805A..80E1.{6}HGFEDCBA829000";

    ASSERT_EQ(actual, expected);
}

TEST(LegacySamUtilTest, buildPowerOnDataFilter_whenUnknownRegex_shouldIAE)
{
    ASSERT_THROW(
        LegacySamUtil::buildPowerOnDataFilter(
            LegacySam::ProductType::UNKNOWN, "HGFEDCBA"),
        IllegalArgumentException);
}

// C++: does not apply as the regex cannot be null.
// TEST(
//     LegacySamUtilTest,
//     buildPowerOnDataFilter_whenNoSerialNumber_shouldBuildRightRegex)
// {
//     const std::string actual = LegacySamUtil::buildPowerOnDataFilter(
//         LegacySam::ProductType::SAM_C1, nullptr);
//     const std::string expected = "3B(.{6}|.{10})805A..80C1.{6}.{8}829000";
//
//     ASSERT_EQ(actual, expected);
// }
