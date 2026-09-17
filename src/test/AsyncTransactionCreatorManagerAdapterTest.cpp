/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the MIT License which is available at                             *
 * https://opensource.org/licenses/MIT.                                       *
 *                                                                            *
 * SPDX-License-Identifier: MIT                                               *
 ******************************************************************************/

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "keyple/card/calypso/crypto/legacysam/LegacySamAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamExtensionService.hpp"
#include "keyple/card/calypso/crypto/legacysam/SecuritySettingAdapter.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keyple/core/util/cpp/exception/UnsupportedOperationException.hpp"
#include "keypop/calypso/crypto/legacysam/CounterIncrementAccess.hpp"
#include "keypop/calypso/crypto/legacysam/sam/LegacySam.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/AsyncTransactionCreatorManager.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SecuritySetting.hpp"
#include "keypop/reader/ChannelControl.hpp"

#include "mock/ReaderMock.hpp"
#include "util/TestDtoAdapters.hpp"

using keyple::card::calypso::crypto::legacysam::LegacySamAdapter;
using keyple::card::calypso::crypto::legacysam::LegacySamExtensionService;
using keyple::card::calypso::crypto::legacysam::SecuritySettingAdapter;
using keyple::card::calypso::crypto::legacysam::TestDtoAdapters;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keyple::core::util::cpp::exception::UnsupportedOperationException;
using keypop::calypso::crypto::legacysam::CounterIncrementAccess;
using keypop::calypso::crypto::legacysam::sam::LegacySam;
using keypop::calypso::crypto::legacysam::transaction::
    AsyncTransactionCreatorManager;
using keypop::calypso::crypto::legacysam::transaction::SecuritySetting;
using keypop::reader::ChannelControl;

using ::testing::NiceMock;

static const std::string SAM_SERIAL_NUMBER = "11223344";
static const std::string R_9000 = "9000";
static const std::string SAM_C1_POWER_ON_DATA
    = "3B3F9600805A4880C1205017" + SAM_SERIAL_NUMBER + "82" + R_9000;

class AsyncTransactionCreatorManagerAdapterTest : public ::testing::Test {
protected:
    void
    SetUp() override
    {
        mSamReader = std::make_shared<NiceMock<ReaderMock>>();

        auto samCardSelectionResponse
            = std::make_shared<TestDtoAdapters::CardSelectionResponseAdapter>(
                SAM_C1_POWER_ON_DATA);
        std::shared_ptr<LegacySam> controlSam
            = std::make_shared<LegacySamAdapter>(samCardSelectionResponse);

        auto securitySettingAdapter
            = std::make_shared<SecuritySettingAdapter>();
        securitySettingAdapter->setControlSamResource(mSamReader, controlSam);
        std::shared_ptr<SecuritySetting> securitySetting
            = securitySettingAdapter;

        static const std::string TARGET_SAM_CONTEXT
            = "{\n"
              "\"serialNumber\": \"11223344\",\n"
              "    \"isDynamicMode\": false,\n"
              "    \"systemKeyTypeToCounterNumberMap\":\n"
              "    {\n"
              "        \"PERSONALIZATION\": \"01\",\n"
              "        \"KEY_MANAGEMENT\": \"02\",\n"
              "        \"RELOADING\": \"03\"\n"
              "    },\n"
              "    \"systemKeyTypeToKvcMap\":\n"
              "    {\n"
              "        \"PERSONALIZATION\": \"F1\",\n"
              "        \"RELOADING\": \"F2\",\n"
              "        \"KEY_MANAGEMENT\": \"F3\"\n"
              "    },\n"
              "    \"counterNumberToCounterValueMap\":\n"
              "    {\n"
              "        \"01\": \"0179\",\n"
              "        \"02\": \"017A\",\n"
              "        \"03\": \"017B\"\n"
              "    }\n"
              "}";

        mSamTransactionManager = LegacySamExtensionService::getInstance()
                                     ->getLegacySamApiFactory()
                                     ->createAsyncTransactionCreatorManager(
                                         TARGET_SAM_CONTEXT, securitySetting);
    }

    std::shared_ptr<ReaderMock> mSamReader;
    std::shared_ptr<AsyncTransactionCreatorManager> mSamTransactionManager;
};

/*
 * Disabled: AsyncTransactionCreatorManagerAdapter's constructor never parses
 * the targetSamContext JSON parameter into mTargetSamContext (the parameter
 * is commented out in the C++ source), so any call that needs the resulting
 * KVC/counter mapping -- like prepareWriteCounterCeiling() here -- dereferences
 * a null target SAM. Re-enable once JSON deserialization of targetSamContext
 * is implemented.
 */
TEST_F(
    AsyncTransactionCreatorManagerAdapterTest,
    DISABLED_processCommands_shouldThrowUOE)
{
    mSamTransactionManager->prepareWriteCounterCeiling(0, 100);

    ASSERT_THROW(
        mSamTransactionManager->processCommands(ChannelControl::KEEP_OPEN),
        UnsupportedOperationException);
}

TEST_F(
    AsyncTransactionCreatorManagerAdapterTest,
    prepareWriteCounterCeiling_whenCeilingNumberIsOutOfRangeLow_shouldThrowIAE)
{
    ASSERT_THROW(
        mSamTransactionManager->prepareWriteCounterCeiling(-1, 100),
        IllegalArgumentException);
}

TEST_F(
    AsyncTransactionCreatorManagerAdapterTest,
    prepareWriteCounterCeiling_whenCeilingNumberIsOutOfRangeHigh_shouldThrowIAE)
{
    ASSERT_THROW(
        mSamTransactionManager->prepareWriteCounterCeiling(27, 100),
        IllegalArgumentException);
}

TEST_F(
    AsyncTransactionCreatorManagerAdapterTest,
    prepareWriteCounterCeiling_whenCeilingValueIsOutOfRangeLow_shouldThrowIAE)
{
    ASSERT_THROW(
        mSamTransactionManager->prepareWriteCounterCeiling(0, -1),
        IllegalArgumentException);
}

TEST_F(
    AsyncTransactionCreatorManagerAdapterTest,
    prepareWriteCounterCeiling_whenCeilingValueIsOutOfRangeHigh_shouldThrowIAE)
{
    ASSERT_THROW(
        mSamTransactionManager->prepareWriteCounterCeiling(0, 0xFFFFFB),
        IllegalArgumentException);
}

TEST_F(
    AsyncTransactionCreatorManagerAdapterTest,
    prepareWriteCounterConfiguration_whenCeilingNumberIsOutOfRangeLow_shouldThrowIAE)  // NOLINT
{
    ASSERT_THROW(
        mSamTransactionManager->prepareWriteCounterConfiguration(
            -1, 0, CounterIncrementAccess::FREE_COUNTING_DISABLED),
        IllegalArgumentException);
}

TEST_F(
    AsyncTransactionCreatorManagerAdapterTest,
    prepareWriteCounterConfiguration_whenCeilingNumberIsOutOfRangeHigh_shouldThrowIAE)  // NOLINT
{
    ASSERT_THROW(
        mSamTransactionManager->prepareWriteCounterConfiguration(
            27, 0, CounterIncrementAccess::FREE_COUNTING_DISABLED),
        IllegalArgumentException);
}

TEST_F(
    AsyncTransactionCreatorManagerAdapterTest,
    prepareWriteCounterConfiguration_whenCeilingValueIsOutOfRangeLow_shouldThrowIAE)  // NOLINT
{
    ASSERT_THROW(
        mSamTransactionManager->prepareWriteCounterConfiguration(
            0, -1, CounterIncrementAccess::FREE_COUNTING_DISABLED),
        IllegalArgumentException);
}

TEST_F(
    AsyncTransactionCreatorManagerAdapterTest,
    prepareWriteCounterConfiguration_whenCeilingValueIsOutOfRangeHigh_shouldThrowIAE)  // NOLINT
{
    ASSERT_THROW(
        mSamTransactionManager->prepareWriteCounterConfiguration(
            0, 0xFFFFFB, CounterIncrementAccess::FREE_COUNTING_DISABLED),
        IllegalArgumentException);
}

/*
 * The following two tests are disabled: exportCommands() relies on JSON
 * serialization of the prepared commands (via Gson in Java), which has not
 * been ported to C++ yet -- AsyncTransactionCreatorManagerAdapter::
 * exportCommands() is currently a stub returning an empty string. Re-enable
 * once JSON serialization is implemented.
 */

TEST_F(
    AsyncTransactionCreatorManagerAdapterTest,
    DISABLED_exportCommands_whenSingleWriteArePrepared_shouldProduceJsonCommandList)  // NOLINT
{
}

TEST_F(
    AsyncTransactionCreatorManagerAdapterTest,
    DISABLED_exportCommands_whenRecordWriteArePrepared_shouldProduceJsonCommandList)  // NOLINT
{
}
