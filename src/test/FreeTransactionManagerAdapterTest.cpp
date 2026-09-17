/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the MIT License which is available at                             *
 * https://opensource.org/licenses/MIT.                                       *
 *                                                                            *
 * SPDX-License-Identifier: MIT                                               *
 ******************************************************************************/

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamExtensionService.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keypop/calypso/crypto/legacysam/SystemKeyType.hpp"
#include "keypop/calypso/crypto/legacysam/sam/LegacySam.hpp"
#include "keypop/calypso/crypto/legacysam/spi/LegacySamRevocationServiceSpi.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/FreeTransactionManager.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/InvalidSignatureException.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SamRevokedException.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SamTraceabilityMode.hpp"
#include "keypop/card/CardSelectionResponseApi.hpp"
#include "keypop/card/spi/ApduRequestSpi.hpp"
#include "keypop/card/spi/CardRequestSpi.hpp"
#include "keypop/reader/ChannelControl.hpp"
#include "keypop/reader/InvalidCardResponseException.hpp"

#include "mock/ReaderMock.hpp"
#include "util/TestDtoAdapters.hpp"

using keyple::card::calypso::crypto::legacysam::DtoAdapters;
using keyple::card::calypso::crypto::legacysam::LegacySamAdapter;
using keyple::card::calypso::crypto::legacysam::LegacySamExtensionService;
using keyple::card::calypso::crypto::legacysam::TestDtoAdapters;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keyple::core::util::cpp::exception::IllegalStateException;
using keypop::calypso::crypto::legacysam::SystemKeyType;
using keypop::calypso::crypto::legacysam::sam::LegacySam;
using keypop::calypso::crypto::legacysam::spi::LegacySamRevocationServiceSpi;
using keypop::calypso::crypto::legacysam::transaction::
    BasicSignatureComputationData;
using keypop::calypso::crypto::legacysam::transaction::
    BasicSignatureVerificationData;
using keypop::calypso::crypto::legacysam::transaction::FreeTransactionManager;
using keypop::calypso::crypto::legacysam::transaction::
    InvalidSignatureException;
using keypop::calypso::crypto::legacysam::transaction::SamRevokedException;
using keypop::calypso::crypto::legacysam::transaction::SamTraceabilityMode;
using keypop::calypso::crypto::legacysam::transaction::
    TraceableSignatureComputationData;
using keypop::calypso::crypto::legacysam::transaction::
    TraceableSignatureVerificationData;
using keypop::card::ApduResponseApi;
using keypop::card::CardResponseApi;
using keypop::card::spi::ApduRequestSpi;
using keypop::card::spi::CardRequestSpi;
using keypop::reader::ChannelControl;
using keypop::reader::InvalidCardResponseException;

using ::testing::_;
using ::testing::InSequence;
using ::testing::NiceMock;
using ::testing::Return;

using BasicSignatureComputationDataAdapter
    = DtoAdapters::BasicSignatureComputationDataAdapter;
using BasicSignatureVerificationDataAdapter
    = DtoAdapters::BasicSignatureVerificationDataAdapter;
using TraceableSignatureComputationDataAdapter
    = DtoAdapters::TraceableSignatureComputationDataAdapter;
using TraceableSignatureVerificationDataAdapter
    = DtoAdapters::TraceableSignatureVerificationDataAdapter;

class LegacySamRevocationServiceSpiMock : public LegacySamRevocationServiceSpi {
public:
    MOCK_METHOD(
        bool,
        isSamRevoked,
        (const std::vector<uint8_t>& serialNumber),
        (const, override));
    MOCK_METHOD(
        bool,
        isSamRevoked,
        (const std::vector<uint8_t>& serialNumber, const int counterValue),
        (const, override));
};

namespace {

const std::string SAM_SERIAL_NUMBER = "11223344";
const std::string CIPHER_MESSAGE = "A1A2A3A4A5A6A7A8";
const std::string CIPHER_MESSAGE_SIGNATURE = "C1C2C3C4C5C6C7C8";
const std::string CIPHER_MESSAGE_INCORRECT_SIGNATURE = "C1C2C3C4C5C6C7C9";
const std::string CIPHER_MESSAGE_SIGNATURE_3_BYTES = "C1C2C3";
const std::string PSO_MESSAGE = "A1A2A3A4A5A6A7A8A9AA";
const std::string PSO_MESSAGE_SAM_TRACEABILITY = "B1B2B3B4B5B6B7B8B9BA";
const std::string PSO_MESSAGE_SIGNATURE = "C1C2C3C4C5C6C7C8";
const std::string SPECIFIC_KEY_DIVERSIFIER = "AABBCCDD";

const std::string R_9000 = "9000";
const std::string R_INCORRECT_SIGNATURE = "6988";

const std::string SAM_C1_POWER_ON_DATA
    = "3B3F9600805A4880C1205017" + SAM_SERIAL_NUMBER + "82" + R_9000;

const std::string C_SELECT_DIVERSIFIER = "8014000004" + SAM_SERIAL_NUMBER;
const std::string C_SELECT_DIVERSIFIER_SPECIFIC
    = "8014000004" + SPECIFIC_KEY_DIVERSIFIER;
const std::string C_DATA_CIPHER_DEFAULT = "801C40000A0102" + CIPHER_MESSAGE;
const std::string R_DATA_CIPHER_DEFAULT = CIPHER_MESSAGE_SIGNATURE + R_9000;

const std::string C_PSO_COMPUTE_SIGNATURE_DEFAULT
    = "802A9E9A0EFF010288" + PSO_MESSAGE;
const std::string R_PSO_COMPUTE_SIGNATURE_DEFAULT
    = PSO_MESSAGE_SIGNATURE + R_9000;

const std::string C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL
    = "802A9E9A10FF0102480001" + PSO_MESSAGE;
const std::string R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL
    = PSO_MESSAGE_SAM_TRACEABILITY + PSO_MESSAGE_SIGNATURE + R_9000;

const std::string C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL
    = "802A9E9A10FF0102680001" + PSO_MESSAGE;
const std::string R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL
    = PSO_MESSAGE_SAM_TRACEABILITY + PSO_MESSAGE_SIGNATURE + R_9000;

const std::string C_PSO_VERIFY_SIGNATURE_DEFAULT
    = "802A00A816FF010288" + PSO_MESSAGE + PSO_MESSAGE_SIGNATURE;

const std::string C_READ_EVENT_COUNTER_0_8 = "80BE00E100";
const std::string R_READ_EVENT_COUNTER_0_8
    = CIPHER_MESSAGE_SIGNATURE
      + "1000001111111222221333331444441555551666661777771888880000E1AEC11A5CFA"
        "FF408000009000";
const std::string C_READ_EVENT_COUNTER_9_17 = "80BE00E200";
const std::string R_READ_EVENT_COUNTER_9_17
    = CIPHER_MESSAGE_SIGNATURE
      + "2000002111111222222333332444442555552666662777772888880000E1AEC11A5CFA"
        "FF408000009000";
const std::string C_READ_EVENT_COUNTER_18_26 = "80BE00E300";
const std::string R_READ_EVENT_COUNTER_18_26
    = CIPHER_MESSAGE_SIGNATURE
      + "3000003111113222222333333444443555553666663777773888880000E1AEC11A5CFA"
        "FF408000009000";
const std::string C_READ_EVENT_CEILING_0_8 = "80BE00B100";
const std::string R_READ_EVENT_CEILING_0_8
    = CIPHER_MESSAGE_SIGNATURE
      + "2000002111112222222333332444442555552666662777772888880000E1AEC11A5CFA"
        "FF408000009000";
const std::string C_READ_EVENT_CEILING_9_17 = "80BE00B200";
const std::string R_READ_EVENT_CEILING_9_17
    = CIPHER_MESSAGE_SIGNATURE
      + "2000002111111222222333332444442555552666662777772888880000E1AEC11A5CFA"
        "FF408000009000";
const std::string C_READ_EVENT_CEILING_18_26 = "80BE00B300";
const std::string R_READ_EVENT_CEILING_18_26
    = CIPHER_MESSAGE_SIGNATURE
      + "3000003111113222222333333444443555553666663777773888880000E1AEC11A5CFA"
        "FF408000009000";

const std::string C_READ_SYSTEM_KEY_PARAMETER_PERSONALIZATION
    = "80BC00C1020000";
const std::string C_READ_SYSTEM_KEY_PARAMETER_KEY_MANAGEMENT = "80BC00C2020000";
const std::string C_READ_SYSTEM_KEY_PARAMETER_RELOADING = "80BC00C3020000";
const std::string C_READ_SYSTEM_KEY_PARAMETER_AUTHENTICATION = "80BC00C4020000";
const std::string R_READ_SYSTEM_KEY_PARAMETER_PERSONALIZATION
    = CIPHER_MESSAGE_SIGNATURE + "E1F1401112130115161718191AC1"
      + SAM_SERIAL_NUMBER + "FAFF408000009000";
const std::string R_READ_SYSTEM_KEY_PARAMETER_KEY_MANAGEMENT
    = CIPHER_MESSAGE_SIGNATURE + "FDF2402122230225262728292AC2"
      + SAM_SERIAL_NUMBER + "FAFF408000009000";
const std::string R_READ_SYSTEM_KEY_PARAMETER_RELOADING
    = CIPHER_MESSAGE_SIGNATURE + "E7F3403132330335363738393AC3"
      + SAM_SERIAL_NUMBER + "FAFF408000009000";
const std::string R_READ_SYSTEM_KEY_PARAMETER_AUTHENTICATION
    = CIPHER_MESSAGE_SIGNATURE + "FAF4404142430445464748494AC4"
      + SAM_SERIAL_NUMBER + "FAFF408000009000";

MATCHER_P(CardRequestMatches, expected, "")  // cppcheck-suppress syntaxError

{
    const auto& leftApduRequests = expected->getApduRequests();
    const auto& rightApduRequests = arg->getApduRequests();

    if (leftApduRequests.size() != rightApduRequests.size()) {
        return false;
    }

    for (size_t i = 0; i < leftApduRequests.size(); i++) {
        if (leftApduRequests[i]->getApdu() != rightApduRequests[i]->getApdu()) {
            return false;
        }
    }

    return true;
}

std::shared_ptr<CardRequestSpi>
createCardRequest(const std::vector<std::string>& apduCommands)
{
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests;
    for (const auto& apduCommand : apduCommands) {
        apduRequests.push_back(
            std::make_shared<DtoAdapters::ApduRequestAdapter>(
                HexUtil::toByteArray(apduCommand)));
    }
    return std::make_shared<DtoAdapters::CardRequestAdapter>(
        apduRequests, false);
}

std::shared_ptr<CardResponseApi>
createCardResponse(const std::vector<std::string>& apduCommandResponses)
{
    std::vector<std::shared_ptr<ApduResponseApi>> apduResponses;
    for (const auto& apduResponse : apduCommandResponses) {
        apduResponses.push_back(
            std::make_shared<TestDtoAdapters::ApduResponseAdapter>(
                HexUtil::toByteArray(apduResponse)));
    }
    return std::make_shared<TestDtoAdapters::CardResponseAdapter>(
        apduResponses, true);
}

} /* anonymous namespace */

class FreeTransactionManagerAdapterTest : public ::testing::Test {
protected:
    void
    SetUp() override
    {
        mSamReader = std::make_shared<NiceMock<ReaderMock>>();

        auto samCardSelectionResponse
            = std::make_shared<TestDtoAdapters::CardSelectionResponseAdapter>(
                SAM_C1_POWER_ON_DATA);
        mSam = std::make_shared<LegacySamAdapter>(samCardSelectionResponse);

        mSamTransactionManager
            = LegacySamExtensionService::getInstance()
                  ->getLegacySamApiFactory()
                  ->createFreeTransactionManager(mSamReader, mSam);
    }

    std::shared_ptr<ReaderMock> mSamReader;
    std::shared_ptr<LegacySam> mSam;
    std::shared_ptr<FreeTransactionManager> mSamTransactionManager;
};

/*
 * prepareComputeSignature
 */

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_whenDataIsNull_shouldThrowIAE)
{
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(nullptr),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_Basic_whenMessageIsNull_shouldThrowIAE)
{
    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenMessageIsNull_shouldThrowIAE)
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_Basic_whenMessageIsEmpty_shouldThrowIAE)
{
    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(0), 1, 2);
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenMessageIsEmpty_shouldThrowIAE)
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(0), 1, 2);
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_Basic_whenMessageLengthIsGreaterThan208_shouldThrowIAE)  // NOLINT
{
    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(209), 1, 2);
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenTraceabilityModeAndMessageLengthIsGreaterThan206_shouldThrowIAE)  // NOLINT
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(207), 1, 2);
    data->withSamTraceabilityMode(
        0, SamTraceabilityMode::TRUNCATED_SERIAL_NUMBER);
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenNotTraceabilityModeAndMessageLengthIsGreaterThan208_shouldThrowIAE)  // NOLINT
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(209), 1, 2);
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_Basic_whenMessageLengthIsNotMultipleOf8_shouldThrowIAE)  // NOLINT
{
    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(15), 1, 2);
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_Basic_whenMessageLengthIsInCorrectRange_shouldBeSuccessful)  // NOLINT
{
    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(208), 1, 2);
    mSamTransactionManager->prepareComputeSignature(data);

    data->setData(std::vector<uint8_t>(8), 1, 2);
    mSamTransactionManager->prepareComputeSignature(data);

    data->setData(std::vector<uint8_t>(16), 1, 2);
    ASSERT_NO_THROW(mSamTransactionManager->prepareComputeSignature(data));
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenMessageLengthIsInCorrectRange_shouldBeSuccessful)  // NOLINT
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(1), 1, 2);
    mSamTransactionManager->prepareComputeSignature(data);

    data->setData(std::vector<uint8_t>(208), 1, 2);
    mSamTransactionManager->prepareComputeSignature(data);

    data->setData(std::vector<uint8_t>(206), 1, 2);
    data->withSamTraceabilityMode(
        0, SamTraceabilityMode::TRUNCATED_SERIAL_NUMBER);
    ASSERT_NO_THROW(mSamTransactionManager->prepareComputeSignature(data));
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_Basic_whenSignatureSizeIsLessThan1_shouldThrowIAE)
{
    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    data->setSignatureSize(0);
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenSignatureSizeIsLessThan1_shouldThrowIAE)
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    data->setSignatureSize(0);
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_Basic_whenSignatureSizeIsGreaterThan8_shouldThrowIAE)  // NOLINT
{
    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    data->setSignatureSize(9);
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenSignatureSizeIsGreaterThan8_shouldThrowIAE)
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    data->setSignatureSize(9);
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_Basic_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful)  // NOLINT
{
    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(8), 1, 2);
    data->setSignatureSize(1);
    mSamTransactionManager->prepareComputeSignature(data);

    data->setSignatureSize(8);
    ASSERT_NO_THROW(mSamTransactionManager->prepareComputeSignature(data));
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful)  // NOLINT
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    data->setSignatureSize(1);
    mSamTransactionManager->prepareComputeSignature(data);

    data->setSignatureSize(8);
    ASSERT_NO_THROW(mSamTransactionManager->prepareComputeSignature(data));
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenTraceabilityOffsetIsNegative_shouldThrowIAE)
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    data->withSamTraceabilityMode(
        -1, SamTraceabilityMode::TRUNCATED_SERIAL_NUMBER);
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenPartialSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE)  // NOLINT
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    data->withSamTraceabilityMode(
        3 * 8 + 1, SamTraceabilityMode::TRUNCATED_SERIAL_NUMBER);
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenFullSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE)  // NOLINT
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    data->withSamTraceabilityMode(
        2 * 8 + 1, SamTraceabilityMode::FULL_SERIAL_NUMBER);
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenTraceabilityOffsetIsInCorrectRange_shouldBeSuccessful)  // NOLINT
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    data->withSamTraceabilityMode(0, SamTraceabilityMode::FULL_SERIAL_NUMBER);
    mSamTransactionManager->prepareComputeSignature(data);

    data->withSamTraceabilityMode(
        3 * 8, SamTraceabilityMode::TRUNCATED_SERIAL_NUMBER);
    mSamTransactionManager->prepareComputeSignature(data);

    data->withSamTraceabilityMode(
        2 * 8, SamTraceabilityMode::FULL_SERIAL_NUMBER);
    ASSERT_NO_THROW(mSamTransactionManager->prepareComputeSignature(data));
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_Basic_whenKeyDiversifierSizeIs0_shouldThrowIAE)
{
    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    data->setKeyDiversifier(std::vector<uint8_t>(0));
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenKeyDiversifierSizeIs0_shouldThrowIAE)
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    data->setKeyDiversifier(std::vector<uint8_t>(0));
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_Basic_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE)  // NOLINT
{
    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    data->setKeyDiversifier(std::vector<uint8_t>(9));
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE)  // NOLINT
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    data->setKeyDiversifier(std::vector<uint8_t>(9));
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_Basic_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful)  // NOLINT
{
    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(8), 1, 2);
    data->setKeyDiversifier(std::vector<uint8_t>(1));
    mSamTransactionManager->prepareComputeSignature(data);

    data->setKeyDiversifier(std::vector<uint8_t>(8));
    ASSERT_NO_THROW(mSamTransactionManager->prepareComputeSignature(data));
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful)  // NOLINT
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    data->setKeyDiversifier(std::vector<uint8_t>(1));
    mSamTransactionManager->prepareComputeSignature(data);

    data->setKeyDiversifier(std::vector<uint8_t>(8));
    ASSERT_NO_THROW(mSamTransactionManager->prepareComputeSignature(data));
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_Basic_whenTryToGetSignatureButNotProcessed_shouldThrowISE)  // NOLINT
{
    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(8), 1, 2);
    mSamTransactionManager->prepareComputeSignature(data);
    ASSERT_THROW(data->getSignature(), IllegalStateException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenTryToGetSignatureButNotProcessed_shouldThrowISE)  // NOLINT
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    mSamTransactionManager->prepareComputeSignature(data);
    ASSERT_THROW(data->getSignature(), IllegalStateException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenTryToGetSignedDataButNotProcessed_shouldThrowISE)  // NOLINT
{
    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    mSamTransactionManager->prepareComputeSignature(data);
    ASSERT_THROW(data->getSignedData(), IllegalStateException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_Basic_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier)  // NOLINT
{
    auto cardRequest
        = createCardRequest({C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(
        *mSamReader, transmitCardRequest(CardRequestMatches(cardRequest), _))
        .Times(1)
        .WillOnce(Return(cardResponse));

    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(HexUtil::toByteArray(CIPHER_MESSAGE), 1, 2);
    mSamTransactionManager->prepareComputeSignature(data).processCommands(
        ChannelControl::KEEP_OPEN);

    ASSERT_EQ(
        data->getSignature(), HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE));
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier)  // NOLINT
{
    auto cardRequest = createCardRequest(
        {C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    auto cardResponse
        = createCardResponse({R_9000, R_PSO_COMPUTE_SIGNATURE_DEFAULT});

    EXPECT_CALL(
        *mSamReader, transmitCardRequest(CardRequestMatches(cardRequest), _))
        .Times(1)
        .WillOnce(Return(cardResponse));

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    mSamTransactionManager->prepareComputeSignature(data).processCommands(
        ChannelControl::KEEP_OPEN);

    ASSERT_EQ(
        data->getSignature(), HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE));
    ASSERT_EQ(data->getSignedData(), HexUtil::toByteArray(PSO_MESSAGE));
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_Basic_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice)  // NOLINT
{
    auto cardRequest = createCardRequest(
        {C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT, C_DATA_CIPHER_DEFAULT});
    auto cardResponse = createCardResponse(
        {R_9000, R_DATA_CIPHER_DEFAULT, R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(
        *mSamReader, transmitCardRequest(CardRequestMatches(cardRequest), _))
        .Times(1)
        .WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<BasicSignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(CIPHER_MESSAGE), 1, 2);
    auto data2 = std::make_shared<BasicSignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(CIPHER_MESSAGE), 1, 2);
    mSamTransactionManager->prepareComputeSignature(data1);
    mSamTransactionManager->prepareComputeSignature(data2).processCommands(
        ChannelControl::KEEP_OPEN);

    ASSERT_EQ(
        data1->getSignature(), HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE));
    ASSERT_EQ(
        data2->getSignature(), HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE));
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_Basic_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier)  // NOLINT
{
    auto cardRequest = createCardRequest(
        {C_SELECT_DIVERSIFIER_SPECIFIC,
         C_DATA_CIPHER_DEFAULT,
         C_SELECT_DIVERSIFIER,
         C_DATA_CIPHER_DEFAULT,
         C_SELECT_DIVERSIFIER_SPECIFIC,
         C_DATA_CIPHER_DEFAULT});
    auto cardResponse = createCardResponse(
        {R_9000,
         R_DATA_CIPHER_DEFAULT,
         R_9000,
         R_DATA_CIPHER_DEFAULT,
         R_9000,
         R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(
        *mSamReader, transmitCardRequest(CardRequestMatches(cardRequest), _))
        .Times(1)
        .WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<BasicSignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(CIPHER_MESSAGE), 1, 2);
    data1->setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    auto data2 = std::make_shared<BasicSignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(CIPHER_MESSAGE), 1, 2);
    auto data3 = std::make_shared<BasicSignatureComputationDataAdapter>();
    data3->setData(HexUtil::toByteArray(CIPHER_MESSAGE), 1, 2);
    data3->setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    mSamTransactionManager->prepareComputeSignature(data1);
    mSamTransactionManager->prepareComputeSignature(data2);
    mSamTransactionManager->prepareComputeSignature(data3).processCommands(
        ChannelControl::KEEP_OPEN);

    ASSERT_EQ(
        data1->getSignature(), HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE));
    ASSERT_EQ(
        data2->getSignature(), HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE));
    ASSERT_EQ(
        data3->getSignature(), HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE));
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_Basic_whenSignatureSizeIsLessThan8_shouldBeSuccessful)  // NOLINT
{
    auto cardRequest
        = createCardRequest({C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(
        *mSamReader, transmitCardRequest(CardRequestMatches(cardRequest), _))
        .Times(1)
        .WillOnce(Return(cardResponse));

    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(HexUtil::toByteArray(CIPHER_MESSAGE), 1, 2);
    data->setSignatureSize(3);
    mSamTransactionManager->prepareComputeSignature(data).processCommands(
        ChannelControl::KEEP_OPEN);

    ASSERT_EQ(
        data->getSignature(),
        HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE_3_BYTES));
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeSignature_PSO_whenSamTraceabilityModePartialAndNotBusy_shouldBeSuccessful)  // NOLINT
{
    auto cardRequest = createCardRequest(
        {C_SELECT_DIVERSIFIER,
         C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL,
         C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL});
    auto cardResponse = createCardResponse(
        {R_9000,
         R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL,
         R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL});

    EXPECT_CALL(
        *mSamReader, transmitCardRequest(CardRequestMatches(cardRequest), _))
        .Times(1)
        .WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    data1->withSamTraceabilityMode(
        1, SamTraceabilityMode::TRUNCATED_SERIAL_NUMBER);
    data1->withoutBusyMode();
    auto data2 = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    data2->withSamTraceabilityMode(1, SamTraceabilityMode::FULL_SERIAL_NUMBER);
    data2->withoutBusyMode();
    mSamTransactionManager->prepareComputeSignature(data1);
    mSamTransactionManager->prepareComputeSignature(data2).processCommands(
        ChannelControl::KEEP_OPEN);

    ASSERT_EQ(
        data1->getSignature(), HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE));
    ASSERT_EQ(
        data1->getSignedData(),
        HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY));
    ASSERT_EQ(
        data2->getSignature(), HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE));
    ASSERT_EQ(
        data2->getSignedData(),
        HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY));
}

/*
 * prepareVerifySignature
 */

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_whenDataIsNull_shouldThrowIAE)
{
    ASSERT_THROW(
        mSamTransactionManager->prepareVerifySignature(nullptr),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_Basic_whenMessageIsNull_shouldThrowIAE)
{
    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    ASSERT_THROW(
        mSamTransactionManager->prepareVerifySignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_PSO_whenMessageIsNull_shouldThrowIAE)
{
    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    ASSERT_THROW(
        mSamTransactionManager->prepareVerifySignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_Basic_whenMessageIsEmpty_shouldThrowIAE)
{
    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(0), std::vector<uint8_t>(8), 1, 2);
    ASSERT_THROW(
        mSamTransactionManager->prepareVerifySignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_Basic_whenMessageLengthIsGreaterThan208_shouldThrowIAE)  // NOLINT
{
    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(209), std::vector<uint8_t>(8), 1, 2);
    ASSERT_THROW(
        mSamTransactionManager->prepareVerifySignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_PSO_whenTraceabilityModeAndMessageLengthIsGreaterThan206_shouldThrowIAE)  // NOLINT
{
    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(207), std::vector<uint8_t>(8), 1, 2);
    data->withSamTraceabilityMode(
        0, SamTraceabilityMode::TRUNCATED_SERIAL_NUMBER, nullptr);
    ASSERT_THROW(
        mSamTransactionManager->prepareVerifySignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_Basic_whenMessageLengthIsNotMultipleOf8_shouldThrowIAE)  // NOLINT
{
    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(209), std::vector<uint8_t>(15), 1, 2);
    ASSERT_THROW(
        mSamTransactionManager->prepareVerifySignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_Basic_whenMessageLengthIsInCorrectRange_shouldBeSuccessful)  // NOLINT
{
    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(208), std::vector<uint8_t>(8), 1, 2);
    mSamTransactionManager->prepareVerifySignature(data);

    data->setData(std::vector<uint8_t>(8), std::vector<uint8_t>(8), 1, 2);
    mSamTransactionManager->prepareVerifySignature(data);

    data->setData(std::vector<uint8_t>(16), std::vector<uint8_t>(8), 1, 2);
    ASSERT_NO_THROW(mSamTransactionManager->prepareVerifySignature(data));
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_Basic_whenSignatureIsNull_shouldThrowIAE)
{
    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(0), 1, 2);
    ASSERT_THROW(
        mSamTransactionManager->prepareVerifySignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_Basic_whenSignatureSizeIsLessThan1_shouldThrowIAE)
{
    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(0), 1, 2);
    ASSERT_THROW(
        mSamTransactionManager->prepareVerifySignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_Basic_whenSignatureSizeIsGreaterThan8_shouldThrowIAE)
{
    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(9), 1, 2);
    ASSERT_THROW(
        mSamTransactionManager->prepareVerifySignature(data),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_Basic_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful)  // NOLINT
{
    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(8), std::vector<uint8_t>(1), 1, 2);
    mSamTransactionManager->prepareVerifySignature(data);

    data->setData(std::vector<uint8_t>(8), std::vector<uint8_t>(8), 1, 2);
    ASSERT_NO_THROW(mSamTransactionManager->prepareVerifySignature(data));
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_Basic_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful)  // NOLINT
{
    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(8), std::vector<uint8_t>(8), 1, 2);
    data->setKeyDiversifier(std::vector<uint8_t>(1));
    mSamTransactionManager->prepareVerifySignature(data);

    data->setKeyDiversifier(std::vector<uint8_t>(8));
    ASSERT_NO_THROW(mSamTransactionManager->prepareVerifySignature(data));
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_Basic_whenTryToCheckIfSignatureIsValidButNotAlreadyProcessed_shouldThrowISE)  // NOLINT
{
    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(8), std::vector<uint8_t>(8), 1, 2);
    mSamTransactionManager->prepareVerifySignature(data);
    ASSERT_THROW(data->isSignatureValid(), IllegalStateException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_PSO_whenCheckSamRevocationStatusOK_shouldBeSuccessful)  // NOLINT
{
    auto samRevocationServiceSpi
        = std::make_shared<NiceMock<LegacySamRevocationServiceSpiMock>>();
    EXPECT_CALL(
        *samRevocationServiceSpi,
        isSamRevoked(HexUtil::toByteArray("B2B3B4"), 0xB5B6B7))
        .WillRepeatedly(Return(false));

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(
        HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY),
        std::vector<uint8_t>(8),
        1,
        2);
    data->withSamTraceabilityMode(
        8,
        SamTraceabilityMode::TRUNCATED_SERIAL_NUMBER,
        samRevocationServiceSpi);

    ASSERT_NO_THROW(mSamTransactionManager->prepareVerifySignature(data));
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_PSO_whenCheckSamRevocationStatusKOPartial_shouldThrowSRE)  // NOLINT
{
    auto samRevocationServiceSpi
        = std::make_shared<NiceMock<LegacySamRevocationServiceSpiMock>>();
    EXPECT_CALL(
        *samRevocationServiceSpi,
        isSamRevoked(HexUtil::toByteArray("B2B3B4"), 0xB5B6B7))
        .WillRepeatedly(Return(true));

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(
        HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY),
        std::vector<uint8_t>(8),
        1,
        2);
    data->withSamTraceabilityMode(
        8,
        SamTraceabilityMode::TRUNCATED_SERIAL_NUMBER,
        samRevocationServiceSpi);

    ASSERT_THROW(
        mSamTransactionManager->prepareVerifySignature(data),
        SamRevokedException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_PSO_whenCheckSamRevocationStatusKOFull_shouldThrowSRE)  // NOLINT
{
    auto samRevocationServiceSpi
        = std::make_shared<NiceMock<LegacySamRevocationServiceSpiMock>>();
    EXPECT_CALL(
        *samRevocationServiceSpi,
        isSamRevoked(HexUtil::toByteArray("B2B3B4B5"), 0xB6B7B8))
        .WillRepeatedly(Return(true));

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(
        HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY),
        std::vector<uint8_t>(8),
        1,
        2);
    data->withSamTraceabilityMode(
        8, SamTraceabilityMode::FULL_SERIAL_NUMBER, samRevocationServiceSpi);

    ASSERT_THROW(
        mSamTransactionManager->prepareVerifySignature(data),
        SamRevokedException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_Basic_whenSignatureIsValid_shouldUpdateOutputData)
{
    auto cardRequest
        = createCardRequest({C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(
        *mSamReader, transmitCardRequest(CardRequestMatches(cardRequest), _))
        .Times(1)
        .WillOnce(Return(cardResponse));

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(
        HexUtil::toByteArray(CIPHER_MESSAGE),
        HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE),
        1,
        2);
    mSamTransactionManager->prepareVerifySignature(data).processCommands(
        ChannelControl::KEEP_OPEN);

    ASSERT_TRUE(data->isSignatureValid());
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_Basic_whenSignatureIsValidWithSizeLessThan8_shouldUpdateOutputData)  // NOLINT
{
    auto cardRequest
        = createCardRequest({C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(
        *mSamReader, transmitCardRequest(CardRequestMatches(cardRequest), _))
        .Times(1)
        .WillOnce(Return(cardResponse));

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(
        HexUtil::toByteArray(CIPHER_MESSAGE),
        HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE_3_BYTES),
        1,
        2);
    mSamTransactionManager->prepareVerifySignature(data).processCommands(
        ChannelControl::KEEP_OPEN);

    ASSERT_TRUE(data->isSignatureValid());
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_PSO_whenSignatureIsValid_shouldUpdateOutputData)
{
    auto cardRequest = createCardRequest(
        {C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_9000});

    EXPECT_CALL(
        *mSamReader, transmitCardRequest(CardRequestMatches(cardRequest), _))
        .Times(1)
        .WillOnce(Return(cardResponse));

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(
        HexUtil::toByteArray(PSO_MESSAGE),
        HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE),
        1,
        2);
    mSamTransactionManager->prepareVerifySignature(data).processCommands(
        ChannelControl::KEEP_OPEN);

    ASSERT_TRUE(data->isSignatureValid());
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_Basic_whenSignatureIsInvalid_shouldThrowISEAndUpdateOutputData)  // NOLINT
{
    auto cardRequest
        = createCardRequest({C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(
        *mSamReader, transmitCardRequest(CardRequestMatches(cardRequest), _))
        .Times(1)
        .WillOnce(Return(cardResponse));

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(
        HexUtil::toByteArray(CIPHER_MESSAGE),
        HexUtil::toByteArray(CIPHER_MESSAGE_INCORRECT_SIGNATURE),
        1,
        2);

    ASSERT_THROW(
        mSamTransactionManager->prepareVerifySignature(data).processCommands(
            ChannelControl::KEEP_OPEN),
        InvalidSignatureException);

    ASSERT_FALSE(data->isSignatureValid());
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareVerifySignature_PSO_whenSignatureIsInvalid_shouldThrowISEAndUpdateOutputData)  // NOLINT
{
    auto cardRequest = createCardRequest(
        {C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_INCORRECT_SIGNATURE});

    EXPECT_CALL(
        *mSamReader, transmitCardRequest(CardRequestMatches(cardRequest), _))
        .Times(1)
        .WillOnce(Return(cardResponse));

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(
        HexUtil::toByteArray(PSO_MESSAGE),
        HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE),
        1,
        2);

    ASSERT_THROW(
        mSamTransactionManager->prepareVerifySignature(data).processCommands(
            ChannelControl::KEEP_OPEN),
        InvalidSignatureException);

    ASSERT_FALSE(data->isSignatureValid());
}

/*
 * prepareReadCounterStatus / prepareReadSystemKeyParameters
 */

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareReadCounterStatus_whenCounterIsOutOfRange_shouldThrowIAE)
{
    ASSERT_THROW(
        mSamTransactionManager->prepareReadCounterStatus(27),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareReadCounterStatus_whenCounterIsInRange_shouldBeSuccessful)
{
    auto cardRequest = createCardRequest(
        {C_READ_EVENT_COUNTER_0_8, C_READ_EVENT_CEILING_0_8});
    auto cardResponse = createCardResponse(
        {R_READ_EVENT_COUNTER_0_8, R_READ_EVENT_CEILING_0_8});

    EXPECT_CALL(
        *mSamReader, transmitCardRequest(CardRequestMatches(cardRequest), _))
        .Times(1)
        .WillOnce(Return(cardResponse));

    mSamTransactionManager->prepareReadCounterStatus(4);
    mSamTransactionManager->processCommands(ChannelControl::KEEP_OPEN);

    ASSERT_EQ(*mSam->getCounter(4), 0x144444);
    ASSERT_EQ(*mSam->getCounterCeiling(4), 0x244444);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareReadCounterStatus_whenCounterAreInSameRecord_shouldProduceOptimizedApduRequests)  // NOLINT
{
    auto cardRequest = createCardRequest(
        {C_READ_EVENT_COUNTER_0_8,
         C_READ_EVENT_CEILING_0_8,
         C_READ_EVENT_COUNTER_9_17,
         C_READ_EVENT_CEILING_9_17,
         C_READ_EVENT_COUNTER_18_26,
         C_READ_EVENT_CEILING_18_26});
    auto cardResponse = createCardResponse(
        {R_READ_EVENT_COUNTER_0_8,
         R_READ_EVENT_CEILING_0_8,
         R_READ_EVENT_COUNTER_9_17,
         R_READ_EVENT_CEILING_9_17,
         R_READ_EVENT_COUNTER_18_26,
         R_READ_EVENT_CEILING_18_26});

    EXPECT_CALL(
        *mSamReader, transmitCardRequest(CardRequestMatches(cardRequest), _))
        .Times(1)
        .WillOnce(Return(cardResponse));

    mSamTransactionManager->prepareReadCounterStatus(1);
    mSamTransactionManager->prepareReadCounterStatus(4);
    mSamTransactionManager->prepareReadCounterStatus(11);
    mSamTransactionManager->prepareReadCounterStatus(22);
    mSamTransactionManager->processCommands(ChannelControl::KEEP_OPEN);

    ASSERT_EQ(*mSam->getCounter(1), 0x111111);
    ASSERT_EQ(*mSam->getCounterCeiling(1), 0x211111);
    ASSERT_EQ(*mSam->getCounter(4), 0x144444);
    ASSERT_EQ(*mSam->getCounterCeiling(4), 0x244444);
    ASSERT_EQ(*mSam->getCounter(11), 0x122222);
    ASSERT_EQ(*mSam->getCounterCeiling(11), 0x122222);
    ASSERT_EQ(*mSam->getCounter(22), 0x344444);
    ASSERT_EQ(*mSam->getCounterCeiling(22), 0x344444);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareReadSystemKeyParameters_whenSystemKeyTypeIsNotNull_shouldBeSuccessful)  // NOLINT
{
    auto cardRequest = createCardRequest(
        {C_READ_SYSTEM_KEY_PARAMETER_PERSONALIZATION,
         C_READ_SYSTEM_KEY_PARAMETER_KEY_MANAGEMENT,
         C_READ_SYSTEM_KEY_PARAMETER_RELOADING,
         C_READ_SYSTEM_KEY_PARAMETER_AUTHENTICATION});
    auto cardResponse = createCardResponse(
        {R_READ_SYSTEM_KEY_PARAMETER_PERSONALIZATION,
         R_READ_SYSTEM_KEY_PARAMETER_KEY_MANAGEMENT,
         R_READ_SYSTEM_KEY_PARAMETER_RELOADING,
         R_READ_SYSTEM_KEY_PARAMETER_AUTHENTICATION});

    EXPECT_CALL(
        *mSamReader, transmitCardRequest(CardRequestMatches(cardRequest), _))
        .Times(1)
        .WillOnce(Return(cardResponse));

    mSamTransactionManager->prepareReadSystemKeyParameters(
        SystemKeyType::PERSONALIZATION);
    mSamTransactionManager->prepareReadSystemKeyParameters(
        SystemKeyType::KEY_MANAGEMENT);
    mSamTransactionManager->prepareReadSystemKeyParameters(
        SystemKeyType::RELOADING);
    mSamTransactionManager->prepareReadSystemKeyParameters(
        SystemKeyType::AUTHENTICATION);
    mSamTransactionManager->processCommands(ChannelControl::KEEP_OPEN);

    const std::vector<SystemKeyType> systemKeyTypes
        = {SystemKeyType::PERSONALIZATION,
           SystemKeyType::KEY_MANAGEMENT,
           SystemKeyType::RELOADING,
           SystemKeyType::AUTHENTICATION};

    for (const auto type : systemKeyTypes) {
        uint8_t kvc;
        switch (type) {
        case SystemKeyType::PERSONALIZATION:
            kvc = 0xF1;
            break;
        case SystemKeyType::KEY_MANAGEMENT:
            kvc = 0xF2;
            break;
        case SystemKeyType::RELOADING:
            kvc = 0xF3;
            break;
        case SystemKeyType::AUTHENTICATION:
            kvc = 0xF4;
            break;
        default:
            FAIL() << "Unexpected key type";
            return;
        }
        ASSERT_EQ(mSam->getSystemKeyParameter(type)->getKvc(), kvc);
        ASSERT_EQ(mSam->getSystemKeyParameter(type)->getAlgorithm(), 0x40);
        for (int i = 1; i <= 10; i++) {
            if (i == 4) {
                /* don't test PAR4 */
                continue;
            }
            ASSERT_EQ(
                mSam->getSystemKeyParameter(type)->getParameterValue(i),
                static_cast<uint8_t>(static_cast<int>(type) * 16 + i));
        }
    }
}

/*
 * processCommands
 */

TEST_F(
    FreeTransactionManagerAdapterTest,
    processCommands_whenNoError_shouldClearCommandList)
{
    auto cardRequest1 = createCardRequest(
        {C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    auto cardResponse1
        = createCardResponse({R_9000, R_PSO_COMPUTE_SIGNATURE_DEFAULT});

    auto cardRequest2 = createCardRequest({C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    auto cardResponse2 = createCardResponse({R_PSO_COMPUTE_SIGNATURE_DEFAULT});

    {
        InSequence seq;
        EXPECT_CALL(
            *mSamReader,
            transmitCardRequest(CardRequestMatches(cardRequest1), _))
            .Times(1)
            .WillOnce(Return(cardResponse1));
        EXPECT_CALL(
            *mSamReader,
            transmitCardRequest(CardRequestMatches(cardRequest2), _))
            .Times(1)
            .WillOnce(Return(cardResponse2));
    }

    auto data1 = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    mSamTransactionManager->prepareComputeSignature(data1).processCommands(
        ChannelControl::KEEP_OPEN);

    auto data2 = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    mSamTransactionManager->prepareComputeSignature(data2).processCommands(
        ChannelControl::KEEP_OPEN);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    processCommands_whenError_shouldClearCommandList)
{
    auto cardRequest1 = createCardRequest(
        {C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    auto cardResponse1 = createCardResponse({R_9000, R_INCORRECT_SIGNATURE});

    auto cardRequest2 = createCardRequest({C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    auto cardResponse2 = createCardResponse({R_PSO_COMPUTE_SIGNATURE_DEFAULT});

    {
        InSequence seq;
        EXPECT_CALL(
            *mSamReader,
            transmitCardRequest(CardRequestMatches(cardRequest1), _))
            .Times(1)
            .WillOnce(Return(cardResponse1));
        EXPECT_CALL(
            *mSamReader,
            transmitCardRequest(CardRequestMatches(cardRequest2), _))
            .Times(1)
            .WillOnce(Return(cardResponse2));
    }

    auto data1 = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeSignature(data1).processCommands(
            ChannelControl::KEEP_OPEN),
        InvalidCardResponseException);

    auto data2 = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    mSamTransactionManager->prepareComputeSignature(data2).processCommands(
        ChannelControl::KEEP_OPEN);
}

/*
 * Disabled: exportTargetSamContextForAsyncTransaction() relies on JSON
 * serialization of the target SAM context (via Gson in Java), which has not
 * been ported to C++ yet -- the equivalent C++ production code is currently a
 * stub. Re-enable once JSON serialization is implemented.
 */
TEST_F(
    FreeTransactionManagerAdapterTest,
    DISABLED_exportTargetSamContextForAsyncTransaction_shouldBeSuccessful)
{
}

/*
 * Null argument checks
 */

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareGenerateCardAsymmetricKeyPair_whenKeyPairContainerIsNull_shouldThrowIAE)  // NOLINT
{
    ASSERT_THROW(
        mSamTransactionManager->prepareGenerateCardAsymmetricKeyPair(nullptr),
        IllegalArgumentException);
}

TEST_F(
    FreeTransactionManagerAdapterTest,
    prepareComputeCardCertificate_whenDataIsNull_shouldThrowIAE)
{
    ASSERT_THROW(
        mSamTransactionManager->prepareComputeCardCertificate(nullptr),
        IllegalArgumentException);
}
