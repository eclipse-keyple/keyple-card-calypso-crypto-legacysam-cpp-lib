/******************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * See the NOTICE file(s) distributed with this work for additional           *
 * information regarding copyright ownership.                                 *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the Eclipse Public License 2.0 which is available at              *
 * http://www.eclipse.org/legal/epl-2.0                                       *
 *                                                                            *
 * SPDX-License-Identifier: EPL-2.0                                           *
 ******************************************************************************/

#include "keyple/card/calypso/crypto/legacysam/FreeTransactionManagerAdapter.hpp"

#include <memory>
#include <set>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/CommandCardGenerateAsymmetricKeyPair.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandDataCipher.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandGetData.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandPsoComputeCertificate.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandPsoComputeSignature.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandPsoVerifySignature.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandReadCeilings.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandReadCounter.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandReadKeyParameters.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandReadParameters.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandSelectDiversifier.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandWriteKey.hpp"
#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamConstants.hpp"
#include "keyple/core/util/ByteArrayUtil.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/KeypleAssert.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SamRevokedException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::Assert;
using keyple::core::util::ByteArrayUtil;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keypop::calypso::crypto::legacysam::transaction::SamRevokedException;

using BasicSignatureComputationDataAdapter
    = DtoAdapters::BasicSignatureComputationDataAdapter;
using KeyPairContainerAdapter = DtoAdapters::KeyPairContainerAdapter;
using TraceableSignatureComputationDataAdapter
    = DtoAdapters::TraceableSignatureComputationDataAdapter;

const std::string FreeTransactionManagerAdapter::MSG_INPUT_OUTPUT_DATA
    = "input/output data";
const std::string FreeTransactionManagerAdapter::MSG_SIGNATURE_SIZE
    = "signature size";
const std::string
    FreeTransactionManagerAdapter::MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8
    = "key diversifier size is in range [1..8]";

FreeTransactionManagerAdapter::FreeTransactionManagerAdapter(
    std::shared_ptr<ProxyReaderApi> targetSamReader,
    std::shared_ptr<LegacySamAdapter> targetSam)
: CommonTransactionManagerAdapter(targetSamReader, targetSam, nullptr, nullptr)
, mSamKeyDiversifier(targetSam->getSerialNumber())
{
}

FreeTransactionManager&
FreeTransactionManagerAdapter::prepareGetData(GetDataTag tag)
{
    addTargetSamCommand(std::make_shared<CommandGetData>(getContext(), tag));

    return *this;
}

FreeTransactionManager&
FreeTransactionManagerAdapter::prepareGenerateCardAsymmetricKeyPair(
    std::shared_ptr<KeyPairContainer> keyPairContainer)
{
    Assert::getInstance().notNull(keyPairContainer, "keyPairContainer");
    if (!std::dynamic_pointer_cast<KeyPairContainerAdapter>(keyPairContainer)) {
        throw IllegalArgumentException(
            "The provided keyPairContainer must be an instance of "
            "'KeyPairContainerAdapter'");
    }
    addTargetSamCommand(
        std::make_shared<CommandCardGenerateAsymmetricKeyPair>(
            getContext(), keyPairContainer));

    return *this;
}

FreeTransactionManager&
FreeTransactionManagerAdapter::prepareComputeCardCertificate(
    std::shared_ptr<LegacyCardCertificateComputationData> data)
{
    Assert::getInstance().notNull(data, "data");
    if (!std::dynamic_pointer_cast<LegacyCardCertificateComputationDataAdapter>(
            data)) {
        throw IllegalArgumentException(
            "The provided data must be an instance of "
            "'LegacyCardCertificateComputationDataAdapter'");
    }
    addTargetSamCommand(
        std::make_shared<CommandPsoComputeCertificate>(getContext(), data));

    return *this;
}

FreeTransactionManager&
FreeTransactionManagerAdapter::preparePlainWriteLock(
    uint8_t lockIndex,
    uint8_t lockParameters,
    const std::vector<uint8_t>& lockValue)
{
    Assert::getInstance().isEqual(
        lockValue.size(),
        LegacySamConstants::LOCK_VALUE_LENGTH,
        "lockValue.length");

    addTargetSamCommand(
        std::make_shared<CommandWriteKey>(
            getContext(),
            CommandWriteKey::buildPlainLockDataBlock(
                lockIndex, lockParameters, lockValue)));

    return *this;
}

FreeTransactionManager&
FreeTransactionManagerAdapter::prepareComputeSignature(
    std::shared_ptr<SignatureComputationDataBase> data)
{
    std::shared_ptr<BasicSignatureComputationDataAdapter> basicDataAdapter(
        std::dynamic_pointer_cast<BasicSignatureComputationDataAdapter>(data));
    if (basicDataAdapter) {
        // Basic signature
        Assert::getInstance()
            .notNull(basicDataAdapter, MSG_INPUT_OUTPUT_DATA)
            .isInRange(
                basicDataAdapter->getData().size(),
                1,
                208,
                "length of data to sign")
            .isTrue(
                basicDataAdapter->getData().size() % 8 == 0,
                "length of data to sign is a multiple of 8")
            .isInRange(
                basicDataAdapter->getSignatureSize(), 1, 8, MSG_SIGNATURE_SIZE)
            .isTrue(
                basicDataAdapter->getKeyDiversifier().empty()
                    || (basicDataAdapter->getKeyDiversifier().size() >= 1
                        && basicDataAdapter->getKeyDiversifier().size() <= 8),
                MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

        prepareSelectDiversifierIfNeeded(basicDataAdapter->getKeyDiversifier());
        addTargetSamCommand(
            std::make_shared<CommandDataCipher>(
                getContext(), basicDataAdapter, nullptr));

    } else {
        std::shared_ptr<TraceableSignatureComputationDataAdapter>
            traceableDataAdapter(
                std::dynamic_pointer_cast<
                    TraceableSignatureComputationDataAdapter>(data));
        if (traceableDataAdapter) {
            // Traceable signature
            bool traceabilityOffsetInRange
                = !traceableDataAdapter->isSamTraceabilityMode()
                  || (traceableDataAdapter->getTraceabilityOffset() >= 0
                      && traceableDataAdapter->getTraceabilityOffset()
                             <= static_cast<int>(
                                 ((traceableDataAdapter->getData().size() * 8)
                                  - (traceableDataAdapter
                                                 ->getSamTraceabilityMode()
                                             == SamTraceabilityMode::
                                                 TRUNCATED_SERIAL_NUMBER
                                         ? 7 * 8
                                         : 8 * 8))));
            Assert::getInstance()
                .notNull(traceableDataAdapter, "input/output data")
                .isInRange(
                    traceableDataAdapter->getData().size(),
                    1,
                    traceableDataAdapter->isSamTraceabilityMode() ? 206 : 208,
                    "length of data to sign")
                .isInRange(
                    traceableDataAdapter->getSignatureSize(),
                    1,
                    8,
                    "signature size")
                .isTrue(
                    traceabilityOffsetInRange,
                    "traceability offset is in range")
                .isTrue(
                    traceableDataAdapter->getKeyDiversifier().empty()
                        || (traceableDataAdapter->getKeyDiversifier().size()
                                >= 1
                            && traceableDataAdapter->getKeyDiversifier().size()
                                   <= 8),
                    "key diversifier size is in range [1..8]");

            prepareSelectDiversifierIfNeeded(
                traceableDataAdapter->getKeyDiversifier());
            addTargetSamCommand(
                std::make_shared<CommandPsoComputeSignature>(
                    getContext(), traceableDataAdapter));

        } else {
            throw IllegalArgumentException(
                "The provided data must be an instance of "
                "'BasicSignatureComputationDataAdapter'"
                " or 'TraceableSignatureComputationDataAdapter'");
        }
    }

    return *this;
}

FreeTransactionManager&
FreeTransactionManagerAdapter::prepareVerifySignature(
    std::shared_ptr<SignatureVerificationDataBase> data)
{
    std::shared_ptr<BasicSignatureVerificationDataAdapter> basicDataAdapter(
        std::dynamic_pointer_cast<BasicSignatureVerificationDataAdapter>(data));
    if (basicDataAdapter) {
        // Basic signature
        Assert::getInstance()
            .notNull(basicDataAdapter, MSG_INPUT_OUTPUT_DATA)
            .isInRange(
                basicDataAdapter->getData().size(),
                1,
                208,
                "length of signed data to verify")
            .isTrue(
                basicDataAdapter->getData().size() % 8 == 0,
                "length of data to verify is a multiple of 8")
            .isInRange(
                basicDataAdapter->getSignature().size(),
                1,
                8,
                MSG_SIGNATURE_SIZE)
            .isTrue(
                basicDataAdapter->getKeyDiversifier().empty()
                    || (basicDataAdapter->getKeyDiversifier().size() >= 1
                        && basicDataAdapter->getKeyDiversifier().size() <= 8),
                "key diversifier size is in range [1..8]");

        prepareSelectDiversifierIfNeeded(basicDataAdapter->getKeyDiversifier());
        addTargetSamCommand(
            std::make_shared<CommandDataCipher>(
                getContext(), nullptr, basicDataAdapter));

    } else {
        std::shared_ptr<TraceableSignatureVerificationDataAdapter>
            traceableDataAdapter(
                std::dynamic_pointer_cast<
                    TraceableSignatureVerificationDataAdapter>(data));
        if (traceableDataAdapter) {
            // Traceable signature
            const bool isTracebilityOffsetInRange
                = !traceableDataAdapter->isSamTraceabilityMode()
                  || (traceableDataAdapter->getTraceabilityOffset() >= 0
                      && traceableDataAdapter->getTraceabilityOffset()
                             <= static_cast<int>(
                                 ((traceableDataAdapter->getData().size() * 8)
                                  - (traceableDataAdapter
                                                 ->getSamTraceabilityMode()
                                             == SamTraceabilityMode::
                                                 TRUNCATED_SERIAL_NUMBER
                                         ? 7 * 8
                                         : 8 * 8))));

            Assert::getInstance()
                .notNull(traceableDataAdapter, "input/output data")
                .isInRange(
                    traceableDataAdapter->getData().size(),
                    1,
                    traceableDataAdapter->isSamTraceabilityMode() ? 206 : 208,
                    "length of signed data to verify")
                .isInRange(
                    traceableDataAdapter->getSignature().size(),
                    1,
                    8,
                    "signature size")
                .isTrue(
                    isTracebilityOffsetInRange,
                    "traceability offset is in range")
                .isTrue(
                    traceableDataAdapter->getKeyDiversifier().empty()
                        || (traceableDataAdapter->getKeyDiversifier().size()
                                >= 1
                            && traceableDataAdapter->getKeyDiversifier().size()
                                   <= 8),
                    MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

            // Check SAM revocation status if requested.
            if (traceableDataAdapter->getSamRevocationService()) {
                // Extract the SAM serial number and the counter value from the
                // data.
                std::vector<uint8_t> samSerialNumber
                    = ByteArrayUtil::extractBytes(
                        traceableDataAdapter->getData(),
                        traceableDataAdapter->getTraceabilityOffset(),
                        traceableDataAdapter->getSamTraceabilityMode()
                                == SamTraceabilityMode::TRUNCATED_SERIAL_NUMBER
                            ? 3
                            : 4);

                int samCounterValue = ByteArrayUtil::extractInt(
                    ByteArrayUtil::extractBytes(
                        traceableDataAdapter->getData(),
                        traceableDataAdapter->getTraceabilityOffset()
                            + (traceableDataAdapter->getSamTraceabilityMode()
                                       == SamTraceabilityMode::
                                           TRUNCATED_SERIAL_NUMBER
                                   ? 3 * 8
                                   : 4 * 8),
                        3),
                    0,
                    3,
                    false);

                // Is SAM revoked ?
                if (traceableDataAdapter->getSamRevocationService()
                        ->isSamRevoked(samSerialNumber, samCounterValue)) {
                    throw SamRevokedException(
                        "SAM with serial number ["
                        + HexUtil::toHex(samSerialNumber)
                        + "] and counter value ["
                        + std::to_string(samCounterValue) + "] is revoked");
                }
            }

            prepareSelectDiversifierIfNeeded(
                traceableDataAdapter->getKeyDiversifier());
            addTargetSamCommand(
                std::make_shared<CommandPsoVerifySignature>(
                    getContext(), traceableDataAdapter));

        } else {
            throw IllegalArgumentException(
                "The provided data must be an instance of "
                "'SignatureVerificationDataAdapter'");
        }
    }

    return *this;
}

FreeTransactionManager&
FreeTransactionManagerAdapter::prepareReadSamParameters()
{
    addTargetSamCommand(std::make_shared<CommandReadParameters>(getContext()));

    return *this;
}

FreeTransactionManager&
FreeTransactionManagerAdapter::prepareReadSystemKeyParameters(
    SystemKeyType systemKeyType)
{
    addTargetSamCommand(
        std::make_shared<CommandReadKeyParameters>(
            getContext(), systemKeyType));

    return *this;
}

FreeTransactionManager&
FreeTransactionManagerAdapter::prepareReadWorkKeyParameters(int recordNumber)
{
    Assert::getInstance().isInRange(
        recordNumber,
        LegacySamConstants::MIN_KEY_RECORD_NUMBER,
        LegacySamConstants::MAX_KEY_RECORD_NUMBER,
        "recordNumber");
    addTargetSamCommand(
        std::make_shared<CommandReadKeyParameters>(getContext(), recordNumber));

    return *this;
}

FreeTransactionManager&
FreeTransactionManagerAdapter::prepareReadWorkKeyParameters(
    uint8_t kif, uint8_t kvc)
{
    addTargetSamCommand(
        std::make_shared<CommandReadKeyParameters>(getContext(), kif, kvc));

    return *this;
}

FreeTransactionManager&
FreeTransactionManagerAdapter::prepareReadCounterStatus(int counterNumber)
{
    Assert::getInstance().isInRange(
        counterNumber,
        LegacySamConstants::MIN_COUNTER_NUMBER,
        LegacySamConstants::MAX_COUNTER_NUMBER,
        "counterNumber");
    for (const auto& command : getTargetSamCommands()) {
        auto readCounterCommand
            = std::dynamic_pointer_cast<CommandReadCounter>(command);
        if (readCounterCommand
            && readCounterCommand->getCounterFileRecordNumber()
                   == LegacySamConstants::COUNTER_TO_RECORD_LOOKUP
                       [counterNumber]) {
            // already scheduled
            return *this;
        }
    }
    addTargetSamCommand(
        std::make_shared<CommandReadCounter>(
            getContext(),
            LegacySamConstants::COUNTER_TO_RECORD_LOOKUP[counterNumber]));
    addTargetSamCommand(
        std::make_shared<CommandReadCeilings>(
            getContext(),
            LegacySamConstants::COUNTER_TO_RECORD_LOOKUP[counterNumber]));

    return *this;
}

FreeTransactionManager&
FreeTransactionManagerAdapter::prepareReadAllCountersStatus()
{
    for (int i = 0; i < 3; i++) {
        addTargetSamCommand(
            std::make_shared<CommandReadCounter>(getContext(), i));
        addTargetSamCommand(
            std::make_shared<CommandReadCeilings>(getContext(), i));
    }

    return *this;
}

std::string
FreeTransactionManagerAdapter::exportTargetSamContextForAsyncTransaction()
{
    std::vector<std::shared_ptr<Command>> commands;

    // read system key parameters if not available
    if (!getContext()->getTargetSam()->getSystemKeyParameter(
            SystemKeyType::PERSONALIZATION)) {
        commands.push_back(
            std::make_shared<CommandReadKeyParameters>(
                getContext(), SystemKeyType::PERSONALIZATION));
    }
    if (!getContext()->getTargetSam()->getSystemKeyParameter(
            SystemKeyType::KEY_MANAGEMENT)) {
        commands.push_back(
            std::make_shared<CommandReadKeyParameters>(
                getContext(), SystemKeyType::KEY_MANAGEMENT));
    }
    if (!getContext()->getTargetSam()->getSystemKeyParameter(
            SystemKeyType::RELOADING)) {
        commands.push_back(
            std::make_shared<CommandReadKeyParameters>(
                getContext(), SystemKeyType::RELOADING));
    }
    processTargetSamCommands(commands);
    commands.clear();

    // The parameter PAR4 of each key contains the associated counter number (if
    // a key has no associated counter, the value of its PAR4 is set to 0)
    int counterPersonalization
        = getContext()
              ->getTargetSam()
              ->getSystemKeyParameter(SystemKeyType::PERSONALIZATION)
              ->getParameterValue(4)
          & 0xFF;
    int counterKeyManagement
        = getContext()
              ->getTargetSam()
              ->getSystemKeyParameter(SystemKeyType::KEY_MANAGEMENT)
              ->getParameterValue(4)
          & 0xFF;
    int counterReloading = getContext()
                               ->getTargetSam()
                               ->getSystemKeyParameter(SystemKeyType::RELOADING)
                               ->getParameterValue(4)
                           & 0xFF;

    // store serial number, KVCs and counter number if any in the target SAM
    // context
    auto targetSamContextDto
        = std::make_shared<DtoAdapters::TargetSamContextDto>(
            getContext()->getTargetSam()->getSerialNumber(), false);
    targetSamContextDto
        ->getSystemKeyTypeToKvcMap()[SystemKeyType::PERSONALIZATION]
        = getContext()
              ->getTargetSam()
              ->getSystemKeyParameter(SystemKeyType::PERSONALIZATION)
              ->getKvc();
    targetSamContextDto
        ->getSystemKeyTypeToKvcMap()[SystemKeyType::KEY_MANAGEMENT]
        = getContext()
              ->getTargetSam()
              ->getSystemKeyParameter(SystemKeyType::KEY_MANAGEMENT)
              ->getKvc();
    targetSamContextDto->getSystemKeyTypeToKvcMap()[SystemKeyType::RELOADING]
        = getContext()
              ->getTargetSam()
              ->getSystemKeyParameter(SystemKeyType::RELOADING)
              ->getKvc();
    if (counterPersonalization != 0) {
        targetSamContextDto->getSystemKeyTypeToCounterNumberMap()
            [SystemKeyType::PERSONALIZATION]
            = counterPersonalization;
    }
    if (counterKeyManagement != 0) {
        targetSamContextDto->getSystemKeyTypeToCounterNumberMap()
            [SystemKeyType::KEY_MANAGEMENT]
            = counterKeyManagement;
    }
    if (counterReloading != 0) {
        targetSamContextDto
            ->getSystemKeyTypeToCounterNumberMap()[SystemKeyType::RELOADING]
            = counterReloading;
    }

    // compute needed counter file records
    std::set<int> counterFileRecordNumbers;
    if (counterPersonalization != 0) {
        counterFileRecordNumbers.insert(
            LegacySamConstants::COUNTER_TO_RECORD_LOOKUP
                [counterPersonalization]);
    }
    if (counterKeyManagement != 0) {
        counterFileRecordNumbers.insert(
            LegacySamConstants::COUNTER_TO_RECORD_LOOKUP[counterKeyManagement]);
    }
    if (counterReloading != 0) {
        counterFileRecordNumbers.insert(
            LegacySamConstants::COUNTER_TO_RECORD_LOOKUP[counterReloading]);
    }

    // read counters
    for (int counterFileRecordNumber : counterFileRecordNumbers) {
        commands.push_back(
            std::make_shared<CommandReadCounter>(
                getContext(), counterFileRecordNumber));
    }
    processTargetSamCommands(commands);

    if (counterPersonalization != 0) {
        targetSamContextDto
            ->getCounterNumberToCounterValueMap()[counterPersonalization]
            = *(getContext()->getTargetSam()->getCounter(
                counterPersonalization));
    }
    if (counterKeyManagement != 0) {
        targetSamContextDto
            ->getCounterNumberToCounterValueMap()[counterKeyManagement]
            = *(getContext()->getTargetSam()->getCounter(counterKeyManagement));
    }
    if (counterReloading != 0) {
        targetSamContextDto
            ->getCounterNumberToCounterValueMap()[counterReloading]
            = *(getContext()->getTargetSam()->getCounter(counterReloading));
    }

    // export as json
    // This is a placeholder implementation.
    return "{}";
}

FreeTransactionManager&
FreeTransactionManagerAdapter::processCommands()
{
    processTargetSamCommands(false);

    return *this;
}

void
FreeTransactionManagerAdapter::prepareSelectDiversifierIfNeeded(
    const std::vector<uint8_t>& specificKeyDiversifier)
{
    if (!specificKeyDiversifier.empty()) {
        if (specificKeyDiversifier != mCurrentKeyDiversifier) {
            mCurrentKeyDiversifier = specificKeyDiversifier;
            prepareSelectDiversifier();
        }

    } else {
        prepareSelectDiversifierIfNeeded();
    }
}

void
FreeTransactionManagerAdapter::prepareSelectDiversifierIfNeeded()
{
    if (mCurrentKeyDiversifier != mSamKeyDiversifier) {
        mCurrentKeyDiversifier = mSamKeyDiversifier;
        prepareSelectDiversifier();
    }
}

void
FreeTransactionManagerAdapter::prepareSelectDiversifier()
{
    addTargetSamCommand(
        std::make_shared<CommandSelectDiversifier>(
            getContext(), mCurrentKeyDiversifier));
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
