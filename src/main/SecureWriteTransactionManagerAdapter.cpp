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

#include "keyple/card/calypso/crypto/legacysam/SecureWriteTransactionManagerAdapter.hpp"

#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/CommandGetChallenge.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandReadKeyParameters.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandWriteCeilings.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandWriteKey.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandWriteSamParameters.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamConstants.hpp"
#include "keyple/core/util/KeypleAssert.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::Assert;

SecureWriteTransactionManagerAdapter::SecureWriteTransactionManagerAdapter(
    std::shared_ptr<ProxyReaderApi> targetSamReader,
    std::shared_ptr<LegacySamAdapter> targetSam,
    std::shared_ptr<ProxyReaderApi> controlSamReader,
    std::shared_ptr<LegacySamAdapter> controlSam)
: CommonTransactionManagerAdapter(
      targetSamReader, targetSam, controlSamReader, controlSam)
{
}

SecureWriteTransactionManager&
SecureWriteTransactionManagerAdapter::prepareWriteSamParameters(
    const std::vector<uint8_t>& parameters)
{
    core::util::Assert::getInstance().isEqual(
        parameters.size(),
        LegacySamConstants::SAM_PARAMETERS_LENGTH,
        "parameters.length");

    if (!getContext()->getTargetSam()->getSystemKeyParameter(
            SystemKeyType::PERSONALIZATION)) {
        addTargetSamCommand(
            std::make_shared<CommandReadKeyParameters>(
                getContext(), SystemKeyType::PERSONALIZATION));
    }

    addTargetSamCommand(std::make_shared<CommandGetChallenge>(getContext(), 8));
    addTargetSamCommand(
        std::make_shared<CommandWriteSamParameters>(getContext(), parameters));

    return *this;
}

SecureWriteTransactionManager&
SecureWriteTransactionManagerAdapter::prepareTransferSystemKey(
    SystemKeyType systemKeyType,
    uint8_t kvc,
    const std::vector<uint8_t>& systemKeyParameters)
{
    return prepareTransferSystemKeyInternal(
        systemKeyType, kvc, systemKeyParameters, false);
}

SecureWriteTransactionManager&
SecureWriteTransactionManagerAdapter::prepareTransferSystemKeyDiversified(
    SystemKeyType systemKeyType,
    uint8_t kvc,
    const std::vector<uint8_t>& systemKeyParameters)
{
    return prepareTransferSystemKeyInternal(
        systemKeyType, kvc, systemKeyParameters, true);
}

SecureWriteTransactionManager&
SecureWriteTransactionManagerAdapter::prepareTransferSystemKeyInternal(
    SystemKeyType systemKeyType,
    uint8_t kvc,
    const std::vector<uint8_t>& systemKeyParameters,
    bool isDiversified)
{
    core::util::Assert::getInstance().isEqual(
        systemKeyParameters.size(),
        LegacySamConstants::KEY_PARAMETERS_LENGTH,
        "systemKeyParameters.length");

    if (!getContext()->getTargetSam()->getSystemKeyParameter(
            SystemKeyType::PERSONALIZATION)) {
        addTargetSamCommand(
            std::make_shared<CommandReadKeyParameters>(
                getContext(), SystemKeyType::PERSONALIZATION));
    }

    addTargetSamCommand(std::make_shared<CommandGetChallenge>(getContext(), 8));

    addTargetSamCommand(
        std::make_shared<CommandWriteKey>(
            getContext(),
            systemKeyType,
            kvc,
            systemKeyParameters,
            isDiversified));

    return *this;
}

SecureWriteTransactionManager&
SecureWriteTransactionManagerAdapter::prepareTransferWorkKey(
    uint8_t kif,
    uint8_t kvc,
    const std::vector<uint8_t>& workKeyParameters,
    int targetRecordNumber)
{
    return prepareTransferWorkKeyInternal(
        kif, kvc, workKeyParameters, targetRecordNumber, false, {});
}

SecureWriteTransactionManager&
SecureWriteTransactionManagerAdapter::prepareTransferWorkKeyDiversified(
    uint8_t kif,
    uint8_t kvc,
    const std::vector<uint8_t>& workKeyParameters,
    int targetRecordNumber)
{
    return prepareTransferWorkKeyInternal(
        kif, kvc, workKeyParameters, targetRecordNumber, true, {});
}

SecureWriteTransactionManager&
SecureWriteTransactionManagerAdapter::prepareTransferWorkKeyDiversified(
    uint8_t kif,
    uint8_t kvc,
    const std::vector<uint8_t>& workKeyParameters,
    int targetRecordNumber,
    const std::vector<uint8_t>& diversifier)
{
    return prepareTransferWorkKeyInternal(
        kif, kvc, workKeyParameters, targetRecordNumber, true, diversifier);
}

SecureWriteTransactionManager&
SecureWriteTransactionManagerAdapter::prepareTransferWorkKeyInternal(
    uint8_t kif,
    uint8_t kvc,
    const std::vector<uint8_t>& workKeyParameters,
    int targetRecordNumber,
    bool diversified,
    const std::vector<uint8_t>& diversifier)
{
    core::util::Assert::getInstance()
        .isEqual(
            workKeyParameters.size(),
            LegacySamConstants::KEY_PARAMETERS_LENGTH,
            "workKeyParameters.length")
        .isInRange(targetRecordNumber, 0, 126, "targetRecordNumber");

    if (!getContext()->getTargetSam()->getSystemKeyParameter(
            SystemKeyType::KEY_MANAGEMENT)) {
        addTargetSamCommand(
            std::make_shared<CommandReadKeyParameters>(
                getContext(), SystemKeyType::KEY_MANAGEMENT));
    }

    addTargetSamCommand(std::make_shared<CommandGetChallenge>(getContext(), 8));

    if (diversifier.empty()) {
        addTargetSamCommand(
            std::make_shared<CommandWriteKey>(
                getContext(),
                kif,
                kvc,
                targetRecordNumber,
                workKeyParameters,
                diversified));
    } else {
        addTargetSamCommand(
            std::make_shared<CommandWriteKey>(
                getContext(),
                kif,
                kvc,
                targetRecordNumber,
                workKeyParameters,
                diversifier));
    }

    return *this;
}

SecureWriteTransactionManager&
SecureWriteTransactionManagerAdapter::prepareTransferLock(
    uint8_t lockIndex, uint8_t lockParameters)
{
    return prepareTransferLockInternal(lockIndex, lockParameters, false);
}

SecureWriteTransactionManager&
SecureWriteTransactionManagerAdapter::prepareTransferLockDiversified(
    uint8_t lockIndex, uint8_t lockParameters)
{
    return prepareTransferLockInternal(lockIndex, lockParameters, true);
}

SecureWriteTransactionManager&
SecureWriteTransactionManagerAdapter::prepareTransferLockInternal(
    uint8_t lockIndex, uint8_t lockParameters, bool isDiversified)
{
    if (!getContext()->getTargetSam()->getSystemKeyParameter(
            SystemKeyType::KEY_MANAGEMENT)) {
        addTargetSamCommand(
            std::make_shared<CommandReadKeyParameters>(
                getContext(), SystemKeyType::KEY_MANAGEMENT));
    }

    addTargetSamCommand(std::make_shared<CommandGetChallenge>(getContext(), 8));
    addTargetSamCommand(
        std::make_shared<CommandWriteKey>(
            getContext(), lockIndex, lockParameters, isDiversified));

    return *this;
}

SecureWriteTransactionManager&
SecureWriteTransactionManagerAdapter::preparePlainWriteLock(
    uint8_t lockIndex,
    uint8_t lockParameters,
    const std::vector<uint8_t>& lockValue)
{
    core::util::Assert::getInstance().isEqual(
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

SecureWriteTransactionManager&
SecureWriteTransactionManagerAdapter::prepareWriteCounterCeiling(
    int counterNumber, int ceilingValue)
{
    core::util::Assert::getInstance()
        .isInRange(
            counterNumber,
            LegacySamConstants::MIN_COUNTER_CEILING_NUMBER,
            LegacySamConstants::MAX_COUNTER_CEILING_NUMBER,
            "counterNumber")
        .isInRange(
            ceilingValue,
            LegacySamConstants::MIN_COUNTER_CEILING_VALUE,
            LegacySamConstants::MAX_COUNTER_CEILING_VALUE,
            "ceilingValue");

    if (!getContext()->getTargetSam()->getSystemKeyParameter(
            SystemKeyType::RELOADING)) {
        addTargetSamCommand(
            std::make_shared<CommandReadKeyParameters>(
                getContext(), SystemKeyType::RELOADING));
    }
    addTargetSamCommand(std::make_shared<CommandGetChallenge>(getContext(), 8));
    addTargetSamCommand(
        std::make_shared<CommandWriteCeilings>(
            getContext(), counterNumber, ceilingValue));

    return *this;
}

SecureWriteTransactionManager&
SecureWriteTransactionManagerAdapter::prepareWriteCounterConfiguration(
    int counterNumber,
    int ceilingValue,
    CounterIncrementAccess counterIncrementAccess)
{
    core::util::Assert::getInstance()
        .isInRange(
            counterNumber,
            LegacySamConstants::MIN_COUNTER_CEILING_NUMBER,
            LegacySamConstants::MAX_COUNTER_CEILING_NUMBER,
            "counterNumber")
        .isInRange(
            ceilingValue,
            LegacySamConstants::MIN_COUNTER_CEILING_VALUE,
            LegacySamConstants::MAX_COUNTER_CEILING_VALUE,
            "ceilingValue");

    for (const auto& command : getTargetSamCommands()) {
        auto writeCeilingsCommand
            = std::dynamic_pointer_cast<CommandWriteCeilings>(command);
        if (writeCeilingsCommand
            && writeCeilingsCommand->getCounterFileRecordNumber()
                   == LegacySamConstants::COUNTER_TO_RECORD_LOOKUP
                       [counterNumber]) {
            writeCeilingsCommand->addCounter(
                counterNumber, ceilingValue, counterIncrementAccess);

            return *this;
        }
    }

    if (!getContext()->getTargetSam()->getSystemKeyParameter(
            SystemKeyType::RELOADING)) {
        addTargetSamCommand(
            std::make_shared<CommandReadKeyParameters>(
                getContext(), SystemKeyType::RELOADING));
    }
    addTargetSamCommand(std::make_shared<CommandGetChallenge>(getContext(), 8));
    addTargetSamCommand(
        std::make_shared<CommandWriteCeilings>(
            getContext(), counterNumber, ceilingValue, counterIncrementAccess));

    return *this;
}

SecureWriteTransactionManager&
SecureWriteTransactionManagerAdapter::processCommands()
{
    processTargetSamCommands(false);
    return *this;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
