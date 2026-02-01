/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
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

#include "keyple/card/calypso/crypto/legacysam/AsyncTransactionCreatorManagerAdapter.hpp"

#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/Command.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandWriteCeilings.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamConstants.hpp"
#include "keyple/card/calypso/crypto/legacysam/SecuritySettingAdapter.hpp"
#include "keyple/core/util/KeypleAssert.hpp"
#include "keyple/core/util/cpp/exception/UnsupportedOperationException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::Assert;
using keyple::core::util::cpp::exception::UnsupportedOperationException;

AsyncTransactionCreatorManagerAdapter::AsyncTransactionCreatorManagerAdapter(
    const std::string& /* targetSamContextJson* */,
    const std::shared_ptr<SecuritySetting> securitySetting)
: CommonTransactionManagerAdapter(
      nullptr,
      nullptr,
      std::dynamic_pointer_cast<SecuritySettingAdapter>(securitySetting)
          ->getControlSamReader(),
      std::dynamic_pointer_cast<SecuritySettingAdapter>(securitySetting)
          ->getControlSam())
{
}

AsyncTransactionCreatorManager&
AsyncTransactionCreatorManagerAdapter::prepareWriteCounterCeiling(
    const int counterNumber, const int ceilingValue)
{
    Assert::getInstance()
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

    addTargetSamCommand(
        std::make_shared<CommandWriteCeilings>(
            getContext(), mTargetSamContext, counterNumber, ceilingValue));

    return *this;
}

AsyncTransactionCreatorManager&
AsyncTransactionCreatorManagerAdapter::prepareWriteCounterConfiguration(
    const int counterNumber,
    const int ceilingValue,
    const CounterIncrementAccess counterIncrementAccess)
{
    Assert::getInstance()
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
        auto commandWriteCeilings
            = std::dynamic_pointer_cast<CommandWriteCeilings>(command);
        if (commandWriteCeilings
            && commandWriteCeilings->getCounterFileRecordNumber()
                   == LegacySamConstants::COUNTER_TO_RECORD_LOOKUP
                       [counterNumber]) {
            commandWriteCeilings->addCounter(
                counterNumber, ceilingValue, counterIncrementAccess);
            return *this;
        }
    }

    addTargetSamCommand(
        std::make_shared<CommandWriteCeilings>(
            getContext(),
            mTargetSamContext,
            counterNumber,
            ceilingValue,
            counterIncrementAccess));

    return *this;
}

std::string
AsyncTransactionCreatorManagerAdapter::exportCommands() const
{
    const std::vector<std::shared_ptr<Command>> commands
        = getTargetSamCommands();

    for (const auto& command : commands) {
        command->finalizeRequest();
    }

    // JsonObject jsonObject = new JsonObject();

    std::vector<std::string> cardCommandTypes;

    for (const auto& command : commands) {
        cardCommandTypes.push_back(typeid(command).name());
    }

    // jsonObject.add(SAM_COMMANDS_TYPES,
    // JsonUtil.getParser().toJsonTree(cardCommandTypes));
    // jsonObject.add(SAM_COMMANDS, JsonUtil.getParser().toJsonTree(commands));

    return "";  // jsonObject.toString();
}

AsyncTransactionCreatorManager&
AsyncTransactionCreatorManagerAdapter::processCommands()
{
    throw UnsupportedOperationException(
        std::string("processCommands() is not allowed during the creation of")
        + "an asynchronous transaction");
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
