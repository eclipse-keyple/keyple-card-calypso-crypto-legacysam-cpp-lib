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

#include "keyple/card/calypso/crypto/legacysam/CommonTransactionManagerAdapter.hpp"

#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/CommandExecutor.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

const std::string CommonTransactionManagerAdapter::SAM_COMMANDS_TYPES
    = "samCommandsTypes";
const std::string CommonTransactionManagerAdapter::SAM_COMMANDS = "samCommands";

CommonTransactionManagerAdapter::CommonTransactionManagerAdapter(
    std::shared_ptr<ProxyReaderApi> targetSamReader,
    std::shared_ptr<LegacySamAdapter> targetSam,
    std::shared_ptr<ProxyReaderApi> controlSamReader,
    std::shared_ptr<LegacySamAdapter> controlSam)
: mTargetSamReader(targetSamReader)
, mTargetSam(targetSam)
, mControlSamReader(controlSamReader)
, mControlSam(controlSam)
, mTargetSamCommands(std::vector<std::shared_ptr<Command>>())
{
}

std::shared_ptr<CommandContextDto>
CommonTransactionManagerAdapter::getContext() const
{
    return std::make_shared<CommandContextDto>(
        mTargetSam, mControlSamReader, mControlSam);
}

void
CommonTransactionManagerAdapter::addTargetSamCommand(
    std::shared_ptr<Command> samCommand)
{
    mTargetSamCommands.push_back(samCommand);
}

const std::vector<std::shared_ptr<Command>>&
CommonTransactionManagerAdapter::getTargetSamCommands() const
{
    return mTargetSamCommands;
}

void
CommonTransactionManagerAdapter::processTargetSamCommands(
    bool closePhysicalChannel)
{
    CommandExecutor::processCommands(
        mTargetSamCommands, mTargetSamReader, closePhysicalChannel);

    mTargetSamCommands.clear();
}

void
CommonTransactionManagerAdapter::processTargetSamCommands(
    std::vector<std::shared_ptr<Command>> commands)
{
    CommandExecutor::processCommands(commands, mTargetSamReader, false);
}

void
CommonTransactionManagerAdapter::processTargetSamCommandsAlreadyFinalized(
    bool closePhysicalChannel)
{
    CommandExecutor::processCommandsAlreadyFinalized(
        mTargetSamCommands, mTargetSamReader, closePhysicalChannel);

    mTargetSamCommands.clear();
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
