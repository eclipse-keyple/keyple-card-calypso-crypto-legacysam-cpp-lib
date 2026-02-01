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

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/Command.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

/**
 * Abstract class of all transaction manager adapters.
 *
 * @since 0.3.0
 */
class CommonTransactionManagerAdapter {
public:
    // JSON field names
    static const std::string SAM_COMMANDS_TYPES;
    static const std::string SAM_COMMANDS;

    /**
     * Constructor
     * @param targetSamReader The reader through which the target SAM
     * communicates.
     * @param targetSam The target legacy SAM.
     * @param controlSamReader The reader through which the control SAM
     * communicates.
     * @param controlSam The control legacy SAM.
     */
    CommonTransactionManagerAdapter(
        std::shared_ptr<ProxyReaderApi> targetSamReader,
        std::shared_ptr<LegacySamAdapter> targetSam,
        std::shared_ptr<ProxyReaderApi> controlSamReader,
        std::shared_ptr<LegacySamAdapter> controlSam);

    /**
     * Gets the command context.
     *
     * @return An instance of CommandContextDto.
     * @since 0.3.0
     */
    std::shared_ptr<CommandContextDto> getContext() const;

    /**
     * Adds a command to be executed be the target SAM.
     * @param samCommand The command to be added.
     * @since 0.3.0
     */
    void addTargetSamCommand(std::shared_ptr<Command> samCommand);

    /**
     * Gets the list of added target SAM commands.
     *
     * @return A not null list of commands.
     * @since 0.3.0
     */
    const std::vector<std::shared_ptr<Command>>& getTargetSamCommands() const;

    /**
     * Executes all previously added commands for the target SAM. If a command
     * needs to be finalized, especially with the help of a control SAM, then it
     * will be.
     *
     * @param closePhysicalChannel True if the physical channel must be closed
     * after the operation.
     * @since 0.3.0
     */
    void processTargetSamCommands(bool closePhysicalChannel);

    /**
     * Executes all previously added commands for the target SAM when they are
     * already finalized (in an asynchronous operation for example).
     *
     * @param closePhysicalChannel True if the physical channel must be closed
     * after the operation.
     * @since 0.3.0
     */
    void processTargetSamCommandsAlreadyFinalized(bool closePhysicalChannel);

    /**
     * Executes all provided commands for the target SAM. If a command needs to
     * be finalized, especially with the help of a control SAM, then it will be.
     *
     * The method leaves the physical channel open, allowing for subsequent
     * commands to be executed on the same reader.
     *
     * @param commands A not null list of Command.
     * @since 0.3.0
     */
    void
    processTargetSamCommands(std::vector<std::shared_ptr<Command>> commands);

private:
    /**
     *
     */
    std::shared_ptr<ProxyReaderApi> mTargetSamReader;

    /**
     *
     */
    std::shared_ptr<LegacySamAdapter> mTargetSam;

    /**
     *
     */
    std::shared_ptr<ProxyReaderApi> mControlSamReader;

    /**
     *
     */
    std::shared_ptr<LegacySamAdapter> mControlSam;

    /**
     *
     */
    std::vector<std::shared_ptr<Command>> mTargetSamCommands;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
