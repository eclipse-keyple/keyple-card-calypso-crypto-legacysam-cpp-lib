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
#include "keypop/card/CardResponseApi.hpp"
#include "keypop/card/ChannelControl.hpp"
#include "keypop/card/ProxyReaderApi.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::card::CardResponseApi;
using keypop::card::ChannelControl;
using keypop::card::ProxyReaderApi;

/**
 * Utility class to factorize command management.
 *
 * @since 0.3.0
 */
class CommandExecutor {
public:
    /**
     * Requests the execution of all commands provided by the SAM inserted in
     * the supplied card reader, and finalizes any commands that require it.
     *
     * @param commands A non-null list of Command.
     * @param closePhysicalChannel True if the physical channel must be closed
     * after the operation.
     * @since 0.3.0
     */
    static void processCommands(
        const std::vector<std::shared_ptr<Command>>& commands,
        std::shared_ptr<ProxyReaderApi> samReader,
        bool closePhysicalChannel);

    /**
     * Requests the execution of all commands provided by the SAM inserted in
     * the supplied card reader without finalizing it.
     *
     * @param commands A non-null list of Command.
     * @param closePhysicalChannel True if the physical channel must be closed
     * after the operation.
     * @since 0.3.0
     */
    static void processCommandsAlreadyFinalized(
        const std::vector<std::shared_ptr<Command>>& commands,
        std::shared_ptr<ProxyReaderApi> samReader,
        bool closePhysicalChannel);

private:
    /**
     *
     */
    static const std::string MSG_SAM_READER_COMMUNICATION_ERROR;
    static const std::string MSG_SAM_COMMUNICATION_ERROR;
    static const std::string MSG_SAM_COMMAND_ERROR;
    static const std::string MSG_WHILE_TRANSMITTING_COMMANDS;

    /**
     *
     */
    CommandExecutor() = default;

    /**
     * Executes the provided commands.
     *
     * @param commands The commands.
     * @param closePhysicalChannel True if the physical channel must be closed
     * after the operation.
     */
    static void executeCommands(
        const std::vector<std::shared_ptr<Command>>& commands,
        std::shared_ptr<ProxyReaderApi> samReader,
        bool closePhysicalChannel);

    /**
     * Creates a list of ApduRequestSpi from a list of Command.
     *
     * @param commands The list of commands.
     * @return An empty list if there is no command.
     * @since 0.3.0
     */
    static std::vector<std::shared_ptr<ApduRequestSpi>>
    getApduRequests(const std::vector<std::shared_ptr<Command>>& commands);

    /**
     * Transmits a card request, processes and converts any exceptions.
     *
     * @param cardRequest The card request to transmit.
     * @param channelControl The channel control.
     * @return The card response.
     */
    static std::shared_ptr<CardResponseApi> transmitCardRequest(
        std::shared_ptr<CardRequestSpi> cardRequest,
        std::shared_ptr<ProxyReaderApi> samReader,
        ChannelControl channelControl);
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
