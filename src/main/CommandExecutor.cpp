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

#include "keyple/card/calypso/crypto/legacysam/CommandExecutor.hpp"

#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/Command.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandException.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandRef.hpp"
#include "keypop/calypso/card/transaction/InconsistentDataException.hpp"
#include "keypop/calypso/card/transaction/UnexpectedCommandStatusException.hpp"
#include "keypop/card/CardBrokenCommunicationException.hpp"
#include "keypop/card/CardResponseApi.hpp"
#include "keypop/card/ChannelControl.hpp"
#include "keypop/card/ReaderBrokenCommunicationException.hpp"
#include "keypop/card/UnexpectedStatusWordException.hpp"
#include "keypop/reader/CardCommunicationException.hpp"
#include "keypop/reader/ReaderCommunicationException.hpp"
#include "keypop/reader/selection/InvalidCardResponseException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::card::transaction::InconsistentDataException;
using keypop::calypso::card::transaction::UnexpectedCommandStatusException;
using keypop::card::CardBrokenCommunicationException;
using keypop::card::CardResponseApi;
using keypop::card::ChannelControl;
using keypop::card::ReaderBrokenCommunicationException;
using keypop::card::UnexpectedStatusWordException;
using keypop::reader::CardCommunicationException;
using keypop::reader::ReaderCommunicationException;
using keypop::reader::selection::InvalidCardResponseException;

const std::string CommandExecutor::MSG_SAM_READER_COMMUNICATION_ERROR
    = "A communication error with the SAM reader occurred ";
const std::string CommandExecutor::MSG_SAM_COMMUNICATION_ERROR
    = "A communication error with the SAM occurred ";
const std::string CommandExecutor::MSG_SAM_COMMAND_ERROR
    = "A SAM command error occurred ";
const std::string CommandExecutor::MSG_WHILE_TRANSMITTING_COMMANDS
    = "while transmitting commands";

void
CommandExecutor::processCommands(
    const std::vector<std::shared_ptr<Command>>& commands,
    std::shared_ptr<ProxyReaderApi> samReader,
    bool closePhysicalChannel)
{
    if (commands.empty()) {
        return;
    }

    std::vector<std::shared_ptr<Command>> cardRequestCommands;

    for (const auto& command : commands) {
        if (command->isControlSamRequiredToFinalizeRequest()) {
            executeCommands(cardRequestCommands, samReader, false);
            cardRequestCommands.clear();
        }

        command->finalizeRequest();
        cardRequestCommands.push_back(command);
    }

    executeCommands(cardRequestCommands, samReader, closePhysicalChannel);
}

void
CommandExecutor::processCommandsAlreadyFinalized(
    const std::vector<std::shared_ptr<Command>>& commands,
    std::shared_ptr<ProxyReaderApi> samReader,
    bool closePhysicalChannel)
{
    if (commands.empty()) {
        return;
    }

    executeCommands(commands, samReader, closePhysicalChannel);
}

void
CommandExecutor::executeCommands(
    const std::vector<std::shared_ptr<Command>>& commands,
    std::shared_ptr<ProxyReaderApi> samReader,
    bool closePhysicalChannel)
{
    /* Retrieve the list of C-APDUs */
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests
        = getApduRequests(commands);

    /* Wrap the list of C-APDUs into a card request */
    std::shared_ptr<CardRequestSpi> cardRequest
        = std::make_shared<DtoAdapters::CardRequestAdapter>(apduRequests, true);

    /* Transmit the commands to the card */
    std::shared_ptr<CardResponseApi> cardResponse = transmitCardRequest(
        cardRequest,
        samReader,
        closePhysicalChannel ? ChannelControl::CLOSE_AFTER
                             : ChannelControl::KEEP_OPEN);

    /* Retrieve the list of R-APDUs */
    std::vector<std::shared_ptr<ApduResponseApi>> apduResponses
        = cardResponse->getApduResponses();

    /*
     * If there are more responses than requests, then we are unable to fill the
     * card image. In this case we stop processing immediately because it may be
     * a case of fraud, and we throw a desynchronized exception.
     */
    if (apduResponses.size() > commands.size()) {
        throw InconsistentDataException(
            "The number of commands/responses does not match: nb commands = "
            + std::to_string(commands.size())
            + ", nb responses = " + std::to_string(apduResponses.size()));
    }

    /*
     * We go through all the responses (and not the requests) because there may
     * be fewer in the case of an error that occurred in strict mode. In this
     * case the last response will raise an exception.
     */
    for (int i = 0; i < static_cast<int>(apduResponses.size()); i++) {
        std::shared_ptr<Command> command = commands[i];

        try {
            command->parseResponse(apduResponses[i]);

        } catch (const CommandException& e) {
            throw UnexpectedCommandStatusException(
                MSG_SAM_COMMAND_ERROR
                    + "while processing responses to SAM commands: "
                    + command->getCommandRef().getName(),
                e);
        }
    }

    /*
     * Finally, if no error has occurred and there are fewer responses than
     * requests, then we throw a desynchronized exception.
     */
    if (apduResponses.size() < commands.size()) {
        throw InconsistentDataException(
            "The number of commands/responses does not match: nb commands = "
            + std::to_string(commands.size())
            + ", nb responses = " + std::to_string(apduResponses.size()));
    }
}

std::vector<std::shared_ptr<ApduRequestSpi>>
CommandExecutor::getApduRequests(
    const std::vector<std::shared_ptr<Command>>& commands)
{
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests;

    if (!commands.empty()) {
        for (const auto& command : commands) {
            apduRequests.push_back(command->getApduRequest());
        }
    }

    return apduRequests;
}

std::shared_ptr<CardResponseApi>
CommandExecutor::transmitCardRequest(
    std::shared_ptr<CardRequestSpi> cardRequest,
    std::shared_ptr<ProxyReaderApi> samReader,
    ChannelControl channelControl)
{
    std::shared_ptr<CardResponseApi> cardResponse;

    try {
        cardResponse
            = samReader->transmitCardRequest(cardRequest, channelControl);

    } catch (const ReaderBrokenCommunicationException& e) {
        throw ReaderCommunicationException(
            MSG_SAM_READER_COMMUNICATION_ERROR
                + MSG_WHILE_TRANSMITTING_COMMANDS,
            e);

    } catch (const CardBrokenCommunicationException& e) {
        throw CardCommunicationException(
            MSG_SAM_COMMUNICATION_ERROR + MSG_WHILE_TRANSMITTING_COMMANDS, e);

    } catch (const UnexpectedStatusWordException& e) {
        cardResponse = e.getCardResponse();
    }

    return cardResponse;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
