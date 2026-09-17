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
#include "keyple/core/util/HexUtil.hpp"
#include "keypop/calypso/card/transaction/InconsistentDataException.hpp"
#include "keypop/card/CardBrokenCommunicationException.hpp"
#include "keypop/card/CardResponseApi.hpp"
#include "keypop/card/ChannelControl.hpp"
#include "keypop/card/ReaderBrokenCommunicationException.hpp"
#include "keypop/card/UnexpectedStatusWordException.hpp"
#include "keypop/reader/CardCommunicationException.hpp"
#include "keypop/reader/InvalidCardResponseException.hpp"
#include "keypop/reader/ReaderCommunicationException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::HexUtil;
using keypop::calypso::card::transaction::InconsistentDataException;
using keypop::card::CardBrokenCommunicationException;
using keypop::card::CardResponseApi;
using keypop::card::ReaderBrokenCommunicationException;
using keypop::card::UnexpectedStatusWordException;
using keypop::reader::CardCommunicationException;
using keypop::reader::InvalidCardResponseException;
using keypop::reader::ReaderCommunicationException;

const std::string CommandExecutor::MSG_SAM_READER_COMMUNICATION_ERROR
    = "Failed to communicate with SAM reader";
const std::string CommandExecutor::MSG_SAM_COMMUNICATION_ERROR
    = "Failed to communicate with SAM";
const std::string CommandExecutor::MSG_WHILE_TRANSMITTING_COMMANDS
    = " while transmitting commands.";

void
CommandExecutor::processCommands(
    const std::vector<std::shared_ptr<Command>>& commands,
    std::shared_ptr<ProxyReaderApi> samReader,
    ChannelControl channelControl)
{
    if (commands.empty()) {
        return;
    }

    std::vector<std::shared_ptr<Command>> cardRequestCommands;

    for (const auto& command : commands) {
        if (command->isControlSamRequiredToFinalizeRequest()) {
            executeCommands(
                cardRequestCommands, samReader, ChannelControl::KEEP_OPEN);
            cardRequestCommands.clear();
        }

        command->finalizeRequest();
        cardRequestCommands.push_back(command);
    }

    executeCommands(cardRequestCommands, samReader, channelControl);
}

void
CommandExecutor::processCommandsAlreadyFinalized(
    const std::vector<std::shared_ptr<Command>>& commands,
    std::shared_ptr<ProxyReaderApi> samReader,
    ChannelControl channelControl)
{
    if (commands.empty()) {
        return;
    }

    executeCommands(commands, samReader, channelControl);
}

void
CommandExecutor::executeCommands(
    const std::vector<std::shared_ptr<Command>>& commands,
    std::shared_ptr<ProxyReaderApi> samReader,
    ChannelControl channelControl)
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
        channelControl == ChannelControl::CLOSE_AFTER
            ? keypop::card::ChannelControl::CLOSE_AFTER
            : keypop::card::ChannelControl::KEEP_OPEN);

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
            "The number of commands/responses does not match. Expected "
            + std::to_string(commands.size()) + " responses, got "
            + std::to_string(apduResponses.size()));
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
            const std::string sw
                = command->getApduResponse() != nullptr
                      ? HexUtil::toHex(
                            static_cast<std::uint16_t>(
                                command->getApduResponse()->getStatusWord()))
                      : "null";
            throw InvalidCardResponseException(
                "Failed to process SAM response. Command: "
                    + command->getCommandRef().getName() + ", SW: " + sw,
                e);
        }
    }

    /*
     * Finally, if no error has occurred and there are fewer responses than
     * requests, then we throw a desynchronized exception.
     */
    if (apduResponses.size() < commands.size()) {
        throw InconsistentDataException(
            "The number of commands/responses does not match. Expected "
            + std::to_string(commands.size()) + " responses, got "
            + std::to_string(apduResponses.size()));
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
    keypop::card::ChannelControl channelControl)
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
