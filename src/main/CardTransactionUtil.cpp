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

#include "keyple/card/calypso/crypto/legacysam/CardTransactionUtil.hpp"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "keypop/calypso/crypto/symmetric/SymmetricCryptoIOException.hpp"
#include "keypop/card/CardBrokenCommunicationException.hpp"
#include "keypop/card/ChannelControl.hpp"
#include "keypop/card/ReaderBrokenCommunicationException.hpp"
#include "keypop/card/UnexpectedStatusWordException.hpp"
#include "keypop/reader/CardCommunicationException.hpp"
#include "keypop/reader/ReaderCommunicationException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::crypto::symmetric::SymmetricCryptoIOException;
using keypop::card::CardBrokenCommunicationException;
using keypop::card::ReaderBrokenCommunicationException;
using keypop::card::UnexpectedStatusWordException;
using keypop::reader::CardCommunicationException;
using keypop::reader::ReaderCommunicationException;

const std::string CardTransactionUtil::MSG_SAM_READER_COMMUNICATION_ERROR
    = "Failed to communicate with SAM reader";
const std::string CardTransactionUtil::MSG_SAM_COMMUNICATION_ERROR
    = "Failed to communicate with SAM";
const std::string CardTransactionUtil::MSG_WHILE_TRANSMITTING_COMMANDS
    = " while transmitting commands.";
const std::string CardTransactionUtil::MSG_FAILED_TO_PROCESS_SAM_RESPONSE
    = "Failed to process SAM response.";

std::vector<std::shared_ptr<ApduRequestSpi>>
CardTransactionUtil::getApduRequests(
    const std::vector<std::shared_ptr<Command>>& commands)
{
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests;
    for (const auto& command : commands) {
        apduRequests.push_back(command->getApduRequest());
    }

    return apduRequests;
}

std::shared_ptr<CardResponseApi>
CardTransactionUtil::transmitCardRequest(
    std::shared_ptr<CardRequestSpi> cardRequest,
    std::shared_ptr<ProxyReaderApi> samReader,
    std::shared_ptr<LegacySam> sam,
    std::vector<std::vector<uint8_t>>& transactionAuditData)
{
    std::shared_ptr<CardResponseApi> cardResponse;
    try {
        cardResponse = samReader->transmitCardRequest(
            cardRequest, keypop::card::ChannelControl::KEEP_OPEN);

    } catch (const ReaderBrokenCommunicationException& e) {
        saveTransactionAuditData(
            cardRequest, e.getCardResponse(), transactionAuditData);
        throw SymmetricCryptoIOException(
            MSG_SAM_READER_COMMUNICATION_ERROR
                + MSG_WHILE_TRANSMITTING_COMMANDS,
            ReaderCommunicationException(
                MSG_SAM_READER_COMMUNICATION_ERROR
                    + MSG_WHILE_TRANSMITTING_COMMANDS
                    + getTransactionAuditDataAsString(
                        transactionAuditData, sam),
                e));

    } catch (const CardBrokenCommunicationException& e) {
        saveTransactionAuditData(
            cardRequest, e.getCardResponse(), transactionAuditData);
        throw SymmetricCryptoIOException(
            MSG_SAM_COMMUNICATION_ERROR + MSG_WHILE_TRANSMITTING_COMMANDS,
            CardCommunicationException(
                MSG_SAM_COMMUNICATION_ERROR + MSG_WHILE_TRANSMITTING_COMMANDS
                    + getTransactionAuditDataAsString(
                        transactionAuditData, sam),
                e));

    } catch (const UnexpectedStatusWordException& e) {
        cardResponse = e.getCardResponse();
    }

    saveTransactionAuditData(cardRequest, cardResponse, transactionAuditData);

    return cardResponse;
}

void
CardTransactionUtil::saveTransactionAuditData(
    std::shared_ptr<CardRequestSpi> cardRequest,
    std::shared_ptr<CardResponseApi> cardResponse,
    std::vector<std::vector<uint8_t>>& transactionAuditData)
{
    if (cardResponse) {
        auto requests = cardRequest->getApduRequests();
        auto responses = cardResponse->getApduResponses();
        for (size_t i = 0; i < responses.size(); i++) {
            transactionAuditData.push_back(requests[i]->getApdu());
            transactionAuditData.push_back(responses[i]->getApdu());
        }
    }
}

std::string
CardTransactionUtil::getTransactionAuditDataAsString(
    const std::vector<std::vector<uint8_t>>& /*transactionAuditData*/,
    std::shared_ptr<LegacySam> /*sam*/)
{
    return std::string("\nTransaction audit JSON data: {") + "\"sam\":" + "TODO"
           + ", " + "\"apdus\":"
           + "TODO" /*JsonUtil.toJson(transactionAuditData) */ + "}";
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
