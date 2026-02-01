/******************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://calypsonet.org/    *
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

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/Command.hpp"
#include "keypop/card/CardResponseApi.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::card::CardResponseApi;

/**
 * Util to build and transmit APDU requests.
 *
 * @since 2.0.0
 */
class CardTransactionUtil {
public:
    /**
     * Creates a list of ApduRequestSpi from a list of Command.
     *
     * @param commands The list of commands.
     * @return An empty list if there is no command.
     * @since 2.0.0
     */
    static std::vector<std::shared_ptr<ApduRequestSpi>>
    getApduRequests(const std::vector<std::shared_ptr<Command>>& commands);

    /**
     * Transmits a card request, processes and converts any exceptions.
     *
     * @param cardRequest The card request to transmit.
     * @param samReader The sam reader.
     * @param sam The sam.
     * @param transactionAuditData The transaction audit data.
     * @return The card response.
     * @since 2.0.0
     */
    static std::shared_ptr<CardResponseApi> transmitCardRequest(
        std::shared_ptr<CardRequestSpi> cardRequest,
        std::shared_ptr<ProxyReaderApi> samReader,
        std::shared_ptr<LegacySam> sam,
        std::vector<std::vector<uint8_t>>& transactionAuditData);

    /**
     * Returns a string representation of the transaction audit data.
     *
     * @param transactionAuditData The transaction audit data.
     * @param sam The sam.
     * @return A not empty string.
     * @since 2.0.0
     */
    static std::string getTransactionAuditDataAsString(
        const std::vector<std::vector<uint8_t>>& transactionAuditData,
        std::shared_ptr<LegacySam> sam);

    /**
     *
     */
    static const std::string MSG_SAM_READER_COMMUNICATION_ERROR;
    static const std::string MSG_SAM_COMMUNICATION_ERROR;
    static const std::string MSG_WHILE_TRANSMITTING_COMMANDS;
    static const std::string MSG_SAM_COMMAND_ERROR;

private:
    /**
     *
     */
    CardTransactionUtil() = default;

    /**
     * Saves the provided exchanged APDU commands in the list of transaction
     * audit data.
     *
     * @param cardRequest The card request.
     * @param cardResponse The associated card response.
     * @param transactionAuditData The audit data list.
     * @since 2.0.0
     */
    static void saveTransactionAuditData(
        std::shared_ptr<CardRequestSpi> cardRequest,
        std::shared_ptr<CardResponseApi> cardResponse,
        std::vector<std::vector<uint8_t>>& transactionAuditData);
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
