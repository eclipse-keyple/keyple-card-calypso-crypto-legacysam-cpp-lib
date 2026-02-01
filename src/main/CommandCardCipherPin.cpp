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

#include "keyple/card/calypso/crypto/legacysam/CommandCardCipherPin.hpp"

#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/CounterOverflowException.hpp"
#include "keyple/card/calypso/crypto/legacysam/DataAccessException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/cpp/System.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;
using keyple::core::util::cpp::System;
using keyple::core::util::cpp::exception::IllegalArgumentException;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandCardCipherPin::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6700,
              std::make_shared<StatusProperties>(
                  "Incorrect Lc", typeid(IllegalParameterException))},
             {0x6900,
              std::make_shared<StatusProperties>(
                  "An event counter cannot be incremented",
                  typeid(CounterOverflowException))},

             {0x6985,
              std::make_shared<StatusProperties>(
                  "Preconditions not satisfied",
                  typeid(AccessForbiddenException))},
             {0x6A00,
              std::make_shared<StatusProperties>(
                  "Incorrect P1 or P2", typeid(IllegalParameterException))},
             {0x6A83,
              std::make_shared<StatusProperties>(
                  "Record not found: ciphering key not found",
                  typeid(DataAccessException))}});
        return m;
    }();

CommandCardCipherPin::CommandCardCipherPin(
    std::shared_ptr<DtoAdapters::CommandContextDto> context,
    std::uint8_t cipheringKif,
    std::uint8_t cipheringKvc,
    const std::vector<std::uint8_t>& currentPin)
: Command(CommandRef::CARD_CIPHER_PIN, 0, context)
{
    if (currentPin.size() != 4) {
        throw IllegalArgumentException("Bad current PIN value");
    }

    const std::uint8_t cla = context->getTargetSam()->getClassByte();

    std::uint8_t p1;
    std::uint8_t p2;

    /* No new PIN is provided, we consider it's a PIN verification. */

    p1 = 0x80;
    p2 = 0xFF; /* KIF and KVC in incoming data */

    auto data = std::vector<std::uint8_t>(6);
    data[0] = cipheringKif;
    data[1] = cipheringKvc;
    System::arraycopy(currentPin, 0, data, 2, 4);

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            cla, getCommandRef().getInstructionByte(), p1, p2, data)));
}

CommandCardCipherPin::CommandCardCipherPin(
    std::shared_ptr<DtoAdapters::CommandContextDto> context,
    std::uint8_t cipheringKif,
    std::uint8_t cipheringKvc,
    const std::vector<std::uint8_t>& currentPin,
    const std::vector<std::uint8_t>& newPin)
: Command(CommandRef::CARD_CIPHER_PIN, 0, context)
{
    if (currentPin.size() != 4) {
        throw IllegalArgumentException("Bad current PIN value");
    }

    if (newPin.size() != 4) {
        throw IllegalArgumentException("Bad new PIN value");
    }

    const std::uint8_t cla = context->getTargetSam()->getClassByte();

    std::uint8_t p1;
    std::uint8_t p2;

    /* A new PIN is provided, we consider it's a PIN update. */

    p1 = 0x40;
    p2 = 0xFF; /* KIF and KVC in incoming data */

    auto data = std::vector<std::uint8_t>(10);
    System::arraycopy(newPin, 0, data, 6, 4);
    data[0] = cipheringKif;
    data[1] = cipheringKvc;

    System::arraycopy(currentPin, 0, data, 2, 4);

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            cla, getCommandRef().getInstructionByte(), p1, p2, data)));
}

const std::vector<std::uint8_t>&
CommandCardCipherPin::getCipheredData() const
{
    return mCipheredData;
}

void
CommandCardCipherPin::finalizeRequest()
{
    /* nothing to do */
}

bool
CommandCardCipherPin::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandCardCipherPin::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
    mCipheredData = apduResponse->getDataOut();
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandCardCipherPin::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
