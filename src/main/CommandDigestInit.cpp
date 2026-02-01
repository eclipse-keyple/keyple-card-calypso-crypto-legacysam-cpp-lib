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

#include "keyple/card/calypso/crypto/legacysam/CommandDigestInit.hpp"

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
    CommandDigestInit::STATUS_TABLE = [] {
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
                  "Incorrect P2", typeid(IllegalParameterException))},
             {0x6A83,
              std::make_shared<StatusProperties>(
                  "Record not found: signing key not found",
                  typeid(DataAccessException))}});
        return m;
    }();

CommandDigestInit::CommandDigestInit(
    std::shared_ptr<CommandContextDto> context,
    bool verificationMode,
    bool confidentialSessionMode,
    std::uint8_t workKif,
    std::uint8_t workKvc,
    const std::vector<std::uint8_t>& digestData)
: Command(CommandRef::DIGEST_INIT, 0, context)
{
    if (workKif == 0x00 || workKvc == 0x00) {
        throw IllegalArgumentException("Bad kif or kvc!");
    }

    const std::uint8_t cla = context->getTargetSam()->getClassByte();
    std::uint8_t p1 = 0x00;

    if (verificationMode) {
        p1 += 1;
    }

    if (confidentialSessionMode) {
        p1 += 2;
    }

    const std::uint8_t p2 = 0xFF;

    std::vector<std::uint8_t> dataIn(2 + digestData.size());
    dataIn[0] = workKif;
    dataIn[1] = workKvc;

    System::arraycopy(digestData, 0, dataIn, 2, digestData.size());

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            cla, getCommandRef().getInstructionByte(), p1, p2, dataIn)));
}

void
CommandDigestInit::finalizeRequest()
{
    /* nothing to do */
}

bool
CommandDigestInit::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandDigestInit::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandDigestInit::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
