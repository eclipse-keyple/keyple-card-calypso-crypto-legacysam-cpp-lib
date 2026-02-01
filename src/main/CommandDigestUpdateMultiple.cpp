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

#include "keyple/card/calypso/crypto/legacysam/CommandDigestUpdateMultiple.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IncorrectInputDataException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;
using keyple::core::util::cpp::exception::IllegalArgumentException;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandDigestUpdateMultiple::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6700,
              std::make_shared<StatusProperties>(
                  "Incorrect Lc", typeid(IllegalParameterException))},
             {0x6985,
              std::make_shared<StatusProperties>(
                  "Preconditions not satisfied",
                  typeid(AccessForbiddenException))},
             {0x6A80,
              std::make_shared<StatusProperties>(
                  "Incorrect value in the incoming data: incorrect structure",
                  typeid(IncorrectInputDataException))},
             {0x6B00,
              std::make_shared<StatusProperties>(
                  "Incorrect P1 or P2", typeid(IllegalParameterException))}});
        return m;
    }();

CommandDigestUpdateMultiple::CommandDigestUpdateMultiple(
    std::shared_ptr<CommandContextDto> context,
    const std::vector<uint8_t>& digestData)
: Command(CommandRef::DIGEST_UPDATE, 0, context)
{
    const std::uint8_t cla = context->getTargetSam()->getClassByte();
    const std::uint8_t p1 = 0x80;
    const std::uint8_t p2 = 0x00;

    if (digestData.size() > 255) {
        throw IllegalArgumentException("Digest data null or too long!");
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            cla, getCommandRef().getInstructionByte(), p1, p2, digestData)));
}

void
CommandDigestUpdateMultiple::finalizeRequest()
{
    /* Nothing to do */
}

bool
CommandDigestUpdateMultiple::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandDigestUpdateMultiple::parseResponse(
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandDigestUpdateMultiple::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
