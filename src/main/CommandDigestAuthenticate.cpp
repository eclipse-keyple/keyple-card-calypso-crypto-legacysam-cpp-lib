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

#include "keyple/card/calypso/crypto/legacysam/CommandDigestAuthenticate.hpp"

#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/card/calypso/crypto/legacysam/SecurityDataException.hpp"
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
    CommandDigestAuthenticate::STATUS_TABLE = [] {
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
             {0x6988,
              std::make_shared<StatusProperties>(
                  "Incorrect signature", typeid(SecurityDataException))}});
        return m;
    }();

CommandDigestAuthenticate::CommandDigestAuthenticate(
    std::shared_ptr<CommandContextDto> context,
    const std::vector<uint8_t>& signature)
: Command(CommandRef::DIGEST_AUTHENTICATE, 0, context)
{
    if (signature.size() != 4 && signature.size() != 8
        && signature.size() != 16) {
        throw IllegalArgumentException(
            "Signature is not the right length : length is "
            + std::to_string(signature.size()));
    }

    const std::uint8_t cla = context->getTargetSam()->getClassByte();
    const std::uint8_t p1 = 0x00;
    const std::uint8_t p2 = 0x00;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            cla, getCommandRef().getInstructionByte(), p1, p2, signature)));
}

void
CommandDigestAuthenticate::finalizeRequest()
{
    /* nothing to do */
}

bool
CommandDigestAuthenticate::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandDigestAuthenticate::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandDigestAuthenticate::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
