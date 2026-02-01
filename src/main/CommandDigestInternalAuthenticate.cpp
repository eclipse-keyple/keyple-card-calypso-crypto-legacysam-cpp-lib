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

#include "keyple/card/calypso/crypto/legacysam/CommandDigestInternalAuthenticate.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/core/util/ApduUtil.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandDigestInternalAuthenticate::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6985,
              std::make_shared<StatusProperties>(
                  std::string("Preconditions not satisfied:\n")
                      + "- Session not in 'ongoing' state.\n"
                      + "- Session not opened in Extended mode.\n"
                      + "- Session opened in Verification mode.\n"
                      + "- Authentication not allowed by the key (not an AES "
                        "key).\n"
                      + "- 250th occurrence since session start",
                  typeid(AccessForbiddenException))},
             {0x6B00,
              std::make_shared<StatusProperties>(
                  "Incorrect P1", typeid(IllegalParameterException))}});
        return m;
    }();

CommandDigestInternalAuthenticate::CommandDigestInternalAuthenticate(
    const std::shared_ptr<CommandContextDto> context)
: Command(CommandRef::DIGEST_INTERNAL_AUTHENTICATE, 8, context)
{
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            context->getTargetSam()->getClassByte(),
            getCommandRef().getInstructionByte(),
            0x80,
            0x00,
            8)));
}

const std::vector<uint8_t>&
CommandDigestInternalAuthenticate::getTerminalSignature() const
{
    return mTerminalSignature;
}

void
CommandDigestInternalAuthenticate::finalizeRequest()
{
    /* Nothing to do */
}

bool
CommandDigestInternalAuthenticate::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandDigestInternalAuthenticate::parseResponse(
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);

    mTerminalSignature = apduResponse->getDataOut();
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandDigestInternalAuthenticate::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
