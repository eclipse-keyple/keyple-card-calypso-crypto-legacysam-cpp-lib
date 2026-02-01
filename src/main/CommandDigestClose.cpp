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

#include "keyple/card/calypso/crypto/legacysam/CommandDigestClose.hpp"

#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/core/util/ApduUtil.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandDigestClose::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6985,
              std::make_shared<StatusProperties>(
                  "Preconditions not satisfied",
                  typeid(AccessForbiddenException))}});
        return m;
    }();

CommandDigestClose::CommandDigestClose(
    std::shared_ptr<CommandContextDto> context, int expectedResponseLength)
: Command(CommandRef::DIGEST_CLOSE, expectedResponseLength, context)
{
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            context->getTargetSam()->getClassByte(),
            getCommandRef().getInstructionByte(),
            0x00,
            0x00,
            expectedResponseLength)));
}
const std::vector<std::uint8_t>&
CommandDigestClose::getMac() const
{
    return mMac;
}

void
CommandDigestClose::finalizeRequest()
{
    /* nothing to do */
}

bool
CommandDigestClose::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandDigestClose::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
    mMac = apduResponse->getDataOut();
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandDigestClose::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
