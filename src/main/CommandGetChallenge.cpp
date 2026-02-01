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

#include "keyple/card/calypso/crypto/legacysam/CommandGetChallenge.hpp"

#include <map>
#include <memory>

#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/core/util/ApduUtil.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandGetChallenge::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6700,
              std::make_shared<StatusProperties>(
                  "Incorrect Le", typeid(IllegalParameterException))}});

        return m;
    }();

CommandGetChallenge::CommandGetChallenge(
    std::shared_ptr<DtoAdapters::CommandContextDto> context,
    int expectedResponseLength)
: Command(CommandRef::GET_CHALLENGE, expectedResponseLength, context)
{
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            context->getTargetSam()->getClassByte(),
            getCommandRef().getInstructionByte(),
            0,
            0,
            expectedResponseLength)));
}

void
CommandGetChallenge::finalizeRequest()
{
    /* nothing to do */
}

bool
CommandGetChallenge::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandGetChallenge::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
    getContext()->getTargetSam()->setChallenge(apduResponse->getDataOut());
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandGetChallenge::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
