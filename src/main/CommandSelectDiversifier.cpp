
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

#include "keyple/card/calypso/crypto/legacysam/CommandSelectDiversifier.hpp"

#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandRef.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/cpp/System.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::card::calypso::crypto::legacysam::CommandRef;
using keyple::core::util::ApduUtil;
using keyple::core::util::cpp::System;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandSelectDiversifier::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {0x6700,
             std::make_shared<StatusProperties>(
                 "Incorrect Lc", typeid(IllegalParameterException))});
        m.insert(
            {0x6985,
             std::make_shared<StatusProperties>(
                 "Preconditions not satisfied: the SAM is locked",
                 typeid(AccessForbiddenException))});

        return m;
    }();

CommandSelectDiversifier::CommandSelectDiversifier(
    std::shared_ptr<DtoAdapters::CommandContextDto> context,
    const std::vector<uint8_t>& diversifier)
: Command(CommandRef::SELECT_DIVERSIFIER, 0, context)
{
    auto _diversifier = diversifier;

    /* Format the diversifier on 4 or 8 bytes if needed. */
    if (diversifier.size() != 4 && diversifier.size() != 8) {
        const int newLength = diversifier.size() < 4 ? 4 : 8;
        std::vector<uint8_t> tmp;
        System::arraycopy(
            diversifier,
            0,
            tmp,
            newLength - diversifier.size(),
            diversifier.size());
        _diversifier = tmp;
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            context->getTargetSam()->getClassByte(),
            getCommandRef().getInstructionByte(),
            0,
            0,
            _diversifier)));
}

void
CommandSelectDiversifier::finalizeRequest()
{
    /* Nothing to do */
}

bool
CommandSelectDiversifier::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandSelectDiversifier::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandSelectDiversifier::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
