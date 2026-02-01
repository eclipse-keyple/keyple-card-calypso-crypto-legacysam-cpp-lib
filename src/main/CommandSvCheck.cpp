
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

#include "keyple/card/calypso/crypto/legacysam/CommandSvCheck.hpp"

#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamConstants.hpp"
#include "keyple/card/calypso/crypto/legacysam/SecurityDataException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/ByteArrayUtil.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/System.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/InvalidSignatureException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;
using keyple::core::util::ByteArrayUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::System;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keypop::calypso::crypto::legacysam::transaction::
    InvalidSignatureException;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandSvCheck::STATUS_TABLE = [] {
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

CommandSvCheck::CommandSvCheck(std::shared_ptr<CommandContextDto> context)
: Command(CommandRef::SV_CHECK, 0, context)
{
    const std::uint8_t cla = context->getTargetSam()->getClassByte();
    const std::uint8_t p1 = 0x00;
    const std::uint8_t p2 = 0x00;

    /* The operation is "abort" */
    const std::vector<std::uint8_t> noInput = {0};
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            cla,
            getCommandRef().getInstructionByte(),
            p1,
            p2,
            noInput)));  // Case 3 without input data.
}

CommandSvCheck::CommandSvCheck(
    std::shared_ptr<CommandContextDto> context,
    const std::vector<std::uint8_t>& svCardSignature)
: Command(CommandRef::SV_CHECK, 0, context)
{
    if (svCardSignature.size() != 3 && svCardSignature.size() != 6) {
        throw IllegalArgumentException("Invalid svCardSignature");
    }

    const std::uint8_t cla = context->getTargetSam()->getClassByte();
    const std::uint8_t p1 = 0x00;
    const std::uint8_t p2 = 0x00;

    /* The operation is not "abort" */
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            cla,
            getCommandRef().getInstructionByte(),
            p1,
            p2,
            svCardSignature)));
}

void
CommandSvCheck::finalizeRequest()
{
    /* Nothing to do */
}

bool
CommandSvCheck::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandSvCheck::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandSvCheck::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
