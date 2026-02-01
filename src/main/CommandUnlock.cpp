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

#include "keyple/card/calypso/crypto/legacysam/CommandUnlock.hpp"

#include <map>
#include <memory>
#include <stdexcept>
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
    CommandUnlock::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6700,
              std::make_shared<StatusProperties>(
                  "Incorrect Le", typeid(IllegalParameterException))},
             {0x6985,
              std::make_shared<StatusProperties>(
                  "Preconditions not satisfied (SAM not locked?)",
                  typeid(AccessForbiddenException))},
             {0x6988,
              std::make_shared<StatusProperties>(
                  "Incorrect UnlockData", typeid(SecurityDataException))}});

        return m;
    }();

CommandUnlock::CommandUnlock(
    LegacySam::ProductType productType, const std::vector<uint8_t>& unlockData)
: Command(CommandRef::UNLOCK, 0, nullptr)
{
    const uint8_t cla
        = productType == LegacySam::ProductType::SAM_S1DX ? 0x94 : 0x80;
    const uint8_t p1 = 0x00;
    const uint8_t p2 = 0x00;

    if (unlockData.size() != 8 && unlockData.size() != 16) {
        throw IllegalArgumentException(
            "Unlock data should be 8 ou 16 bytes long!");
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            cla, getCommandRef().getInstructionByte(), p1, p2, unlockData)));
}

void
CommandUnlock::finalizeRequest()
{
    /* nothing to do */
}

bool
CommandUnlock::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandUnlock::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandUnlock::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
