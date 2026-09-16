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

#include "keyple/card/calypso/crypto/legacysam/CommandReadParameters.hpp"

#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/CounterOverflowException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamConstants.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/cpp/System.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;
using keyple::core::util::cpp::System;
const int CommandReadParameters::SW_DATA_NOT_SIGNED_WARNING = 0x6200;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandReadParameters::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6900,
              std::make_shared<StatusProperties>(
                  "An event counter cannot be incremented",
                  typeid(CounterOverflowException))},
             {0x6A00,
              std::make_shared<StatusProperties>(
                  "Incorrect P1 or P2", typeid(IllegalParameterException))},
             {0x6200,
              std::make_shared<StatusProperties>(
                  "Correct execution with warning: data not signed")}});
        return m;
    }();

CommandReadParameters::CommandReadParameters(
    std::shared_ptr<DtoAdapters::CommandContextDto> context)
: Command(CommandRef::READ_PARAMETERS, 48, context)
{
    const uint8_t cla = context->getTargetSam()->getClassByte();
    const uint8_t p1 = 0x00;
    const uint8_t p2 = 0xA0;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            cla, getCommandRef().getInstructionByte(), p1, p2)));
}

void
CommandReadParameters::finalizeRequest()
{
    /* nothing to do */
}

bool
CommandReadParameters::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandReadParameters::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
    std::vector<uint8_t> keyParameter(
        LegacySamConstants::SAM_PARAMETERS_LENGTH);
    System::arraycopy(
        apduResponse->getApdu(),
        8,
        keyParameter,
        0,
        LegacySamConstants::SAM_PARAMETERS_LENGTH);
    getContext()->getTargetSam()->setSamParameters(
        std::make_shared<SamParametersAdapter>(keyParameter));
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandReadParameters::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
