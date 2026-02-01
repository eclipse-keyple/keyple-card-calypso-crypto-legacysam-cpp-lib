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

#include "keyple/card/calypso/crypto/legacysam/CommandReadCeilings.hpp"

#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/CounterOverflowException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/ByteArrayUtil.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;
using keyple::core::util::ByteArrayUtil;

const int CommandReadCeilings::SW_DATA_NOT_SIGNED_WARNING = 0x6200;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandReadCeilings::STATUS_TABLE = [] {
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

CommandReadCeilings::CommandReadCeilings(
    std::shared_ptr<DtoAdapters::CommandContextDto> context,
    int ceilingFileRecordNumber)
: Command(CommandRef::READ_CEILINGS, 48, context)
, mCeilingFileRecordNumber(ceilingFileRecordNumber)
{
    const std::uint8_t cla = context->getTargetSam()->getClassByte();
    const std::uint8_t p1 = 0x00;
    const std::uint8_t p2 = 0xB1 + ceilingFileRecordNumber;

    auto adapter = std::make_shared<ApduRequestAdapter>(
        ApduUtil::build(cla, getCommandRef().getInstructionByte(), p1, p2));
    adapter->addSuccessfulStatusWord(SW_DATA_NOT_SIGNED_WARNING);
    setApduRequest(adapter);
}

void
CommandReadCeilings::finalizeRequest()
{
    /* nothing to do */
}

bool
CommandReadCeilings::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandReadCeilings::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);

    const std::vector<std::uint8_t> dataOut = apduResponse->getDataOut();
    std::shared_ptr<LegacySamAdapter> targetSam = getContext()->getTargetSam();
    const std::uint16_t counterIncrementConfig = static_cast<std::uint16_t>(
        ByteArrayUtil::extractInt(dataOut, 27, 2, false));

    for (int i = 0; i < 9; i++) {
        targetSam->putCounterCeilingValue(
            (mCeilingFileRecordNumber * 9) + i,
            ByteArrayUtil::extractInt(dataOut, 8 + (3 * i), 3, false));

        targetSam->putCounterIncrementConfiguration(
            (mCeilingFileRecordNumber * 9) + i,
            (counterIncrementConfig & (1 << i)) != 0
                ? CounterIncrementAccess::FREE_COUNTING_ENABLED
                : CounterIncrementAccess::FREE_COUNTING_DISABLED);
    }
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandReadCeilings::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
