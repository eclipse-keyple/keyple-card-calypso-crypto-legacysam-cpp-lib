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

#include "keyple/card/calypso/crypto/legacysam/CommandReadCounter.hpp"

#include <map>
#include <memory>

#include "keyple/card/calypso/crypto/legacysam/CounterOverflowException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/core/util/ApduUtil.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;

const int CommandReadCounter::SW_DATA_NOT_SIGNED_WARNING = 0x6200;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandReadCounter::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6900,
              std::make_shared<StatusProperties>(
                  "An event counter cannot be incremented",
                  typeid(CounterOverflowException))},
             {0x6A00,
              std::make_shared<StatusProperties>(
                  "Incorrect P2", typeid(IllegalParameterException))},
             {0x6200,
              std::make_shared<StatusProperties>(
                  "Correct execution with warning: data not signed")}});
        return m;
    }();

CommandReadCounter::CommandReadCounter(
    std::shared_ptr<DtoAdapters::CommandContextDto> context,
    int counterFileRecordNumber)
: Command(CommandRef::READ_EVENT_COUNTER, 48, context)
, mCounterFileRecordNumber(counterFileRecordNumber)
{
    const uint8_t cla = context->getTargetSam()->getClassByte();
    const uint8_t p2 = (0xE1 + counterFileRecordNumber);

    auto adapter = std::make_shared<ApduRequestAdapter>(
        ApduUtil::build(cla, getCommandRef().getInstructionByte(), 0x00, p2));
    adapter->addSuccessfulStatusWord(SW_DATA_NOT_SIGNED_WARNING);
    setApduRequest(adapter);
}

int
CommandReadCounter::getCounterFileRecordNumber() const
{
    return mCounterFileRecordNumber;
}

void
CommandReadCounter::finalizeRequest()
{
    /* nothing to do */
}

bool
CommandReadCounter::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandReadCounter::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
    getContext()->getTargetSam()->setChallenge(apduResponse->getDataOut());
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandReadCounter::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
