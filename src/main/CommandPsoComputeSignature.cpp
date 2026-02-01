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

#include "keyple/card/calypso/crypto/legacysam/CommandPsoComputeSignature.hpp"

#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/CounterOverflowException.hpp"
#include "keyple/card/calypso/crypto/legacysam/DataAccessException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IncorrectInputDataException.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamConstants.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/ByteArrayUtil.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/System.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;
using keyple::core::util::ByteArrayUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::System;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandPsoComputeSignature::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6700,
              std::make_shared<StatusProperties>(
                  "Incorrect Lc", typeid(IllegalParameterException))},
             {0x6900,
              std::make_shared<StatusProperties>(
                  "An event counter cannot be incremented",
                  typeid(CounterOverflowException))},
             {0x6985,
              std::make_shared<StatusProperties>(
                  "Preconditions not satisfied",
                  typeid(AccessForbiddenException))},
             {0x6A80,
              std::make_shared<StatusProperties>(
                  "Incorrect value in the incoming data",
                  typeid(IncorrectInputDataException))},
             {0x6A83,
              std::make_shared<StatusProperties>(
                  "Record not found: signing key not found",
                  typeid(DataAccessException))},
             {0x6B00,
              std::make_shared<StatusProperties>(
                  "Incorrect P1 or P2", typeid(IllegalParameterException))}});
        return m;
    }();

CommandPsoComputeSignature::CommandPsoComputeSignature(
    std::shared_ptr<CommandContextDto> context,
    std::shared_ptr<TraceableSignatureComputationDataAdapter> data)
: Command(CommandRef::PSO_COMPUTE_SIGNATURE, 0, context)
, mData(data)
{
    const std::uint8_t cla = context->getTargetSam()->getClassByte();
    const std::uint8_t inst = getCommandRef().getInstructionByte();
    const std::uint8_t p1 = 0x9E;
    const std::uint8_t p2 = 0x9A;

    /* DataIn */
    const int messageOffset = data->isSamTraceabilityMode() ? 6 : 4;
    const int messageSize = data->getData().size();
    std::vector<std::uint8_t> dataIn(messageOffset + messageSize);

    /*
     * SignKeyNum: Selection of the key by KIF and KVC given in the incoming
     * data.
     */
    dataIn[0] = 0xFF;

    /* SignKeyRef: KIF and KVC of the signing key. */
    dataIn[1] = data->getKif();
    dataIn[2] = data->getKvc();

    /*
     * OpMode: Operating mode, equal to XYh, with:
     * X: Mode
     */
    std::uint8_t opMode = 0;  // %0000 Normal mode
    if (data->isSamTraceabilityMode()) {
        if (data->getSamTraceabilityMode()
            == SamTraceabilityMode::TRUNCATED_SERIAL_NUMBER) {
            opMode |= 4;  // %x100
        } else {
            opMode |= 6;  // %x110
        }
    }
    if (data->isBusyMode()) {
        opMode |= 8;  // %1xx0
    }
    opMode <<= 4;
    /* Y: Signature size (in bytes) */
    opMode |= data->getSignatureSize();
    dataIn[3] = opMode;

    /*
     * TraceOffset (optional): Bit offset in MessageIn of the SAM traceability
     * data.
     */
    if (data->isSamTraceabilityMode()) {
        ByteArrayUtil::copyBytes(data->getTraceabilityOffset(), dataIn, 4, 2);
    }

    /* MessageIn: Message to sign. */
    System::arraycopy(data->getData(), 0, dataIn, messageOffset, messageSize);

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, inst, p1, p2, dataIn)));
}

void
CommandPsoComputeSignature::finalizeRequest()
{
    /* Nothing to do */
}

bool
CommandPsoComputeSignature::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandPsoComputeSignature::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
    if (apduResponse->getDataOut().size() > 0) {
        if (mData->isSamTraceabilityMode()) {
            mData->setSignedData(
                Arrays::copyOf(
                    apduResponse->getDataOut(), mData->getData().size()));
        } else {
            mData->setSignedData(mData->getData());
        }

        mData->setSignature(
            Arrays::copyOfRange(
                apduResponse->getDataOut(),
                apduResponse->getDataOut().size() - mData->getSignatureSize(),
                apduResponse->getDataOut().size()));
    }
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandPsoComputeSignature::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
