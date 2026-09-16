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

#include "keyple/card/calypso/crypto/legacysam/CommandSamGenerateKey.hpp"

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
    CommandSamGenerateKey::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<StatusProperties>> m(
            Command::STATUS_TABLE);
        return m;
    }();

CommandSamGenerateKey::CommandSamGenerateKey(
    std::shared_ptr<CommandContextDto> context,
    std::uint8_t targetKeyReference,
    std::uint8_t cipheringKvc,
    std::uint8_t sourceKif,
    std::uint8_t sourceKvc,
    const std::vector<std::uint8_t>& keyParameters,
    bool isTransferredObjectDiversified)
: Command(CommandRef::SAM_GENERATE_KEY, 48, context)
{
    const std::uint8_t cla = context->getTargetSam()->getClassByte();
    const std::uint8_t inst = getCommandRef().getInstructionByte();

    const std::uint8_t p1 = isTransferredObjectDiversified ? 0x01 : 0x00;
    std::vector<std::uint8_t> dataIn(13);
    dataIn[0] = cipheringKvc;
    dataIn[1] = sourceKif;
    dataIn[2] = sourceKvc;
    System::arraycopy(keyParameters, 0, dataIn, 3, 10);

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, inst, p1, targetKeyReference, dataIn)));
}

CommandSamGenerateKey::CommandSamGenerateKey(
    std::shared_ptr<CommandContextDto> context,
    std::uint8_t targetKeyReference,
    std::uint8_t cipheringKvc,
    std::uint8_t sourceKif,
    std::uint8_t sourceKvc,
    const std::vector<std::uint8_t>& keyParameters,
    bool isTransferredObjectDiversified,
    const std::vector<std::uint8_t>& arbitraryDiversifier)
: Command(CommandRef::SAM_GENERATE_KEY, 48, context)
{
    const std::uint8_t cla = context->getTargetSam()->getClassByte();
    const std::uint8_t inst = getCommandRef().getInstructionByte();

    const std::uint8_t p1 = isTransferredObjectDiversified ? 0x01 : 0x00;
    std::vector<std::uint8_t> dataIn(13 + 8);
    dataIn[0] = cipheringKvc;
    dataIn[1] = sourceKif;
    dataIn[2] = sourceKvc;
    System::arraycopy(keyParameters, 0, dataIn, 3, 10);
    System::arraycopy(arbitraryDiversifier, 0, dataIn, 13, 8);

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, inst, p1, targetKeyReference, dataIn)));
}

const std::vector<std::uint8_t>&
CommandSamGenerateKey::getCipheredData() const
{
    return mCipheredData;
}

void
CommandSamGenerateKey::finalizeRequest()
{
    /* Nothing to do */
}

bool
CommandSamGenerateKey::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandSamGenerateKey::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
    mCipheredData = apduResponse->getDataOut();
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandSamGenerateKey::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
