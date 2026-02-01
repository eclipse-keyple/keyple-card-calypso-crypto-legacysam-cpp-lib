
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

#include "keyple/card/calypso/crypto/legacysam/CommandSvPrepareLoad.hpp"

#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/DataAccessException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IncorrectInputDataException.hpp"
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
    CommandSvPrepareLoad::STATUS_TABLE = [] {
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
             {0x6A00,
              std::make_shared<StatusProperties>(
                  "Incorrect P1 or P2", typeid(IllegalParameterException))},
             {0x6A80,
              std::make_shared<StatusProperties>(
                  "Incorrect incoming data",
                  typeid(IncorrectInputDataException))},
             {0x6A83,
              std::make_shared<StatusProperties>(
                  "Record not found: ciphering key not found",
                  typeid(DataAccessException))}});
        return m;
    }();

CommandSvPrepareLoad::CommandSvPrepareLoad(
    std::shared_ptr<CommandContextDto> context,
    std::shared_ptr<SvCommandSecurityDataApi> data)
: Command(CommandRef::SV_PREPARE_LOAD, 0, context)
, mData(data)
{
    const std::uint8_t cla = context->getTargetSam()->getClassByte();
    const std::uint8_t inst = getCommandRef().getInstructionByte();
    const std::uint8_t p1 = 0x01;
    const std::uint8_t p2 = 0xFF;

    /* header(4) + SvReload data (15) = 19 bytes */
    std::vector<std::uint8_t> dataIn(19 + data->getSvGetResponse().size());

    System::arraycopy(data->getSvGetRequest(), 0, dataIn, 0, 4);
    System::arraycopy(
        data->getSvGetResponse(),
        0,
        dataIn,
        4,
        data->getSvGetResponse().size());
    System::arraycopy(
        data->getSvCommandPartialRequest(),
        0,
        dataIn,
        4 + data->getSvGetResponse().size(),
        data->getSvCommandPartialRequest().size());

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, inst, p1, p2, dataIn)));
}

void
CommandSvPrepareLoad::finalizeRequest()
{
    /* Nothing to do */
}

bool
CommandSvPrepareLoad::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandSvPrepareLoad::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
    const std::vector<std::uint8_t> dataOut = apduResponse->getDataOut();
    mData->setSerialNumber(getContext()->getTargetSam()->getSerialNumber())
        .setTerminalChallenge(Arrays::copyOfRange(dataOut, 0, 3))
        .setTransactionNumber(Arrays::copyOfRange(dataOut, 3, 6))
        .setTerminalSvMac(Arrays::copyOfRange(dataOut, 6, dataOut.size()));
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandSvPrepareLoad::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
