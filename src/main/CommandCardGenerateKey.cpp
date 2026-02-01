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

#include "keyple/card/calypso/crypto/legacysam/CommandCardGenerateKey.hpp"

#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/DataAccessException.hpp"
#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IncorrectInputDataException.hpp"
#include "keyple/core/util/ApduUtil.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandCardGenerateKey::STATUS_TABLE = [] {
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
                  "Incorrect incoming data: unknown or incorrect format",
                  typeid(IncorrectInputDataException))},
             {0x6A83,
              std::make_shared<StatusProperties>(
                  "Record not found: ciphering key or key to cipher not found",
                  typeid(DataAccessException))}});
        return m;
    }();

CommandCardGenerateKey::CommandCardGenerateKey(
    std::shared_ptr<DtoAdapters::CommandContextDto> context,
    uint8_t cipheringKif,
    uint8_t cipheringKvc,
    uint8_t sourceKif,
    uint8_t sourceKvc)
: Command(CommandRef::CARD_GENERATE_KEY, 0, context)
{
    const uint8_t cla = context->getTargetSam()->getClassByte();

    uint8_t p1;
    uint8_t p2;
    std::vector<uint8_t> data;

    if (cipheringKif == 0 && cipheringKvc == 0) {
        /* Case where the source key is ciphered by the null key */
        p1 = 0xFF;
        p2 = 0x00;

        data.resize(3);
        data[0] = sourceKif;
        data[1] = sourceKvc;
        data[2] = 0x90;

    } else {
        p1 = 0xFF;
        p2 = 0xFF;

        data.resize(5);
        data[0] = cipheringKif;
        data[1] = cipheringKvc;
        data[2] = sourceKif;
        data[3] = sourceKvc;
        data[4] = 0x90;
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(core::util::ApduUtil::build(
            cla, getCommandRef().getInstructionByte(), p1, p2, data)));
}

const std::vector<uint8_t>&
CommandCardGenerateKey::getCipheredData() const
{
    return mCipheredData;
}

void
CommandCardGenerateKey::finalizeRequest()
{
    /* Nothing to do */
}

bool
CommandCardGenerateKey::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandCardGenerateKey::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
    mCipheredData = apduResponse->getDataOut();
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandCardGenerateKey::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
