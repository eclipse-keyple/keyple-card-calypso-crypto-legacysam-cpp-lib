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

#include "keyple/card/calypso/crypto/legacysam/CommandCardGenerateAsymmetricKeyPair.hpp"

#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/DataAccessException.hpp"
#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IncorrectInputDataException.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamConstants.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::Arrays;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandCardGenerateAsymmetricKeyPair::STATUS_TABLE = [] {
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
             {0x6A80,
              std::make_shared<StatusProperties>(
                  "Incorrect value in the incoming data (OID unknown)",
                  typeid(IncorrectInputDataException))},
             {0x6B00,
              std::make_shared<StatusProperties>(
                  "Incorrect P1", typeid(IllegalParameterException))}});
        return m;
    }();

CommandCardGenerateAsymmetricKeyPair::CommandCardGenerateAsymmetricKeyPair(
    std::shared_ptr<DtoAdapters::CommandContextDto> context,
    std::shared_ptr<KeyPairContainer> keyPairContainer)
: Command(
      CommandRef::CARD_GENERATE_ASYMMETRIC_KEY_PAIR,
      LegacySamConstants::TagInfo::GENERATED_CARD_ECC_KEY_PAIR.getTotalLength(),
      context)
, mKeyPairContainer(
      std::dynamic_pointer_cast<KeyPairContainerAdapter>(keyPairContainer))
{
    const uint8_t cla = context->getTargetSam()->getClassByte();
    const uint8_t inst = getCommandRef().getInstructionByte();
    const uint8_t p1 = 0x80;
    const uint8_t p2 = 0x00;
    const std::vector<uint8_t> oid
        = core::util::HexUtil::toByteArray("06082A8648CE3D030107");

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            core::util::ApduUtil::build(cla, inst, p1, p2, oid, 0x63)));
}

void
CommandCardGenerateAsymmetricKeyPair::finalizeRequest()
{
    /* Nothing to do */
}

bool
CommandCardGenerateAsymmetricKeyPair::isControlSamRequiredToFinalizeRequest()
    const
{
    return false;
}

void
CommandCardGenerateAsymmetricKeyPair::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);

    std::vector<uint8_t> dataOut = apduResponse->getDataOut();
    if (!dataOut.empty()) {
        /* Check BER-TLV header */
        std::vector<uint8_t> header
            = LegacySamConstants::TagInfo::GENERATED_CARD_ECC_KEY_PAIR
                  .getHeader();
        for (size_t i = 0; i < header.size(); i++) {
            if (dataOut[i] != header[i]) {
                throw DataAccessException("Inconsistent BER-TLV tag");
            }
        }

        mKeyPairContainer->setKeyPair(
            Arrays::copyOfRange(dataOut, header.size(), dataOut.size()));
    }
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandCardGenerateAsymmetricKeyPair::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
