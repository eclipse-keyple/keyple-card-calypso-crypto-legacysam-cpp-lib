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

#include "keyple/card/calypso/crypto/legacysam/CommandGenerateAsymmetricKeyPair.hpp"

#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/DataAccessException.hpp"
#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IncorrectInputDataException.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamConstants.hpp"
#include "keyple/card/calypso/crypto/legacysam/transaction/KeyPairContainer.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/HexUtil.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;
using keypoe::core::util::HexUtil;

CommandGenerateAsymmetricKeyPair::CommandGenerateAsymmetricKeyPair(
    std::shared_ptr<DtoAdapters::CommandContextDto> context,
    std::shared_ptr<transaction::KeyPairContainer> keyPairContainer)
: Command(
      CommandRef::CARD_GENERATE_ASYMMETRIC_KEY_PAIR,
      LegacySamConstants::TagInfo::GENERATED_CARD_ECC_KEY_PAIR.getTotalLength(),
      context)
, keyPairContainer_(
      std::dynamic_pointer_cast<DtoAdapters::KeyPairContainerAdapter>(
          keyPairContainer))
{
    const uint8_t cla = context->getTargetSam()->getClassByte();
    const uint8_t inst = getCommandRef().getInstructionByte();
    const uint8_t p1 = 0x80;
    const uint8_t p2 = 0x00;
    const std::vector<uint8_t> oid
        = core::util::HexUtil::toByteArray("06082A8648CE3D030107");

    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(
            core::util::ApduUtil::build(cla, inst, p1, p2, oid, 0x63)));
}

std::map<uint16_t, Command::StatusProperties>
CommandGenerateAsymmetricKeyPair::getStatusTable()
{
    std::map<uint16_t, StatusProperties> statusTable
        = Command::getStatusTable();
    statusTable[0x6700] = StatusProperties(
        "Incorrect Lc", std::type_index(typeid(IllegalParameterException)));
    statusTable[0x6985] = StatusProperties(
        "Preconditions not satisfied",
        std::type_index(typeid(AccessForbiddenException)));
    statusTable[0x6A80] = StatusProperties(
        "Incorrect value in the incoming data (OID unknown)",
        std::type_index(typeid(IncorrectInputDataException)));
    statusTable[0x6B00] = StatusProperties(
        "Incorrect P1", std::type_index(typeid(IllegalParameterException)));
    return statusTable;
}

void
CommandGenerateAsymmetricKeyPair::finalizeRequest()
{
    // Nothing to do
}

bool
CommandGenerateAsymmetricKeyPair::isControlSamRequiredToFinalizeRequest()
{
    return false;
}

void
CommandGenerateAsymmetricKeyPair::parseResponse(
    std::shared_ptr<keyple::card::ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
    std::vector<uint8_t> dataOut = apduResponse->getDataOut();
    if (!dataOut.empty()) {
        // check BER-TLV header
        std::vector<uint8_t> header
            = LegacySamConstants::TagInfo::GENERATED_CARD_ECC_KEY_PAIR
                  .getHeader();
        for (size_t i = 0; i < header.size(); i++) {
            if (dataOut[i] != header[i]) {
                throw DataAccessException("Inconsistent BER-TLV tag");
            }
        }
        keyPairContainer_->setKeyPair(
            std::vector<uint8_t>(
                dataOut.begin() + header.size(), dataOut.end()));
    }
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
