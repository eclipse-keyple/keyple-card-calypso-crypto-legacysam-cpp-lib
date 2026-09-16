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

#include "keyple/card/calypso/crypto/legacysam/CommandPsoComputeCertificate.hpp"

#include <algorithm>
#include <cstring>
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
#include "keyple/core/util/cpp/Arrays.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;
using keyple::core::util::cpp::Arrays;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandPsoComputeCertificate::STATUS_TABLE = [] {
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
             {0x6A88,
              std::make_shared<StatusProperties>(
                  "Unknown incoming data object (incorrect tag)",
                  typeid(DataAccessException))},
             {0x6B00,
              std::make_shared<StatusProperties>(
                  "Incorrect P1 or P2", typeid(IllegalParameterException))}});
        return m;
    }();

CommandPsoComputeCertificate::CommandPsoComputeCertificate(
    std::shared_ptr<CommandContextDto> context,
    std::shared_ptr<LegacyCardCertificateComputationData> data)
: Command(
      CommandRef::PSO_COMPUTE_CERTIFICATE,
      LegacySamConstants::TagInfo::GENERATED_CARD_CERTIFICATE.getTotalLength(),
      context)
, mData(
      std::dynamic_pointer_cast<LegacyCardCertificateComputationDataAdapter>(
          data))
{
    const std::uint8_t cla = context->getTargetSam()->getClassByte();
    const std::uint8_t inst = getCommandRef().getInstructionByte();
    const std::uint8_t p1 = 0xEE;
    const std::uint8_t p2 = 0xAC;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            cla, inst, p1, p2, generateCardPublicKeyData(mData), 0xFF)));
}

std::vector<std::uint8_t>
CommandPsoComputeCertificate::generateCardPublicKeyData(
    std::shared_ptr<LegacyCardCertificateComputationDataAdapter> data)
{
    /* BER-TLV header */
    std::vector<std::uint8_t> header
        = LegacySamConstants::TagInfo::CARD_PUBLIC_KEY_DATA.getHeader();

    /*
     * Allocate buffer size according to the presence of cardPublicKey, adjust
     * length byte accordingly
     */
    std::vector<std::uint8_t> cardPublicKeyData;
    if (!data->getCardPublicKey().empty()) {
        header[2] = 127;  // change default length
    }

    std::copy(
        header.begin(), header.end(), std::back_inserter(cardPublicKeyData));

    /* AID length */
    cardPublicKeyData.push_back(
        static_cast<std::uint8_t>(data->getAid().size()));

    /* AID */
    const std::vector<std::uint8_t> aid = data->getAid();
    std::copy(aid.begin(), aid.end(), std::back_inserter(cardPublicKeyData));

    /* AID padding */
    cardPublicKeyData.resize(
        cardPublicKeyData.size() + LegacySamConstants::AID_SIZE_MAX
            - aid.size(),
        0);

    /* Serial number */
    const std::vector<uint8_t> serial = data->getSerialNumber();
    std::copy(
        serial.begin(), serial.end(), std::back_inserter(cardPublicKeyData));

    /* RFU */
    cardPublicKeyData.resize(cardPublicKeyData.size() + 4, 0);

    /* Start date */
    size_t previousSize = cardPublicKeyData.size();
    cardPublicKeyData.resize(cardPublicKeyData.size() + 4);
    const uint32_t startDate = data->getStartDateBcd();
    std::memcpy(cardPublicKeyData.data() + previousSize, &startDate, 4);

    /* End date */
    previousSize = cardPublicKeyData.size();
    cardPublicKeyData.resize(cardPublicKeyData.size() + 4);
    const uint32_t endDate = data->getEndDateBcd();
    std::memcpy(cardPublicKeyData.data() + previousSize, &endDate, 4);

    /* Rights (RFU) */
    cardPublicKeyData.resize(cardPublicKeyData.size() + 1, 0);

    /* Startup information */
    const std::vector<std::uint8_t>& info = data->getStartupInfo();
    std::copy(info.begin(), info.end(), std::back_inserter(cardPublicKeyData));

    /* RFU */
    cardPublicKeyData.resize(cardPublicKeyData.size() + 18, 0);

    /* Public key if provided */
    const std::vector<std::uint8_t>& publicKey = data->getCardPublicKey();
    if (!publicKey.empty()) {
        std::copy(
            publicKey.begin(),
            publicKey.end(),
            std::back_inserter(cardPublicKeyData));
    }

    return cardPublicKeyData;
}

void
CommandPsoComputeCertificate::finalizeRequest()
{
    /* Nothing to do */
}

bool
CommandPsoComputeCertificate::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandPsoComputeCertificate::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
    const std::vector<std::uint8_t> dataOut = apduResponse->getDataOut();
    if (dataOut.size() > 0) {
        /* Check BER-TLV header */
        const std::vector<std::uint8_t>& header
            = LegacySamConstants::TagInfo::GENERATED_CARD_CERTIFICATE
                  .getHeader();
        for (int i = 0; i < static_cast<int>(header.size()); i++) {
            if (dataOut[i] != header[i]) {
                throw DataAccessException("Inconsistent BER-TLV tag");
            }
        }

        mData->setCertificate(
            Arrays::copyOfRange(dataOut, header.size(), dataOut.size()));
    }
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandPsoComputeCertificate::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
