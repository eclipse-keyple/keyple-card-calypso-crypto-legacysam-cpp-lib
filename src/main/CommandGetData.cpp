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

#include "keyple/card/calypso/crypto/legacysam/CommandGetData.hpp"

#include <algorithm>
#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/DataAccessException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
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
    CommandGetData::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6700,
              std::make_shared<StatusProperties>(
                  "Incorrect Lc", typeid(IllegalParameterException))},
             {0x6A88,
              std::make_shared<StatusProperties>(
                  "Data referenced by P1-P2 not available",
                  typeid(DataAccessException))}});

        return m;
    }();

CommandGetData::CommandGetData(
    std::shared_ptr<DtoAdapters::CommandContextDto> context, GetDataTag tag)
: Command(CommandRef::GET_DATA, getExpectedTotalLength(tag), context)
, mTagInfo(LegacySamConstants::TagInfo::valueOf(name(tag)))
{
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            context->getTargetSam()->getClassByte(),
            getCommandRef().getInstructionByte(),
            mTagInfo.getMsb(),
            mTagInfo.getLsb(),
            std::min(mTagInfo.getLength(), 255))));
}

int
CommandGetData::getExpectedTotalLength(GetDataTag tag)
{
    return LegacySamConstants::TagInfo::valueOf(name(tag)).getTotalLength();
}

void
CommandGetData::finalizeRequest()
{
    /* nothing to do */
}

bool
CommandGetData::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandGetData::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
    const std::vector<std::uint8_t> dataOut = apduResponse->getDataOut();

    // check BER-TLV header
    const std::vector<std::uint8_t> header = mTagInfo.getHeader();

    for (int i = 0; i < static_cast<int>(header.size()); i++) {
        if (dataOut[i] != header[i]) {
            throw new DataAccessException("Inconsistent BER-TLV tag");
        }
    }

    getContext()->getTargetSam()->setCaCertificate(
        Arrays::copyOfRange(dataOut, header.size(), dataOut.size()));
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandGetData::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
