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

#include "keyple/card/calypso/crypto/legacysam/CommandSamDataCipher.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandRef.hpp"
#include "keyple/card/calypso/crypto/legacysam/CounterOverflowException.hpp"
#include "keyple/card/calypso/crypto/legacysam/DataAccessException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/card/generic/ApduRequestAdapter.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/cpp/System.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::card::generic::ApduRequestAdapter;
using keyple::core::util::ApduUtil;
using keyple::core::util::cpp::System;
using keyple::core::util::cpp::exception::IllegalArgumentException;

using StatusProperties = Command::StatusProperties;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandSamDataCipher::STATUS_TABLE = [] {
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
                  std::string("Preconditions not satisfied:\n")
                      + "- The SAM is locked.\n"
                      + "- Ciphering key: ciphering forbidden (CipherEnableBit "
                        "of PAR1 is"
                      + " set to0)",
                  typeid(AccessForbiddenException))},
             {0x6A00,
              std::make_shared<StatusProperties>(
                  "Incorrect P1 (!=%0xxxxx0) or P2",
                  typeid(IllegalParameterException))},
             {0x6A83,
              std::make_shared<StatusProperties>(
                  "Record not found: deciphering key not found",
                  typeid(DataAccessException))}});

        return m;
    }();

CommandSamDataCipher::CommandSamDataCipher(
    std::shared_ptr<DtoAdapters::CommandContextDto> context,
    int recordNumber,
    DataType dataType,
    const std::vector<uint8_t>& plainData)
: Command(CommandRef::SAM_DATA_CIPHER, 48, context)
{
    const uint8_t cla = context->getTargetSam()->getClassByte();
    const uint8_t inst = getCommandRef().getInstructionByte();
    const uint8_t p1 = 0;

    uint8_t p2;

    switch (dataType) {
    case DataType::CAAD_RECORD:
        p2 = 0xE7 + recordNumber;
        break;
    case DataType::CEILINGS_FILE_RECORD:
        p2 = 0xB1 + recordNumber;
        break;
    case DataType::ONE_CEILING_VALUE:
        p2 = 0xB8;
        break;
    case DataType::PARAMETERS_RECORD:
        p2 = 0xA0;
        break;
    default:
        throw IllegalArgumentException("Invalid DataType: ");  // + dataType);
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, inst, p1, p2, plainData)));
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandSamDataCipher::getStatusTable() const
{
    return STATUS_TABLE;
}

void
CommandSamDataCipher::finalizeRequest()
{
    /* nothing to do */
}

bool
CommandSamDataCipher::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandSamDataCipher::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);

    System::arraycopy(apduResponse->getApdu(), 0, mCipheredData, 0, 48);
}

const std::vector<uint8_t>&
CommandSamDataCipher::getCipheredData() const
{
    return mCipheredData;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
