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

#include "keyple/card/calypso/crypto/legacysam/CommandReadKeyParameters.hpp"

#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/CounterOverflowException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;
using keyple::core::util::cpp::exception::IllegalStateException;

const int CommandReadKeyParameters::SW_KEY_NOT_FOUND = 0x6A83;
const int CommandReadKeyParameters::SW_DATA_NOT_SIGNED_WARNING = 0x6200;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandReadKeyParameters::STATUS_TABLE = [] {
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
             {0x6A00,
              std::make_shared<StatusProperties>(
                  "Incorrect P2", typeid(IllegalParameterException))},
             {0x6A83,
              std::make_shared<StatusProperties>(
                  "Record not found: key to read not found",
                  typeid(DataAccessException))},
             {0x6200,
              std::make_shared<StatusProperties>(
                  "Correct execution with warning: data not signed")}});
        return m;
    }();

CommandReadKeyParameters::CommandReadKeyParameters(
    std::shared_ptr<DtoAdapters::CommandContextDto> context,
    SystemKeyType systemKeyType)
: Command(CommandRef::READ_KEY_PARAMETERS, 32, context)
, mSystemKeyType(systemKeyType)
, mRecordNumber(0)
{
    if (!context) {
        throw IllegalParameterException("context cannot be null");
    }

    const std::uint8_t cla = context->getTargetSam()->getClassByte();
    const std::uint8_t inst = getCommandRef().getInstructionByte();
    const std::uint8_t p1 = 0;

    std::uint8_t p2;

    switch (systemKeyType) {
    case SystemKeyType::PERSONALIZATION:
        p2 = 0xC1;
        break;
    case SystemKeyType::KEY_MANAGEMENT:
        p2 = 0xC2;
        break;
    case SystemKeyType::RELOADING:
        p2 = 0xC3;
        break;
    case SystemKeyType::AUTHENTICATION:
        p2 = 0xC4;
        break;
    default:
        throw IllegalStateException(
            "Unexpected value: "
            + std::to_string(static_cast<int>(systemKeyType)));
    }

    const std::vector<std::uint8_t> dataIn = {0x00, 0x00};

    const auto apdu = std::make_shared<ApduRequestAdapter>(
        ApduUtil::build(cla, inst, p1, p2, dataIn));
    apdu->addSuccessfulStatusWord(SW_DATA_NOT_SIGNED_WARNING);
    apdu->addSuccessfulStatusWord(SW_KEY_NOT_FOUND);
    setApduRequest(apdu);

    addSubName(name(mSystemKeyType));
}

CommandReadKeyParameters::CommandReadKeyParameters(
    std::shared_ptr<DtoAdapters::CommandContextDto> context,
    const std::uint8_t kif,
    const std::uint8_t kvc)
: Command(CommandRef::READ_KEY_PARAMETERS, 32, context)
, mSystemKeyType(SystemKeyType::UNKNOWN)
, mRecordNumber(0)
{
    if (!context) {
        throw IllegalParameterException("context cannot be null");
    }

    const std::uint8_t cla = context->getTargetSam()->getClassByte();
    const std::uint8_t inst = getCommandRef().getInstructionByte();
    const std::uint8_t p1 = 0;
    const std::uint8_t p2 = 0xF0;
    const std::vector<std::uint8_t> dataIn = {kif, kvc};

    mKifKvc = static_cast<std::uint16_t>((kif << 8) | (kvc & 0xFF));

    auto adapter = std::make_shared<ApduRequestAdapter>(
        ApduUtil::build(cla, inst, p1, p2, dataIn));
    adapter->addSuccessfulStatusWord(SW_DATA_NOT_SIGNED_WARNING);
    setApduRequest(adapter);

    addSubName("Work key");
}

CommandReadKeyParameters::CommandReadKeyParameters(
    std::shared_ptr<DtoAdapters::CommandContextDto> context, int recordNumber)
: Command(CommandRef::READ_KEY_PARAMETERS, 32, context)
, mSystemKeyType(SystemKeyType::UNKNOWN)
, mRecordNumber(recordNumber)
{
    if (!context) {
        throw IllegalParameterException("context cannot be null");
    }

    const std::uint8_t cla = context->getTargetSam()->getClassByte();
    const std::uint8_t inst = getCommandRef().getInstructionByte();
    const std::uint8_t p1 = 0;
    const std::uint8_t p2 = recordNumber;
    const std::vector<std::uint8_t> dataIn = {0x00, 0x00};

    auto adapter = std::make_shared<ApduRequestAdapter>(
        ApduUtil::build(cla, inst, p1, p2, dataIn));
    adapter->addSuccessfulStatusWord(SW_DATA_NOT_SIGNED_WARNING);
    adapter->addSuccessfulStatusWord(SW_KEY_NOT_FOUND);
    setApduRequest(adapter);

    addSubName("Work key");
}

void
CommandReadKeyParameters::finalizeRequest()
{
    /* nothing to do */
}

bool
CommandReadKeyParameters::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandReadKeyParameters::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
    getContext()->getTargetSam()->setChallenge(apduResponse->getDataOut());
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandReadKeyParameters::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
