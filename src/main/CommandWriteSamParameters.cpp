/******************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://calypsonet.org/    *
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

#include "keyple/card/calypso/crypto/legacysam/CommandWriteSamParameters.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandGiveRandom.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandSamDataCipher.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandSamGenerateKey.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandSelectDiversifier.hpp"
#include "keyple/card/calypso/crypto/legacysam/CounterOverflowException.hpp"
#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IncorrectInputDataException.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamUtil.hpp"
#include "keyple/card/calypso/crypto/legacysam/SecurityDataException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/ByteArrayUtil.hpp"
#include "keyple/core/util/cpp/System.hpp"
#include "keypop/calypso/crypto/legacysam/SystemKeyType.hpp"
#include "keypop/card/ApduResponseApi.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;
using keyple::core::util::ByteArrayUtil;
using keyple::core::util::cpp::System;

using CommandContextDto = DtoAdapters::CommandContextDto;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandWriteSamParameters::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6700,
              std::make_shared<StatusProperties>(
                  "Incorrect Lc", typeid(IllegalParameterException))},
             {0x6985,
              std::make_shared<StatusProperties>(
                  std::string("Preconditions not satisfied:\n")
                      + "- The SAM is locked.\n"
                      + "- In P1, b7 is equal to 1.\n"
                      + "- CipherEnableBit of PAR1 is 0.\n"
                      + "- Dynamic mode and the outgoing challenge is "
                        "unavailable.\n"
                      + "- SystemLockEnableBit=1.\n"
                      + "- Static mode and StaticCipherEnableBit=0",
                  typeid(AccessForbiddenException))},
             {0x6900,
              std::make_shared<StatusProperties>(
                  "An event counter cannot be incremented",
                  typeid(CounterOverflowException))},
             {0x6988,
              std::make_shared<StatusProperties>(
                  "Incorrect signature", typeid(SecurityDataException))},
             {0x6A00,
              std::make_shared<StatusProperties>(
                  "Incorrect P2", typeid(IllegalParameterException))},
             {0x6A80,
              std::make_shared<StatusProperties>(
                  "Incorrect decrypted data",
                  typeid(IncorrectInputDataException))},
             {0x6A83,
              std::make_shared<StatusProperties>(
                  "Record not found: deciphering key not found",
                  typeid(DataAccessException))}});
        return m;
    }();

CommandWriteSamParameters::CommandWriteSamParameters(
    std::shared_ptr<CommandContextDto> context,
    const std::vector<std::uint8_t>& samParameters)
: Command(CommandRef::WRITE_PARAMETERS, 0, context)
{
    mPlainData = std::vector<std::uint8_t>(30);
    System::arraycopy(samParameters, 0, mPlainData, 1, samParameters.size());
}

void
CommandWriteSamParameters::finalizeRequest()
{
    mPlainData[0] = getContext()
                        ->getTargetSam()
                        ->getSystemKeyParameter(SystemKeyType::PERSONALIZATION)
                        ->getKvc();

    auto controlSamContext = std::make_shared<CommandContextDto>(
        getContext()->getControlSam(), nullptr, nullptr);

    /* Add commands */
    addControlSamCommand(
        std::make_shared<CommandSelectDiversifier>(
            controlSamContext,
            getContext()->getTargetSam()->getSerialNumber()));

    addControlSamCommand(
        std::make_shared<CommandGiveRandom>(
            controlSamContext, getContext()->getTargetSam()->popChallenge()));

    auto commandSamDataCipher = std::make_shared<CommandSamDataCipher>(
        controlSamContext,
        0,
        CommandSamDataCipher::DataType::PARAMETERS_RECORD,
        mPlainData);

    addControlSamCommand(commandSamDataCipher);
    processControlSamCommand();

    const std::uint8_t cla = getContext()->getTargetSam()->getClassByte();
    const std::uint8_t inst = CommandRef::WRITE_PARAMETERS.getInstructionByte();
    const std::uint8_t p1 = LegacySamConstants::DYNAMIC_MODE_CIPHERING;
    const std::uint8_t p2 = 0xA0;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            cla, inst, p1, p2, commandSamDataCipher->getCipheredData())));
}

bool
CommandWriteSamParameters::isControlSamRequiredToFinalizeRequest() const
{
    return true;
}

void
CommandWriteSamParameters::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandWriteSamParameters::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
