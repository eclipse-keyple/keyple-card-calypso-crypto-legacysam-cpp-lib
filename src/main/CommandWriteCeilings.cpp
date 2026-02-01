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

#include "keyple/card/calypso/crypto/legacysam/CommandWriteCeilings.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandGiveRandom.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandSamDataCipher.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandSelectDiversifier.hpp"
#include "keyple/card/calypso/crypto/legacysam/CounterOverflowException.hpp"
#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IncorrectInputDataException.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamUtil.hpp"
#include "keyple/card/calypso/crypto/legacysam/SecurityDataException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/ByteArrayUtil.hpp"
#include "keypop/calypso/crypto/legacysam/SystemKeyType.hpp"
#include "keypop/card/ApduResponseApi.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;
using keyple::core::util::ByteArrayUtil;

using CommandContextDto = DtoAdapters::CommandContextDto;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandWriteCeilings::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6700,
              std::make_shared<StatusProperties>(
                  "Incorrect Lc", typeid(IllegalParameterException))},
             {0x6985,
              std::make_shared<StatusProperties>(
                  "Preconditions not satisfied:\n"
                  "- The SAM is locked.\n"
                  "- In P1, b7 is equal to 1.\n"
                  "- CipherEnableBit of PAR1 is 0.\n"
                  "- Dynamic mode and the outgoing challenge is unavailable.\n"
                  "- Static mode and StaticCipherEnableBit=0",
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
                  "Incorrect decrypted data, including:\n"
                  "- Full ceiling record update (P2!=B8h) with DES/DESX key44 "
                  "and at "
                  "least one ceiling is increased by more than 131,071.\n"
                  "- One ceiling update (P2=B8h): reference>26, or the 25 last "
                  "data "
                  "bytes are not all null",
                  typeid(IncorrectInputDataException))},
             {0x6A83,
              std::make_shared<StatusProperties>(
                  "Record not found: deciphering key not found",
                  typeid(DataAccessException))}});

        return m;
    }();

CommandWriteCeilings::CommandWriteCeilings(
    std::shared_ptr<DtoAdapters::CommandContextDto> context,
    std::shared_ptr<DtoAdapters::TargetSamContextDto> targetSamContext,
    int counterNumber,
    int ceilingValue)
: Command(
      CommandRef::WRITE_CEILINGS,
      LegacySamConstants::PLAIN_CEILING_DATA_BLOCK_SIZE,
      context)
, mTargetSamContext(targetSamContext)
, mPlainData(LegacySamConstants::PLAIN_CEILING_DATA_BLOCK_SIZE)
, mCounterFileRecordNumber(-1)
{
    /*
     * Build the plain data block to be ciphered later.
     * If targetSamContext is null (dynamic mode), get the KVC from the
     * LegacySam.
     */
    mPlainData[0] = (mTargetSamContext == nullptr)
                        ? getContext()
                              ->getTargetSam()
                              ->getSystemKeyParameter(SystemKeyType::RELOADING)
                              ->getKvc()
                        : mTargetSamContext->getSystemKeyTypeToKvcMap()
                              .find(SystemKeyType::RELOADING)
                              ->second;
    mPlainData[1] = static_cast<uint8_t>(counterNumber);
    ByteArrayUtil::copyBytes(ceilingValue, mPlainData, 2, 3);
}

CommandWriteCeilings::CommandWriteCeilings(
    std::shared_ptr<DtoAdapters::CommandContextDto> context,
    int counterNumber,
    int ceilingValue)
: CommandWriteCeilings(context, nullptr, counterNumber, ceilingValue)
{
}

CommandWriteCeilings::CommandWriteCeilings(
    std::shared_ptr<DtoAdapters::CommandContextDto> context,
    std::shared_ptr<DtoAdapters::TargetSamContextDto> targetSamContext,
    int counterNumber,
    int ceilingValue,
    CounterIncrementAccess counterIncrementAccess)
: Command(
      CommandRef::WRITE_CEILINGS,
      LegacySamConstants::PLAIN_CEILING_DATA_BLOCK_SIZE,
      context)
, mTargetSamContext(targetSamContext)
, mPlainData(LegacySamConstants::PLAIN_CEILING_DATA_BLOCK_SIZE)
, mCounterFileRecordNumber(
      LegacySamConstants::COUNTER_TO_RECORD_LOOKUP[counterNumber])
{
    /*
     * If targetSamContext is null (dynamic mode), get the KVC from the
     * LegacySam.
     */
    mPlainData[0] = (mTargetSamContext == nullptr)
                        ? getContext()
                              ->getTargetSam()
                              ->getSystemKeyParameter(SystemKeyType::RELOADING)
                              ->getKvc()
                        : mTargetSamContext->getSystemKeyTypeToKvcMap()
                              .find(SystemKeyType::RELOADING)
                              ->second;

    addCounter(counterNumber, ceilingValue, counterIncrementAccess);
}

CommandWriteCeilings::CommandWriteCeilings(
    std::shared_ptr<DtoAdapters::CommandContextDto> context,
    int counterNumber,
    int ceilingValue,
    CounterIncrementAccess counterIncrementAccess)
: CommandWriteCeilings(
      context, nullptr, counterNumber, ceilingValue, counterIncrementAccess)
{
}

void
CommandWriteCeilings::addCounter(
    int counterNumber,
    int ceilingValue,
    CounterIncrementAccess counterIncrementAccess)
{
    /* Update the plain data block to be ciphered later. */
    ByteArrayUtil::copyBytes(
        ceilingValue, mPlainData, (counterNumber % 9) * 3 + 1, 3);

    /* Keep the config into a map. */
    mCounterNumberToManualCounterIncrementAuthorizedMap[counterNumber % 9]
        = counterIncrementAccess;
}

int
CommandWriteCeilings::getCounterFileRecordNumber() const
{
    return mCounterFileRecordNumber;
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandWriteCeilings::getStatusTable() const
{
    return STATUS_TABLE;
}

void
CommandWriteCeilings::finalizeRequest()
{
    auto controlSamContext = std::make_shared<CommandContextDto>(
        getContext()->getControlSam(), nullptr, nullptr);

    /* Add commands. */
    addControlSamCommand(
        std::make_shared<CommandSelectDiversifier>(
            controlSamContext,
            (mTargetSamContext == nullptr)
                ? getContext()->getTargetSam()->getSerialNumber()
                : mTargetSamContext->getSerialNumber()));

    std::vector<uint8_t> challenge
        = (mTargetSamContext == nullptr)
              ? getContext()->getTargetSam()->popChallenge()
              : LegacySamUtil::computeStaticModeChallenge(
                    mTargetSamContext, SystemKeyType::RELOADING);

    addControlSamCommand(
        std::make_shared<CommandGiveRandom>(controlSamContext, challenge));

    if (mCounterFileRecordNumber != -1) {
        computePlainData();
    }

    auto commandSamDataCipher = std::make_shared<CommandSamDataCipher>(
        controlSamContext,
        mCounterFileRecordNumber,
        (mCounterFileRecordNumber == -1)
            ? CommandSamDataCipher::DataType::ONE_CEILING_VALUE
            : CommandSamDataCipher::DataType::CEILINGS_FILE_RECORD,
        mPlainData);

    addControlSamCommand(commandSamDataCipher);

    processControlSamCommand();

    const uint8_t cla = 0x80;
    const uint8_t inst = getCommandRef().getInstructionByte();
    const uint8_t p1 = (mTargetSamContext == nullptr)
                           ? LegacySamConstants::DYNAMIC_MODE_CIPHERING
                           : LegacySamConstants::STATIC_MODE_CIPHERING;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            cla,
            inst,
            p1,
            (mCounterFileRecordNumber == -1)
                ? LegacySamConstants::SINGLE_CEILING_REFERENCE
                : static_cast<uint8_t>(
                      LegacySamConstants::FIRST_EVENT_CEILING_RECORD_REFERENCE
                      + mCounterFileRecordNumber),
            commandSamDataCipher->getCipheredData())));
}

void
CommandWriteCeilings::computePlainData()
{
    std::uint16_t configBits = 0;

    for (int i = 0; i < 9; i++) {
        auto it = mCounterNumberToManualCounterIncrementAuthorizedMap.find(i);
        CounterIncrementAccess config;
        if (it == mCounterNumberToManualCounterIncrementAuthorizedMap.end()) {
            config = getContext()->getTargetSam()->getCounterIncrementAccess(
                (mCounterFileRecordNumber * 9) + i);
        } else {
            config = it->second;
        }

        if (config == CounterIncrementAccess::FREE_COUNTING_ENABLED
            && (i != 0 || mCounterFileRecordNumber != 0)) {
            configBits |= 1 << i;
        }
    }

    ByteArrayUtil::copyBytes(configBits, mPlainData, 28, 2);
}

bool
CommandWriteCeilings::isControlSamRequiredToFinalizeRequest() const
{
    return true;
}

void
CommandWriteCeilings::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
