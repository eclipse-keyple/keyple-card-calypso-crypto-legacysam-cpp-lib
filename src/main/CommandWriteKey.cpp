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

#include "keyple/card/calypso/crypto/legacysam/CommandWriteKey.hpp"

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
    CommandWriteKey::STATUS_TABLE = [] {
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
                      + "- Lock secret and LockedLock=1 at last reset.\n"
                      + "- CipherEnableBit of PAR1 is 0.\n"
                      + "- Dynamic mode ciphering and the outgoing challenge "
                        "is "
                      + "unavailable.\n"
                      + "- System key and SystemLockEnableBit=1.\n"
                      + "- Work key and WorkKeysLockEnableBit=1.\n"
                      + "- Work key and no empty record in the Work Key File.\n"
                      + "- Plain lock secret loading and PlainWriteDisabled=1 "
                        "at last"
                      + " reset.\n"
                      + "- Plain work key loading and "
                        "PlainWorkKeyInputEnableBit=0.\n"
                      + "- Work key loading by record number reference and "
                        "record is "
                      + "not empty.\n"
                      + "- Static mode and StaticCipherEnableBit=0",
                  typeid(AccessForbiddenException))},
             {0x6988,
              std::make_shared<StatusProperties>(
                  "Incorrect signature", typeid(SecurityDataException))},
             {0x6A00,
              std::make_shared<StatusProperties>(
                  std::string("P1 or P2 incorrect:\n")
                      + "- Incorrect data reference (P2≠01h to 7Eh, C0h, E0h "
                        "and "
                      + "F0h).\n"
                      + "- Ciphered data and random value (P1=%01xxxxxx).\n"
                      + "- System key and plain data (P1=%1xxxxxxx and "
                        "P2=C0h).\n"
                      + "- Random value for system or lock secret (P2=C0h or "
                        "E0h and "
                      + "P1=%x1xxxxxx).",
                  typeid(IllegalParameterException))},
             {0x6A80,
              std::make_shared<StatusProperties>(
                  std::string("Incorrect plain or decrypted data:\n")
                      + "- P2 different from P2 in command header.\n"
                      + "- Ciphered mode and incorrect decrypted data.\n"
                      + "- Received parameters incorrect (unknown ALG).\n"
                      + "- Incorrect KIF for a system key (KIF≠%1xxxxxxx).\n"
                      + "- Incorrect KIF for the lock secret (KIF≠EFh).\n"
                      + "- Ciphered system or work key writing: PAR7 to PAR10 "
                        "bytes "
                      + "not all null.\n" + "- Work key already exists.\n"
                      + "- Work key, given KIF=E1h or FDh, and "
                        "SystemLockEnableBit "
                      + "=1.\n"
                      + "- CAAD Transfer Control data present and PAR6≤80h or "
                        ">87h.\n"
                      + "- CAAD Transfer Control data do not match CAAD record "
                      + "indicated by PAR6–80h",
                  typeid(IncorrectInputDataException))},
             {0x6A83,
              std::make_shared<StatusProperties>(
                  std::string("Record not found:\n")
                      + "- Deciphering key not found.\n"
                      + "- CAAD Transfer Control data present and target CAAD "
                      + "record empty",
                  typeid(DataAccessException))},
             {0x6A87,
              std::make_shared<StatusProperties>(
                  std::string("Lc inconsistent with P1 or P2:\n")
                      + "- Plain data and CAAD Transfer Control data present "
                        "(Lc=50h).\n"
                      + "- Not a work key and CAAD Transfer Control data "
                        "present (Lc=50h).",
                  typeid(IncorrectInputDataException))}});
        return m;
    }();

CommandWriteKey::CommandWriteKey(
    std::shared_ptr<CommandContextDto> context,
    SystemKeyType systemKeyType,
    std::uint8_t kvc,
    const std::vector<std::uint8_t>& keyParameters,
    bool isTransferredKeyDiversified)
: Command(CommandRef::WRITE_KEY, 0, context)
, mTargetKeyReference(LegacySamConstants::TARGET_IS_SYSTEM_KEY_FILE)
, mCipheringKeyType(SystemKeyType::PERSONALIZATION)
, mSourceKeyKif(LegacySamConstants::SYSTEM_KEY_TYPE_KIF_MAP.at(systemKeyType))
, mSourceKeyKvc(kvc)
, mKeyParameters(keyParameters)
, mIsTransferredObjectDiversified(isTransferredKeyDiversified)
{
}

CommandWriteKey::CommandWriteKey(
    std::shared_ptr<CommandContextDto> context,
    std::uint8_t kif,
    std::uint8_t kvc,
    int targetRecordNumber,
    const std::vector<std::uint8_t>& keyParameters,
    bool isTransferredKeyDiversified)
: Command(CommandRef::WRITE_KEY, 0, context)
, mTargetKeyReference(
      targetRecordNumber == 0 ? LegacySamConstants::RECORD_CHOSEN_BY_THE_SAM
                              : targetRecordNumber)
, mCipheringKeyType(SystemKeyType::KEY_MANAGEMENT)
, mSourceKeyKif(kif)
, mSourceKeyKvc(kvc)
, mKeyParameters(keyParameters)
, mIsTransferredObjectDiversified(isTransferredKeyDiversified)
{
}

CommandWriteKey::CommandWriteKey(
    std::shared_ptr<CommandContextDto> context,
    std::uint8_t kif,
    std::uint8_t kvc,
    int targetRecordNumber,
    const std::vector<std::uint8_t>& keyParameters,
    const std::vector<std::uint8_t>& diversifier)
: Command(CommandRef::WRITE_KEY, 0, context)
, mTargetKeyReference(
      targetRecordNumber == 0 ? LegacySamConstants::RECORD_CHOSEN_BY_THE_SAM
                              : targetRecordNumber)
, mCipheringKeyType(SystemKeyType::KEY_MANAGEMENT)
, mSourceKeyKif(kif)
, mSourceKeyKvc(kvc)
, mKeyParameters(keyParameters)
, mIsTransferredObjectDiversified(true)
, mArbitraryDiversifier(diversifier)
{
}

CommandWriteKey::CommandWriteKey(
    std::shared_ptr<CommandContextDto> context,
    std::uint8_t lockIndex,
    std::uint8_t lockParameters,
    bool isTransferredLockDiversified)
: Command(CommandRef::WRITE_KEY, 0, context)
, mTargetKeyReference(LegacySamConstants::TARGET_IS_LOCK_FILE)
, mCipheringKeyType(SystemKeyType::PERSONALIZATION)
, mSourceKeyKif(LegacySamConstants::LOCK_KIF)
, mSourceKeyKvc(lockIndex)
, mIsTransferredObjectDiversified(isTransferredLockDiversified)
{
    std::vector<std::uint8_t> lockParametersAsKeyParameters(
        LegacySamConstants::KEY_PARAMETERS_LENGTH);
    lockParametersAsKeyParameters[5] = lockParameters;
    mKeyParameters = lockParametersAsKeyParameters;
}

CommandWriteKey::CommandWriteKey(
    std::shared_ptr<CommandContextDto> context,
    const std::vector<std::uint8_t>& plainLockDataBlock)
: Command(CommandRef::WRITE_KEY, 0, context)
, mTargetKeyReference(LegacySamConstants::TARGET_IS_LOCK_FILE)
, mCipheringKeyType(SystemKeyType::UNKNOWN)
, mSourceKeyKif(0)
, mSourceKeyKvc(0)
, mKeyParameters({0})
, mIsTransferredObjectDiversified(false)
, mCipheringKeyKvc(0)
, mWriteKeyCommandData(plainLockDataBlock)
{
}

void
CommandWriteKey::finalizeRequest()
{
    std::uint8_t p1;
    if (mWriteKeyCommandData.empty()) {
        mCipheringKeyKvc = getContext()
                               ->getTargetSam()
                               ->getSystemKeyParameter(mCipheringKeyType)
                               ->getKvc();

        /* It is a key transfer */
        auto controlSamContext = std::make_shared<CommandContextDto>(
            getContext()->getControlSam(), nullptr, nullptr);
        std::vector<std::uint8_t> diversifier(8);
        System::arraycopy(
            getContext()->getTargetSam()->getSerialNumber(),
            0,
            diversifier,
            4,
            4);
        addControlSamCommand(
            std::make_shared<CommandSelectDiversifier>(
                controlSamContext, diversifier));
        addControlSamCommand(
            std::make_shared<CommandGiveRandom>(
                controlSamContext,
                getContext()->getTargetSam()->popChallenge()));

        auto commandSamGenerateKey = std::make_shared<CommandSamGenerateKey>(
            controlSamContext,
            mTargetKeyReference,
            mCipheringKeyKvc,
            mSourceKeyKif,
            mSourceKeyKvc,
            mKeyParameters,
            mIsTransferredObjectDiversified,
            mArbitraryDiversifier);
        addControlSamCommand(commandSamGenerateKey);
        processControlSamCommand();

        mWriteKeyCommandData = commandSamGenerateKey->getCipheredData();
        p1 = 0x00;
    } else {
        p1 = (0x80);  // plain data mode
    }

    const std::uint8_t cla = getContext()->getTargetSam()->getClassByte();
    const std::uint8_t ins = CommandRef::WRITE_KEY.getInstructionByte();

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(ApduUtil::build(
            cla, ins, p1, mTargetKeyReference, mWriteKeyCommandData)));
}

bool
CommandWriteKey::isControlSamRequiredToFinalizeRequest() const
{
    return true;
}

void
CommandWriteKey::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandWriteKey::getStatusTable() const
{
    return STATUS_TABLE;
}

std::vector<std::uint8_t>
CommandWriteKey::buildPlainLockDataBlock(
    std::uint8_t lockIndex,
    std::uint8_t lockParameters,
    const std::vector<std::uint8_t>& lockValue)
{
    std::vector<std::uint8_t> lockFile(LegacySamConstants::LOCK_FILE_SIZE);
    lockFile[0] = LegacySamConstants::LOCK_KIF;
    lockFile[1] = lockIndex;
    lockFile[7] = lockParameters;
    System::arraycopy(
        lockValue, 0, lockFile, 13, LegacySamConstants::LOCK_VALUE_LENGTH);

    std::vector<std::uint8_t> plainDataBlock(
        LegacySamConstants::KEY_DATA_BLOCK_SIZE);
    System::arraycopy(
        lockFile, 0, plainDataBlock, 8, LegacySamConstants::LOCK_FILE_SIZE);
    plainDataBlock[37] = LegacySamConstants::TARGET_IS_LOCK_FILE;
    plainDataBlock[45] = 0x80;

    return plainDataBlock;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
