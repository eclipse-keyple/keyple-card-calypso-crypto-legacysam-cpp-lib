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

#include "keyple/card/calypso/crypto/legacysam/CommandDataCipher.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/CounterOverflowException.hpp"
#include "keyple/card/calypso/crypto/legacysam/DataAccessException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/System.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/InvalidSignatureException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::System;
using keypop::calypso::crypto::legacysam::transaction::
    InvalidSignatureException;

const std::map<int, const std::shared_ptr<StatusProperties>>
    CommandDataCipher::STATUS_TABLE = [] {
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
                      + "- Cipher or sign forbidden (DataCipherEnableBit of "
                      + "PAR5 is 0).\n"
                      + "- Ciphering or signing mode, and ciphering forbidden"
                      + "(CipherEnableBit of PAR1 is 0).\n"
                      + "- Decipher mode, and deciphering forbidden "
                      + "(DecipherDataEnableBit of PAR1 is 0).\n" + "- AES key",
                  typeid(AccessForbiddenException))},
             {0x6A83,
              std::make_shared<StatusProperties>(
                  "Record not found: ciphering key not found",
                  typeid(DataAccessException))},
             {0x6B00,
              std::make_shared<StatusProperties>(
                  "Incorrect P1", typeid(IllegalParameterException))}});
        return m;
    }();

CommandDataCipher::CommandDataCipher(
    std::shared_ptr<CommandContextDto> context,
    std::shared_ptr<BasicSignatureComputationDataAdapter>
        signatureComputationData,
    std::shared_ptr<BasicSignatureVerificationDataAdapter>
        signatureVerificationData)
: Command(CommandRef::DATA_CIPHER, 0, context)
, mSignatureComputationData(signatureComputationData)
, mSignatureVerificationData(signatureVerificationData)
{
    const std::uint8_t cla = context->getTargetSam()->getClassByte();
    const std::uint8_t inst = getCommandRef().getInstructionByte();
    const std::uint8_t p1 = 0x40;
    const std::uint8_t p2 = 0x00;

    std::vector<std::uint8_t> dataIn(0);

    if (signatureComputationData != nullptr) {
        dataIn.resize(2 + signatureComputationData->getData().size());
        dataIn[0] = signatureComputationData->getKif();
        dataIn[1] = signatureComputationData->getKvc();
        System::arraycopy(
            signatureComputationData->getData(),
            0,
            dataIn,
            2,
            signatureComputationData->getData().size());

    } else if (signatureVerificationData != nullptr) {
        dataIn.resize(2 + signatureVerificationData->getData().size());
        dataIn[0] = signatureVerificationData->getKif();
        dataIn[1] = signatureVerificationData->getKvc();
        System::arraycopy(
            signatureVerificationData->getData(),
            0,
            dataIn,
            2,
            signatureVerificationData->getData().size());
    }

    const std::vector<uint8_t> apdu
        = signatureVerificationData == nullptr
                  && signatureComputationData == nullptr
              ? ApduUtil::build(cla, inst, p1, p2)
              : ApduUtil::build(cla, inst, p1, p2, dataIn);

    setApduRequest(std::make_shared<ApduRequestAdapter>(apdu));
}

void
CommandDataCipher::finalizeRequest()
{
    /* nothing to do */
}

bool
CommandDataCipher::isControlSamRequiredToFinalizeRequest() const
{
    return false;
}

void
CommandDataCipher::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    setResponseAndCheckStatus(apduResponse);
    if (apduResponse->getDataOut().size() > 0) {
        if (mSignatureComputationData != nullptr) {
            mSignatureComputationData->setSignature(
                Arrays::copyOfRange(
                    apduResponse->getDataOut(),
                    0,
                    mSignatureComputationData->getSignatureSize()));

        } else if (mSignatureVerificationData != nullptr) {
            const std::vector<std::uint8_t> computedSignature
                = Arrays::copyOfRange(
                    apduResponse->getDataOut(),
                    0,
                    mSignatureVerificationData->getSignature().size());
            mSignatureVerificationData->setSignatureValid(
                Arrays::equals(
                    computedSignature,
                    mSignatureVerificationData->getSignature()));
        }
        if (mSignatureVerificationData != nullptr
            && !mSignatureVerificationData->isSignatureValid()) {
            throw InvalidSignatureException("Invalid signature");
        }
    }
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
CommandDataCipher::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
