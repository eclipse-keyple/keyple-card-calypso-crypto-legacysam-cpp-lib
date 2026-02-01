#******************************************************************************
#* Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
#*                                                                            *
#* See the NOTICE file(s) distributed with this work for additional           *
#* information regarding copyright ownership.                                 *
#*                                                                            *
#* This program and the accompanying materials are made available under the   *
#* terms of the Eclipse Public License 2.0 which is available at              *
#* http://www.eclipse.org/legal/epl-2.0                                       *
#*                                                                            *
#* SPDX-License-Identifier: EPL-2.0                                           *
#******************************************************************************/

SET(LIBRARY_NAME keyplecardcalypsocryptolegacysamcpplib)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DKEYPLECARDCALYPSOCRYPTOLEGACYSAM_EXPORT")

# Include deps
INCLUDE("CMakeLists.txt.keyple-card-generic")
INCLUDE("CMakeLists.txt.keypop-calypso-card")
INCLUDE("CMakeLists.txt.keypop-calypso-crypto-legacysam")
INCLUDE("CMakeLists.txt.keypop-calypso-crypto-symmetric")

ADD_LIBRARY(

    ${LIBRARY_NAME}

    ${LIBRARY_TYPE}

    ${CMAKE_CURRENT_SOURCE_DIR}/AsyncTransactionCreatorManagerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/AsyncTransactionExecutorManagerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CardTransactionUtil.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Command.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandCardCipherPin.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandCardGenerateAsymmetricKeyPair.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandCardGenerateKey.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandDataCipher.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandDigestAuthenticate.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandDigestClose.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandDigestInit.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandDigestInternalAuthenticate.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandDigestUpdate.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandDigestUpdateMultiple.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandExecutor.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandGetChallenge.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandGetData.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandGiveRandom.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandPsoComputeCertificate.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandPsoComputeSignature.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandPsoVerifySignature.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandReadCeilings.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandReadCounter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandReadKeyParameters.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandReadParameters.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandRef.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandSamDataCipher.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandSamGenerateKey.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandSelectDiversifier.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandSvCheck.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandSvPrepareDebitOrUndebit.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandSvPrepareLoad.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandUnlock.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandWriteCeilings.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandWriteKey.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommandWriteSamParameters.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CommonTransactionManagerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ContextSettingAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/DtoAdapters.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/FreeTransactionManagerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/KeyParameterAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/LegacySamAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/LegacySamApiFactoryAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/LegacySamConstants.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/LegacySamExtensionService.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/LegacySamResourceProfileExtensionAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/LegacySamSelectionExtensionAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/LegacySamUtil.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SamParametersAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SecureWriteTransactionManagerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SecuritySettingAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SymmetricCryptoCardTransactionManagerAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SymmetricCryptoCardTransactionManagerFactoryAdapter.cpp
)

TARGET_INCLUDE_DIRECTORIES(

    ${LIBRARY_NAME}

    PUBLIC

    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
)

TARGET_LINK_LIBRARIES(

    ${LIBRARY_NAME}

    PUBLIC

    Keyple::Card::Generic
    Keypop::Calypso::Card
    Keypop::Calypso::Crypto::LegacySam
    Keypop::Calypso::Crypto::Symmetric
)

ADD_LIBRARY(

    Keyple::Card::Calypso::Crypto::LegacySam

    ALIAS

    ${LIBRARY_NAME}
)
