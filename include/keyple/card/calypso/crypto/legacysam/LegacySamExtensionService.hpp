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

#pragma once

#include <memory>
#include <string>

#include "keyple/card/calypso/crypto/legacysam/ContextSettingAdapter.hpp"
#include "keyple/core/common/KeypleCardExtension.hpp"
#include "keyple/core/service/resource/spi/CardResourceProfileExtension.hpp"
#include "keypop/calypso/crypto/legacysam/LegacySamApiFactory.hpp"
#include "keypop/calypso/crypto/legacysam/sam/LegacySamSelectionExtension.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::card::calypso::crypto::legacysam::ContextSettingAdapter;
using keyple::core::common::KeypleCardExtension;
using keyple::core::service::resource::spi::CardResourceProfileExtension;
using keypop::calypso::crypto::legacysam::LegacySamApiFactory;
using keypop::calypso::crypto::legacysam::sam::LegacySamSelectionExtension;

/**
 * Card extension dedicated to the management of Calypso legacy SAMs (SAM-C1,
 * HSM-C1, etc.).
 *
 * @since 0.2.0
 */
class LegacySamExtensionService final : public KeypleCardExtension {
public:
    /**
     * Returns the service instance.
     *
     * @return A not null reference.
     * @since 0.2.0
     */
    static std::shared_ptr<LegacySamExtensionService> getInstance();

    /**
     * Returns the context setting.
     *
     * @return A not null ContextSetting.
     * @since 0.4.0
     */
    std::shared_ptr<ContextSetting> getContextSetting();

    /**
     * Returns a LegacySamApiFactory.
     *
     * @return A not null reference.
     * @since 0.4.0
     */
    std::shared_ptr<LegacySamApiFactory> getLegacySamApiFactory();

    /**
     * Returns a CardResourceProfileExtension to be used with the card resource
     * service.
     *
     * @param legacySamSelectionExtension The legacy SAM selection extension to
     * use.
     * @return A not null reference.
     * @throw IllegalArgumentException If no SAM selection is provided.
     * @since 0.2.0
     */
    std::shared_ptr<CardResourceProfileExtension>
    createLegacySamResourceProfileExtension(
        std::shared_ptr<LegacySamSelectionExtension>
            legacySamSelectionExtension);

    /**
     * Returns a CardResourceProfileExtension to be used with the card resource
     * service.
     *
     * @param legacySamSelectionExtension The legacy SAM selection extension to
     * use.
     * @param powerOnDataRegex A regular expression.
     * @return A not null reference.
     * @throw IllegalArgumentException If no SAM selection is provided.
     * @throw IllegalArgumentException If the regular expression is null or
     * empty.
     * @since 0.2.0
     */
    std::shared_ptr<CardResourceProfileExtension>
    createLegacySamResourceProfileExtension(
        std::shared_ptr<LegacySamSelectionExtension>
            legacySamSelectionExtension,
        const std::string& powerOnDataRegex);

    /**
     * {@inheritDoc}
     *
     * @since 0.2.0
     */
    const std::string getCommonApiVersion() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.2.0
     */
    const std::string getReaderApiVersion() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.2.0
     */
    const std::string getCardApiVersion() const override;

private:
    LegacySamExtensionService();

    static std::shared_ptr<LegacySamExtensionService> mInstance;
    std::shared_ptr<ContextSettingAdapter> mContextSetting;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
