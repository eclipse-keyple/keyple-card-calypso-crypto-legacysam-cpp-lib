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

#pragma once

#include <cstdint>
#include <memory>
#include <optional>

#include "keyple/card/calypso/crypto/legacysam/ContextSetting.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

/**
 * Adapter of ContextSetting.
 *
 * @since 0.4.0
 */
class ContextSettingAdapter final : public ContextSetting {
public:
    /**
     * @brief Default constructor.
     * @since 0.4.0
     */
    ContextSettingAdapter();

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    ContextSetting&
    setContactReaderPayloadCapacity(int payloadCapacity) override;

    /**
     * Returns the contact reader payload capacity.
     *
     * @return null if no payload capacity has been defined.
     * @since 0.4.0
     */
    std::shared_ptr<int> getContactReaderPayloadCapacity() const;

private:
    /**
     *
     */
    std::shared_ptr<int> mContactReaderPayloadCapacity;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
