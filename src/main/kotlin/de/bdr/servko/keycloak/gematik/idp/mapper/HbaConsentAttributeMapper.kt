/*
 *  Copyright 2023 Bundesdruckerei GmbH and/or its affiliates
 *  and other contributors.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package de.bdr.servko.keycloak.gematik.idp.mapper

import de.bdr.servko.keycloak.gematik.idp.model.CardType

class HbaConsentAttributeMapper : AbstractGematikAuthenticatorConsentAttributeMapper() {

    override val cardType: CardType
        get() = CardType.HBA

    override fun getId(): String = "gematik-idp-authenticator-hba-consent-attribute-mapper"

    override fun getHelpText(): String =
        "Save client consent for HBA from Authenticator, into the specified user attribute."

    override fun getDisplayType(): String = "Gematik Authenticator HBA Consent Attributes"

}
