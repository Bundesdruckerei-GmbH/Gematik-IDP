/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */
package de.bdr.servko.keycloak.gematik.idp.exception

import org.keycloak.broker.provider.IdentityBrokerException;

class IdpUnavailableException(message:String): IdentityBrokerException(message)
