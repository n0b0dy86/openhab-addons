/*
 * Copyright (c) 2010-2025 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.groupepsa.internal.bridge;

import java.io.IOException;
import java.time.Instant;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.openhab.binding.groupepsa.internal.rest.exceptions.GroupePSACommunicationException;
import org.openhab.core.auth.client.oauth2.AccessTokenResponse;
import org.openhab.core.auth.client.oauth2.OAuthClientService;
import org.openhab.core.auth.client.oauth2.OAuthException;
import org.openhab.core.auth.client.oauth2.OAuthResponseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The {@link GroupePSAAuthenticator} should authenticate at the PSA API
 * 
 * @author Christoph Pfeifer - Initial contribution
 *
 */
class GroupePSAAuthenticator {

    private static final String REDIRECT_URI = "mymop://oauth2redirect/de";

    private final Logger logger = LoggerFactory.getLogger(GroupePSAAuthenticator.class);

    private final ScheduledExecutorService executor;
    private final OAuthClientService localOAuthService;

    GroupePSAAuthenticator(OAuthClientService localOAuthService, ScheduledExecutorService executor) {
        this.localOAuthService = localOAuthService;
        this.executor = executor;
    }

    public String getAuthorizationURL(String scope) throws GroupePSACommunicationException {
        if (localOAuthService == null) {
            throw new GroupePSACommunicationException("OAuth service is unexpectedly null");
        }
        try {
            return localOAuthService.getAuthorizationUrl(REDIRECT_URI, scope, null) + "&locale=de-DE";
        } catch (OAuthException e) {
            throw new GroupePSACommunicationException(
                    "Unable to generate authorization URL: " + GroupePSABridgeHandler.getRootCause(e).getMessage(), e);
        }
    }

    public String newAccessToken(String authorizationCode) throws GroupePSACommunicationException {
        if (localOAuthService == null) {
            throw new GroupePSACommunicationException("OAuth service is unexpectedly null");
        }
        try {
            final String code;
            if (authorizationCode.startsWith("mymop://")) {
                code = localOAuthService.extractAuthCodeFromAuthResponse(authorizationCode);
            } else {
                code = authorizationCode;
            }
            final AccessTokenResponse result = localOAuthService.getAccessTokenResponseByAuthorizationCode(code,
                    REDIRECT_URI);
            renewAccessToken(result);
            return result.getAccessToken();
        } catch (OAuthException | IOException | OAuthResponseException e) {
            throw new GroupePSACommunicationException(
                    "Unable to authenticate: " + GroupePSABridgeHandler.getRootCause(e).getMessage(), e);
        }
    }

    private void renewAccessToken(AccessTokenResponse accessTokenResponse) {
        final Instant expireDate = accessTokenResponse.getCreatedOn().plusSeconds(accessTokenResponse.getExpiresIn())
                .minusSeconds(20);
        executor.schedule(() -> {
            try {
                renewAccessToken(localOAuthService.refreshToken());
            } catch (OAuthException | IOException | OAuthResponseException e) {
                logger.error("Could not refresh access token!", e);
            }
        }, expireDate.getEpochSecond() - Instant.now().getEpochSecond(), TimeUnit.SECONDS);
    }
}
