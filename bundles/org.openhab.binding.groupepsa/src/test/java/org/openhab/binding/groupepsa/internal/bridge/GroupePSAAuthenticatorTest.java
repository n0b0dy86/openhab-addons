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

import java.util.HashMap;
import java.util.UUID;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openhab.binding.groupepsa.internal.rest.exceptions.GroupePSACommunicationException;
import org.openhab.core.auth.client.oauth2.OAuthClientService;
import org.openhab.core.auth.client.oauth2.OAuthFactory;
import org.openhab.core.auth.oauth2client.internal.OAuthFactoryImpl;
import org.openhab.core.auth.oauth2client.internal.OAuthStoreHandlerImpl;
import org.openhab.core.io.net.http.ExtensibleTrustManager;
import org.openhab.core.io.net.http.internal.ExtensibleTrustManagerImpl;
import org.openhab.core.io.net.http.internal.WebClientFactoryImpl;
import org.openhab.core.test.storage.VolatileStorageService;

/**
 * Testing the {@link GroupePSAAuthenticator}
 * 
 * @author Christoph Pfeifer - Initial contribution
 *
 */
class GroupePSAAuthenticatorTest {

    private final String username = "real";
    private final String password = "real";
    private final String clientId = "07364655-93cb-4194-8158-6b035ac2c24c";
    private final String clientSecret = "F2kK7lC5kF5qN7tM0wT8kE3cW1dP0wC5pI6vC0sQ5iP5cN8cJ8";

    private OAuthClientService oAuthClientService;

    @BeforeEach
    public void setUp() {
        final TestWebClientFactoryImpl webClient = new TestWebClientFactoryImpl(new ExtensibleTrustManagerImpl());
        webClient.initThreads();
        final OAuthFactory factory = new OAuthFactoryImpl(webClient,
                new OAuthStoreHandlerImpl(new VolatileStorageService()));
        final String tokenUrl = "https://idpcvs.opel.com/am/oauth2/access_token";
        final String authorizationUrl = "https://idpcvs.opel.com/am/oauth2/authorize";
        final String scope = "profile openid";
        this.oAuthClientService = factory.createOAuthClientService(UUID.randomUUID().toString(), tokenUrl,
                authorizationUrl, clientId, clientSecret, scope, true);
    }

    @Test
    void testAuthorizationURL() throws GroupePSACommunicationException {
        final GroupePSAAuthenticator authenticator = new GroupePSAAuthenticator(username, password, clientSecret,
                clientId, oAuthClientService);
        final String token = authenticator.getAuthorizationURL("profile openid");
        Assertions.assertNotNull(token);
        Assertions.assertFalse(token.isBlank());
    }

    private final class TestWebClientFactoryImpl extends WebClientFactoryImpl {

        public TestWebClientFactoryImpl(ExtensibleTrustManager extensibleTrustManager) {
            super(extensibleTrustManager);
        }

        private void initThreads() {
            activate(new HashMap<>());
        }
    }
}
