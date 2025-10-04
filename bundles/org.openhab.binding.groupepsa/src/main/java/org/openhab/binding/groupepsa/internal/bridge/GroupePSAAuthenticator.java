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

import org.openhab.binding.groupepsa.internal.rest.exceptions.GroupePSACommunicationException;
import org.openhab.core.auth.client.oauth2.AccessTokenResponse;
import org.openhab.core.auth.client.oauth2.OAuthClientService;
import org.openhab.core.auth.client.oauth2.OAuthException;
import org.openhab.core.auth.client.oauth2.OAuthResponseException;

/**
 * The {@link GroupePSAAuthenticator} should authenticate at the PSA API
 * 
 * @author Christoph Pfeifer - Initial contribution
 *
 */
class GroupePSAAuthenticator {

    private static final String REDIRECT_URI = "mymop://oauth2redirect/de";

    private final String username;
    private final String password;
    private final String clientSecret;
    private final String clientId;
    private final OAuthClientService localOAuthService;

    GroupePSAAuthenticator(String username, String password, String clientSecret, String clientId,
            OAuthClientService localOAuthService) {
        this.username = username;
        this.password = password;
        this.clientSecret = clientSecret;
        this.clientId = clientId;
        this.localOAuthService = localOAuthService;
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
            final AccessTokenResponse result = localOAuthService
                    .getAccessTokenResponseByAuthorizationCode(authorizationCode, REDIRECT_URI);
            return result.getAccessToken();
        } catch (OAuthException | IOException | OAuthResponseException e) {
            throw new GroupePSACommunicationException(
                    "Unable to authenticate: " + GroupePSABridgeHandler.getRootCause(e).getMessage(), e);
        }
    }

    /**
     * private String authorizationCodeFromLoginPage(String authorizationUrl)
     * throws GroupePSACommunicationException {
     * 
     * final WebDriver driver = new HtmlUnitDriver();
     * 
     * try { driver.get(authorizationUrl); final String page =
     * driver.getPageSource();
     * 
     * final WebElement email = driver.findElement(By.name("username")); final
     * WebElement pass = driver.findElement(By.name("password"));
     * 
     * email.sendKeys(username); pass.sendKeys(password);
     * 
     * final WebElement loginBtn =
     * driver.findElement(By.cssSelector("button[type=submit]"));
     * loginBtn.click();
     * 
     * Thread.sleep(3000);
     * 
     * final WebElement okayBtn = driver.findElement(By.name(""));
     * okayBtn.click();
     * 
     * Thread.sleep(3000);
     * 
     * return driver.getCurrentUrl();
     * 
     * } catch (Exception e) { throw new GroupePSACommunicationException(
     * "Unable process authorization site: " +
     * GroupePSABridgeHandler.getRootCause(e).getMessage(), e); } finally {
     * driver.quit(); } }
     */
}
