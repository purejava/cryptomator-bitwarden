package org.purejava.integrations.keychain;

import com.bitwarden.sdk.BitwardenClient;
import com.bitwarden.sdk.BitwardenSettings;
import org.cryptomator.integrations.keychain.KeychainAccessException;
import org.cryptomator.integrations.keychain.KeychainAccessProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

public class BitwardenAccess implements KeychainAccessProvider {

    private static final Logger LOG = LoggerFactory.getLogger(BitwardenAccess.class);

    private final BitwardenSettings bitwardenSettings = new BitwardenSettings();
    private final BitwardenClient bitwardenClient;
    private final String accessToken;
    private final UUID organizationId;
    private final String apiUrl = "https://api.bitwarden.com";
    private final String identityUrl = "https://identity.bitwarden.com";
    private final String URL_SCHEME = "https://";
    private final String APP_NAME = "Cryptomator";

    public BitwardenAccess() {
        // ToDo fix missing or wrong env vars
        this.accessToken = System.getenv("BITWARDEN_ACCESS_TOKEN");
        this.organizationId = UUID.fromString(System.getenv("BITWARDEN_ORGANIZATION_ID"));
        this.bitwardenSettings.setApiUrl(apiUrl);
        this.bitwardenSettings.setIdentityUrl(identityUrl);
        this.bitwardenClient = new BitwardenClient(bitwardenSettings);
        this.bitwardenClient.accessTokenLogin(accessToken);
    }

    @Override
    public String displayName() { return "Bitwarden"; }

    // ToDo check, if this is ok no or wrong IDs
    @Override
    public boolean isSupported() { return true; }

    // ToDo check, if this is ok
    @Override
    public boolean isLocked() { return false; }

    @Override
    public void storePassphrase(String vault, CharSequence password) throws KeychainAccessException {
        storePassphrase(vault, "Vault", password);
    }

    @Override
    public void storePassphrase(String vault, String name, CharSequence password) throws KeychainAccessException {
        var projectResponse = bitwardenClient.projects().create(organizationId, APP_NAME);
        var projectId = projectResponse.getID();
        var secretResponse = bitwardenClient.secrets().create(vault, password.toString(), "", organizationId, new UUID[]{projectId});
    }

    @Override
    public char[] loadPassphrase(String vault) throws KeychainAccessException {
        return null;
    }

    @Override
    public void deletePassphrase(String vault) throws KeychainAccessException {
    }

    @Override
    public void changePassphrase(String vault, CharSequence password) throws KeychainAccessException {
        changePassphrase(vault, "Vault", password);
    }

    @Override
    public void changePassphrase(String vault, String name, CharSequence password) throws KeychainAccessException {
    }
}
