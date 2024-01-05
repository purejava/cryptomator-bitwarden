package org.purejava.integrations.keychain;

import com.bitwarden.sdk.BitwardenClient;
import com.bitwarden.sdk.BitwardenClientException;
import com.bitwarden.sdk.BitwardenSettings;
import org.cryptomator.integrations.keychain.KeychainAccessException;
import org.cryptomator.integrations.keychain.KeychainAccessProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
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
        // ToDo check, what happens, if network is unavailable
        this.accessToken = System.getenv("BITWARDEN_ACCESS_TOKEN");
        this.organizationId = UUID.fromString(System.getenv("BITWARDEN_ORGANIZATION_ID"));
        this.bitwardenSettings.setApiUrl(apiUrl);
        this.bitwardenSettings.setIdentityUrl(identityUrl);
        this.bitwardenClient = new BitwardenClient(bitwardenSettings);
        this.bitwardenClient.accessTokenLogin(accessToken);
    }

    @Override
    public String displayName() { return "Bitwarden"; }

    // ToDo check, if this is ok, no for wrong IDs
    @Override
    public boolean isSupported() { return true; }

    @Override
    public boolean isLocked() { return false; }

    @Override
    public void storePassphrase(String vault, CharSequence password) throws KeychainAccessException {
        storePassphrase(vault, "Vault", password);
    }

    @Override
    public void storePassphrase(String vault, String name, CharSequence password) throws KeychainAccessException {
        UUID projectId;
        try {
            var project = Arrays.stream(bitwardenClient.projects().list(organizationId).getData())
                    .filter(r -> r.getName().equals(APP_NAME))
                    .findFirst();
            if (project.isPresent()) {
                projectId = project.get().getID();
            } else {
                projectId = bitwardenClient.projects().create(organizationId, APP_NAME).getID();
            }

            var secret = Arrays.stream(bitwardenClient.secrets().list(organizationId).getData())
                    .filter(r -> r.getKey().equals(vault))
                    .findFirst();
            if (secret.isEmpty()) {
                bitwardenClient.secrets().create(vault, password.toString(), "Password for vault: " + name, organizationId, new UUID[]{ projectId });
            }
            LOG.debug("Passphrase successfully stored");
        } catch (BitwardenClientException | IllegalArgumentException e) {
            throw new KeychainAccessException("Storing the passphrase failed", e);
        }
    }

    @Override
    public char[] loadPassphrase(String vault) throws KeychainAccessException {
        try {
            var secret = Arrays.stream(bitwardenClient.secrets().list(organizationId).getData())
                    .filter(r -> r.getKey().equals(vault))
                    .findFirst();
            if (secret.isEmpty()) {
                LOG.debug("No Passphrase found");
                return null;
            } else {
                LOG.debug("Passphrase loaded");
                return bitwardenClient.secrets().get(secret.get().getID()).getValue().toCharArray();
            }
        } catch (BitwardenClientException | IllegalArgumentException e) {
            throw new KeychainAccessException("Loading the passphrase failed", e);
        }
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
        UUID projectId;
        try {
            var project = Arrays.stream(bitwardenClient.projects().list(organizationId).getData())
                    .filter(r -> r.getName().equals(APP_NAME))
                    .findFirst();
            if (project.isPresent()) {
                projectId = project.get().getID();
            } else {
                projectId = bitwardenClient.projects().create(organizationId, APP_NAME).getID();
            }

            var secret = Arrays.stream(bitwardenClient.secrets().list(organizationId).getData())
                    .filter(r -> r.getKey().equals(vault))
                    .findFirst();
            if (secret.isEmpty()) {
                LOG.debug("Passphrase not found");
            } else {
                LOG.debug("Passphrase found and updated");
                bitwardenClient.secrets().update(secret.get().getID(), vault, password.toString(), "Password for vault: " + name, organizationId, new UUID[]{ projectId });
            }
        } catch (BitwardenClientException | IllegalArgumentException e) {
            throw new KeychainAccessException("Updating the passphrase failed", e);
        }
    }
}
