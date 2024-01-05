package org.purejava.integrations.keychain;

import com.bitwarden.sdk.BitwardenClient;
import com.bitwarden.sdk.BitwardenClientException;
import com.bitwarden.sdk.BitwardenSettings;
import com.bitwarden.sdk.schema.SecretIdentifierResponse;
import org.cryptomator.integrations.keychain.KeychainAccessException;
import org.cryptomator.integrations.keychain.KeychainAccessProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

public class BitwardenAccess implements KeychainAccessProvider {

    private static final Logger LOG = LoggerFactory.getLogger(BitwardenAccess.class);

    private final BitwardenSettings bitwardenSettings = new BitwardenSettings();
    private final BitwardenClient bitwardenClient;
    private final String accessToken;
    private final UUID organizationId;
    private final String apiUrl = "https://api.bitwarden.com";
    private final String identityUrl = "https://identity.bitwarden.com";
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
        try {
            var projectId = getprojectId();
            var secret = getSecret(vault);
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
            var secret = getSecret(vault);
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
        try {
            var secret = getSecret(vault);
            if (secret.isEmpty()) {
                LOG.debug("Passphrase not found");
            } else {
                LOG.debug("Passphrase found and deleted");
                bitwardenClient.secrets().delete(new UUID[]{ secret.get().getID() });
            }
        } catch (BitwardenClientException | IllegalArgumentException e) {
            throw new KeychainAccessException("Deleting the passphrase failed", e);
        }
    }

    @Override
    public void changePassphrase(String vault, CharSequence password) throws KeychainAccessException {
        changePassphrase(vault, "Vault", password);
    }

    @Override
    public void changePassphrase(String vault, String name, CharSequence password) throws KeychainAccessException {
        try {
            var projectId = getprojectId();
            var secret = getSecret(vault);
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

    /**
     * Lookup projectId or generate a new project, in case none with the given name exists.
     * @return The projectId of the project.
     */
    private UUID getprojectId() throws BitwardenClientException {
        var project = Arrays.stream(bitwardenClient.projects().list(organizationId).getData())
                .filter(r -> r.getName().equals(APP_NAME))
                .findFirst();
        if (project.isPresent()) {
            return project.get().getID();
        } else {
            return bitwardenClient.projects().create(organizationId, APP_NAME).getID();
        }
    }

    /**
     * Find a secret for the given key (vault).
     * @param vault The identifier for the secret we are looking for.
     * @return      An Optional containing the secret or an empty Optional, in case, no secret was found.
     * @throws BitwardenClientException Communication with the Bitwarden back end failed due to technical reasons.
     */
    private Optional<SecretIdentifierResponse> getSecret(String vault) throws BitwardenClientException {
        return Arrays.stream(bitwardenClient.secrets().list(organizationId).getData())
                .filter(r -> r.getKey().equals(vault))
                .findFirst();
    }
}
