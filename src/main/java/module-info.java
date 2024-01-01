module org.purejava.integrations.keychain.bitwarden {
    requires java.desktop;
    requires org.slf4j;
    requires org.cryptomator.integrations.api;
    requires sdk;

    exports org.purejava.integrations.keychain;
}