package io.nats.authcalloutbcfips;

import io.nats.authcallout.AuthCalloutServiceExample;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import java.security.Provider;
import java.security.Security;

import static org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider.PROVIDER_NAME;

public class AuthCalloutServiceBcFipsExample {
    public static void main(String[] args) throws Exception {
        setupBcFips();

        // Normally set via JVM argument:
        // -Dio.nats.nkey.security.provider=BCFIPS
        System.setProperty("io.nats.nkey.security.provider", PROVIDER_NAME);
        // or
        // -Dio.nats.nkey.security.provider
        // System.setProperty("io.nats.nkey.security.provider", "");
        // if BCFIPS is configured as the default provider

        AuthCalloutServiceExample.main(args);
    }

    private static void setupBcFips() {
        // For test purposes. This is not a BCFIPS guide.
        if (Security.getProvider(PROVIDER_NAME) != null) {
            return;
        }
        Security.setProperty("ssl.KeyManagerFactory.algorithm", "PKIX");
        Security.setProperty("ssl.TrustManagerFactory.algorithm", "PKIX");
        Security.setProperty("org.bouncycastle.fips.approved_only", "true");

        for (Provider otherProvider : Security.getProviders()) {
            String providerName = otherProvider.getName();
            if (!"SUN".equals(providerName)) {
                Security.removeProvider(providerName);
            }
        }

        Security.insertProviderAt(new BouncyCastleFipsProvider("C:DEFRND[SHA256];ENABLE{ALL};"), 1);
    }
}
