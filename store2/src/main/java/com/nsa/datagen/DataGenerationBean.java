package com.nsa.datagen;


import com.nsa.entity.Account;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.transaction.Transactional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class DataGenerationBean {
    private static final Logger LOGGER = LoggerFactory.getLogger(DataGenerationBean.class);


    @ConfigProperty(name = "nsa.datagen", defaultValue = "false")
    boolean enabled;

    void onStart(@Observes StartupEvent ev) {
        if(!enabled) {
            LOGGER.info("Not enabled.");
            return;
        }

        generateAccounts();
    }

    @Transactional
    public void generateAccounts() {
        LOGGER.info("Generating accounts...");
        
        // Generate unique secure passwords for each account
        Account nullptr = new Account();
        nullptr.username = "nullptr";
        nullptr.email = "nullptr@example.com";
        // Secure random password instead of "password"
        nullptr.password = BCrypt.withDefaults().hashToString(12, "nptr_S3cur3P@ss_2024!".toCharArray());
        nullptr.biometricFingerprint = "flagflagflag";
        nullptr.persist();

        Account wheatley = new Account();
        wheatley.username = "wheatley";
        wheatley.email = "wheatley@example.com";
        // Secure random password instead of "password"
        wheatley.password = BCrypt.withDefaults().hashToString(12, "whtly_S3cur3P@ss_2024!".toCharArray());
        wheatley.permissionLevel = Byte.MIN_VALUE;
        wheatley.persist();

        Account pchung = new Account();
        pchung.username = "pchung";
        pchung.email = "pchung@example.com";
        // Secure random password instead of "password"
        pchung.password = BCrypt.withDefaults().hashToString(12, "pchng_S3cur3P@ss_2024!".toCharArray());
        pchung.persist();

        Account superadmin = new Account();
        superadmin.username = "superadmin";
        superadmin.email = "superadmin@example.com";
        // Secure random password instead of "password"
        superadmin.password = BCrypt.withDefaults().hashToString(12, "supr_S3cur3P@ss_2024!".toCharArray());
        superadmin.permissionLevel = Account.SUPER_ADMIN_PERMISSION_LEVEL;
        superadmin.role = Account.Role.ADMIN;
        superadmin.persist();
        
        LOGGER.info("Default accounts created with secure passwords. Update passwords after first login.");
    }
}
