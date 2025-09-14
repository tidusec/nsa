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
        Account nullptr = new Account();
        nullptr.username = "nullptr";
        nullptr.email = "nullptr@example.com";
        // the password is 'password'
        nullptr.password = "$2a$12$12ch2GaRW20Biug.PZ/LPOm9iUfQoz7KdhfQVxuY0.ZmwpkQL.j1i";
        nullptr.biometricFingerprint = "flagflagflag";
        nullptr.persist();

        Account wheatley = new Account();
        wheatley.username = "wheatley";
        wheatley.email = "wheatley@example.com";
        wheatley.password = "$2a$12$12ch2GaRW20Biug.PZ/LPOm9iUfQoz7KdhfQVxuY0.ZmwpkQL.j1i";
        wheatley.permissionLevel = Byte.MIN_VALUE;
        wheatley.persist();

        Account pchung = new Account();
        pchung.username = "pchung";
        pchung.email = "pchung@example.com";
        pchung.password = "$2a$12$12ch2GaRW20Biug.PZ/LPOm9iUfQoz7KdhfQVxuY0.ZmwpkQL.j1i";
        pchung.persist();

        Account superadmin = new Account();
        superadmin.username = "superadmin";
        superadmin.email = "superadmin@example.com";
        superadmin.password = "$2a$12$12ch2GaRW20Biug.PZ/LPOm9iUfQoz7KdhfQVxuY0.ZmwpkQL.j1i";
        superadmin.permissionLevel = Account.SUPER_ADMIN_PERMISSION_LEVEL;
        superadmin.role = Account.Role.ADMIN;
        superadmin.persist();
    }
}
