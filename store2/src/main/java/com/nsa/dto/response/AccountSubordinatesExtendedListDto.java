package com.nsa.dto.response;

import com.nsa.entity.Account;
import io.quarkus.runtime.annotations.RegisterForReflection;

import java.util.Objects;

@RegisterForReflection
public class AccountSubordinatesExtendedListDto extends AccountSubordinatesListDto {
    public final String biometricFingerprint;

    public AccountSubordinatesExtendedListDto(String username, String email, Account.Role role, byte permissionLevel, String biometricFingerprint) {
        super(username, email, role, permissionLevel);
        this.biometricFingerprint = biometricFingerprint;
    }
}
