package com.nsa.dto.request;

import com.nsa.entity.Account;

public record AccountDetailDto(
    String firstname,
    String lastname,
    String username,
    String email,
    Account.Role role,
    Byte permissionLevel,
    Account.Clearance clearance,
    String biometricFingerprint
) {
}
