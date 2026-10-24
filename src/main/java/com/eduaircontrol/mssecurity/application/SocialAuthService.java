package com.eduaircontrol.mssecurity.application;

import com.eduaircontrol.mssecurity.domain.model.User;
import com.eduaircontrol.mssecurity.domain.model.UserIdentity;
import com.eduaircontrol.mssecurity.application.port.InstitutionRepository;
import com.eduaircontrol.mssecurity.application.port.UserIdentityRepository;
import com.eduaircontrol.mssecurity.application.port.UserRepository;
import com.eduaircontrol.mssecurity.application.port.UserRoleRepository;
import com.eduaircontrol.mssecurity.application.port.RoleRepository;
import com.eduaircontrol.mssecurity.domain.exception.NotFoundException;
import com.eduaircontrol.mssecurity.domain.exception.ValidationException;
import java.time.Instant;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Login social (Google, Facebook). Auto-provisiona usuarios nuevos y vincula
 * cuentas existentes por email.
 */
@Service
@RequiredArgsConstructor
public class SocialAuthService {

    private final UserIdentityRepository userIdentityRepository;
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final RoleRepository roleRepository;
    private final InstitutionRepository institutionRepository;

    /**
     * Busca o crea el usuario a partir de los datos del proveedor social.
     * Si el usuario ya existe por email, lo vincula <b>solo si el proveedor
     * verifico el email</b>. Si no, lo crea sin contraseña (se asigna
     * institutionId despues del onboarding).
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public SocialResult findOrCreate(String provider, String providerUserId, String email,
                                     boolean emailVerified, String displayName, String avatarUrl) {
        if (email == null || email.isBlank()) {
            throw new ValidationException("The social provider did not return an email");
        }

        // 1. Buscar vinculo existente por provider + providerUserId
        var existingLink = userIdentityRepository.findByProviderAndProviderUserId(provider, providerUserId);
        if (existingLink.isPresent()) {
            User user = userRepository.findById(existingLink.get().getUserId())
                    .orElseThrow(() -> new NotFoundException("Linked user not found"));
            return new SocialResult(user, existingLink.get(), true);
        }

        // 2. Buscar usuario por email (cuenta existente). Solo se vincula si el
        // proveedor declara el email verificado; si no, se rechaza el login social
        // (evita tomar una cuenta existente con un email sin confirmar).
        var existingUser = userRepository.findByEmail(email);
        if (existingUser.isPresent()) {
            if (!emailVerified) {
                throw new ValidationException(
                        "The provider did not verify this email; cannot link to an existing account");
            }
            User user = existingUser.get();
            // No guardar el usuario, solo el vinculo
            UserIdentity identity = new UserIdentity(user.getId(), provider, providerUserId,
                    email, displayName, avatarUrl);
            userIdentityRepository.save(identity);
            return new SocialResult(user, identity, true);
        }

        // 3. Crear usuario nuevo (sin contraseña, sin institucion).
        // El ID lo genera la base: preasignarlo con save() hace merge de una fila
        // inexistente y falla. La unicidad la garantizan uq_users_email/username
        // y el catch de abajo (race condition).
        User user = new User();
        user.setEmail(email.toLowerCase().trim());
        user.setUsername(email.split("@")[0] + "_" + provider);
        user.setPasswordHash(null);
        user.setEmailVerified(emailVerified);
        user.setFailedAttempts(0);
        user.setInstitutionId(null);
        user.setCreatedAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        User saved;
        try {
            saved = userRepository.save(user);
        } catch (RuntimeException e) {
            // Usuario ya existe (race condition), reintentar lookup
            final String normalizedEmail = email.toLowerCase().trim();
            saved = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> e);
            UserIdentity existingIdentity = userIdentityRepository
                    .findByUserIdAndProvider(saved.getId(), provider).orElse(null);
            return new SocialResult(saved, existingIdentity, true);
        }

        final User savedUser = saved;
        // Asignar rol USER por defecto
        roleRepository.findByName("USER").ifPresent(role -> {
            com.eduaircontrol.mssecurity.domain.model.UserRole ur =
                    new com.eduaircontrol.mssecurity.domain.model.UserRole(
                            savedUser.getId(), role.getId(), Instant.now());
            userRoleRepository.save(ur);
        });

        UserIdentity identity = new UserIdentity(savedUser.getId(), provider, providerUserId,
                email, displayName, avatarUrl);
        userIdentityRepository.save(identity);

        return new SocialResult(savedUser, identity, false);
    }

    /**
     * Asigna la institucion al usuario social despues del onboarding, a partir
     * del companyCode (mismo formato que el registro: ABC-0000).
     */
    public void assignInstitution(UUID userId, String companyCode) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("User not found: " + userId));
        if (companyCode == null || companyCode.isBlank()) {
            throw new ValidationException("companyCode must not be blank");
        }
        var institution = institutionRepository.findByCode(companyCode.trim().toUpperCase())
                .orElseThrow(() -> new ValidationException("Unknown institution: " + companyCode));
        user.setInstitutionId(institution.getId());
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);
    }

    public record SocialResult(User user, UserIdentity identity, boolean existing) {
    }
}
