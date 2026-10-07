package com.eduaircontrol.mssecurity.infrastructure.security;

import com.eduaircontrol.mssecurity.application.port.InstitutionRepository;
import com.eduaircontrol.mssecurity.application.port.RoleRepository;
import com.eduaircontrol.mssecurity.application.port.UserRepository;
import com.eduaircontrol.mssecurity.application.port.UserRoleRepository;
import com.eduaircontrol.mssecurity.domain.model.Role;
import com.eduaircontrol.mssecurity.domain.model.User;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

/**
 * Autentica email + contraseña + {@code companyCode} contra la institución del
 * usuario (ADR-016). Usado por el formulario de login del Authorization Server.
 */
@Component
@RequiredArgsConstructor
public class CompanyCodeAuthenticationProvider implements AuthenticationProvider {

    private final UserRepository userRepository;
    private final InstitutionRepository institutionRepository;
    private final UserRoleRepository userRoleRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String email = authentication.getName();
        String password = authentication.getCredentials() == null ? null
                : authentication.getCredentials().toString();
        String companyCode = extractCompanyCode(authentication);

        User user = userRepository.findByEmail(email)
                .filter(User::isActive)
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        if (password == null || !passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new BadCredentialsException("Invalid credentials");
        }
        boolean institutionMatches = companyCode != null && !companyCode.isBlank()
                && institutionRepository.findById(user.getInstitutionId())
                        .map(institution -> institution.getCode().equalsIgnoreCase(companyCode.trim()))
                        .orElse(false);
        if (!institutionMatches) {
            throw new BadCredentialsException("Invalid credentials");
        }

        List<SimpleGrantedAuthority> authorities = rolesOf(user.getId()).stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .toList();
        SecurityUser principal = new SecurityUser(user.getId(), user.getInstitutionId(),
                user.getCampusId(), user.getEmail(), user.getPasswordHash(), authorities);
        UsernamePasswordAuthenticationToken result =
                new UsernamePasswordAuthenticationToken(principal, null, authorities);
        // Normaliza los detalles a WebAuthenticationDetails estándar: el custom no es
        // deserializable por el Jackson de Spring Authorization Server (atributos OAuth2).
        if (authentication.getDetails() instanceof WebAuthenticationDetails details) {
            result.setDetails(new WebAuthenticationDetails(details.getRemoteAddress(), details.getSessionId()));
        }
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private String extractCompanyCode(Authentication authentication) {
        Object details = authentication.getDetails();
        if (details instanceof CompanyCodeAuthenticationDetails companyCodeDetails) {
            return companyCodeDetails.getCompanyCode();
        }
        return null;
    }

    private List<String> rolesOf(UUID userId) {
        return userRoleRepository.findByUserId(userId).stream()
                .map(userRole -> roleRepository.findById(userRole.getRoleId()).map(Role::getName).orElse(null))
                .filter(Objects::nonNull)
                .sorted()
                .toList();
    }
}
