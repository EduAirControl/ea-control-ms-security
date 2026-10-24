package com.eduaircontrol.mssecurity.infrastructure.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.eduaircontrol.mssecurity.application.AuthService;
import com.eduaircontrol.mssecurity.application.SocialAuthService;
import com.eduaircontrol.mssecurity.application.port.SocialCodeStore;
import com.eduaircontrol.mssecurity.application.port.SocialStateStore;
import com.eduaircontrol.mssecurity.domain.exception.ValidationException;
import com.eduaircontrol.mssecurity.domain.model.Institution;
import com.eduaircontrol.mssecurity.domain.model.InstitutionStatus;
import com.eduaircontrol.mssecurity.infrastructure.outbound.persistence.InstitutionJpaRepository;
import com.eduaircontrol.mssecurity.infrastructure.outbound.persistence.UserJpaRepository;
import com.eduaircontrol.mssecurity.infrastructure.security.TestKeys;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest(properties = "app.social.callback-base-url=http://auth.example.com")
@ActiveProfiles("test")
@AutoConfigureMockMvc
class SocialAuthControllerTest {

    static {
        TestKeys.ensureGenerated();
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SocialAuthService socialAuthService;

    @Autowired
    private AuthService authService;

    @Autowired
    private UserJpaRepository userRepository;

    @Autowired
    private InstitutionJpaRepository institutionRepository;

    @MockitoBean
    private SocialCodeStore socialCodeStore;

    @MockitoBean
    private SocialStateStore socialStateStore;

    private final Map<String, UUID> codes = new ConcurrentHashMap<>();
    private final Map<String, String> states = new ConcurrentHashMap<>();

    @BeforeEach
    void setUp() {
        codes.clear();
        states.clear();
        doAnswer(invocation -> {
            codes.put(invocation.getArgument(0), invocation.getArgument(1));
            return null;
        }).when(socialCodeStore).store(anyString(), any());
        doAnswer(invocation -> codes.remove(invocation.getArgument(0)))
                .when(socialCodeStore).consume(anyString());

        doAnswer(invocation -> {
            states.put(invocation.getArgument(0), invocation.getArgument(1));
            return null;
        }).when(socialStateStore).store(anyString(), anyString());
        doAnswer(invocation -> states.remove(invocation.getArgument(0)))
                .when(socialStateStore).consume(anyString());

        if (institutionRepository.findByCode("SEN-4444").isEmpty()) {
            institutionRepository.save(Institution.builder()
                    .code("SEN-4444")
                    .name("SENA")
                    .status(InstitutionStatus.ACTIVE)
                    .build());
        }
    }

    private UUID createSocialUser(String email) {
        return socialAuthService.findOrCreate("google", "sub-" + email, email, true, "Test User", null)
                .user().getId();
    }

    @Test
    void googleAuthRedirectsToProviderWithConfiguredCallback() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/v1/auth/oauth2/google"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String location = result.getResponse().getRedirectedUrl();
        assertThat(location).startsWith("https://accounts.google.com/o/oauth2/v2/auth");
        assertThat(location).contains(
                "redirect_uri=http%3A%2F%2Fauth.example.com%2Fapi%2Fv1%2Fauth%2Foauth2%2Fgoogle%2Fcallback");
        // El flujo incluye un state anti-CSRF.
        assertThat(location).contains("state=");
    }

    /** Un callback sin state valido se rechaza y vuelve al frontend con error. */
    @Test
    void googleCallbackWithoutStateIsRejected() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/v1/auth/oauth2/google/callback")
                        .param("code", "whatever"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl()).contains("error=invalid_state");
    }

    /** Un email NO verificado no puede vincularse a una cuenta existente. */
    @Test
    void unverifiedEmailIsNotLinkedToAnExistingAccount() {
        createSocialUser("existing@example.com");

        assertThatThrownBy(() -> socialAuthService.findOrCreate(
                "facebook", "fb-sub", "existing@example.com", false, "Otro", null))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("verify");
    }

    @Test
    void facebookAuthRedirectsToProviderWithConfiguredCallback() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/v1/auth/oauth2/facebook"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String location = result.getResponse().getRedirectedUrl();
        assertThat(location).startsWith("https://www.facebook.com/");
        assertThat(location).contains("redirect_uri=http%3A%2F%2Fauth.example.com%2Fapi%2Fv1%2Fauth%2Foauth2%2Ffacebook%2Fcallback");
    }

    @Test
    void exchangeReturnsTokensAndConsumesTheCode() throws Exception {
        UUID userId = createSocialUser("social1@example.com");
        codes.put("code-1", userId);

        mockMvc.perform(post("/api/v1/auth/oauth2/social/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"code-1\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.user.id").value(userId.toString()))
                .andExpect(jsonPath("$.needsOnboarding").value(true));

        // El codigo es de un solo uso: el segundo canje falla
        mockMvc.perform(post("/api/v1/auth/oauth2/social/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"code-1\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void exchangeWithUnknownCodeReturnsUnauthorized() throws Exception {
        mockMvc.perform(post("/api/v1/auth/oauth2/social/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"does-not-exist\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void exchangeWithBlankCodeReturnsBadRequest() throws Exception {
        mockMvc.perform(post("/api/v1/auth/oauth2/social/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void onboardingRequiresAuthentication() throws Exception {
        mockMvc.perform(post("/api/v1/auth/oauth2/onboarding")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"companyCode\":\"SEN-4444\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void onboardingAssignsInstitutionByCompanyCode() throws Exception {
        UUID userId = createSocialUser("social2@example.com");
        String token = authService.loginWithUser(userId).accessToken();

        mockMvc.perform(post("/api/v1/auth/oauth2/onboarding")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"companyCode\":\"SEN-4444\"}"))
                .andExpect(status().isNoContent());

        UUID institutionId = institutionRepository.findByCode("SEN-4444").orElseThrow().getId();
        assertThat(userRepository.findById(userId).orElseThrow().getInstitutionId())
                .isEqualTo(institutionId);

        // Con institucion asignada, el canje ya no pide onboarding
        codes.put("code-2", userId);
        mockMvc.perform(post("/api/v1/auth/oauth2/social/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"code-2\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.needsOnboarding").value(false));
    }

    @Test
    void onboardingWithUnknownCompanyCodeReturnsBadRequest() throws Exception {
        UUID userId = createSocialUser("social3@example.com");
        String token = authService.loginWithUser(userId).accessToken();

        mockMvc.perform(post("/api/v1/auth/oauth2/onboarding")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"companyCode\":\"ZZZ-9999\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void onboardingWithMalformedCompanyCodeReturnsBadRequest() throws Exception {
        UUID userId = createSocialUser("social4@example.com");
        String token = authService.loginWithUser(userId).accessToken();

        mockMvc.perform(post("/api/v1/auth/oauth2/onboarding")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"companyCode\":\"nope\"}"))
                .andExpect(status().isBadRequest());
    }
}
