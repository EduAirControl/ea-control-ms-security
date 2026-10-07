package com.eduaircontrol.mssecurity.infrastructure.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

/**
 * Detalles de autenticación que incluyen el {@code companyCode} enviado por el
 * formulario de login (ADR-016).
 */
public class CompanyCodeAuthenticationDetails extends WebAuthenticationDetails {

    private final String companyCode;

    public CompanyCodeAuthenticationDetails(HttpServletRequest request) {
        super(request);
        this.companyCode = request.getParameter("companyCode");
    }

    public String getCompanyCode() {
        return companyCode;
    }
}
