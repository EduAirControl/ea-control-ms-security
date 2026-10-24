package com.eduaircontrol.mssecurity.application.port;

/**
 * Envío del código de recuperación de contraseña por correo.
 */
public interface RecoveryCodeMailer {

    void sendRecoveryCode(String toEmail, String code);
}
