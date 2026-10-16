package com.eduaircontrol.mssecurity.infrastructure.outbound.mail;

import com.eduaircontrol.mssecurity.application.port.RecoveryCodeMailer;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

/**
 * Envía el código de recuperación por SMTP (Gmail con contraseña de aplicación
 * en producción). Si {@code spring.mail.host} está vacío o no hay
 * {@link JavaMailSender} disponible se registra el código en el log en lugar de
 * enviarlo, para que desarrollo y tests funcionen sin SMTP. Un fallo de envío
 * nunca propaga excepción: el endpoint de forgot-password debe seguir
 * respondiendo 204 (anti-enumeración de cuentas).
 */
@Slf4j
@Component
public class GmailMailAdapter implements RecoveryCodeMailer {

    private final ObjectProvider<JavaMailSender> mailSenderProvider;
    private final String host;
    private final String from;
    private final String username;

    public GmailMailAdapter(ObjectProvider<JavaMailSender> mailSenderProvider,
                            @Value("${spring.mail.host:}") String host,
                            @Value("${app.mail.from:}") String from,
                            @Value("${spring.mail.username:}") String username) {
        this.mailSenderProvider = mailSenderProvider;
        this.host = host;
        this.from = from;
        this.username = username;
    }

    @Override
    public void sendRecoveryCode(String toEmail, String code) {
        JavaMailSender sender = mailSenderProvider.getIfAvailable();
        if (host == null || host.isBlank() || sender == null) {
            log.info("Password reset code for {}: {} (dev only — send by email in production)",
                    toEmail, code);
            return;
        }
        try {
            MimeMessage message = sender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(from.isBlank() ? username : from);
            helper.setTo(toEmail);
            helper.setSubject("Código de recuperación — EduAirControl");
            helper.setText(textBody(code), false);
            helper.setText(htmlBody(code), true);
            sender.send(message);
            log.info("Password reset code sent to {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send password reset code to {}", toEmail, e);
        }
    }

    private String textBody(String code) {
        return """
                Hola,

                Recibimos una solicitud para restablecer tu contraseña en EduAirControl.

                Tu código de recuperación es: %s

                El código caduca en 15 minutos. Si no solicitaste este cambio, puedes\
                 ignorar este correo.

                — Equipo EduAirControl
                """.formatted(code);
    }

    private String htmlBody(String code) {
        return """
                <html><body style="font-family:Arial,Helvetica,sans-serif;background:#f4f6f8;padding:24px;">
                <div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:8px;padding:32px;">
                  <h2 style="color:#1a3c5e;margin-top:0;">EduAirControl</h2>
                  <p>Hola,</p>
                  <p>Recibimos una solicitud para restablecer tu contraseña. Tu código de recuperación es:</p>
                  <p style="text-align:center;font-size:32px;letter-spacing:8px;font-weight:bold;color:#1a3c5e;margin:24px 0;">
                    %s
                  </p>
                  <p>El código caduca en <strong>15 minutos</strong>.</p>
                  <p style="color:#666666;font-size:13px;">Si no solicitaste este cambio, puedes ignorar este correo.</p>
                  <p style="color:#666666;font-size:13px;">— Equipo EduAirControl</p>
                </div>
                </body></html>
                """.formatted(code);
    }
}
