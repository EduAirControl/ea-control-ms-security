package com.eduaircontrol.mssecurity.infrastructure.outbound.mail;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;

import static org.assertj.core.api.Assertions.assertThat;

class GmailMailAdapterTest {

    @SuppressWarnings("unchecked")
    private static ObjectProvider<JavaMailSender> providerOf(JavaMailSender sender) {
        ObjectProvider<JavaMailSender> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(sender);
        return provider;
    }

    private static MimeMessage realMimeMessage() {
        return new MimeMessage(Session.getInstance(new Properties()));
    }

    @Test
    void logsCodeWhenSmtpHostIsBlank() {
        JavaMailSender sender = mock(JavaMailSender.class);
        GmailMailAdapter adapter = new GmailMailAdapter(providerOf(sender), "", "", "from@example.com");

        adapter.sendRecoveryCode("user@example.com", "123456");

        verify(sender, never()).send(any(MimeMessage.class));
    }

    @Test
    void logsCodeWhenMailSenderIsMissing() {
        @SuppressWarnings("unchecked")
        ObjectProvider<JavaMailSender> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        GmailMailAdapter adapter = new GmailMailAdapter(provider, "smtp.gmail.com", "", "from@example.com");

        adapter.sendRecoveryCode("user@example.com", "123456");

        assertThatCode(() -> adapter.sendRecoveryCode("user@example.com", "123456"))
                .doesNotThrowAnyException();
    }

    @Test
    void sendsMailWhenSmtpHostIsConfigured() throws Exception {
        JavaMailSender sender = mock(JavaMailSender.class);
        MimeMessage message = realMimeMessage();
        when(sender.createMimeMessage()).thenReturn(message);
        GmailMailAdapter adapter = new GmailMailAdapter(providerOf(sender), "smtp.gmail.com",
                "from@example.com", "from@example.com");

        adapter.sendRecoveryCode("user@example.com", "654321");

        ArgumentCaptor<MimeMessage> captor = ArgumentCaptor.forClass(MimeMessage.class);
        verify(sender).send(captor.capture());
        MimeMessage sent = captor.getValue();
        assertThat(sent.getSubject()).isEqualTo("Código de recuperación — EduAirControl");
        assertThat(sent.getAllRecipients()[0].toString()).contains("user@example.com");
        assertThat(collectContent(sent)).contains("654321");
    }

    private static String collectContent(jakarta.mail.Part part) throws Exception {
        Object content = part.getContent();
        if (content instanceof jakarta.mail.Multipart multipart) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < multipart.getCount(); i++) {
                sb.append(collectContent(multipart.getBodyPart(i)));
            }
            return sb.toString();
        }
        return String.valueOf(content);
    }

    @Test
    void neverThrowsWhenSendFails() {
        JavaMailSender sender = mock(JavaMailSender.class);
        when(sender.createMimeMessage()).thenReturn(realMimeMessage());
        org.mockito.Mockito.doThrow(new MailSendException("smtp down"))
                .when(sender).send(any(MimeMessage.class));
        GmailMailAdapter adapter = new GmailMailAdapter(providerOf(sender), "smtp.gmail.com",
                "from@example.com", "from@example.com");

        assertThatCode(() -> adapter.sendRecoveryCode("user@example.com", "123456"))
                .doesNotThrowAnyException();
    }
}
