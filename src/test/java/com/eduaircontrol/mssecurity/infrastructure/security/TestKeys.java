package com.eduaircontrol.mssecurity.infrastructure.security;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 * Genera un par de claves RSA en memoria al cargar la clase y escribe ambos PEM
 * en {@code target/test-keys/}, que es donde apunta {@code application-test.properties}.
 * Ninguna clave se versiona (R-002): el unico par que vivia en el repo era la
 * clave dev comprometida.
 *
 * <p>Las clases de test (unitarias o {@code @SpringBootTest}) deben invocar
 * {@link #ensureGenerated()} en un bloque {@code static} ANTES de construir
 * {@link JwtService} o de arrancar el contexto de Spring.
 */
public final class TestKeys {

    /** Donde application-test.properties apunta para firmar (unit tests). */
    public static final String PRIVATE_KEY_PATH = "target/test-keys/test-private.pem";

    /** Donde application-test.properties apunta para validar (unit tests). */
    public static final String PUBLIC_KEY_PATH = "target/test-keys/test-public.pem";

    static {
        ensureGenerated();
    }

    private TestKeys() {
    }

    /** Idempotente: regenera el par y lo vuelca a disco. */
    public static synchronized void ensureGenerated() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            writePrivateKey((RSAPrivateKey) pair.getPrivate());
            writePublicKey((RSAPublicKey) pair.getPublic());
        } catch (Exception e) {
            throw new ExceptionInInitializerError(
                    new IllegalStateException("No se pudo generar el par de claves de test", e));
        }
    }

    private static void writePrivateKey(RSAPrivateKey key) throws Exception {
        Path file = Path.of(PRIVATE_KEY_PATH);
        Files.createDirectories(file.getParent());
        Files.writeString(file, wrapPem("PRIVATE KEY", key.getEncoded()), StandardCharsets.US_ASCII);
    }

    private static void writePublicKey(RSAPublicKey key) throws Exception {
        Path file = Path.of(PUBLIC_KEY_PATH);
        Files.createDirectories(file.getParent());
        Files.writeString(file, wrapPem("PUBLIC KEY", key.getEncoded()), StandardCharsets.US_ASCII);
    }

    private static String wrapPem(String type, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
    }
}
