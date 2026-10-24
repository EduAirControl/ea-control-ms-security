package com.eduaircontrol.mssecurity.application.port;

/**
 * Estado anti-CSRF del flujo OAuth2 social (parametro {@code state}).
 *
 * <p>Se genera al iniciar el login (redirect al proveedor) y se valida y consume
 * en el callback. Un {@code state} ausente, desconocido o ya usado se rechaza, lo
 * que corta el login-CSRF: un atacante no puede conocer el {@code state} de la
 * victima, asi que no puede completar el callback por ella.
 */
public interface SocialStateStore {

    void store(String state, String provider);

    /**
     * Devuelve el proveedor asociado al {@code state} y lo consume (single-use).
     * Devuelve {@code null} si el state no existe o ya fue usado.
     */
    String consume(String state);
}
