package com.eduaircontrol.mssecurity.application.port;

import java.util.UUID;

/**
 * Códigos sociales de un solo uso (login Google/Facebook). El callback del
 * proveedor deja aquí un código que el frontend intercambia por tokens; al
 * consumirse se elimina, de modo que un código solo puede canjearse una vez.
 */
public interface SocialCodeStore {

    void store(String code, UUID userId);

    /**
     * Devuelve el userId asociado al código y lo consume (single-use).
     * Devuelve {@code null} si el código no existe o ya fue usado.
     */
    UUID consume(String code);
}
