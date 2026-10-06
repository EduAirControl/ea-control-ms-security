package com.eduaircontrol.mssecurity.infrastructure.inbound.web.dto;

/** Salud según auth-service.yaml: status + db + redis (Redis no usado aún: disconnected). */
public record ServiceHealthResponse(String status, String db, String redis) {

    public static ServiceHealthResponse healthy() {
        return new ServiceHealthResponse("ok", "connected", "disconnected");
    }

    public static ServiceHealthResponse databaseDown() {
        return new ServiceHealthResponse("down", "disconnected", "disconnected");
    }
}
