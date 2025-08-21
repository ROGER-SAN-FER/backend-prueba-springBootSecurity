package com.prueba.springbootsecurity.features.auth.model.dto;

import jakarta.validation.constraints.NotBlank;

public record LogoutRequest(
        @NotBlank(message = "refreshToken es requerido")
        String refreshToken
){

}