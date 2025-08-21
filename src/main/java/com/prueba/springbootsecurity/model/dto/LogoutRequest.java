package com.prueba.springbootsecurity.model.dto;

import jakarta.validation.constraints.NotBlank;

public record LogoutRequest(
        @NotBlank(message = "refreshToken es requerido")
        String refreshToken
){

}