package com.aramolla.jwt.auth.jwt.response;

import com.aramolla.jwt.global.response.error.ErrorCode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class JwtErrorResponder {
    private final ObjectMapper objectMapper; // 얜 EnableAutoConfiguration 의해 기본적으로 스프링 Bean에 등록되어있음.

    public JwtErrorResponder(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public void sendErrorResponse(
        HttpServletResponse response,
        ErrorCode errorCode
    ) throws IOException {
        response.setCharacterEncoding("utf-8");

        JwtExceptionResponse responseJson = new JwtExceptionResponse(
            HttpStatus.valueOf(HttpServletResponse.SC_UNAUTHORIZED),
            errorCode.getHttpStatus(),
            errorCode.getMessage(),
            LocalDateTime.now().toString()
        );

        String jsonToString = objectMapper.writeValueAsString(responseJson);
        response.getWriter().write(jsonToString);
    }

}
