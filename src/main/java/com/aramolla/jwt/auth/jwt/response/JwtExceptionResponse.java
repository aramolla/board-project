package com.aramolla.jwt.auth.jwt.response;

import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@NoArgsConstructor
public class JwtExceptionResponse {

    private HttpStatus httpStatus; // 상태 메세지
    private int status; // 상태 코드
    private String message; // 상태 메세지
    private String timestamp;

    public JwtExceptionResponse(
        HttpStatus httpStatus,
        int status,
        String message,
        String timestamp
    ) {
        this.httpStatus = httpStatus;
        this.status = status;
        this.message = message;
        this.timestamp = timestamp;
    }

}