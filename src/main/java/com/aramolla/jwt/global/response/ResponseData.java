package com.aramolla.jwt.global.response;

import com.aramolla.jwt.global.response.error.ErrorCode;
import com.aramolla.jwt.global.response.success.SuccessCode;
import com.aramolla.jwt.util.TimeConverter;
import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import org.springframework.http.ResponseEntity;

@Getter
@Builder
@ToString
public class ResponseData<T> {

    private final int status;
    private final String message;
    private final SuccessCode successCode;
    private final ErrorCode errorCode;
    private final String timestamp;
    private T data;

    //  <=============== SUCCESS(DATA X) ===============>
    public static ResponseEntity<ResponseData> success(SuccessCode successCode) {
        return ResponseEntity
            .status(successCode.getHttpStatus())
            .body(ResponseData.builder()
                .status(successCode.getHttpStatus())
                .message(successCode.getMessage())
                .successCode(successCode)
                .timestamp(TimeConverter.DatetimeToString(LocalDateTime.now()))
                .build()
            );
    }


    //  <=============== SUCCESS(DATA O) ===============>
    public static <T> ResponseEntity<ResponseData<T>> success(
        SuccessCode successCode,
        T data
    ) {
        return ResponseEntity
            .status(successCode.getHttpStatus())
            .body(ResponseData.<T>builder()
                .status(successCode.getHttpStatus())
                .message(successCode.getMessage())
                .successCode(successCode)
                .data(data)
                .timestamp(TimeConverter.DatetimeToString(LocalDateTime.now()))
                .build()
            );
    }
    // <=============== ERROR(DATA X) ===============>
    public static ResponseEntity<ResponseData> error(ErrorCode errorCode) {
        return ResponseEntity
            .status(errorCode.getHttpStatus())
            .body(ResponseData.builder()
                .status(errorCode.getHttpStatus())
                .message(errorCode.getMessage())
                .errorCode(errorCode)
                .timestamp(TimeConverter.DatetimeToString(LocalDateTime.now()))
                .build()
            );
    }
    // <=============== ERROR(DATA O) ===============>
    public static <T> ResponseEntity<ResponseData<T>> error(
        ErrorCode errorCode,
        T data
    ) {
        return ResponseEntity
            .status(errorCode.getHttpStatus())
            .body(ResponseData.<T>builder()
                .status(errorCode.getHttpStatus())
                .message(errorCode.getMessage())
                .errorCode(errorCode)
                .data(data)
                .timestamp(TimeConverter.DatetimeToString(LocalDateTime.now()))
                .build()
            );
    }

}