package com.aramolla.jwt.chat.config;

import com.aramolla.jwt.auth.jwt.token.JwtParser;
import com.aramolla.jwt.auth.jwt.token.JwtProperties;
import io.jsonwebtoken.Claims;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class StompHandler implements ChannelInterceptor {
    // 순수 웹소켓에서는 connect되면 connect session객체 만들고 connect가 끊기면 session객체 지우는 작업을 했는데 STOMP는 알아서 관리가 됨
    // 여기서 해주는 작업은 인증 작업

//    private final SecretKey secretKey;
    private final JwtParser jwtParser;

    public StompHandler(
        JwtProperties jwtProperties,
        JwtParser jwtParser
    ) {
        this.jwtParser = jwtParser;
//        this.secretKey = jwtProperties.getSecretKey();
    }


    @Override
    public Message<?> preSend(Message<?> message, MessageChannel channel) {
        final StompHeaderAccessor accessor = StompHeaderAccessor.wrap(message); //accessor안에서 토큰 꺼내기

        if(StompCommand.CONNECT == accessor.getCommand()) { // connect요청을 항상 먼저하니 여기서만 토큰 검증을 해도 됨
            log.info("Connect 요청시 토큰 유효성 검증");
            String bearerToken = accessor.getFirstNativeHeader("Authorization"); //"Authorization" 헤더에 bearer토큰 넣어 보내기
            String token = bearerToken.substring(7);

            // 토큰 검증 및 claims추출
            Claims claims = jwtParser.parseToken(token).getPayload(); //.sub이라는 변수로 할당되어 프론트에 전달되니 프론트에서 전역 로컬스토리지에 세팅
            log.info("토큰 검증 및 Claim추출");
        }

        return message;
    }


}
