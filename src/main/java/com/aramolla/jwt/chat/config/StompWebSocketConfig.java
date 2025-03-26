package com.aramolla.jwt.chat.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

@Configuration
@EnableWebSocketMessageBroker // broker라는 말이 들어가면 stomp임
@RequiredArgsConstructor
public class StompWebSocketConfig implements WebSocketMessageBrokerConfigurer {

    private final StompHandler stompHandler;

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/connect")
            .setAllowedOrigins("http://localhost:3000")
            .withSockJS(); // ws가 아닌 http 엔드포인트를 사용할 수 있게 해주는 SockJS라이브러리를 통하는 요청 허용
    }

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {


        // /publish로 시작하는 url에 메세지가 발행이 되면 @Controller객체의 @MessageMapping메서드로 메세지가 전달(라우팅)
        registry.setApplicationDestinationPrefixes("/publish"); //  /publish/{몇번방} 형태로 메세지가 발행해야함

        registry.enableSimpleBroker("/topic");  //  /topic/{몇번방} 형태로 메세지를 수신해야함
    }

    @Override // 웹소켓 요청(connect, subscribe, diconnect)등의 요청시에는 http 헤더 http메세지를 넣어올 수 있고 이를 interceptors하여 토큰을 검증
    public void configureClientInboundChannel(ChannelRegistration registration) {

        registration.interceptors(stompHandler);
    }


}
