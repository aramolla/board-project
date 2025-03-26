//package com.aramolla.jwt.chat.config;
//
//import lombok.RequiredArgsConstructor;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.web.socket.config.annotation.EnableWebSocket;
//import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
//import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
//
//@Configuration
//@EnableWebSocket
//@RequiredArgsConstructor
//public class WebSocketConfig implements WebSocketConfigurer { // 스프링이 시작되면 WebSocketConfig이 사작이 됨
//
//    private final SimpleWebSocketHandler simpleWebSocketHandler;
//
//    @Override // websocket 소스코드를 처리할 websocket 핸들러 등록
//    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
//
//        // "/connect"로 WebSocket 연결 요청이 들어오면, simpleWebSocketHandler핸들러 클래스가 처리
//        registry.addHandler(simpleWebSocketHandler,"/connect")
//            .setAllowedOrigins("http://localhost:3000"); //웹소켓 프로토콜에 대한 cors 예외 처리
//
//
//    }
//}
