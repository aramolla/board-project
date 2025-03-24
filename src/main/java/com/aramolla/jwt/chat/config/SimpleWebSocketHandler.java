package com.aramolla.jwt.chat.config;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.BinaryMessage;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.PongMessage;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

// connect로 웹소켓 연겲요청이 들어왔을대 처리할 클래스
@Component
@Slf4j
public class SimpleWebSocketHandler extends TextWebSocketHandler {

    private final Set<WebSocketSession> sessions = ConcurrentHashMap.newKeySet(); //HashSet은 thread safe하지 않음(연결이 동시에 들어왔을때 안정적으로 세션이 저장되지 않을 수 있음)

    //  연결 후 set자료구조에 사용자 정보 등록
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        sessions.add(session);
        log.info("connected: {}", session.getId());

    }

    // 메세지가 들어왔을때 처리
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        String payload = message.getPayload(); // 페이로드에 실제 메세지가 담겨있음
        log.info("received: {}", payload);
        for (WebSocketSession s : sessions) { // 모든 세션한테 내가 받은 메세지를 보냄
            if(s.isOpen()) { // 현재 받아 줄 수 있으면 보냄
                s.sendMessage(new TextMessage(payload));

            }

        }

    }

    // 연결 끊기면 제외 처리
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
        sessions.remove(session); // 세션 삭제
        log.info("disconnected: {}", session.getId());
    }



}
