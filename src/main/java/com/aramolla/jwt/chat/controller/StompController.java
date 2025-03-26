package com.aramolla.jwt.chat.controller;

import com.aramolla.jwt.chat.dto.ChatMessageReqDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.handler.annotation.DestinationVariable;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.simp.SimpMessageSendingOperations;
import org.springframework.stereotype.Controller;

@Controller
@Slf4j
@RequiredArgsConstructor
public class StompController {
    private final SimpMessageSendingOperations messagTemplate; // 토픽에 메세지를 전달하기 위한 목적의 객체

    // 아래 코드 덩어리 자체가 브로커의 역할을 함, 메세지를 받고 어디에서 온 메세지인지 확인하고 해당 room에 메세지를 보
    @MessageMapping("/{roomId}") // 클라이언트에서 특정 /publish/roomId 형태로 메시지를 발행시 MessageMapping이 수신
    public void sendMessage(@DestinationVariable Long roomId, ChatMessageReqDto chatMessageReqDto) {
        log.info(chatMessageReqDto.getMessage());
        messagTemplate.convertAndSend("/topic/" + roomId, chatMessageReqDto ); // @SendTo("/topic/{roomId}")를 대신 함

    }

}
