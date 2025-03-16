package com.aramolla.jwt.auth.oauth2.service;

import com.aramolla.jwt.auth.oauth2.domain.SocialType;
import com.aramolla.jwt.auth.oauth2.dto.CustomOAuth2User;
import com.aramolla.jwt.auth.oauth2.dto.GoogleUserInfo;
import com.aramolla.jwt.auth.oauth2.dto.NaverUserInfo;
import com.aramolla.jwt.auth.oauth2.dto.OAuth2UserInfo;
import com.aramolla.jwt.member.domain.Member;
import com.aramolla.jwt.member.domain.Role;
import com.aramolla.jwt.member.repository.MemberRepository;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

// 리소스서버에서 데이터를 받아서 각각의 데이터 형식에 맞게 받아주는 전처리 과정
@Slf4j
@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(request); // 이 메서드가 가지는 생성자를 super를 이용해 가져옴
        System.out.printf(oAuth2User.toString()); // 확인을 위함

        // registrationId, url에서 소셜사이트 이름을 가져옴(naver, google)
        String registrationId = request.getClientRegistration().getRegistrationId();
        // registrationId으로 SocialType 저장.
        SocialType socialType = getSocialType(registrationId);
        // SocialType별 oAuth2UserInfo형으로 info객체를 생성
        OAuth2UserInfo oAuth2UserInfo = getOAuth2UserInfo(socialType, oAuth2User.getAttributes());
        //리소스 서버에서 발급 받은 정보로 사용자를 특정할 아이디값을 만듬 - naver dkfk1640@naver.com
        String username = oAuth2UserInfo.getProvider()+" "+oAuth2UserInfo.getProviderId(); // 리소스에서 받은 값은 해당 유저들까리 겹칠 수 있기 떄문에 우리 서버에서 관리할 수 있는 특정한 usename을 만듬, OAuth2 로그인 시 키(PK)가 되는 값

        // repository에 username이 있는지 조회
        Member existMember = memberRepository.findByEmail(username)
            .orElse(null);

        if(existMember == null) { // 첫 로그인인 경우 -> repository에 회원 정보 저장
            Member member = Member.builder()
                .socialType(socialType)
                .name(oAuth2UserInfo.getName())
                .email(username) // naver dkfk1640@naver.com
                .socialLoginId(oAuth2UserInfo.getProviderId())
                .build();

            log.info("새로운 소셜 로그인 회원 생성 {}", member);
            memberRepository.save(member);

            return new CustomOAuth2User(member, oAuth2User.getAttributes());

        } else{ // 로그인 한 적이 있는 경우 -> 유저 정보 업데이트
            existMember.updatename(oAuth2UserInfo.getName());
            existMember.updateUsername(username); // naver dkfk1640@naver.com

            return new CustomOAuth2User(existMember, oAuth2User.getAttributes());
        }


    }

    private SocialType getSocialType(String registrationId) { // registrationId, 이 아이디가 어디에서(구글,네이버) 온 값인지 확인
        try {
            return SocialType.valueOf(registrationId.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("지원하지 않는 소셜 로그인입니다: " + registrationId);
        }
    }

    public static OAuth2UserInfo getOAuth2UserInfo( // 소셜 타입에 맞는 데이터 들고오기
        SocialType socialType,
        Map<String, Object> attributes
    ) {
        switch (socialType) {
            case GOOGLE: return new GoogleUserInfo(attributes);
            case NAVER: return new NaverUserInfo(attributes);
            default: throw new IllegalArgumentException("유효하지 않는 소셜 입니다.");
        }
    }



}
