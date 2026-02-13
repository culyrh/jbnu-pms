package jbnu.jbnupms.security.oauth;

import jbnu.jbnupms.common.exception.CustomException;
import jbnu.jbnupms.common.exception.ErrorCode;
import jbnu.jbnupms.security.oauth.config.OAuth2Properties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.net.SocketTimeoutException;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2UserInfoService {

    private final RestTemplate oauth2RestTemplate;  // Bean으로 주입받음
    private final OAuth2Properties oauth2Properties;

    /**
     * OAuth provider로부터 사용자 정보 가져오기
     * - 상세한 에러 처리 (401, 403, 5xx, 네트워크 오류 구분)
     * - Provider 설정 외부화
     */
    public Map<String, Object> getUserInfo(String provider, String accessToken) {
        String userInfoUri = getUserInfoUri(provider);

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<Map> response = oauth2RestTemplate.exchange(
                    userInfoUri,
                    HttpMethod.GET,
                    entity,
                    Map.class
            );

            log.info("Successfully retrieved user info from provider: {}", provider);
            return response.getBody();

        } catch (HttpClientErrorException e) {
            // 4xx 에러 상세 처리
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                log.error("OAuth token is invalid or expired for provider: {}", provider);
                throw new CustomException(
                        ErrorCode.INVALID_TOKEN,
                        "OAuth 토큰이 유효하지 않거나 만료되었습니다.");
            } else if (e.getStatusCode() == HttpStatus.FORBIDDEN) {
                log.error("OAuth token does not have required scopes for provider: {}", provider);
                throw new CustomException(
                        ErrorCode.FORBIDDEN,
                        "OAuth 토큰에 필요한 권한이 없습니다.");
            } else {
                log.error("OAuth provider client error: status={}, provider={}", e.getStatusCode(), provider);
                throw new CustomException(
                        ErrorCode.BAD_REQUEST,
                        "OAuth provider로부터 잘못된 요청 응답을 받았습니다.");
            }

        } catch (HttpServerErrorException e) {
            // 5xx 에러 처리
            log.error("OAuth provider server error: status={}, provider={}", e.getStatusCode(), provider);
            throw new CustomException(
                    ErrorCode.INTERNAL_SERVER_ERROR,
                    "OAuth provider 서버에 일시적인 문제가 발생했습니다. 잠시 후 다시 시도해주세요.");

        } catch (ResourceAccessException e) {
            // 네트워크 오류 처리 (타임아웃, 연결 오류)
            if (e.getCause() instanceof SocketTimeoutException) {
                log.error("OAuth provider request timeout for provider: {}", provider);
                throw new CustomException(
                        ErrorCode.INTERNAL_SERVER_ERROR,
                        "OAuth provider 서버 응답 시간이 초과되었습니다. 잠시 후 다시 시도해주세요.");
            } else {
                log.error("OAuth provider connection error for provider: {}", provider, e);
                throw new CustomException(
                        ErrorCode.INTERNAL_SERVER_ERROR,
                        "OAuth provider 서버에 연결할 수 없습니다. 잠시 후 다시 시도해주세요.");
            }

        } catch (Exception e) {
            // 기타 예외
            log.error("Unexpected error while fetching OAuth user info from provider: {}", provider, e);
            throw new CustomException(
                    ErrorCode.INTERNAL_SERVER_ERROR,
                    "OAuth 로그인 처리 중 오류가 발생했습니다.");
        }
    }

    /**
     * Provider 설정 외부화
     */
    private String getUserInfoUri(String provider) {
        OAuth2Properties.ProviderConfig providerConfig = oauth2Properties.getProvider(provider);

        if (providerConfig == null || providerConfig.getUserInfoUri() == null) {
            log.error("Unsupported OAuth provider or missing configuration: {}", provider);
            throw new CustomException(ErrorCode.OAUTH2_PROVIDER_NOT_SUPPORTED,
                    "지원하지 않는 OAuth provider입니다: " + provider);
        }

        return providerConfig.getUserInfoUri();
    }
}