package jbnu.jbnupms.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2LoginRequest {

    @NotBlank(message = "provider는 필수입니다.")
    private String provider; // "GOOGLE" 등

    @NotBlank(message = "accessToken은 필수입니다.")
    private String accessToken; // 프론트에서 받은 OAuth provider의 access token
}