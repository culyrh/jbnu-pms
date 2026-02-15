package jbnu.jbnupms.domain.user.controller;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import jbnu.jbnupms.common.response.CommonResponse;
import jbnu.jbnupms.domain.user.dto.*;
import jbnu.jbnupms.domain.user.service.AuthService;
import jbnu.jbnupms.domain.user.service.VerificationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.net.URI;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final VerificationService verificationService;

    @Operation(summary = "인증 코드 발송")
    @PostMapping("/verification/send")
    public ResponseEntity<CommonResponse<Void>> sendVerificationCode(
            @Valid @RequestBody SendVerificationRequest request) {
        verificationService.sendVerificationCode(request.getEmail(), request.getType());
        return ResponseEntity.ok(CommonResponse.success(null));
    }

    // 인증 코드 확인 (선택적 - 프론트에서 즉시 피드백용)
    @Operation(summary = "인증 코드 확인")
    @PostMapping("/verification/verify")
    public ResponseEntity<CommonResponse<Void>> verifyCode(
            @Valid @RequestBody VerifyCodeRequest request) {
        verificationService.verifyCode(request.getEmail(), request.getCode(), request.getType());
        return ResponseEntity.ok(CommonResponse.success(null));
    }

    @Operation(summary = "회원가입")
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntity<CommonResponse<Long>> register(@Valid @RequestBody RegisterRequest request) {
        Long userId = authService.register(request);
        return ResponseEntity.created(URI.create("/users/" + userId))
                .body(CommonResponse.success(userId));
    }

    @Operation(summary = "이메일 중복 확인")
    @GetMapping("/check-email")
    public ResponseEntity<CommonResponse<EmailCheckResponse>> checkEmail(@RequestParam String email) {
        return ResponseEntity.ok(CommonResponse.success(authService.checkEmailAvailability(email)));
    }

    @Operation(summary = "로그인")
    @PostMapping("/login")
    public ResponseEntity<CommonResponse<TokenResponse>> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(CommonResponse.success(authService.login(request)));
    }

    @Operation(summary = "액세스 토큰 갱신")
    @PostMapping("/refresh")
    public ResponseEntity<CommonResponse<TokenResponse>> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(CommonResponse.success(authService.refresh(request)));
    }

    @Operation(summary = "로그아웃")
    @PostMapping("/logout")
    public ResponseEntity<CommonResponse<Void>> logout(@AuthenticationPrincipal UserDetails userDetails) {
        Long userId = Long.parseLong(userDetails.getUsername());
        authService.logout(userId);
        return ResponseEntity.ok().build();
    }

    @Operation(summary = "OAuth2 로그인")
    @PostMapping("/oauth2/login")
    public ResponseEntity<CommonResponse<TokenResponse>> oauth2Login(@Valid @RequestBody OAuth2LoginRequest request) {
        return ResponseEntity.ok(CommonResponse.success(authService.oauth2Login(request)));
    }

    @Operation(summary = "비밀번호 재설정")
    @PostMapping("/password/reset")
    public ResponseEntity<CommonResponse<Void>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request);
        return ResponseEntity.ok(CommonResponse.success(null));
    }
}