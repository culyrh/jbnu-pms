package jbnu.jbnupms.domain.user.controller;

import jakarta.validation.Valid;
import jbnu.jbnupms.common.response.CommonResponse;
import jbnu.jbnupms.domain.user.dto.*;
import jbnu.jbnupms.domain.user.service.AuthService;
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

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntity<CommonResponse<Long>> register(@Valid @RequestBody RegisterRequest request) {
        Long userId = authService.register(request);
        return ResponseEntity.created(URI.create("/users/" + userId)).body(CommonResponse.success(userId));
    }

    // 이메일 중복 확인
    @GetMapping("/check-email")
    public ResponseEntity<CommonResponse<EmailCheckResponse>> checkEmail(@RequestParam String email) {
        return ResponseEntity.ok(CommonResponse.success(authService.checkEmailAvailability(email)));
    }

    @PostMapping("/login")
    public ResponseEntity<CommonResponse<TokenResponse>> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(CommonResponse.success(authService.login(request)));
    }

    @PostMapping("/refresh")
    public ResponseEntity<CommonResponse<TokenResponse>> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(CommonResponse.success(authService.refresh(request)));
    }

    @PostMapping("/logout")
    public ResponseEntity<CommonResponse<Void>> logout(@AuthenticationPrincipal UserDetails userDetails) {
        Long userId = Long.parseLong(userDetails.getUsername());
        authService.logout(userId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/oauth2/login")
    public ResponseEntity<CommonResponse<TokenResponse>> oauth2Login(@Valid @RequestBody OAuth2LoginRequest request) {
        return ResponseEntity.ok(CommonResponse.success(authService.oauth2Login(request)));
    }
}