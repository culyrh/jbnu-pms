package jbnu.jbnupms.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jbnu.jbnupms.common.exception.ErrorCode;
import jbnu.jbnupms.common.exception.ErrorResponse;
import jbnu.jbnupms.common.exception.CustomException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

        private final ObjectMapper objectMapper;

        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

                CustomException exception = (CustomException) request.getAttribute("exception");
                ErrorCode errorCode = exception != null ? exception.getErrorCode() : ErrorCode.UNAUTHORIZED;

                log.error("Unauthorized error: {}", errorCode.getMessage());

                ErrorResponse errorResponse = ErrorResponse.builder()
                                .timestamp(LocalDateTime.now())
                                .status(errorCode.getHttpStatus().value())
                                .code(errorCode.name())
                                .message(errorCode.getMessage())
                                .build();

                response.setStatus(errorCode.getHttpStatus().value());
                response.setContentType("application/json;charset=UTF-8");
                response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        }
}
