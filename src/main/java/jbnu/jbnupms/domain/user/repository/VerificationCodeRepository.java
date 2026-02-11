package jbnu.jbnupms.domain.user.repository;

import jbnu.jbnupms.domain.user.entity.VerificationCode;
import jbnu.jbnupms.domain.user.entity.VerificationType;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface VerificationCodeRepository extends CrudRepository<VerificationCode, String> {

    Optional<VerificationCode> findByEmailAndType(String email, VerificationType type);

    void deleteByEmailAndType(String email, VerificationType type);
}