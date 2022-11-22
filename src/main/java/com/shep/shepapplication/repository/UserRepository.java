package com.shep.shepapplication.repository;

import com.shep.shepapplication.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity,Long> {
    UserEntity findFirstByLogin(String login);
    UserEntity findFirstByEmail(String email);
    Optional<UserEntity> findByLogin(String login);
}
