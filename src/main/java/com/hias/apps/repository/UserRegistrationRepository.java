package com.hias.apps.repository;

import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.hias.apps.domain.UserRegister;

@Repository
public interface UserRegistrationRepository extends JpaRepository<UserRegister, Long> {

	 @Query(
			 value = "SELECT * FROM user_registration ur where ur.username = :username AND ur.token = :token", 
		        nativeQuery=true
	)
	public Optional<UserRegister> findUserByUsernameToken(@Param("username") String username, @Param("token") String token);
	
	@Modifying
	@Transactional
	@Query("UPDATE UserRegister SET isConfirm = true  WHERE username = :username")
	public void updateIsConfirmByUsername(@Param("username") String username); 
	
	@Query("Select count(*) FROM UserRegister where username = :username AND email = :email")
	public int countUserExist(@Param("username") String username, @Param("email")String email);
	
	@Query(
			 value = "SELECT * FROM user_registration ur where ur.email = :email AND ur.is_confirm='N'", 
		        nativeQuery=true
	)
	public Optional<UserRegister> findUserRegisterByEmail(@Param("email") String email);
	
	@Modifying
	@Transactional
	@Query("UPDATE UserRegister SET token = :uuid  WHERE email = :email AND isConfirm='N'")
	public void updateUUID(@Param("email") String email, @Param("uuid") String uuid);
}
