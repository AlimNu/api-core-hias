package com.hias.apps.repository;

import java.util.List;
import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.hias.apps.domain.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

	@Query(value = "SELECT * FROM user u where u.username = :username", nativeQuery = true)
	public Optional<User> findByUsername(@Param("username") String username);

	@Query("Select count(*) FROM User where username = :username AND password = :password")
	public int findUsernamePassword(@Param("username") String username, @Param("password") String password);

	@Query(value = "SELECT * FROM user u where u.email = :email", nativeQuery = true)
	public Optional<User> findByEmail(@Param("email") String email);

	@Query(value = "SELECT * FROM user u where u.reset_password = :id AND is_reset= 'Y'", nativeQuery = true)
	public Optional<User> findByResetid(@Param("id") String id);

	@Modifying
	@Transactional
	@Query("UPDATE User SET password = :password  WHERE username = :username")
	public void updatePassword(String password, String username);

	@Query(value = "SELECT u.* "
			+ "FROM user u where u.category_user = :status", nativeQuery = true)
	public List<User> findByStatus(@Param("status") String status);

	@Query(value = "SELECT u.* "
			+ "FROM user u where u.id = :id", nativeQuery = true)
	public List<User> findById(@Param("id") String id);


	@Query("Select c from User c where c.fullname like %:fullname%")
	List<User> findByFullName(@Param("fullname") String fullname);
	
	User findByEmailIgnoreCase(String emailId);

}
