package com.hias.apps.repository;

import org.springframework.data.repository.CrudRepository;

import com.hias.apps.domain.VerificationToken;

public interface VerificationTokenRepository extends CrudRepository<VerificationToken, String> {
	VerificationToken findByConfirmationToken(String confirmationToken);
}
