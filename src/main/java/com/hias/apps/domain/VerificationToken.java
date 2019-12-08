package com.hias.apps.domain;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;



@Entity
public class VerificationToken {
		@Id
	    @GeneratedValue(strategy = GenerationType.AUTO)
	    @Column(name="token_id")
	    private long tokenid;

	    @Column(name="confirmation_token")
	    private String confirmationToken;

	    @Temporal(TemporalType.TIMESTAMP)
	    private Date createdDate;

	    @OneToOne(targetEntity = User.class, fetch = FetchType.EAGER)
	    @JoinColumn(name = "user_id", referencedColumnName = "id")
	    private Optional<User> user;

	    public VerificationToken() {
			// TODO Auto-generated constructor stub
		}
	    public VerificationToken(Optional<User> user, String tokens) {
	        this.user = user;
	        createdDate = new Date();
	        confirmationToken = tokens;
	    }

		public long getTokenid() {
			return tokenid;
		}

		public void setTokenid(long tokenid) {
			this.tokenid = tokenid;
		}

		public String getConfirmationToken() {
			return confirmationToken;
		}

		public void setConfirmationToken(String confirmationToken) {
			this.confirmationToken = confirmationToken;
		}

		public Date getCreatedDate() {
			return createdDate;
		}

		public void setCreatedDate(Date createdDate) {
			this.createdDate = createdDate;
		}
		public Optional<User> getUser() {
			return user;
		}
		public void setUser(Optional<User> user) {
			this.user = user;
		}	

}
