package com.hias.apps.dto;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonProperty;

public class UserDto {

	 @JsonProperty("userId")
	    private Long userId;
	 @JsonProperty("username")
	    private String username;
	 @JsonProperty("fullname")
	    private String fullname;
	 @JsonProperty("email")
	    private String email;
	 @JsonProperty("status")
	    private String status;
	 @JsonProperty("registerDate")
	    private Date registerDate;
	 @JsonProperty("password")
	    private String password;
	public Long getUserId() {
		return userId;
	}
	public void setUserId(Long userId) {
		this.userId = userId;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getStatus() {
		return status;
	}
	public void setStatus(String status) {
		this.status = status;
	}
	public Date getRegisterDate() {
		return registerDate;
	}
	public void setRegisterDate(Date registerDate) {
		this.registerDate = registerDate;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getFullname() {
		return fullname;
	}
	public void setFullname(String fullname) {
		this.fullname = fullname;
	}
	 
	
}
