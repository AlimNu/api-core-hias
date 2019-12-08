package com.hias.apps.domain;

import java.util.*;

import javax.persistence.*;
import javax.persistence.TemporalType;

import org.hibernate.annotations.Type;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.*;

@SuppressWarnings("serial")
@Entity
@Table(name = "user")
public class User implements UserDetails {

	@GeneratedValue(strategy = GenerationType.AUTO)
	@Id
	@JsonIgnore
	private Long id;

	@Column(name = "fullname", nullable = false)
	@JsonProperty("fullName")
	private String fullname;

	@Column(name = "username", nullable = true, unique = true)
	@JsonProperty("userName")
	private String username;

	@Column(name = "password", nullable = false)
	@JsonIgnore
	private String password;

	@Column(name = "email", nullable = false, unique = true)
	@JsonProperty("email")
	private String email;


	@Column(name = "status", nullable = false)
	@JsonProperty("status")
	private String status;

	@Type(type = "yes_no")
	@Column(name = "isLogin", nullable = false)
	@JsonIgnore
	private boolean isLogin;

	@Temporal(TemporalType.TIMESTAMP)
	@Column(name = "register_date", nullable = false)
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
	@JsonProperty("registerDate")
	private Date registerDate;

	@Column(name = "category_user", nullable = false)
	@JsonProperty("category")
	private String categoryUser;

	@Column(name = "reset_password", nullable = true)
	@JsonIgnore
	private String resetPassword;

	@Type(type = "yes_no")
	@Column(name = "isReset", nullable = true)
	@JsonIgnore
	private boolean isReset;

	@Column(name = "img_profile")
	private String imageProfile;

	@Column(name = "share_url", nullable = true)
	private String shareUrl;

	@OneToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "user_id", nullable = false)
	@JsonIgnore
	private UserRegister userRegister;
	
	@Column(name = "enabled")
    private boolean enabled;

	@ManyToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
	@JoinTable(name = "users_roles", joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"), inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id"))
	@JsonProperty("roles")
	private Collection<Role> roles;

	@OneToOne(mappedBy = "user")
	private Cart cart;



//	@OneToOne
//	@JoinColumn(name = "cart_id")
//	@JsonIgnore
//	private Cart cart;

//	@OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL, mappedBy = "userProperties")
//	private Video userProperties;

	
	public User() {
        super();
        this.enabled=false;
    }


	public Collection<Role> getRoles() {
		return roles;
	}

	public void setRoles(Collection<Role> roles) {
		this.roles = roles;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getFullname() {
		return fullname;
	}

	public void setFullname(String fullname) {
		this.fullname = fullname;
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

	public boolean isLogin() {
		return isLogin;
	}

	public void setLogin(boolean isLogin) {
		this.isLogin = isLogin;
	}

	public UserRegister getUserRegister() {
		return userRegister;
	}

	public void setUserRegister(UserRegister userRegister) {
		this.userRegister = userRegister;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public Date getRegisterDate() {
		return registerDate;
	}

	public void setRegisterDate(Date registerDate) {
		this.registerDate = registerDate;
	}

	public String getCategoryUser() {
		return categoryUser;
	}

	public void setCategoryUser(String categoryUser) {
		this.categoryUser = categoryUser;
	}

	public Cart getCart() {
		return cart;
	}

	public void setCart(Cart cart) {
		this.cart = cart;
	}

	//	public Video getUserProperties() {
//		return userProperties;
//	}
//
//	public void setUserProperties(Video userProperties) {
//		this.userProperties = userProperties;
//	}

	@JsonIgnore
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		// TODO Auto-generated method stub
		HashSet<GrantedAuthority> authorities = new HashSet<GrantedAuthority>(roles.size());
		for (Role role : roles) {
			authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getRoleName()));
		}
		return authorities;
	}

	@Override
	public boolean isAccountNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}


	@Override
	public boolean isAccountNonLocked() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return true;
	}

	public String getResetPassword() {
		return resetPassword;
	}

	public void setResetPassword(String resetPassword) {
		this.resetPassword = resetPassword;
	}

	public boolean isReset() {
		return isReset;
	}

	public void setReset(boolean isReset) {
		this.isReset = isReset;
	}

	public String getImageProfile() {
		return imageProfile;
	}

	public void setImageProfile(String imageProfßile) {
		this.imageProfile = imageProfile;
	}

	public String getShareUrl() {
		return shareUrl;
	}

	public void setShareUrl(String shareUrl) {
		this.shareUrl = shareUrl;
	}


	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	
}
