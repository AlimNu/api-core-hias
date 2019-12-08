package com.hias.apps.controller;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.validation.Valid;

import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.validation.BindingResult;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.ModelAndView;

import com.hias.apps.domain.Role;
import com.hias.apps.domain.User;
import com.hias.apps.domain.UserProfile;
import com.hias.apps.domain.UserRegister;
import com.hias.apps.domain.VerificationToken;
import com.hias.apps.dto.RegisterDto;
import com.hias.apps.dto.UserDto;
import com.hias.apps.repository.UserRepository;
import com.hias.apps.repository.VerificationTokenRepository;
import com.hias.apps.security.JwtTokenProvider;
import com.hias.apps.service.EmailSenderService;
import com.hias.apps.service.RoleService;
import com.hias.apps.service.UserRegisterService;
import com.hias.apps.service.UsersService;
import com.hias.apps.util.ErrorResponse;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;

@RestController
@CrossOrigin
@RequestMapping("/register")
@Api(value = "/register", description = "Registration New Member", produces = "application/json")
public class UserRegistrationController {

	@Autowired
	private UserRegisterService registerService;

	@Autowired
	private RoleService roleService;

	@Autowired
	private UsersService userService;

	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	/**Constants*/
	public static final String USER_TYPE_FREE = "member";
	public static final String STATUS_USER_REGISTER = "active";

	@SuppressWarnings("unchecked")
	@ApiOperation(value = "Registration New Member", response = RegisterDto.class)
	@ApiResponses(value = {
			@ApiResponse(code = 200, message = "Register Success", response = RegisterDto.class),
			@ApiResponse(code = 500, message = "Register Failed"),
			@ApiResponse(code = 404, message = "Register Not Found") })
	@PostMapping
	public ResponseEntity<?> registerAction(@RequestBody RegisterDto request){
		JSONObject response = new JSONObject();
		String[] genderArr = new String[] {"male", "female","nonbiner"};
//		if (!Arrays.asList(genderArr).contains(request.getGender())) {
//			response.put("data", null);
//			response.put("success", false);
//			response.put("error", new ErrorResponse("Invalid Gender", 400));
//			return new ResponseEntity<>(response, HttpStatus.OK);
//		}

		UserRegister userRegister = registerService.convertObject(request);
//		String usernameBase64  = null;
		String uuid = null;
		if(userRegister != null) {
			String password = registerService.hashingPassword(userRegister.getPassword());
//			usernameBase64 = registerService.convertUsername(userRegister.getUsername());
			uuid = UUID.randomUUID().toString();
			userRegister.setPassword(password);
			userRegister.setConfirm(false);
			userRegister.setToken(uuid);

			userRegister.setExpiredToken(registerService.createExpired());
		}
		int userExist = registerService.checkUserExist(userRegister.getUsername(), userRegister.getEmail());
		if(userExist == 0) {
			try {
				registerService.insertUserRegistration(userRegister);
				try {
					insertUser(userRegister.getUsername(), userRegister.getToken());

					Optional<User> user = userService.findByUsername(userRegister.getUsername());
					UserProfile userProfile = null;
					Map<String, Object> mapData = new HashMap<>();
					if(user.isPresent()) {
						List<String> listRole = new ArrayList<String>();
						listRole.add("MEMBER");
						String tokens = jwtTokenProvider.createToken(userRegister.getUsername(), listRole);
						userProfile = registerService.convertObjectUserProofile(user.get());
						mapData.put("user", userProfile);
						mapData.put("type", "Bearer");
						mapData.put("token", tokens);
					}
					Map<String, Object> mapResponse = new HashMap<>();
					mapResponse.put("register", mapData);
					response.put("data", mapResponse);
					response.put("success", true);
					response.put("error", null);
				} catch (Exception e) {
					response.put("data", null);
					response.put("success", false);
					response.put("error", new ErrorResponse(e.getMessage().toString(), 500));
				}
			}catch (Exception e) {
				response.put("data", null);
				response.put("success", false);
				response.put("error", new ErrorResponse(e.getMessage().toString(), 500));
			}
		}else {
			response.put("data", null);
			response.put("success", false);
			response.put("error", new ErrorResponse("Username Or Email already exist", 500));
		}
		return new ResponseEntity<JSONObject>(response, HttpStatus.OK);
	}
	private void insertUser(String username,String token) {
		List<Role> listRole = new ArrayList<Role>();
		UserRegister userRegister = registerService.getUserByUsernameToken(username,token);
		registerService.updateIsConfirm(username);
		Role roleId = roleService.getSelectedRoleByName(USER_TYPE_FREE);
		listRole.add(roleId);
		User user = registerService.convertRegisterToUser(userRegister);
		user.setRoles(listRole);
		user.setUserRegister(userRegister);
		user.setStatus(STATUS_USER_REGISTER);
		user.setCategoryUser(USER_TYPE_FREE);
//		userRegister.setConfirm("N");
		user.setRegisterDate(new Date());
		user.setImageProfile("https://s3-ap-southeast-1.amazonaws.com/circledoo/28825-200.png");
		userService.insertUser(user);
	}

	
	//  new Registration Service
	@Autowired
    private UserRepository userRepository;

    @Autowired
    private VerificationTokenRepository confirmationTokenRepository;

    @Autowired
    private EmailSenderService emailSenderService;

    @RequestMapping(value="/register", method = RequestMethod.GET)
    public ModelAndView displayRegistration(ModelAndView modelAndView, User user)
    {
        modelAndView.addObject("user", user);
        modelAndView.setViewName("register");
        return modelAndView;
    }

    @RequestMapping(value="/register", method = RequestMethod.POST)
    public ModelAndView registerUser(ModelAndView modelAndView, User user)
    {

        User existingUser = userRepository.findByEmailIgnoreCase(user.getEmail());
        if(existingUser != null)
        {
            modelAndView.addObject("message","This email already exists!");
            modelAndView.setViewName("error");
        }
        else
        {
            userRepository.save(user);

            VerificationToken confirmationToken = new VerificationToken(user);

            confirmationTokenRepository.save(confirmationToken);

            SimpleMailMessage mailMessage = new SimpleMailMessage();
            mailMessage.setTo(user.getEmail());
            mailMessage.setSubject("Complete Registration!");
            mailMessage.setFrom("xxx@gmail.com");
            mailMessage.setText("To confirm your account, please click here : "
            +"http://localhost:8085/confirm-account?token="+confirmationToken.getConfirmationToken());

            emailSenderService.sendEmail(mailMessage);

            modelAndView.addObject("emailId", user.getEmail());

            modelAndView.setViewName("successfulRegisteration");
        }

        return modelAndView;
    }

    @RequestMapping(value="/confirm-account", method= {RequestMethod.GET, RequestMethod.POST})
    public ModelAndView confirmUserAccount(ModelAndView modelAndView, @RequestParam("token")String confirmationToken)
    {
    	VerificationToken token = confirmationTokenRepository.findByConfirmationToken(confirmationToken);

        if(token != null)
        {
            User user = userRepository.findByEmailIgnoreCase(token.getUser().getEmail());
            user.setEnabled(true);
            userRepository.save(user);
            modelAndView.setViewName("accountVerified");
        }
        else
        {
            modelAndView.addObject("message","The link is invalid or broken!");
            modelAndView.setViewName("error");
        }

        return modelAndView;
    }
    // getters and setters
}


