package com.example.apitest.validator;


import com.example.apitest.User.entity.User;
import com.example.apitest.User.repository.UserRepository;
import com.example.apitest.User.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;

@RestController
public class RestApiTestController {

    private final UserService userService;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public RestApiTestController(UserService userService, UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userService = userService;
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @GetMapping("/home")
    public String home(){
        return "<h1>home</h1>";
    }

    @PostMapping("/token")
    public String token() {
        return "<h1>token</h1>";
    }


    @PostMapping("/signup")
    public ResponseEntity signup(@Valid @RequestBody User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userService.createUser(user);
        Map<String ,String > map = new HashMap<>();
        map.put("message","Success");
        return new ResponseEntity<>(map, HttpStatus.CREATED);
    }

    @GetMapping("/api/v1/user")
    public String user() {
        return "user";
    }
    // 추가
    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }
}
