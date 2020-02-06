package com.imooc.user.controller;

import com.imooc.thrift.user.UserInfo;
import com.imooc.thrift.user.dto.UserDTO;
import com.imooc.user.redis.RedisClient;
import com.imooc.user.response.LoginResponse;
import com.imooc.user.response.Response;
import com.imooc.user.thrift.ServiceProvider;
import org.apache.commons.lang.StringUtils;
import org.apache.thrift.TException;
import org.apache.tomcat.util.buf.HexUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

@Controller
@RequestMapping("/user")
public class UserController {

    @Autowired
    private ServiceProvider serviceProvider;

    @Autowired
    private RedisClient redisClient;

    @GetMapping("/login")
    public String login() {
        return "/login";
    }

    @PostMapping("/login")
    @ResponseBody
    public Response login(@RequestParam("username")String username,
                          @RequestParam("password")String password) {
        //1.验证用户名密码
        UserInfo userInfo = null;
        try {
            userInfo = serviceProvider.getUserService().getUserName(username);
        } catch (TException e) {
            e.printStackTrace();
            return new Response("10001", "username or password is error");
        }
        if (userInfo == null) {
            return new Response("10001", "username or password is error");
        }
        if (!userInfo.getPassword().equalsIgnoreCase(md5(password))) {
            System.out.println(md5(password));
            return new Response("10001", "username or password is error");
        }

        //2.生成token
        String token = genToken();

        //3.缓存用户
        redisClient.set(token, toDTO(userInfo), 3600);

        return new LoginResponse(token);
    }

    @PostMapping("/sendVerifyCode")
    @ResponseBody
    public Response sendVerifyCode(@RequestParam(value = "mobile", required = false)String mobile,
                                   @RequestParam(value = "email", required = false)String email) {
        String code = randomCode("0123456789", 6);
        try {
            boolean result = false;
            if (StringUtils.isNotBlank(mobile)) {
                result = serviceProvider.getMessageService().sendMobileMessage(mobile, code);
                redisClient.set(mobile, code);
            } else if (StringUtils.isNotBlank(email)) {
                result = serviceProvider.getMessageService().sendEmailMessage(email, code);
                redisClient.set(email, code);
            } else {
                return new Response("10002", "mobile or email is required");
            }
            if (!result) {
                return new Response("10003", "send VerifyCode failed");
            }
        } catch (TException e) {
            e.printStackTrace();
            return new Response("99999", "出异常了");
        }
        return new Response("10000", "success");
    }

    @PostMapping("/register")
    @ResponseBody
    public Response register(@RequestParam("username")String username,
                             @RequestParam("password")String password,
                             @RequestParam(value = "mobile", required = false)String mobile,
                             @RequestParam(value = "email", required = false)String email,
                             @RequestParam("verifyCode")String verifyCode) {
        if (StringUtils.isBlank(mobile) && StringUtils.isBlank(email)) {
            return new Response("1002", "mobile or email is required");
        }

        if (StringUtils.isNotBlank(mobile)) {
            String redisCode = redisClient.get(mobile);
            if (!verifyCode.equals(redisCode)) {
                return new Response("10004", "verifycode invalid");
            }
        }else {
            String redisCode = redisClient.get(email);
            if (!verifyCode.equals(redisCode)) {
                return new Response("10004", "verifycode invalid");
            }
        }
        UserInfo userInfo = new UserInfo();
        userInfo.setUsername(username);
        userInfo.setPassword(md5(password));
        userInfo.setMobile(mobile);
        userInfo.setEmail(email);
        try {
            serviceProvider.getUserService().registerUser(userInfo);
        } catch (TException e) {
            e.printStackTrace();
            return new Response("99999", "出异常了");
        }
        return new Response("10000", "success");
    }

    @PostMapping("/authentication")
    @ResponseBody
    public UserDTO authentication(@RequestHeader("token")String token) {
        return redisClient.get(token);
    }

    private UserDTO toDTO(UserInfo userInfo) {
        UserDTO userDTO = new UserDTO();
        BeanUtils.copyProperties(userInfo, userDTO);
        return userDTO;
    }

    private String genToken() {
        return randomCode("0123456789abcdefghijklmnopqrstuvwxyz", 32);
    }

    private String randomCode(String s, int size) {
        StringBuilder result = new StringBuilder(size);
        Random random = new Random();
        for (int i=0;i<size;i++) {
            int loc = random.nextInt(s.length());
            result.append(s.charAt(loc));
        }
        return result.toString();
    }

    private String md5(String password) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] bytes = md5.digest(password.getBytes("utf-8"));
            return HexUtils.toHexString(bytes);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }
}
