package com.example.demo.security.utils;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * @author chenxin
 * @Description 获取当前用户的工具类
 * @date 2023/11/22 16:17
 */
public class CurrentUserUtils {


    private final UserService userService;

    public User getCurrentUser() {
        return userService.find(getCurrentUserName());
    }

    private  String getCurrentUserName() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() != null) {
            return (String) authentication.getPrincipal();
        }
        return null;
    }
}
