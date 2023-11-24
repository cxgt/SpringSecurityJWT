package com.example.demo.security.exception;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Description 用来出来当前登陆的用户没有权限访问当前资源的异常
 * @author chenxin
 * @date 2023/11/22 15:20
 */
public class JwtAccessDeniedHandler implements AccessDeniedHandler {


    /**
     * 当用户尝试访问需要权限才能的REST资源而权限不足的时候， 将调用此方法发送403响应以及错误信息
     * @param httpServletRequest
     * @param httpServletResponse
     * @param e
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
        e=new AccessDeniedException("The current user does not have permission to access this resource");
        httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN,e.getMessage());
    }
}
