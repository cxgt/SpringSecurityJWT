package com.example.demo.security.fliter;

import com.example.demo.security.constant.SecurityConstants;
import com.example.demo.security.utils.JwtTokenUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author chenxin
 * @Description 过滤器处理所有HTTP请求，并检查是否存在带有正确令牌的Authorization标头。
 * 例如，如果令牌未过期或签名密钥正确。
 * @date 2023/11/22 15:38
 */
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final StringRedisTemplate stringRedisTemplate;
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager,StringRedisTemplate stringRedisTemplate) {
        super(authenticationManager);
        this.stringRedisTemplate=stringRedisTemplate;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        String token = request.getHeader(SecurityConstants.TOKEN_HEADER);
        //token为空 或者不符合规则 清空上下文
        if(token == null || !token.startsWith(SecurityConstants.TOKEN_PREFIX)){
            SecurityContextHolder.clearContext();
            chain.doFilter(request,response);
            return;
        }

        String tokenValue=token.replace(SecurityConstants.TOKEN_PREFIX,"");
        UsernamePasswordAuthenticationToken authentication=null;
        try {
            String previousToken = stringRedisTemplate.opsForValue().get(JwtTokenUtils.getId(tokenValue));
            if(!previousToken.equals(tokenValue)){
                SecurityContextHolder.clearContext();
                chain.doFilter(request,response);
                return;
            }
            authentication = JwtTokenUtils.getAuthentication(tokenValue);
        }catch (Exception e){
            logger.error("jwt Exception"+e.getMessage());
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request,response);

    }
}
