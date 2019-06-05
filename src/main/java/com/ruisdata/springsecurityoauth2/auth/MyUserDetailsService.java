/**
 * 
 */
package com.ruisdata.springsecurityoauth2.auth;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.social.security.SocialUser;
import org.springframework.social.security.SocialUserDetails;
import org.springframework.social.security.SocialUserDetailsService;
import org.springframework.stereotype.Component;

/**
 * @author zhailiang
 *
 */
@Component
public class MyUserDetailsService implements UserDetailsService, SocialUserDetailsService {
	@Autowired
	private ObjectMapper objectMapper;

	private Logger logger = LoggerFactory.getLogger(getClass());

	private PasswordEncoder passwordEncoder;

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.security.core.userdetails.UserDetailsService#
	 * loadUserByUsername(java.lang.String)
	 */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		logger.info("表单登录用户名:" + username);
		SocialUserDetails socialUserDetails = buildUser(username);
		logger.info("------------------------");
        try {
            logger.info(objectMapper.writeValueAsString(socialUserDetails));
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return buildUser(username);
	}

	@Override
	public SocialUserDetails loadUserByUserId(String userId) throws UsernameNotFoundException {
		logger.info("设计登录用户Id:" + userId);
		return buildUser(userId);
	}

	private SocialUserDetails buildUser(String userId) {
		// 根据用户名查找用户信息
		//根据查找到的用户信息判断用户是否被冻结
		passwordEncoder = new BCryptPasswordEncoder();
		String password = passwordEncoder.encode("123456");
		logger.info("数据库密码是:"+password);
		return new SocialUser(userId, password,
				true, true, true, true,
				AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
	}

}
