package com.oauth.server.config;

import com.google.common.collect.ImmutableMap;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.Objects;

/**
 * 自定义Token
 * @author Cheng Yufei
 * @create 2020-11-02 14:34
 **/
public class CustomTokenEnhancer implements TokenEnhancer {

	/**
	 * 将用户标识添加到jwt的额外信息中去
	 * @param accessToken
	 * @param authentication
	 * @return
	 */
	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

		Authentication userAuthentication = authentication.getUserAuthentication();

		//在客户端授权许可类型请求获取access_token时，没有用户的概念，所以用户的认证信息时null
		if (Objects.isNull(userAuthentication)) {
			return accessToken;
		}

		Object principal = userAuthentication.getPrincipal();
		((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(ImmutableMap.of("userDetail", principal));
		return accessToken;
	}
}
