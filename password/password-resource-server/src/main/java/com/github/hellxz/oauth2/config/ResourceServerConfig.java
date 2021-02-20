package com.github.hellxz.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import sun.misc.Resource;

import java.rmi.Remote;
//首先来了解下Oatuh2中的几个名字，方便下文的阐述。
//Third-party application: 第三方应用
//Resource Owner: 资源持有者，一般就是用户自身
//Authorization server: 认证服务器
//Resource server: 资源服务器，即具体资源的存储方。与认证服务器是不同的逻辑节点，但是在物理上，双方是可以在一起的
//User Agent: 用户代理，一般就是指的浏览器
//Http Service: 服务提供者，也就是持有Resource Server的存在方。可以理解为类似QQ，或者微信这样具备用户信息的服务者。


@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
    @Bean
    public RemoteTokenServices remoteTokenServices() {
        final RemoteTokenServices tokenServices = new RemoteTokenServices();
        tokenServices.setClientId("client-a");
        tokenServices.setClientSecret("client-a-secret");
        tokenServices.setCheckTokenEndpointUrl("http://localhost:8080/oauth/check_token");
        return tokenServices;
    }

    //    Oauth2提供的默认端点（endpoints）
    ///oauth/authorize：授权端点
    ///oauth/token：令牌端点
    ///oauth/confirm_access：用户确认授权提交端点
    ///oauth/error：授权服务错误信息端点
    ///oauth/check_token：用于资源服务访问的令牌解析端点
    ///oauth/token_key：提供公有密匙的端点，如果使用JWT令牌的话

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.stateless(true);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        //session创建策略
        //•always - 如果一个会话尚不存在，将始终创建一个会话
        //•ifRequired - 仅在需要时创建会话（默认）
        //•never - 框架永远不会创建会话本身，但如果它已经存在，它将使用一个
        //•stateless - Spring Security不会创建或使用任何会话(默认)
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
        //所有请求需要认证
        http.authorizeRequests().anyRequest().authenticated();
    }
}
