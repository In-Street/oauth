###授权服务器端设置登录成功为重定向时：
1. oauth_client_details表未设置redirect_url ，访问 client端 http://localhost:9092/app/securedPage
```
结果提示：client至少需要注册一个 redirect_uri
```
2. 数据库中设置redirect_url ：http://www.baidu.com
```
结果提示：注册的redirect_url 中没有 http://localhost:9092/app/login
```

3. 将 http://localhost:9092/app/login 添加到数据库中
```
访问securedPage，跳转到 server端的登录页面，登录成功后回跳到  securedPage 页面。
```
4. 通过 http://localhost:9092/app/remoteApi?type=admin访问时
```
跳转到登录，登录成功后跳转到 /remoteApi?type=admin 可以返回接口结果。但是在 访问 /remoteApi?type=read 后，
返回 http://localhost:9092/app/remoteApi 没有在client的redirect_url中注册。
需将 http://localhost:9092/app/remoteApi 添加到表。
```

### 认证流程
Authentication 接口:

1.定义了一些方法获取用户的相关内容
```
getAuthorities 方法用来获取用户的权限。
getCredentials 方法用来获取用户凭证，一般来说就是密码。
getDetails 方法用来获取用户携带的详细信息，可能是当前请求之类的东西。
getPrincipal 方法用来获取当前用户，可能是一个用户名，也可能是一个用户对象。
isAuthenticated 当前用户是否认证成功。
```
2. 多个实现类中常用UsernamePasswordAuthenticationToken、RememberMeAuthenticationToken。每个Authentication都有AuthenticationProvider去处理校验。UsernamePasswordAuthenticationToken用
    DaoAuthenticationProvider来实现用户名、密码的登录校验，其中的support方法来判断AuthenticationProvider是否支持当前的的Authentication。
    
3. 一次完成的认证流程包含多个AuthenticationProvider，他们由ProviderManager进行管理。 ProviderManager # authenticate 方法逐个遍历 AuthenticationProvider # authenticate 方法认证。

4. 自定义过滤器【验证码检验】会破坏原有的spring security 过滤链，可通过认证流程分析，采用自定义AuthenticationProvider 来代替DaoAuthenticationProvider，
   重写 additionalAuthenticationChecks 方法添加验证码检验功能即可。或者在代替UsernamePasswordAuthenticationFilter的自定义CustomAuthenticationFilter类中校验。

###json格式登录形式中，添加账号多端登录的控制
####SessionRegistryImpl 类用于会话信息统一管理：
```
1. 在registerNewSession 方法中添加新session，存于ConcurrentMap中，key是 登录用户principal，value是该用户的sessionId集合。
   principal用于key，因为在基于数据库管理用户时，User类有重写基于username的equals方法、hashCode方法。
2.用户注销登录，sessionid 需要移除，相关操作在 removeSessionInformation 方法中完成 。
```
#### 自提供 SessionAuthenticationStrategy
```
1. 由于代替了UsernamePasswordAuthenticationFilter，所以在WebSecurityConfig的configure()关于session的配置会失效。需要在自定义过滤器中重新配置。
2. 重新 new SessionRegistryImple()，来管理会话信息。
3.  new  ConcurrentSessionControlAuthenticationStrategy(SessionRegistryImple) 来提供SessionAuthenticationStrategy, setMaximumSessions(1), 
    构造CompositeSessionAuthenticationStrategy，放于CustomAuthenticationFilter类。
4. ConcurrentSessionControlAuthenticationStrategy -> onAuthentication 方法校验 该用户已注册的session集合和setMaximumSessions的允许最大session值比较处理
```
#### WebSecurityConfig 中替换ConcurrentSessionFilter
```
1. 由于重新new 了SessionRegistryImpl，ConcurrentSessionFilter类中也用到了，所以需要自定义。
 http.addFilterAt(new ConcurrentSessionFilter(sessionRegistryImpl(), strategy -> {},ConcurrentSessionFilter.class)
```
#### 用户session的注册
```
CustomAuthenticationFilter 接受用户登录信息后，要注册进 SessionRegistry
```

### 防止会话固定攻击
```
WebSecurityConfig configure 方法中设置：http.sessionManagement().sessionFixation().xxxx

1. migrateSession: 默认，登录成功后生成新session，将旧session信息复制到新session中。

2. none：不做任何事情，继续使用旧的 session。

3. changeSessionId: 表示 session 不变，但是会修改 sessionid，这实际上用到了 Servlet 容器提供的防御会话固定攻击。

4. newSession:  表示登录后创建一个新的 session。
  
```

###TODO
2.角色继承无效、
3.指定接口使用fullyAuthenticated 无效,仍能通过remember me 用户进行访问。
4. 在client模块中自定义WebSecurity的Order导致的过滤链顺序问题,与@EnableOAuth2Sso。
5. nginx中配置多个client服务，无法正常访问client接口。