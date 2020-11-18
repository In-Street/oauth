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



http://localhost:9092/app/login,http://localhost:9092/app/remoteApi,http://localhost:9093/app/login,http://localhost:9093/app/remoteApi
