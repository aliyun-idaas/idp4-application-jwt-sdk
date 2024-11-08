# idp4-application-jwt-sdk
jwt应用插件客户端java集成sdk

## 目录说明
- dist  - 编译好的jar或压缩包文件。


## 使用案例
本案例演示JDK1.8以上，其它环境类似，请参考演示项目：[jwt-demo](https://github.com/aliyun-idaas/idp4-application-jwt-demo)  

### 接收令牌

```java
/**
 * id_token是IDaaS请求时带来的，参数名为 "id_token" ， 支持使用GET/POST两种方式放入;
 * PublicKey是在IDaaS里注册应用时生成的，可在应用详情页中JWT PublicKey查看;
 * target_url是IDaaS里注册应用时设置的target_url，此示例代码是通过id_token和PublicKey解析用户信息并完成单点登录。
 */
@RequestMapping(value = "/public/sso/{id}", method = {RequestMethod.GET, RequestMethod.POST})
public String ssoUrl(@RequestParam String id_token, @PathVariable("id") String id, String target_url, Model model, HttpServletRequest request) {
    //1.接收方法，GET和POST均支持
    //2.<解析令牌>为解析id_token并验证用户信息
    SSOConfigDto config = ssoConfigService.findSSOConfigById(id);
    if (null == config) {
        model.addAttribute("error", "system config publicKey do not EXIST");
        return "error";
    }
    try {
        //使用方法1：校验并获取id_token中的所有信息，json格式
        //checkAndGetPayload(id_token, publicKey);
        //使用方法2：校验并获取id_token中的用户名
        return checkAndGetUsername(id_token, target_url, model, request, config.getPublicKey());
    } catch (Exception e) {
        LOG.warn("id_token verifySignature failed", e);
        model.addAttribute("error", "wrong request,not found Username from id_token or id_token has expired");
        return "error";
    }
}
```

### 解析令牌

#### 使用jose4j框架解析

本案例使用jwt开源框架[jose4j](https://bitbucket.org/b_c/jose4j/wiki/Home)

解压`JWT-SDK-1.1.1_1.8.zip`  
引入 `jose4j-0.9.2.jar` `slf4j-api-1.7.21.jar`    
或者使用maven引入
```xml
<dependency>
    <groupId>org.bitbucket.b_c</groupId>
    <artifactId>jose4j</artifactId>
    <version>0.9.2</version>
</dependency>
```

PublicKey: 解析令牌的过程中，我们会使用到应用的 PublicKey。请在 JWT 应用 -> 详细 中将PublicKey字段对应的内容拷贝并存储起来。

```java
private String checkAndGetUsername(String id_token, String target_url, Model model, HttpServletRequest request, String publickey) throws Exception {

        //1. 初始化
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(id_token);
        jws.setKey(JsonWebKey.Factory.newJwk(publickey).getKey());
        //2. 校验id_token是否合法
        final boolean verifySignature = jws.verifySignature();
        if (!verifySignature) {
            LOG.warn("id_token verifySignature failed");
            //校验失败，报错，返回
            model.addAttribute("error", "Retrieve Username error: id_token verifySignature failed");
            return "error";
        }
        //3. 获取jwt中的payload信息，json格式，这里可以自由转换为需要的实体类
        final String payload = jws.getPayload();

        //4. 校验id_token是否过期
        JwtClaims claims = JwtClaims.parse(payload);
        NumericDate expirationTime = claims.getExpirationTime();
        if (expirationTime != null && expirationTime.isBefore(NumericDate.now())) {
            LOG.warn("id_token expired");
            //校验失败，报错，返回
            model.addAttribute("error", "Retrieve Username error: id_token expired");
            return "error";
        }
        //5. 注意校验id_token是否已经登陆过，防重放攻击
        //业务系统自己实现，需要校验有效期内，是否有相同的id_token已经登录
        final String jti = claims.getJwtId();//获取token唯一标识
        //从自身缓存系统判断jti是否已经登录过
        //if(exit(jti)){
        //    model.addAttribute("error", "id_token verifySignature failed");
        //    return error;
        //}
        //save(jti);

        //6.获取到用户信息，检测用户名是否存在自己的业务系统中，isExistedUsername方法为示例实现
        String username = claims.getSubject();
        if (userService.isExistedUsername(username)) {
            //7.如果存在,登录成功，返回登录成功后的界面
            User sysUser = userService.updateLoginTimes(username);
            HttpSession session = request.getSession();
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, saveSecurity(sysUser));

            //8.如果注册应用时添加了target_url，那么返回此自定义url页面
            if (StringUtils.isNotEmpty(target_url)) {
                return "redirect:" + target_url;
            }
            //9.否则返回系统默认操作页面
            return "redirect:../../index";
        } else {
            //10.如果不存在,返回登录失败页面,提示用户不存在
            model.addAttribute("error", "username { " + username + " } not exist");
            return "error";
        }
}
```


#### 使用jjwt框架解析
使用jwt开源框架[jjwt](https://github.com/jwtk/jjwt?tab=readme-ov-file#example-jws-hs)  
使用maven引入  

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.12.6</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.12.6</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId> <!-- or jjwt-gson if Gson is preferred -->
    <version>0.12.6</version>
</dependency>
```

PublicKey: 解析令牌的过程中，我们会使用到应用的 PublicKey。请在 JWT 应用 -> 详细 中将PublicKey字段对应的内容拷贝并存储起来。

```java
    private String checkAndGetUsername(String id_token, String target_url, Model model, HttpServletRequest request, String publickey) throws Exception {
    //1. 初始化
    final RsaPublicJwk key = (RsaPublicJwk) Jwks.parser().build().parse(publickey);
    final RSAPublicKey rsaPublicKey = key.toKey();
    //2. 校验id_token是否合法
    Claims claims ;
    try {
        claims= Jwts.parser()
                .verifyWith(rsaPublicKey)
                .build()
                .parseSignedClaims(id_token)
                .getPayload();
    }catch (SignatureException e){
        LOG.warn("id_token verifySignature failed",e);
        //校验失败，报错，返回
        model.addAttribute("error", "Retrieve Username error: id_token verifySignature failed");
        return "error";
    }

    //3. 校验id_token是否过期
    Date expirationTime = claims.getExpiration();
    if (expirationTime != null && expirationTime.before(new Date())) {
        LOG.warn("id_token expired");
        //校验失败，报错，返回
        model.addAttribute("error", "Retrieve Username error: id_token expired");
        return "error";
    }
    //4. 注意校验id_token是否已经登陆过，防重放攻击
    //业务系统自己实现，需要校验有效期内，是否有相同的id_token已经登录
    final String jti = claims.getId();//获取token唯一标识
    //从自身缓存系统判断jti是否已经登录过
    //if(exit(jti)){
    //    model.addAttribute("error", "id_token verifySignature failed");
    //    return error;
    //}
    //save(jti);

    //5.获取到用户信息，检测用户名是否存在自己的业务系统中，isExistedUsername方法为示例实现
    String username = claims.getSubject();
    if (userService.isExistedUsername(username)) {
        //7.如果存在,登录成功，返回登录成功后的界面
        User sysUser = userService.updateLoginTimes(username);
        HttpSession session = request.getSession();
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, saveSecurity(sysUser));

        //8.如果注册应用时添加了target_url，那么返回此自定义url页面
        if (StringUtils.isNotEmpty(target_url)) {
            return "redirect:" + target_url;
        }
        //9.否则返回系统默认操作页面
        return "redirect:../../index";
    } else {
        //10.如果不存在,返回登录失败页面,提示用户不存在
        model.addAttribute("error", "username { " + username + " } not exist");
        return "error";
    }
}
```
