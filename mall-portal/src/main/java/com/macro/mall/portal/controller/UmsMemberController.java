package com.macro.mall.portal.controller;
import cn.dev33.satoken.stp.SaTokenInfo;

import java.util.*;

import cn.dev33.satoken.stp.StpUtil;
import cn.dev33.satoken.util.SaResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.macro.mall.common.api.CommonResult;
import com.macro.mall.model.UmsMember;
import com.macro.mall.model.UmsMemberLevel;
import com.macro.mall.model.UmsMemberLevelExample;
import com.macro.mall.portal.service.UmsMemberService;
import com.fasterxml.jackson.core.type.TypeReference;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.catalina.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.FormBody;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

import java.util.Map;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
/**
 * 会员登录注册管理Controller
 * Created by macro on 2018/8/3.
 */
@Controller
@Tag(name = "UmsMemberController", description = "会员登录注册管理")
@RequestMapping("/sso")
public class UmsMemberController {
    @Autowired
    private UmsMemberService memberService;
    @Value("${sa-token.token-prefix}")
    private String tokenHead;


    @Operation(summary = "会员注册")
    @RequestMapping(value = "/register", method = RequestMethod.POST)
    @ResponseBody
    public CommonResult register(@RequestParam String username,
                                 @RequestParam String password,
                                 @RequestParam String telephone,
                                 @RequestParam String authCode) {
        memberService.register(username, password, telephone, authCode);
        return CommonResult.success(null,"注册成功");
    }

    @Operation(summary = "会员登录")
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    @ResponseBody
    public CommonResult login(@RequestParam String username,
                              @RequestParam String password) {
        SaTokenInfo saTokenInfo  = memberService.login(username, password);
        if (saTokenInfo  == null) {
            return CommonResult.validateFailed("用户名或密码错误");
        }
        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put("token", saTokenInfo.getTokenValue() );
        tokenMap.put("tokenHead", tokenHead+" ");
        return CommonResult.success(tokenMap);
    }
    public String parseOpenIdFromIdToken(String idToken) {
        try {
            // JWT 格式: header.payload.signature，所以取 payload 部分
            String[] parts = idToken.split("\\.");
            if (parts.length < 2) {
                return null;
            }

            // Base64 解码 payload
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));

            // 解析 JSON，获取 `sub` 作为 OpenID
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> payload = objectMapper.readValue(payloadJson, new TypeReference<Map<String, Object>>() {});
            return (String) payload.get("sub");  // `sub` 一般是用户的唯一标识

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private Map<String, Object> parseIdToken(String idToken) throws IOException {
        // id_token = header.payload.signature (JWT)
        String[] parts = idToken.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("非法 id_token");
        }
        // 解码 payload
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(payloadJson, new TypeReference<>() {});
    }

    public static String getSubFromIdToken(String idToken) throws Exception {
        // 1. 拆分 JWT
        String[] parts = idToken.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("非法的 id_token（JWT 结构不完整）: " + idToken);
        }

        // 2. 只解码 payload (parts[1])
        String base64Payload = parts[1];

        // 3. Base64URL 解码
        byte[] decoded = Base64.getUrlDecoder().decode(base64Payload);

        // 4. 解析 JSON
        String payloadJson = new String(decoded);
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> payloadMap = mapper.readValue(payloadJson, new TypeReference<Map<String, Object>>() {});

        // 5. 提取 `sub`
        String sub = (String) payloadMap.get("sub");
        if (sub == null || sub.isEmpty()) {
            throw new IllegalStateException("id_token 中未包含 sub 字段");
        }
        return sub;
    }


    @Operation(summary = "oidc login")
    @RequestMapping(value = "/oidc_login", method = RequestMethod.GET)
    @ResponseBody
    public CommonResult oidc_login(@RequestParam String code) {
        if (code == null || code.isEmpty()) {
            return CommonResult.validateFailed("授权码为空");
        }
        String tokenUrl = "http://localhost:8080/realms/my-realm/protocol/openid-connect/token";
        String clientId = "my-client";
        String redirectUri = "http://10.0.2.2:8201/mall-portal/sso/oidc_login";

        // 构造 x-www-form-urlencoded 请求体
        RequestBody requestBody = new FormBody.Builder()
                .add("grant_type", "authorization_code")
                .add("client_id", clientId)
                .add("code", code)
                .add("redirect_uri", redirectUri)
                .build();

        // 创建 OkHttp 请求
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
                .url(tokenUrl)
                .post(requestBody)
                .addHeader("Content-Type", "application/x-www-form-urlencoded")
                .build();

        // 发送请求并解析响应
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                String errorBody = response.body() != null ? response.body().string() : "";
                return CommonResult.failed("获取 Token 失败: " + response.code() + " " + response.message()
                        + ", errorBody=" + errorBody);
            }

            // 解析 JSON
            String bodyString = response.body() != null ? response.body().string() : "";
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> tokenData = mapper.readValue(bodyString, new TypeReference<>() {});

            // 提取 id_token
            String idToken = (String) tokenData.get("id_token");
            if (idToken == null || idToken.isEmpty()) {
                return CommonResult.failed("未获取到 id_token，Keycloak 返回=" + bodyString);
            }

            // 可选：解析 id_token，获取用户信息（如 sub, name, email）
            Map<String, Object> idTokenPayload = parseIdToken(idToken);
            String UserName = (String) idTokenPayload.get("preferred_username");
            String sub=getSubFromIdToken(idToken);
            // 返回示例：包含 id_token 以及解码后的字段
            UmsMember umsMember = memberService.getBySub(sub);
            if(umsMember==null){
                memberService.oidc_register(sub,UserName);
                return CommonResult.success(Map.of(
                        "sub", sub,
                        "username", UserName,
                        "status","zhuce"
                ));
            }else{
                SaTokenInfo saTokenInfo=memberService.oidc_login(UserName,sub);
                Map<String, String> tokenMap = new HashMap<>();
                tokenMap.put("token", saTokenInfo.getTokenValue() );
                tokenMap.put("tokenHead", tokenHead+" ");
                return CommonResult.success(tokenMap);

            }
        } catch (IOException e) {
            e.printStackTrace();
            return CommonResult.failed("网络或IO异常: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            return CommonResult.failed("未知异常: " + e.getMessage());
        }
    }

    @Operation(summary = "Google OIDC 登录")
    @RequestMapping(value = "/google_oidc_login", method = RequestMethod.POST)
    @ResponseBody
    public CommonResult googleOidcLogin(@RequestParam String idToken) {
        if (idToken == null || idToken.isEmpty()) {
            return CommonResult.failed("ID Token 为空");
        }

        try {
            String sub = getSubFromIdToken(idToken);
            if (sub == null) {
                return CommonResult.failed("ID Token 中未包含 sub 字段");
            }

            UmsMember umsMember = memberService.getBySub(sub);
            if (umsMember == null) {
                Map<String, Object> idTokenPayload = parseIdToken(idToken);
                String username = (String) idTokenPayload.get("name");
                memberService.oidc_register(sub, username);
                umsMember = memberService.getBySub(sub);
                //return CommonResult.success(Map.of("sub", sub, "username", username, "status", "注册成功"));
            }

            SaTokenInfo saTokenInfo = memberService.oidc_login(umsMember.getUsername(), sub);
            return CommonResult.success(Map.of("token", saTokenInfo.getTokenValue(), "tokenHead", tokenHead + " "));

        } catch (IOException e) {
            return CommonResult.failed("解析 ID Token 时发生错误: " + e.getMessage());
        } catch (Exception e) {
            return CommonResult.failed("未知异常: " + e.getMessage());
        }
    }





    @Operation(summary = "获取会员信息")
    @RequestMapping(value = "/info", method = RequestMethod.GET)
    @ResponseBody
    public CommonResult info() {
        UmsMember member = memberService.getCurrentMember();
        return CommonResult.success(member);
    }

    @Operation(summary = "登出功能")
    @RequestMapping(value = "/logout", method = RequestMethod.POST)
    @ResponseBody
    public CommonResult logout() {
        memberService.logout();
        return CommonResult.success(null);
    }

    @Operation(summary = "获取验证码")
    @RequestMapping(value = "/getAuthCode", method = RequestMethod.GET)
    @ResponseBody
    public CommonResult getAuthCode(@RequestParam String telephone) {
        String authCode = memberService.generateAuthCode(telephone);
        return CommonResult.success(authCode,"获取验证码成功");
    }

    @Operation(summary = "修改密码")
    @RequestMapping(value = "/updatePassword", method = RequestMethod.POST)
    @ResponseBody
    public CommonResult updatePassword(@RequestParam String telephone,
                                 @RequestParam String password,
                                 @RequestParam String authCode) {
        memberService.updatePassword(telephone,password,authCode);
        return CommonResult.success(null,"密码修改成功");
    }
}
