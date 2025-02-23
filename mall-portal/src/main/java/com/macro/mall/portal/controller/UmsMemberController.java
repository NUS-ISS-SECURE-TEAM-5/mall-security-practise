package com.macro.mall.portal.controller;
import com.ejlchina.okhttps.OkHttps;
import cn.dev33.satoken.stp.SaTokenInfo;
import java.util.Base64;
import cn.dev33.satoken.stp.StpUtil;
import cn.dev33.satoken.util.SaResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.macro.mall.common.api.CommonResult;
import com.macro.mall.model.UmsMember;
import com.macro.mall.portal.service.UmsMemberService;
import com.fasterxml.jackson.core.type.TypeReference;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
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


    @Operation(summary = "oidc login")
    @RequestMapping(value = "/oidc_login", method = RequestMethod.POST)
    @ResponseBody
    public CommonResult oidc_login(@RequestParam String code) {
        if (code == null || code.isEmpty()) {
            return CommonResult.validateFailed("授权码为空");
        }

        System.out.println("收到授权码: " + code);

        // 直接返回 code 给前端
        return CommonResult.success(Map.of("code", code));
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
