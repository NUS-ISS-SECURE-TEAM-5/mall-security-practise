package com.macro.mall.filter;

import com.macro.mall.util.XssUtils;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.stream.Collectors;

@Component
public class XssGlobalFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // 1️⃣ 过滤 URL 查询参数
        Map<String, String> sanitizedParams = request.getQueryParams().toSingleValueMap().entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> XssUtils.cleanXss(entry.getValue())));

        // 2️⃣ 过滤请求头
        ServerHttpRequest modifiedRequest = request.mutate()
                .headers(headers -> headers.forEach((key, values) -> {
                    headers.set(key, values.stream()
                            .map(XssUtils::cleanXss)
                            .collect(Collectors.joining(",")));
                }))
                .build();

        return chain.filter(exchange.mutate().request(modifiedRequest).build());
    }

    @Override
    public int getOrder() {
        return -1; // 让 XSS 过滤器优先执行
    }
}
