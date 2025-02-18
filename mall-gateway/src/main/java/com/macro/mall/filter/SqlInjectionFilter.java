package com.macro.mall.filter;

import io.netty.buffer.ByteBufAllocator;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.web.reactive.filter.OrderedWebFilter;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.*;
import org.springframework.http.*;
import org.springframework.http.server.reactive.*;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyExtractors;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;

/**
 * 全局网关过滤器示例：只做 SQL 注入关键字检测
 */
@Slf4j
@Component
public class SqlInjectionFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        log.debug("----SQL 注入防护过滤器生效----");

        ServerHttpRequest request = exchange.getRequest();
        HttpMethod method = request.getMethod();
        if (method == null) {
            return chain.filter(exchange);
        }

        String contentType = request.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE);
        URI uri = request.getURI();

        // 判断是否需要检查 Body 的请求
        boolean needCheckBody = (method == HttpMethod.POST || method == HttpMethod.PUT)
                && contentType != null
                && (contentType.contains(MediaType.APPLICATION_JSON_VALUE)
                || contentType.contains(MediaType.APPLICATION_FORM_URLENCODED_VALUE));

        // 1. 处理 GET 请求：只检查 URI 上的 QueryString
        if (method == HttpMethod.GET) {
            String rawQuery = uri.getRawQuery();
            if (StringUtils.isBlank(rawQuery)) {
                // 没有参数，直接放行
                return chain.filter(exchange);
            }
            log.debug("原始 GET 参数: {}", rawQuery);

            if (detectSqlInjection(rawQuery)) {
                log.error("请求【{}?{}】中存在疑似 SQL 注入关键词，拒绝访问", uri.getPath(), rawQuery);
                return setForbiddenResponse(exchange);
            }
            // 未检测到可疑关键词则直接放行
            return chain.filter(exchange);
        }

        // 2. 处理需要检查 Body 的 POST/PUT 请求
        if (needCheckBody) {
            return DataBufferUtils.join(request.getBody())
                    .flatMap(dataBuffer -> {
                        // 将字节流拼接成字符串
                        byte[] oldBytes = new byte[dataBuffer.readableByteCount()];
                        dataBuffer.read(oldBytes);
                        DataBufferUtils.release(dataBuffer);

                        String bodyString = new String(oldBytes, StandardCharsets.UTF_8);
                        log.debug("{} - {} Body 原始内容: {}", method, uri.getPath(), bodyString);

                        // 检查可疑关键词
                        if (detectSqlInjection(bodyString)) {
                            log.error("请求 [{}] 的 Body 中存在疑似 SQL 注入关键词，拒绝访问", uri.getPath());
                            return setForbiddenResponse(exchange);
                        }

                        // 如果检查通过，重构请求
                        ServerHttpRequest newRequest = rebuildRequestWithBody(request, bodyString);
                        return chain.filter(exchange.mutate().request(newRequest).build());
                    });
        }

        // 3. 其它类型的请求直接放行
        return chain.filter(exchange);
    }

    /**
     * 简易 SQL 注入检测逻辑。
     * 实际生产中可结合更多关键词或正则匹配。
     */
    private boolean detectSqlInjection(String input) {
        if (StringUtils.isBlank(input)) {
            return false;
        }
        String lower = input.toLowerCase();

        // 示例：检测含有 " or " / " and " / "' or '1'='1" 这些片段就返回 true
        // 可进一步拓展更多关键词
        if (lower.contains(" or ")
                || lower.contains(" and ")
                || lower.contains("' or '1'='1")
                || lower.contains("' and '1'='1")
        ) {
            return true;
        }
        return false;
    }

    /**
     * 如果 body 检测通过，则构造新的请求，保证下游还能读取到 body
     */
    private ServerHttpRequest rebuildRequestWithBody(ServerHttpRequest originalRequest, String bodyString) {
        byte[] newBytes = bodyString.getBytes(StandardCharsets.UTF_8);
        DataBuffer bodyDataBuffer = toDataBuffer(newBytes);
        Flux<DataBuffer> bodyFlux = Flux.just(bodyDataBuffer);

        HttpHeaders headers = new HttpHeaders();
        headers.putAll(originalRequest.getHeaders());
        // 修改 Content-Length
        headers.remove(HttpHeaders.CONTENT_LENGTH);
        headers.setContentLength(newBytes.length);

        // 如果只处理 JSON，可直接设置
        if (headers.getContentType() == null) {
            headers.setContentType(MediaType.APPLICATION_JSON);
        }

        return new ServerHttpRequestDecorator(originalRequest) {
            @Override
            public HttpHeaders getHeaders() {
                return headers;
            }

            @Override
            public Flux<DataBuffer> getBody() {
                return bodyFlux;
            }
        };
    }

    /**
     * 将字节数组转换为 DataBuffer
     */
    private DataBuffer toDataBuffer(byte[] bytes) {
        NettyDataBufferFactory nettyDataBufferFactory = new NettyDataBufferFactory(ByteBufAllocator.DEFAULT);
        DataBuffer buffer = nettyDataBufferFactory.allocateBuffer(bytes.length);
        buffer.write(bytes);
        return buffer;
    }

    /**
     * 返回 403 拦截响应
     */
    private Mono<Void> setForbiddenResponse(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] bytes = "{\"message\":\"Forbidden: Suspicious SQL keywords detected\"}"
                .getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        // 优先级最高
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
