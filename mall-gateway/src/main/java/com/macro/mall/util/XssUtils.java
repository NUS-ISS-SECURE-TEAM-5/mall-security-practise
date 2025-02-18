package com.macro.mall.util;

import org.apache.commons.text.StringEscapeUtils;


public class XssUtils {
    public static String cleanXss(String value) {
        if (value == null) {
            return null;
        }
        return StringEscapeUtils.escapeHtml4(value); // 转义 <, >, ", ', &
    }
}
