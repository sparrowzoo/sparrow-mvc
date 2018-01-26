/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.sparrow.web.support;

import com.sparrow.constant.CONFIG;
import com.sparrow.constant.CONSTANT;
import com.sparrow.constant.EXTENSION;
import com.sparrow.constant.magic.SYMBOL;
import com.sparrow.core.Pair;
import com.sparrow.support.ContextHolder;
import com.sparrow.support.protocol.VO;
import com.sparrow.utility.Config;
import com.sparrow.utility.StringUtility;

import java.util.List;

/**
 * @author harry
 */
public class ViewWithModel {
    private VO vo;
    private String url;
    private PageSwitchMode switchMode;
    /**
     * session数据保存地址
     */
    private String flashUrl;

    public static final String SUCCESS = "success";

    public ViewWithModel() {
    }

    public ViewWithModel(String url, PageSwitchMode switchMode) {
        this(url, switchMode, null);
    }

    private ViewWithModel(String url, PageSwitchMode switchMode, VO vo) {
        this.vo = vo;
        this.url = url;
        this.switchMode = switchMode;
        if (this.url.contains(SYMBOL.VERTICAL_LINE)) {
            Pair<String, String> urlPair = Pair.split(this.url, SYMBOL.VERTICAL_LINE);
            this.url = urlPair.getFirst();
            this.flashUrl = urlPair.getSecond();
        }
    }

    public static ViewWithModel forward(VO vo) {
        return new ViewWithModel(SUCCESS, PageSwitchMode.FORWARD, vo);
    }

    public static ViewWithModel transit(VO vo) {
        return new ViewWithModel(SUCCESS, PageSwitchMode.TRANSIT, vo);
    }

    public static ViewWithModel redirect(VO vo) {
        return new ViewWithModel(SUCCESS, PageSwitchMode.REDIRECT, vo);
    }

    public static ViewWithModel forward() {
        return new ViewWithModel(SUCCESS, PageSwitchMode.FORWARD, null);
    }

    public static ViewWithModel transit() {
        return new ViewWithModel(SUCCESS, PageSwitchMode.TRANSIT, null);
    }

    public static ViewWithModel redirect() {
        return new ViewWithModel(SUCCESS, PageSwitchMode.REDIRECT, null);
    }

    public static ViewWithModel forward(String url) {
        return new ViewWithModel(url, PageSwitchMode.FORWARD, null);
    }

    public static ViewWithModel transit(String url) {
        return new ViewWithModel(url, PageSwitchMode.TRANSIT, null);
    }

    public static ViewWithModel redirect(String url) {
        return new ViewWithModel(url, PageSwitchMode.REDIRECT, null);
    }

    public static ViewWithModel forward(String url, VO vo) {
        return new ViewWithModel(url, PageSwitchMode.FORWARD, vo);
    }

    public static ViewWithModel transit(String url, VO vo) {
        return new ViewWithModel(url, PageSwitchMode.TRANSIT, vo);
    }

    public static ViewWithModel redirect(String url, VO vo) {
        return new ViewWithModel(url, PageSwitchMode.REDIRECT, vo);
    }

    public VO getVo() {
        return vo;
    }

    public String getUrl() {
        return url;
    }

    public PageSwitchMode getSwitchMode() {
        return switchMode;
    }

    public String getFlashUrl() {
        return flashUrl;
    }

    /**
     * 根据返回结果判断url
     *
     * @param actionResult 返回结果 direct:login direct:login.jsp direct:login|flash_url.jsp direct:success login login.jsp
     * success
     */

    public static ViewWithModel parse(String actionResult, String referer, String defaultSucceessUrl) {
        String url;
        PageSwitchMode pageSwitchMode = PageSwitchMode.REDIRECT;
        //手动返回url
        if (actionResult.contains(SYMBOL.COLON)) {
            Pair<String, String> switchModeAndUrl = Pair.split(actionResult, SYMBOL.COLON);
            pageSwitchMode = PageSwitchMode.valueOf(switchModeAndUrl.getFirst().toUpperCase());
            url = switchModeAndUrl.getSecond();
        } else {
            url = actionResult;
        }

        if (StringUtility.isNullOrEmpty(url)) {
            url = referer;
        }

        if (StringUtility.isNullOrEmpty(url)) {
            return null;
        }

        if (SUCCESS.equals(url)) {
            url = defaultSucceessUrl;
        }

        //index-->/index
        if (!url.startsWith(CONSTANT.HTTP_PROTOCOL) && !url.startsWith(CONSTANT.HTTPS_PROTOCOL) && !url.startsWith(SYMBOL.SLASH)) {
            url = SYMBOL.SLASH + url;
        }
        // /index-->/index.jsp
        if (!url.contains(SYMBOL.DOT)) {
            String extension = Config.getValue(CONFIG.DEFAULT_PAGE_EXTENSION);
            if (StringUtility.isNullOrEmpty(extension)) {
                extension = EXTENSION.JSP;
            }
            url = url + extension;
        }

        String transitUrl = Config.getValue(CONFIG.TRANSIT_URL);
        if (!StringUtility.isNullOrEmpty(transitUrl) && PageSwitchMode.TRANSIT.equals(pageSwitchMode)) {
            url = transitUrl + "|" + url;
        }

        Object urlParameters = ContextHolder.getInstance().get(CONSTANT.ACTION_RESULT_URL_PARAMETERS);
        if (urlParameters != null) {
            List<Object> listParameters = (List<Object>) urlParameters;
            for (int i = 0; i < listParameters.size(); i++) {
                if (listParameters.get(i) != null) {
                    url = url.replace(SYMBOL.DOLLAR, SYMBOL.AND).replace(
                        "{" + i + "}", listParameters.get(i).toString());
                }
            }
        }
        return new ViewWithModel(url, pageSwitchMode);
    }
}
