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

package com.sparrow.mvc.result.impl;

import com.sparrow.constant.CONFIG;
import com.sparrow.constant.CONFIG_KEY_LANGUAGE;
import com.sparrow.constant.SPARROW_ERROR;
import com.sparrow.core.Pair;
import com.sparrow.mvc.ServletInvokableHandlerMethod;
import com.sparrow.mvc.result.MethodReturnValueResolverHandler;
import com.sparrow.protocol.BusinessException;
import com.sparrow.protocol.Result;
import com.sparrow.protocol.constant.CONSTANT;
import com.sparrow.protocol.constant.magic.SYMBOL;
import com.sparrow.protocol.mvn.PageSwitchMode;
import com.sparrow.protocol.mvn.ViewWithModel;
import com.sparrow.support.web.HttpContext;
import com.sparrow.support.web.ServletUtility;
import com.sparrow.utility.Config;
import com.sparrow.utility.StringUtility;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author harry
 */
public class ViewWithModelMethodReturnValueResolverHandlerImpl implements MethodReturnValueResolverHandler {

    private ServletUtility servletUtility = ServletUtility.getInstance();

    public ViewWithModelMethodReturnValueResolverHandlerImpl() {
    }

    @Override
    public boolean support(ServletInvokableHandlerMethod executionChain) {
        return executionChain.getReturnType().equals(ViewWithModel.class) || executionChain.getReturnType().equals(String.class);
    }

    private void flash(HttpServletRequest request, String flashUrl, String key, Object o) {
        Map<String, Object> values = HttpContext.getContext().getHolder();
        if (o != null) {
            values.put(key, o);
        }
        Pair<String, Map<String, Object>> sessionMap = Pair.create(flashUrl, values);
        request.getSession().setAttribute(CONSTANT.ACTION_RESULT_FLASH_KEY, sessionMap);
        HttpContext.getContext().remove();
    }

    /**
     * 根据返回结果判断url
     *
     * @param actionResult direct:login
     *                     <p>
     *                     direct:login.jsp
     *                     <p>
     *                     direct:login|flash_url.jsp
     *                     <p>
     *                     direct:success
     *                     <p>
     *                     login
     *                     <p>
     *                     login.jsp
     *                     success
     */
    private ViewWithModel parse(String actionResult, String referer, String defaultSuccessUrl) {
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
        url = assembleUrl(referer, defaultSuccessUrl, url, pageSwitchMode);
        switch (pageSwitchMode) {
            case FORWARD:
                return ViewWithModel.forward(url);
            case REDIRECT:
                return ViewWithModel.redirect(url);
            case TRANSIT:
                return ViewWithModel.transit(url);
            default:
                return ViewWithModel.forward(url);
        }
    }

    private String assembleUrl(String referer, String defaultSucceessUrl, String url, PageSwitchMode pageSwitchMode) {
        if (StringUtility.isNullOrEmpty(url)) {
            url = referer;
        }

        if (StringUtility.isNullOrEmpty(url)) {
            return null;
        }

        if (CONSTANT.SUCCESS.equals(url)) {
            url = defaultSucceessUrl;
        }

        if (StringUtility.isNullOrEmpty(url)) {
            return null;
        }
        //index-->/index
        if (!url.startsWith(CONSTANT.HTTP_PROTOCOL) && !url.startsWith(CONSTANT.HTTPS_PROTOCOL) && !url.startsWith(SYMBOL.SLASH)) {
            url = SYMBOL.SLASH + url;
        }

        // /index-->template/index.jsp
        if (PageSwitchMode.FORWARD.equals(pageSwitchMode) && !url.contains(SYMBOL.DOT)) {
            url = servletUtility.assembleActualUrl(url);
        }

        Object urlParameters = HttpContext.getContext().get(CONSTANT.ACTION_RESULT_URL_PARAMETERS);
        if (urlParameters != null) {
            List<Object> listParameters = (List<Object>) urlParameters;
            for (int i = 0; i < listParameters.size(); i++) {
                if (listParameters.get(i) != null) {
                    url = url.replace(SYMBOL.DOLLAR, SYMBOL.AND).replace(
                            "{" + i + "}", listParameters.get(i).toString());
                }
            }
        }
        return url;
    }

    @Override
    public void resolve(ServletInvokableHandlerMethod handlerExecutionChain, Object returnValue, FilterChain chain,
                        HttpServletRequest request,
                        HttpServletResponse response) throws IOException, ServletException {
        String referer = servletUtility.referer(request);
        ViewWithModel viewWithModel = null;

        String url = null;
        if (returnValue instanceof String) {
            viewWithModel = this.parse((String) returnValue, servletUtility.referer(request), handlerExecutionChain.getSuccessUrl());
            url = viewWithModel.getUrl();
        } else if (returnValue instanceof ViewWithModel) {
            viewWithModel = (ViewWithModel) returnValue;
            url = this.assembleUrl(referer, handlerExecutionChain.getSuccessUrl(), viewWithModel.getUrl(), viewWithModel.getSwitchMode());
        }
        //无返回值，直接返回 不处理
        if (viewWithModel == null) {
            chain.doFilter(request, response);
            return;
        }

        String key = StringUtility.setFirstByteLowerCase(viewWithModel.getVo().getClass().getSimpleName());
        if (!StringUtility.isNullOrEmpty(viewWithModel.getFlashUrl())) {
            this.flash(request, viewWithModel.getFlashUrl(), key, viewWithModel.getVo());
        }
        request.setAttribute(key, viewWithModel.getVo());

        if (url == null) {
            chain.doFilter(request, response);
            return;
        }
        String rootPath = Config.getValue(CONFIG.ROOT_PATH);
        String message = Config.getLanguageValue(CONFIG_KEY_LANGUAGE.TRANSIT_SUCCESS_MESSAGE);
        switch (viewWithModel.getSwitchMode()) {
            case REDIRECT:
                if (rootPath != null && !url.startsWith(rootPath)) {
                    url = rootPath + url;
                }
                response.sendRedirect(url);
                break;
            case TRANSIT:
                String transitUrl = Config.getValue(CONFIG.TRANSIT_URL);
                if (transitUrl != null && !transitUrl.startsWith(CONSTANT.HTTP_PROTOCOL)) {
                    transitUrl = rootPath + transitUrl;
                }
                response.sendRedirect(transitUrl + "?" + url);
                break;
            case FORWARD:
                if (rootPath != null && url.startsWith(rootPath)) {
                    url = url.substring(rootPath.length());
                }
                RequestDispatcher dispatcher = request.getRequestDispatcher(url);
                dispatcher.forward(request, response);
                break;
            default:
        }
    }

    @Override
    public void errorResolve(Throwable exception,
                             HttpServletRequest request,
                             HttpServletResponse response) throws IOException, ServletException {

        PageSwitchMode errorPageSwitch = PageSwitchMode.REDIRECT;
        String exceptionSwitchMode = Config.getValue(CONFIG.EXCEPTION_SWITCH_MODE);
        if (!StringUtility.isNullOrEmpty(exceptionSwitchMode)) {
            errorPageSwitch = PageSwitchMode.valueOf(exceptionSwitchMode.toUpperCase());
        }
        BusinessException businessException = null;
        //业务异常
        if (exception instanceof BusinessException) {
            businessException = (BusinessException) exception;
        } else {
            businessException = new BusinessException(SPARROW_ERROR.SYSTEM_SERVER_ERROR);
        }
        Result result = Result.FAIL(businessException);
        //todo set error msg
        //result.setError();

        String rootPath = Config.getValue(CONFIG.ROOT_PATH);
        String referer = servletUtility.referer(request);
        String relativeReferer = referer.substring(rootPath.length() + 1);
        String flashUrl;
        switch (errorPageSwitch) {
            case REDIRECT:
                String url = Config.getValue(CONFIG.ERROR_URL);
                if (StringUtility.isNullOrEmpty(url)) {
                    url = "500";
                }
                flashUrl = servletUtility.assembleActualUrl(url);
                this.flash(request, flashUrl, CONSTANT.EXCEPTION_RESULT, result);
                response.sendRedirect(url);
                break;
            case FORWARD:
                flashUrl = servletUtility.assembleActualUrl(relativeReferer);
                this.flash(request, flashUrl, CONSTANT.EXCEPTION_RESULT, result);
                response.sendRedirect(relativeReferer);
                break;
            case TRANSIT:
                flashUrl = servletUtility.assembleActualUrl(relativeReferer);
                this.flash(request, flashUrl, CONSTANT.EXCEPTION_RESULT, result);
                String transitUrl = Config.getValue(CONFIG.TRANSIT_URL);
                if (transitUrl != null && !transitUrl.startsWith(CONSTANT.HTTP_PROTOCOL)) {
                    transitUrl = Config.getValue(CONFIG.ROOT_PATH) + transitUrl;
                }
                response.sendRedirect(transitUrl + "?" + relativeReferer);
            default:
        }
    }
}
