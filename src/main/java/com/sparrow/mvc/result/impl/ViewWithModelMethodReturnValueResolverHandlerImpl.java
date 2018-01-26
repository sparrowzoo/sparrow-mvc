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
import com.sparrow.constant.CONSTANT;
import com.sparrow.constant.SPARROW_ERROR;
import com.sparrow.core.Pair;
import com.sparrow.exception.BusinessException;
import com.sparrow.mvc.ServletInvocableHandlerMethod;
import com.sparrow.mvc.result.MethodReturnValueResolverHandler;
import com.sparrow.support.ContextHolder;
import com.sparrow.support.protocol.Result;
import com.sparrow.support.web.ServletUtility;
import com.sparrow.utility.Config;
import com.sparrow.utility.StringUtility;
import com.sparrow.web.support.Alert;
import com.sparrow.web.support.PageSwitchMode;
import com.sparrow.web.support.ViewWithModel;

import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * @author harry
 */
public class ViewWithModelMethodReturnValueResolverHandlerImpl implements MethodReturnValueResolverHandler {

    private ServletUtility servletUtility = ServletUtility.getInstance();

    public ViewWithModelMethodReturnValueResolverHandlerImpl() {
    }

    @Override
    public boolean support(ServletInvocableHandlerMethod executionChain) {
        return executionChain.getReturnType().equals(ViewWithModel.class) || executionChain.getReturnType().equals(String.class);
    }

    private void flash(HttpServletRequest request, String flashUrl, String key, Object o) {
        Map<String, Object> values = ContextHolder.getInstance().getHolder();
        if (o != null) {
            values.put(key, o);
        }
        Pair<String, Map<String, Object>> sessionMap = Pair.create(flashUrl, values);
        request.getSession().setAttribute(CONSTANT.ACTION_RESULT_FLASH_KEY, sessionMap);
        ContextHolder.getInstance().remove();
    }

    @Override
    public void resolve(ServletInvocableHandlerMethod handlerExecutionChain, Object returnValue, FilterChain chain,
        HttpServletRequest request,
        HttpServletResponse response) throws IOException, ServletException {
        ViewWithModel viewWithModel;
        if (returnValue instanceof String) {
            viewWithModel = ViewWithModel.parse((String) returnValue, servletUtility.referer(request), handlerExecutionChain.getSuccessUrl());
        } else {
            viewWithModel = (ViewWithModel) returnValue;
        }
        //无返回值，直接返回 不处理
        if (viewWithModel == null) {
            chain.doFilter(request, response);
            return;
        }

        String key = StringUtility.setFirstByteLowerCase(viewWithModel.getVo().getClass().getSimpleName());
        if (!StringUtility.isNullOrEmpty(viewWithModel.getFlashUrl())) {
            this.flash(request, viewWithModel.getFlashUrl(), key, viewWithModel.getVo());
        } else {
            request.setAttribute(key, viewWithModel.getVo());
        }

        String url = viewWithModel.getUrl();
        //如果返回的没有替换
        if (url.equals(ViewWithModel.SUCCESS)) {
            url = handlerExecutionChain.getSuccessUrl();
        }

        //无返回url 如果jsp 直接返回
        if (StringUtility.isNullOrEmpty(url)) {
            chain.doFilter(request, response);
            return;
        }

        String message = "操作成功！";
        ServletUtility servletUtility = ServletUtility.getInstance();
        String referer = servletUtility.referer(request);
        switch (viewWithModel.getSwitchMode()) {
            case REDIRECT:
                response.sendRedirect(url);
                break;
            case TRANSIT:
                String transitType = Config.getValue(CONFIG.TRANSIT_TYPE);
                if (!StringUtility.isNullOrEmpty(transitType)) {
                    //to 策略模式修改
                    if ("alert".equalsIgnoreCase(transitType)) {
                        if (StringUtility.isNullOrEmpty(url) || StringUtility.matchUrl(referer, url)) {
                            Alert.smile(message);
                        } else {
                            Alert.wait(message, url);
                        }
                        response.sendRedirect(referer);
                    }
                } else {
                    String transitUrl = Config.getValue(CONFIG.TRANSIT_URL);
                    if (transitUrl != null && !transitUrl.startsWith(CONSTANT.HTTP_PROTOCOL)) {
                        transitUrl = Config.getValue(CONFIG.ROOT_PATH) + transitUrl;
                    }
                    response.sendRedirect(transitUrl + "?" + url);
                }
                break;
            case FORWARD:
                //http://manage.sparrowzoo.com/login.jsp?http://manage.sparrowzoo.com/default.jsp?http://manage.sparrowzoo.com/administrator/my.jsp
                String rootPath = Config.getValue(CONFIG.ROOT_PATH);
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
            errorPageSwitch = PageSwitchMode.valueOf(exceptionSwitchMode);
        }
        BusinessException businessException = null;
        //业务异常
        if (exception instanceof BusinessException) {
            businessException = (BusinessException) exception;
        } else {
            businessException = new BusinessException(SPARROW_ERROR.SYSTEM_SERVER_ERROR);
        }
        Result result = Result.FAIL(businessException);
        String url = Config.getValue(CONFIG.ERROR_URL);

        if (StringUtility.isNullOrEmpty(url)) {
            url = "/500.jsp";
        }
        this.flash(request, url, CONSTANT.EXCEPTION_RESULT, result);
        switch (errorPageSwitch) {
            case REDIRECT:
                response.sendRedirect(url);
                break;
            case FORWARD:
                String rootPath = Config.getValue(CONFIG.ROOT_PATH);
                if (url.startsWith(rootPath)) {
                    url = url.substring(rootPath.length());
                }
                RequestDispatcher dispatcher = request.getRequestDispatcher(url);
                dispatcher.forward(request, response);
                break;
            case TRANSIT:
                String transitType = Config.getValue(CONFIG.TRANSIT_TYPE);
                String referer = servletUtility.referer(request);
                if (!StringUtility.isNullOrEmpty(transitType)) {
                    //to 策略模式修改
                    if ("alert".equalsIgnoreCase(transitType)) {
                        if (StringUtility.isNullOrEmpty(url) || StringUtility.matchUrl(referer, url)) {
                            Alert.smile(result.getError());
                        } else {
                            Alert.wait(result.getError(), url);
                        }
                        response.sendRedirect(referer);
                    }
                } else {
                    String transitUrl = Config.getValue(CONFIG.TRANSIT_URL);
                    if (transitUrl != null && !transitUrl.startsWith(CONSTANT.HTTP_PROTOCOL)) {
                        transitUrl = Config.getValue(CONFIG.ROOT_PATH) + transitUrl;
                    }
                    response.sendRedirect(transitUrl + "?" + url);
                }
            default:
        }
    }
}
