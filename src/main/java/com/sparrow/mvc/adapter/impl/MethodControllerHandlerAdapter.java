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

package com.sparrow.mvc.adapter.impl;

import com.sparrow.mvc.ServletInvocableHandlerMethod;
import com.sparrow.mvc.adapter.HandlerAdapter;
import com.sparrow.mvc.resolver.HandlerMethodArgumentResolver;
import com.sparrow.mvc.resolver.impl.HandlerMethodArgumentResolverComposite;
import com.sparrow.mvc.resolver.impl.RequestParameterArgumentResolverImpl;
import com.sparrow.mvc.result.MethodReturnValueResolverHandler;
import com.sparrow.mvc.result.impl.JsonMethodReturnValueResolverHandlerImpl;
import com.sparrow.mvc.result.impl.MethodReturnValueResolverHandlerComposite;
import com.sparrow.mvc.result.impl.ViewWithModelMethodReturnValueResolverHandlerImpl;

import java.util.ArrayList;
import java.util.List;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author harry
 */
public class MethodControllerHandlerAdapter implements HandlerAdapter {

    private HandlerMethodArgumentResolverComposite argumentResolverComposite;

    private MethodReturnValueResolverHandlerComposite returnValueResolverHandlerComposite;

    public MethodControllerHandlerAdapter() {
        this.initArgumentResolvers();
        this.initReturnValueResolvers();
    }

    @Override
    public boolean supports(Object handler) {
        return handler instanceof ServletInvocableHandlerMethod;
    }

    @Override
    public Object handle(FilterChain chain, HttpServletRequest request, HttpServletResponse response,
                         Object handler) throws Exception {
        ServletInvocableHandlerMethod invocableHandlerMethod = (ServletInvocableHandlerMethod) handler;
        invocableHandlerMethod.setHandlerMethodArgumentResolverComposite(argumentResolverComposite);
        //返回值处理handler 只会存在一个
        if (!this.returnValueResolverHandlerComposite.support(invocableHandlerMethod)) {
            throw new RuntimeException("return value resolver handler not found");
        }
        invocableHandlerMethod.setController(invocableHandlerMethod.getController());
        return invocableHandlerMethod.invokeAndHandle(chain, request, response);
    }

    @Override
    public long getLastModified(HttpServletRequest request, Object handler) {
        return 0;
    }

    /**
     * 初始化参数解析器
     */
    private void initArgumentResolvers() {
        this.argumentResolverComposite = new HandlerMethodArgumentResolverComposite();
        List<HandlerMethodArgumentResolver> handlerMethodArgumentResolvers = new ArrayList<HandlerMethodArgumentResolver>();
        HandlerMethodArgumentResolver argumentResolver = new RequestParameterArgumentResolverImpl();
        handlerMethodArgumentResolvers.add(argumentResolver);
        this.argumentResolverComposite.addResolvers(handlerMethodArgumentResolvers);
    }

    /**
     * 初始化返回值解析器
     */
    private void initReturnValueResolvers() {
        this.returnValueResolverHandlerComposite = new MethodReturnValueResolverHandlerComposite();
        List<MethodReturnValueResolverHandler> methodReturnValueResolverHandlers = new ArrayList<MethodReturnValueResolverHandler>();
        MethodReturnValueResolverHandler viewWithModelMethodReturnValueResolverHandler = new ViewWithModelMethodReturnValueResolverHandlerImpl();
        MethodReturnValueResolverHandler jsonMethodReturnValueResolverHandler = new JsonMethodReturnValueResolverHandlerImpl();
        methodReturnValueResolverHandlers.add(viewWithModelMethodReturnValueResolverHandler);
        methodReturnValueResolverHandlers.add(jsonMethodReturnValueResolverHandler);
        this.returnValueResolverHandlerComposite.addResolvers(methodReturnValueResolverHandlers);
    }
}
