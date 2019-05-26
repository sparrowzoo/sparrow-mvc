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

package com.sparrow.mvc.resolver.impl;

import com.sparrow.container.Container;
import com.sparrow.container.ContainerAware;
import com.sparrow.mvc.ServletInvokableHandlerMethod;
import com.sparrow.mvc.resolver.HandlerMethodArgumentResolver;
import com.sparrow.web.support.MethodParameter;

import javax.servlet.http.HttpServletRequest;

/**
 * @author harry
 */
public class RequestParameterArgumentResolverImpl implements HandlerMethodArgumentResolver, ContainerAware {

    private Container container;
    private ParameterSupport parameterSupport=ParameterSupport.getInstance();

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return true;
    }

    @Override
    public Object resolveArgument(MethodParameter methodParameter, ServletInvokableHandlerMethod executionChain,
        HttpServletRequest request) throws Exception {
        return parameterSupport.argumentResolve(this.container,methodParameter, executionChain, request.getParameterMap());
    }
    @Override
    public void aware(Container container, String beanName) {
        this.container=container;
    }
}
