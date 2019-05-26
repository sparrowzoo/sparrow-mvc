package com.sparrow.mvc.resolver.impl;

import com.sparrow.cg.MethodAccessor;
import com.sparrow.protocol.constant.magic.SYMBOL;
import com.sparrow.container.Container;
import com.sparrow.core.TypeConverter;
import com.sparrow.mvc.ServletInvokableHandlerMethod;
import com.sparrow.protocol.POJO;
import com.sparrow.utility.CollectionsUtility;
import com.sparrow.utility.HtmlUtility;
import com.sparrow.utility.StringUtility;
import com.sparrow.web.support.MethodParameter;

import java.util.List;
import java.util.Map;

/**
 * Created by harry on 2018/2/1.
 */
class ParameterSupport {
    private static ParameterSupport parameterSupport = new ParameterSupport();

    public static ParameterSupport getInstance() {
        return parameterSupport;
    }

    public Object argumentResolve(Container container, MethodParameter methodParameter, ServletInvokableHandlerMethod executionChain, Map<String, String[]> parameterMap) {
        String parameterName = methodParameter.getParameterName();
        String[] parameters = null;
        String parameter = null;
        if (POJO.class.isAssignableFrom(methodParameter.getParameterType())) {
            Object entity;
            try {
                entity = methodParameter.getParameterType().newInstance();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            MethodAccessor methodAccessor = container
                    .getProxyBean(methodParameter.getParameterType());

            List<TypeConverter> methods = container.getFieldList(methodParameter.getParameterType());
            for (TypeConverter field : methods) {
                String parameterName4Request = StringUtility.setFirstByteLowerCase(field.getName());
                parameters = parameterMap.get(parameterName4Request);

                if (CollectionsUtility.isNullOrEmpty(parameters)) {
                    continue;
                }
                parameter = parameters[0];
                if (executionChain.isValidateRequest()) {
                    parameter = HtmlUtility.encode(parameter);
                }
                methodAccessor.set(entity, field.getName(), field.convert(parameter));
            }
            return entity;
        }
        parameters = parameterMap.get(parameterName);
        if (CollectionsUtility.isNullOrEmpty(parameters)) {
            return null;
        }
        parameter = parameters[0];
        if (methodParameter.getParameterType().equals(String.class)) {
            if (CollectionsUtility.isNullOrEmpty(parameters)) {
                return SYMBOL.EMPTY;
            }
            if (executionChain.isValidateRequest()) {
                parameter = HtmlUtility.encode(parameter);
            }
            return parameter;
        }
        if (methodParameter.getParameterType().equals(String[].class)) {
            if (executionChain.isValidateRequest()) {
                for (int p = 0; p < parameters.length; p++) {
                    parameters[p] = HtmlUtility.encode(parameters[p]);
                }
            }
            return parameters;
        }
        return new TypeConverter(parameterName, methodParameter.getParameterType()).convert(parameter);
    }
}
