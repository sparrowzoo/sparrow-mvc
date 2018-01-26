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

package com.sparrow.mvc;

import com.sparrow.constant.magic.DIGIT;
import com.sparrow.container.Container;
import com.sparrow.core.StrategyFactory;
import com.sparrow.core.spi.ApplicationContext;
import com.sparrow.support.HttpContext;
import com.sparrow.support.UrlRewriteEntity;
import com.sparrow.constant.*;
import com.sparrow.core.Cache;
import com.sparrow.enums.ACTION;
import com.sparrow.support.web.CookieUtility;
import com.sparrow.support.web.WapperedResponse;
import com.sparrow.utility.RegexUtility;
import com.sparrow.utility.StringUtility;
import com.sparrow.utility.Xml;
import com.sparrow.web.support.SparrowServletContainer;
import com.sparrow.support.UrlRewrite;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.channels.FileLock;
import java.util.ArrayList;
import java.util.List;

/**
 * @author harry
 */
public class UrlRewriteFilter extends SparrowServletContainer implements Filter {

    private Logger logger = LoggerFactory.getLogger(UrlRewriteFilter.class);
    private FilterConfig config;

    private CookieUtility cookieUtility;
    private Container container;

    public FilterConfig getConfig() {
        return config;
    }

    private void initRewriteConfig() {

        Document xmlDocument;
        NodeList nodeList = null;
        try {
            xmlDocument = Xml.getXmlDocumentByPath("/urlRewrite.xml", "urlRewrite.dtd");
            nodeList = xmlDocument.getElementsByTagName("page");
        } catch (Exception e) {
            logger.error("init rewrite config", e);
        }

        if (nodeList == null) {
            return;
        }
        List<UrlRewriteEntity> urlRewriteEntities = new ArrayList<UrlRewriteEntity>();
        for (int i = 0; i < nodeList.getLength(); i++) {
            if (nodeList.item(i).getNodeType() != DIGIT.ONE) {
                continue;
            }
            Element element = (Element) nodeList.item(i);
            int cache = 0;
            if (!StringUtility.isNullOrEmpty(element.getAttribute("cache"))) {
                cache = Integer.valueOf(element.getAttribute("cache"));
            }
            UrlRewriteEntity urlRewriteEntity = new UrlRewriteEntity(
                element.getAttribute("url"),
                element.getAttribute("regex"),
                element.getAttribute("directType"),
                cache);
            urlRewriteEntities.add(urlRewriteEntity);
        }
        Cache.getInstance().putToDefaultCache(CACHE_KEY.URL_REWRITE,
            urlRewriteEntities);
    }

    private UrlRewriteEntity getRewriteEntity(String actionKey) {
        List<UrlRewriteEntity> urlRewriteEntities = Cache.getInstance()
            .getValueFromDefaultCache(CACHE_KEY.URL_REWRITE);
        for (UrlRewriteEntity urlRewriteEntity : urlRewriteEntities) {
            // 如果匹配
            String rewriteUrl = RegexUtility.urlRewrite(urlRewriteEntity.getUrl(),
                actionKey, urlRewriteEntity.getRegex());
            if (StringUtility.isNullOrEmpty(rewriteUrl)) {
                continue;
            }
            return new UrlRewriteEntity(rewriteUrl, null,
                urlRewriteEntity.getDirectType(), urlRewriteEntity.getCache());
        }

        String urlRewritePrefix = config.getInitParameter("urlRewritePrefix");
        if (StringUtility.isNullOrEmpty(urlRewritePrefix)) {
            urlRewritePrefix = "forum";
        }
        UrlRewrite urlRewrite = StrategyFactory.getInstance().get(UrlRewrite.class, urlRewritePrefix);
        if (urlRewrite != null) {
            return urlRewrite.parse(actionKey);
        }
        return null;
    }

    @Override
    public void destroy() {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        HttpContext.getContext().setRequest(httpRequest);
        HttpContext.getContext().setResponse(httpResponse);
        String actionKey = super.getActionKey();
        if (actionKey.endsWith(EXTENSION.DO) || actionKey.endsWith(EXTENSION.JSP) || actionKey.endsWith(EXTENSION.JSON)) {
            chain.doFilter(request, response);
            return;
        }
        UrlRewriteEntity urlRewriteEntity = this.getRewriteEntity(actionKey);
        if (urlRewriteEntity == null) {
            chain.doFilter(request, response);
            return;
        }

        ACTION actionStatus = ACTION.valueOf(urlRewriteEntity.getDirectType());
        String jspPageUrl = urlRewriteEntity.getUrl();
        if (!StringUtility.isNullOrEmpty(httpRequest.getQueryString())) {
            jspPageUrl += "?" + httpRequest.getQueryString();
        }
        switch (actionStatus) {
            case URL_REWRITE:
                this.getConfig().getServletContext()
                    .getRequestDispatcher(jspPageUrl)
                    .forward(request, response);
                break;
            case REDIRECT:
                httpResponse.sendRedirect(jspPageUrl);
                break;
            case STATIC_HTML:
                int cacheTime = urlRewriteEntity.getCache();
                String htmlFilePath = this.getConfig().getServletContext()
                    .getRealPath(actionKey);
                if (!htmlFilePath.endsWith(EXTENSION.HTML)) {
                    htmlFilePath += EXTENSION.HTML;
                }
                File htmlFile = new File(htmlFilePath);
                // 静态文件超出有效期(不存在默认为过期)
                boolean isOutTime = true;
                // 文件存在并正常生成成功则判断是否已经过期
                if (htmlFile.exists() && htmlFile.length() != 0) {
                    isOutTime = System.currentTimeMillis()
                        - htmlFile.lastModified() > 1000 * cacheTime;
                }
                // 用户是否在线
                boolean isOnline = !cookieUtility
                    .getUser(httpRequest).getUserId()
                    .equals(USER.VISITOR_ID);
                // 静态文件已经过期或用户在线。则要读动态文件
                if (!isOnline && !isOutTime) {
                    // 页面存在并可以直接访问
                    chain.doFilter(request, response);
                    break;
                }
                String wapperString = null;
                WapperedResponse wapper = new WapperedResponse(httpResponse);
                wapper = new WapperedResponse(httpResponse);
                this.getConfig().getServletContext()
                    .getRequestDispatcher(jspPageUrl)
                    .include(request, wapper);
                wapperString = wapper.getStringData().trim();
                response.getWriter().write(wapperString);
                // 游客登录并且动态文件未出错并且文件已超时）
                if (isOutTime && !isOnline
                    && !wapperString.startsWith(FILE.ERROR_STATIC_HTML)) {
                    String strTitleDirectory = htmlFilePath.substring(0,
                        htmlFilePath.lastIndexOf('\\'));
                    File fTitleDirectory = new File(strTitleDirectory);
                    if (!fTitleDirectory.exists()) {
                        fTitleDirectory.mkdirs();
                    }
                    FileOutputStream fos = new FileOutputStream(htmlFile, false);
                    FileLock fl = fos.getChannel().tryLock();
                    OutputStreamWriter os = new OutputStreamWriter(fos, CONSTANT.CHARSET_UTF_8);
                    BufferedWriter bw = new BufferedWriter(os);
                    if (fl != null && fl.isValid()) {
                        bw.write(wapper.getStringData());
                        fl.release();
                    }
                    bw.flush();
                    os.flush();
                    fos.flush();
                    bw.close();
                    fos.close();
                    os.close();
                }
                break;
            case DIRECT:
            default:
                // 页面存在并可以直接访问
                chain.doFilter(request, response);
                break;
        }
    }

    @Override
    public void init(FilterConfig config) throws ServletException {
        this.initRewriteConfig();
        this.config = config;
        this.container = ApplicationContext.getContainer();
        String cookieUtilityKey=config.getInitParameter("cookieUtility");
        if(StringUtility.isNullOrEmpty(cookieUtilityKey)){
            cookieUtilityKey="cookieUtility";
        }
        this.cookieUtility=this.container.getBean(cookieUtilityKey);
    }
}