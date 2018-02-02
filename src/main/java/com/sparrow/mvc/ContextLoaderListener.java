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

import com.sparrow.constant.CONFIG;
import com.sparrow.constant.magic.SYMBOL;
import com.sparrow.constant.SYS_OBJECT_NAME;
import com.sparrow.core.spi.ApplicationContext;
import com.sparrow.datasource.DataSourceFactory;
import com.sparrow.support.Initializer;
import com.sparrow.utility.Config;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

/**
 * @author harry
 */
public class ContextLoaderListener implements ServletContextListener {

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {

    }

    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        String beansXmlPath= servletContextEvent.getServletContext().getInitParameter("contextConfigLocation");
        String systemConfig= servletContextEvent.getServletContext().getInitParameter("configLocation");
        ApplicationContext.getContainer().init(beansXmlPath,systemConfig);
    }
}
