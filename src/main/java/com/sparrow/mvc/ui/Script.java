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

package com.sparrow.mvc.ui;

import java.io.IOException;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;
import com.sparrow.constant.CONFIG;
import com.sparrow.utility.Config;
import com.sparrow.utility.StringUtility;

/**
 * @author harry
 */
@SuppressWarnings("serial")
public class Script extends TagSupport {
    private String src;
    private Boolean asyn=false;

    public String getSrc() {
        return src;
    }

    public void setSrc(String src) {
        this.src = src;
    }

    public Boolean getAsyn() {
        return asyn;
    }

    public void setAsyn(Boolean asyn) {
        this.asyn = asyn;
    }

    @Override
    public int doStartTag() throws JspException {
        int returnValue = TagSupport.SKIP_BODY;
        String writeHTML = "";
        if (this.getSrc().contains("$language")) {
            Object language = this.pageContext.getSession().getAttribute(
                "language");
            if (language == null) {
                language = Config.getValue(CONFIG.LANGUAGE);
            }
            this.setSrc(this.getSrc().replace("$language", language.toString()));
        }


        writeHTML = "<script language=\"javascript\" type=\"text/javascript\"";
        if(this.asyn) {
            writeHTML += " defer asyn=\"true\" ";
        }
        writeHTML+="  src=\"";
        String src = this.getSrc();
        if (src.contains("$resource")) {
            src = src.replace("$resource",
                Config.getValue(CONFIG.RESOURCE));
        }

        if (src.contains("$rootPath")) {
            src = src.replace("$rootPath",
                Config.getValue(CONFIG.ROOT_PATH));
        }

        if (src.contains("$website")) {
            src = src.replace("$website", Config.getValue(CONFIG.WEBSITE));
        }

        writeHTML += src;


        writeHTML += "?v=" + Config.getValue(CONFIG.RESOURCE_VERSION)
            + "\"></script>";

        try {
            if (!StringUtility.isNullOrEmpty(writeHTML)) {
                this.pageContext.getOut().print(writeHTML);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return returnValue;
    }
}
