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

import com.sparrow.constant.CONFIG_KEY_LANGUAGE;
import com.sparrow.core.spi.JsonFactory;
import com.sparrow.enums.ALERT_TYPE;
import com.sparrow.protocol.POJO;
import com.sparrow.support.web.HttpContext;
import com.sparrow.utility.Config;
import com.sparrow.utility.StringUtility;

/**
 * //{msg:'',type:'sad',title:'',url:'',waitMessage:''}
 *
 * @author harry
 */
public class Alert implements POJO {

    public static void smile(String msg) {
        new Alert(msg, ALERT_TYPE.SMILE, null, null, null).alert();
    }

    public static void sad(String msg) {
        new Alert(msg, ALERT_TYPE.SAD, null, null, null).alert();
    }

    public static void wait(String msg, String url) {
        new Alert(msg, ALERT_TYPE.WAIT, null, url, null).alert();
    }

    public Alert(String msg, ALERT_TYPE type, String title, String url, String waitMessage) {
        this.msg = msg;
        this.type = type.toString().toLowerCase();
        if (StringUtility.isNullOrEmpty(type)) {
            this.type = ALERT_TYPE.SMILE.toString().toLowerCase();
        }
        this.title = title;
        if (StringUtility.isNullOrEmpty(title)) {
            this.title = Config.getLanguageValue(CONFIG_KEY_LANGUAGE.ALERT_TITLE_PREFIX + this.type);
        }
        this.url = url;
        this.waitMessage = waitMessage;
        if (type.equals(ALERT_TYPE.WAIT) && StringUtility.isNullOrEmpty(waitMessage)) {
            this.waitMessage = Config.getLanguageValue(CONFIG_KEY_LANGUAGE.WAIT_MESSAGE);
        }
    }

    private String msg;
    private String type;
    private String title;
    private String url;
    private String waitMessage;

    public String getMsg() {
        return msg;
    }

    public String getType() {
        return type;
    }

    public String getTitle() {
        return title;
    }

    public String getUrl() {
        return url;
    }

    public String getWaitMessage() {
        return waitMessage;
    }

    private void alert() {
        HttpContext.getContext().execute("$.alert(" + JsonFactory.getProvider().toString(this) + ");");
    }
}
