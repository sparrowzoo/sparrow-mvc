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

package com.sparrow.mvc.ui.grid.impl;

import com.sparrow.mvc.ui.grid.FieldParser;
import com.sparrow.mvc.ui.grid.attribute.HyperLinkAttribute;
import com.sparrow.protocol.constant.magic.SYMBOL;
import com.sparrow.utility.Config;
import com.sparrow.utility.StringUtility;

import java.util.List;

/**
 * @author harry
 */
public class HyperLinkFieldParserImpl implements FieldParser {
    @Override
    public String parse(String[] config, List<String> valueList) {
        HyperLinkAttribute hyperLinkAttribute = new HyperLinkAttribute(config);
        String title = hyperLinkAttribute.getTitle(valueList);
        String url = hyperLinkAttribute.getUrl();
        for (int i = 0; i < valueList.size(); i++) {
            url = url.replace("{" + i + "}", valueList.get(i));
        }
        //允许配置为空串
        String t = Config.getLanguageValue(title);
        if (t != null) {
            title = t;
        }
        return String.format("<a href=\"%1$s\" title=\"%2$s\" target=\"%4$s\" class=\"%5$s\">%3$s</a>", url, title, hyperLinkAttribute.subString(title), hyperLinkAttribute.getTarget(), hyperLinkAttribute.getCss());
    }
}
