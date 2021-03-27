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

import com.sparrow.constant.Config;
import com.sparrow.protocol.constant.CONSTANT;
import com.sparrow.mvc.ui.grid.FieldParser;
import com.sparrow.mvc.ui.grid.attribute.ImageAttribute;

import java.util.List;

/**
 * @author harry
 */
public class ImageFieldParserImpl implements FieldParser {
    @Override
    public String parse(String[] config, List<String> valueList) {
        ImageAttribute imageAttribute = new ImageAttribute(config);
        String title = imageAttribute.getTitle(valueList);
        String url = valueList.get(0);
        if (!url.startsWith(CONSTANT.HTTP_PROTOCOL)) {
            url = com.sparrow.utility.Config.getValue(Config.RESOURCE) + url;
        }
        if (title.equals(imageAttribute.getDefaultValue())) {
            return title;
        }
        return String.format("<img src=\"%1$s\" style=\"width:%3$s;height:%4$s\" title=\"%2$s\"/>", url, title, imageAttribute.getWidth(), imageAttribute.getHeight());
    }
}
