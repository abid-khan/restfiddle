/*
 * Copyright 2014 Ranjan Kumar
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.restfiddle.handler.http;

import java.io.IOException;

import org.apache.http.client.methods.HttpDelete;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.stereotype.Component;

import com.restfiddle.dto.RfRequestDTO;

@Component
public class DeleteHandler extends GenericHandler {

    public String process(RfRequestDTO rfRequestDTO) throws IOException {
	String response = "";
	CloseableHttpClient httpclient = HttpClients.createDefault();
	HttpDelete httpDelete = new HttpDelete(rfRequestDTO.getApiUrl());
	httpDelete.addHeader("Content-Type", "application/json");
	try {
	    response = processHttpRequest(httpDelete, httpclient);
	} finally {
	    httpclient.close();
	}
	return response;
    }

}
