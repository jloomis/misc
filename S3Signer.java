package com.ning.http.client.oauth;

import com.ning.http.client.Request;
import com.ning.http.client.RequestBuilderBase;
import com.ning.http.client.SignatureCalculator;
import com.ning.http.util.Base64;
import com.ning.http.util.UTF8Codec;
import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.SortedMap;
import java.util.TimeZone;
import java.util.TreeMap;

/***
 * Amazon S3 signature calculator for use with AsyncHttpClient (https://github.com/AsyncHttpClient/)
 *
 * Requires patch to AHC's ThreadSafeHMAC.java to allow null userAuth:
     private final Mac mac;

+    public ThreadSafeHMAC(ConsumerKey consumerAuth) {
+        this(consumerAuth, null);
+    }
+
     public ThreadSafeHMAC(ConsumerKey consumerAuth, RequestToken userAuth) {
-        byte[] keyBytes = UTF8Codec.toUTF8(consumerAuth.getSecret() + "&" + userAuth.getSecret());
+        byte[] keyBytes = userAuth == null? UTF8Codec.toUTF8(consumerAuth.getSecret()) : UTF8Codec.toUTF8(consumerAuth.getSecret() + "&" + userAuth.getSecret());
         SecretKeySpec signingKey = new SecretKeySpec(keyBytes, HMAC_SHA1_ALGORITHM);
 *
 * Usage:
 * SignatureCalculator signatureCalculator = new S3Signer(new ConsumerKey(MY_AWS_ID, MY_AWS_SECRET));
 * AsyncHttpClient.BoundRequestBuilder builder = client.prepareGet(url);
 * builder.setSignatureCalculator(signatureCalculator);
 *
 * additional dependencies:
 *         <dependency>
             <groupId>joda-time</groupId>
             <artifactId>joda-time</artifactId>
             <version>2.1</version>
         </dependency>
         <dependency>
             <groupId>commons-lang</groupId>
             <artifactId>commons-lang</artifactId>
             <version>2.4</version>
         </dependency>
 */

public class S3Signer implements SignatureCalculator {
    public final static String HEADER_AUTHORIZATION = "Authorization";
    protected final ThreadSafeHMAC mac;

    protected final ConsumerKey consumerAuth;

    public S3Signer(ConsumerKey consumerAuth) {
        this.consumerAuth = consumerAuth;
        this.mac = new ThreadSafeHMAC(consumerAuth);
    }

    @Override
    public void calculateAndAddSignature(String url, Request request, RequestBuilderBase<?> requestBuilder) {
        String date = getDate();
        requestBuilder.addHeader("Date", date);
        String sig = calculateSignature(request, date);
        String authHeader = "AWS " + consumerAuth.getKey() + ":" + sig;
        requestBuilder.setHeader(HEADER_AUTHORIZATION, authHeader);
    }

    public String calculateSignature(Request request, String date){
        StringBuilder signedText = new StringBuilder(100);
        signedText.append(request.getMethod()).append("\n");
        signedText.append("\n");
        String contentType = request.getHeaders().getFirstValue("Content-Type");
        if(contentType != null)
            signedText.append(contentType);
        signedText.append("\n");
        signedText.append(date).append("\n");
        signedText.append(getCanonicalizedHeadersForStringToSign(request));
        signedText.append(getPath(request.getUrl()));
        byte[] rawBase = UTF8Codec.toUTF8(signedText.toString());
        byte[] rawSignature = mac.digest(rawBase);
        return Base64.encode(rawSignature);
    }

// following 3 methods from aws-jdk: http://aws.amazon.com/sdkforjava/
/*
 * Copyright 2010-2012 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
    protected List<String> getHeadersForStringToSign(Request request) {
        List<String> headersToSign = new ArrayList<String>();
        for (Map.Entry<String, List<String>> entry : request.getHeaders().entrySet()) {
            String key = entry.getKey();
            String lowerCaseKey = key.toLowerCase();
            if (lowerCaseKey.startsWith("x-amz")
                    || lowerCaseKey.equals("host")) {
                headersToSign.add(key);
            }
        }

        Collections.sort(headersToSign);
        return headersToSign;
    }

    protected String getPath(String url) {
        URI uri = URI.create(url);
        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        return path;
    }

    protected String getCanonicalizedHeadersForStringToSign(Request request) {
        List<String> headersToSign = getHeadersForStringToSign(request);

        for (int i = 0; i < headersToSign.size(); i++) {
            headersToSign.set(i, headersToSign.get(i).toLowerCase());
        }

        SortedMap<String, String> sortedHeaderMap = new TreeMap<String, String>();
        for (Map.Entry<String, List<String>> entry : request.getHeaders().entrySet()) {
            if (headersToSign.contains(entry.getKey().toLowerCase())) {
                sortedHeaderMap.put(entry.getKey().toLowerCase(), StringUtils.join(entry.getValue().iterator(), ","));
            }
        }

        StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> entry : sortedHeaderMap.entrySet()) {
            builder.append(entry.getKey().toLowerCase()).append(":")
                    .append(entry.getValue()).append("\n");
        }

        return builder.toString();
    }


    private static final DateTimeFormatter f = DateTimeFormat.forPattern("EEE, dd MMM yyyy HH:mm:ss z")
                                            .withLocale(Locale.ENGLISH)
                                            .withZone(DateTimeZone.forTimeZone(TimeZone.getTimeZone("GMT")));
    public String getDate() {
        return f.print(System.currentTimeMillis());
    }
}