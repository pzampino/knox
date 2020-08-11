/*
 *
 *  * Licensed to the Apache Software Foundation (ASF) under one or more
 *  * contributor license agreements. See the NOTICE file distributed with this
 *  * work for additional information regarding copyright ownership. The ASF
 *  * licenses this file to you under the Apache License, Version 2.0 (the
 *  * "License"); you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  * License for the specific language governing permissions and limitations under
 *  * the License.
 *
 */
package org.apache.knox.gateway.service.delegationtoken;

import org.apache.hadoop.security.UserGroupInformation;
import org.easymock.EasyMock;
import org.junit.Test;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;

public class DelegationTokenResourceTest {


    @Test
    public void testValidPod() {
        final String podNS      = "default";
        final String podName    = "ic-test-job-rcgzb";
        final String podAddress = "172.17.0.3";
        final String fsUri      = "/";

        DelegationTokenResource dtr = createResource(podNS, podName, podAddress, fsUri);

        UserGroupInformation knoxUser = UserGroupInformation.createUserForTesting("knox", new String[]{});
        UserGroupInformation.setLoginUser(knoxUser);

        dtr.init();
        dtr.doGet(fsUri);
    }

    @Test
    public void testInvalidPodAddress() {
        final String podNS      = "default";
        final String podName    = "ic-test-job-rcgzb";
        final String podAddress = "172.17.0.4";
        final String fsUri      = "/";

        DelegationTokenResource dtr = createResource(podNS, podName, podAddress, fsUri);

        UserGroupInformation knoxUser = UserGroupInformation.createUserForTesting("knox", new String[]{});
        UserGroupInformation.setLoginUser(knoxUser);

        dtr.init();
        dtr.doGet(fsUri);
    }

    private static HttpServletRequest createHttpRequest(final String podNamespace,
                                                        final String podName,
                                                        final String podAddress,
                                                        final String uri) {
        HttpServletRequest request = EasyMock.createNiceMock(HttpServletRequest.class);
        EasyMock.expect(request.getParameter("namespace")).andReturn(podNamespace).anyTimes();
        EasyMock.expect(request.getParameter("pod")).andReturn(podName).anyTimes();
        EasyMock.expect(request.getParameter("uri")).andReturn(uri).anyTimes();
        EasyMock.expect(request.getRemoteAddr()).andReturn(podAddress).anyTimes();
        EasyMock.replay(request);
        return request;
    }

    private static ServletContext createServletContext() {
        ServletContext sc = EasyMock.createNiceMock(ServletContext.class);
        EasyMock.expect(sc.getInitParameter("knox.dt.namenode.address")).andReturn("http://nn-host:20101").anyTimes();
        EasyMock.expect(sc.getInitParameter("knox.dt.jaas.conf")).andReturn(null).anyTimes();
        EasyMock.expect(sc.getInitParameter("knox.dt.k8s.url")).andReturn(null).anyTimes();
        EasyMock.expect(sc.getInitParameter("knox.dt.k8s.creds")).andReturn(null).anyTimes();
        EasyMock.expect(sc.getInitParameter("knox.dt.authorize.pod")).andReturn("false").anyTimes();
        EasyMock.expect(sc.getInitParameter("knox.dt.allow.user.param")).andReturn("true").anyTimes();
        EasyMock.replay(sc);
        return sc;
    }

    private static DelegationTokenResource createResource(final String podNamespace,
                                                          final String podName,
                                                          final String podAddress,
                                                          final String uri) {
        DelegationTokenResource dtr = new DelegationTokenResource();
        try {
            Field contextField = dtr.getClass().getDeclaredField("context");
            contextField.setAccessible(true);
            contextField.set(dtr, createServletContext());

            Field requestField = dtr.getClass().getDeclaredField("request");
            requestField.setAccessible(true);
            requestField.set(dtr, createHttpRequest(podNamespace, podName, podAddress, uri));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dtr;
    }

}
