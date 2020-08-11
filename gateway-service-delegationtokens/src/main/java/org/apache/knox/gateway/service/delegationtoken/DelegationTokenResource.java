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

import javax.annotation.PostConstruct;
import javax.inject.Singleton;
import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import com.sun.security.auth.callback.TextCallbackHandler;
import de.thetaphi.forbiddenapis.SuppressForbidden;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1OwnerReference;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1PodStatus;
import io.kubernetes.client.util.Config;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.config.ConnectionConfig;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Constructor;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.List;
import java.util.Map;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static javax.ws.rs.core.MediaType.APPLICATION_XML;


@Singleton
@Path(DelegationTokenResource.RESOURCE_PATH)
public class DelegationTokenResource {
    public static final String JGSS_LOGIN_MOUDLE = "com.sun.security.jgss.initiate";

    static final String RESOURCE_PATH = "delegationtoken/api/v1/dt";

    private boolean authorizePod;

    private boolean allowProxyUserParam;

    private String jaasConfig;

    private static final CredentialsProvider EMPTY_CREDENTIALS_PROVIDER = new BasicCredentialsProvider();
    static {
        EMPTY_CREDENTIALS_PROVIDER.setCredentials(AuthScope.ANY,
                new Credentials() {
                    @Override
                    public Principal getUserPrincipal () {
                        return null;
                    }

                    @Override
                    public String getPassword () {
                        return null;
                    }
                });
    }

    @Context
    HttpServletRequest request;

    @Context
    ServletContext context;

    private CoreV1Api api;

    private CloseableHttpClient httpClient;

    private String dtURLBase;

    @PostConstruct
    public void init() {

        String targetNamenodeAddress = context.getInitParameter("knox.dt.namenode.address");
        dtURLBase = targetNamenodeAddress + "/webhdfs/v1/?op=GETDELEGATIONTOKEN&doas=";

        jaasConfig = context.getInitParameter("knox.dt.jaas.conf");
        authorizePod = Boolean.parseBoolean(context.getInitParameter("knox.dt.authorize.pod"));
        allowProxyUserParam = Boolean.parseBoolean(context.getInitParameter("knox.dt.allow.user.param"));

        final String k8sUrl = context.getInitParameter("knox.dt.k8s.url");
        final String tokenFileLocation = context.getInitParameter("knox.dt.k8s.creds");

        ApiClient k8sClient = Config.fromToken(k8sUrl,
                                               getTokenString(tokenFileLocation),
                                               false); // TODO: PJZ: Not validating SSL yet, for simplicity
//        k8sClient.setSslCaCert(getCertInputStream(certFileLocation));
//        k8sClient.getHttpClient().setReadTimeout(0, TimeUnit.SECONDS); // infinite timeout
        io.kubernetes.client.openapi.Configuration.setDefaultApiClient(k8sClient);

        api = new CoreV1Api();

        // Initialize the HTTP client for requesting HDFS DTs
        final Registry<AuthSchemeProvider> authSchemeRegistry =
                RegistryBuilder.<AuthSchemeProvider>create().register(AuthSchemes.SPNEGO, new SPNegoSchemeFactory(true)).build();

        Registry<ConnectionSocketFactory> registry =
                RegistryBuilder.<ConnectionSocketFactory>create()
                        .register("http", PlainConnectionSocketFactory.getSocketFactory())
                        .build();

        PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager(registry);
        connectionManager.setMaxTotal(5);
        connectionManager.setDefaultMaxPerRoute(2);

        ConnectionConfig connectionConfig = ConnectionConfig.custom()
                .setBufferSize(1024)
                .build();
        connectionManager.setDefaultConnectionConfig(connectionConfig);

        SocketConfig socketConfig = SocketConfig.custom()
                .setSoKeepAlive(false)
//                    .setSoLinger(clientContext.socket().linger())
                .setSoReuseAddress(true)
//                    .setSoTimeout(clientContext.socket().timeout())
//                    .setTcpNoDelay(clientContext.socket().tcpNoDelay())
                .build();
        connectionManager.setDefaultSocketConfig(socketConfig);

        RequestConfig.Builder requestConfigBuilder = RequestConfig.custom();
        httpClient = HttpClients.custom()
                                .setConnectionManager(connectionManager)
                                .setDefaultAuthSchemeRegistry(authSchemeRegistry)
                                .setDefaultCredentialsProvider(EMPTY_CREDENTIALS_PROVIDER)
                                .setDefaultRequestConfig(requestConfigBuilder.build())
                                .build();
    }

    @GET
    @Produces({APPLICATION_JSON, APPLICATION_XML})
    public Response doGet(final String uri) {
        return getDelegationToken(uri);
    }

    @POST
    @Produces({APPLICATION_JSON, APPLICATION_XML})
    public Response doPost(final String uri) {
        return getDelegationToken(uri);
    }

    /**
     *
     * @param uri The FileSystem URI for which the delegation token is being requested.
     *
     */
    private Response getDelegationToken(final String uri) {
        final String namespace = request.getParameter("namespace");
        final String podName   = request.getParameter("pod");
//        final URI fsUri        = URI.create(request.getParameter("uri"));

        System.out.println(uri);

        String proxyUser = null;

        String error = "";

        if (authorizePod || !allowProxyUserParam) {
            try {
                V1Pod podInfo =
                        api.readNamespacedPodWithHttpInfo(podName,
                                (namespace != null ? namespace : "default"),
                                null,
                                null,
                                null).getData();

                V1PodStatus podStatus = podInfo.getStatus();
                if (podStatus != null) {
                    // Validate the pod from which the request is coming
                    boolean isAuthorizedPod = !authorizePod || request.getRemoteAddr().equals(podStatus.getPodIP());

                    System.out.println((isAuthorizedPod ? "Authorized" : "Unauthorized") +
                          " pod " + namespace + "/" + podName + " (" + request.getRemoteAddr() + ")"); // TODO: PJZ: Logging

                    if (authorizePod && !isAuthorizedPod) {
                        return Response.serverError().entity("{\n  \"error\" : \"Pod is not authorized.\"\n}").build();
                    }

                    if (isAuthorizedPod) {
                        proxyUser = getProxyUser(podInfo);
                    }
                }
            } catch (ApiException e) {
                e.printStackTrace(); // TODO: PJZ: Logging
                return Response.serverError().entity("{\n  \"error\" : \"Invalid pod: " + namespace + "/" + podName + "\"\n}").build();
            }
        }

        if (proxyUser == null && allowProxyUserParam) {
            proxyUser = request.getParameter("user");
        }

        System.out.println("Kubernetes job owner: " + proxyUser); // TODO: PJZ: Logging
        try {
            // webhdfs/v1/?op=GETDELEGATIONTOKEN[&renewer=<USER>][&service=<SERVICE>][&kind=<KIND>]&doas=
            HttpUriRequest tokenRequest = RequestBuilder.get(dtURLBase + proxyUser).build();

            // Request the delegation token as the knox user, on behalf of the proxyUser
            Subject subject = getKnoxSubject();
            HttpResponse tokenResponse =  Subject.doAs(subject, (PrivilegedAction<HttpResponse>) () -> {
                                                                    HttpResponse r = null;
                                                                    try {
                                                                        r = httpClient.execute(tokenRequest);
                                                                    } catch (IOException e) {
                                                                        e.printStackTrace();
                                                                    }
                                                                    return r;
                                                                });
            int statusCode = tokenResponse.getStatusLine().getStatusCode();
            System.out.println(statusCode);
            String delegationToken = null;
            HttpEntity entity = tokenResponse.getEntity();
            if (entity != null) {
                delegationToken = parseDelegationTokenResponse(EntityUtils.toString(entity, StandardCharsets.UTF_8));
            }
            return Response.ok("{ \"delegation_token\": \"" + delegationToken + "\" }").build();
        } catch (Exception e) {
            e.printStackTrace(); // TODO: PJZ: Logging
            error = e.getMessage();
        }

        return Response.serverError().entity("{\n  \"error\" : \"" + error + "\"\n}").build();
    }

    private String parseDelegationTokenResponse(String entityContent) {
        System.out.println(entityContent);
        String[] parsedResponseContent = entityContent.split(":");
        String dt = parsedResponseContent[2];
        dt = dt.substring(1, dt.indexOf('\"', 1));
        return dt;
    }

    /**
     * Login the knox user based on the specified JAAS configuration.
     *
     * @return The authenticated knox user Subject.
     */
    @SuppressForbidden
    private Subject getKnoxSubject() throws Exception {
        Configuration jaasConf;
        try {
            jaasConf =
                new JAASClientConfig(new File(jaasConfig != null ? jaasConfig : "/jaas.conf").getCanonicalFile().toURI().toURL());
        } catch (Exception e) {
            e.printStackTrace(); // TODO: PJZ: Logging
            throw new Exception(e.toString(), e);
        }

        LoginContext lc = new LoginContext(JGSS_LOGIN_MOUDLE,
                                           null,
                                           new TextCallbackHandler(),
                                           jaasConf);
        lc.login();
        return lc.getSubject();
    }

    /**
     * Determine the proxy user from the calling Kubernetes pod.
     *
     * @param podInfo The Kubernetes pod info
     *
     * @return The value of the &quot;user&quot; pod annotation
     */
    private String getProxyUser(final V1Pod podInfo) {
        String proxyUser = null;

        // Get the user to proxy for the delegation token request
        String userAnnotationValue = null;
        V1ObjectMeta podMetadata = podInfo.getMetadata();
        if (podMetadata != null) {
            List<V1OwnerReference> ownerRefs = podMetadata.getOwnerReferences();
            if (ownerRefs != null) {
                for (V1OwnerReference oref : ownerRefs) {
                    System.out.println("Pod Owner Reference: kind=" + oref.getKind() + ", name=" + oref.getName());
                }
            }

            Map<String, String> podAnnotations = podMetadata.getAnnotations();
            if (podAnnotations != null) {
                for (Map.Entry<String, String> entry : podAnnotations.entrySet()) {
                    System.out.println("Pod Annotation: " + entry.getKey() + "=" + entry.getValue()); // TODO: PJZ: DELETE ME: DEBUG ONLY
                }
                // TODO: PJZ: Get the value of the annotation representing the user who initiated the k8s job
                userAnnotationValue = podAnnotations.get("user");
            }
        }

        proxyUser = userAnnotationValue;
        if (proxyUser == null) {
            System.out.println("Kubernetes job owner unavailable"); // TODO: PJZ: Logging
        }

        return proxyUser;
    }

    /**
     * Get the Kubernetes auth token from the specified file location.
     *
     * @param tokenFileLocation The path to the Kubernetes auth token file.
     *
     * @return The Kubernetes auth token.
     */
    String getTokenString(String tokenFileLocation) {
        String token = "";
        if (tokenFileLocation != null && tokenFileLocation.length() > 0) {
            try (InputStream is = Files.newInputStream(Paths.get(tokenFileLocation));
                 BufferedReader buf = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                token = buf.readLine();
            } catch (IOException e) {
                //throw new TokenServiceException(ex.getMessage(), ErrorCode.BEARER_TOKEN_EXCEPTION);
                throw new RuntimeException("Error getting client token: " + e.getMessage()); // TODO: PJZ: Better exception
            }
        }
        return token;
    }

    private static final class JAASClientConfig extends Configuration {
        private static final Configuration baseConfig = Configuration.getConfiguration();

        private Configuration configFile;

        JAASClientConfig(URL configFileURL) throws Exception {
            if (configFileURL != null) {
                this.configFile = ConfigurationFactory.create(configFileURL.toURI());
            }
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            AppConfigurationEntry[] result = null;

            // Try the config file if it exists
            if (configFile != null) {
                result = configFile.getAppConfigurationEntry(name);
            }

            // If the entry isn't there, delegate to the base configuration
            if (result == null) {
                result = baseConfig.getAppConfigurationEntry(name);
            }

            return result;
        }
    }

    @SuppressWarnings("PMD.AvoidAccessibilityAlteration")
    private static class ConfigurationFactory {
        private static final Class implClazz;
        static {
            // Oracle and OpenJDK use the Sun implementation
            String implName = System.getProperty("java.vendor").contains("IBM") ?
                    "com.ibm.security.auth.login.ConfigFile" : "com.sun.security.auth.login.ConfigFile";

            Class clazz = null;
            try {
                clazz = Class.forName(implName, false, Thread.currentThread().getContextClassLoader());
            } catch (ClassNotFoundException e) {
                e.printStackTrace(); // TODO: PJZ: Logging
            }

            implClazz = clazz;
        }

        static Configuration create(URI uri) {
            Configuration config = null;

            if (implClazz != null) {
                try {
                    Constructor ctor = implClazz.getDeclaredConstructor(URI.class);
                    config = (Configuration) ctor.newInstance(uri);
                } catch (Exception e) {
                    e.printStackTrace(); // TODO: PJZ: Logging
                }
            } else {
                System.out.println("No impl class!"); // TODO: PJZ: Logging
            }

            return config;
        }
    }

}
