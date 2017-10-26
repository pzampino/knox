/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.gateway;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.ws.rs.core.MediaType;

import io.restassured.http.ContentType;
import com.mycila.xmltool.XMLDoc;
import com.mycila.xmltool.XMLTag;
import io.restassured.response.ResponseBody;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.hadoop.gateway.config.GatewayConfig;
import org.apache.hadoop.gateway.services.DefaultGatewayServices;
import org.apache.hadoop.gateway.services.GatewayServices;
import org.apache.hadoop.gateway.services.ServiceLifecycleException;
import org.apache.hadoop.gateway.services.topology.TopologyService;
import org.apache.hadoop.gateway.topology.Param;
import org.apache.hadoop.gateway.topology.Provider;
import org.apache.hadoop.gateway.topology.Service;
import org.apache.hadoop.gateway.topology.Topology;
import org.apache.hadoop.gateway.util.XmlUtils;
import org.apache.hadoop.test.TestUtils;
import org.apache.http.HttpStatus;
import org.apache.log4j.Appender;
import org.hamcrest.MatcherAssert;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import static io.restassured.RestAssured.given;
import static junit.framework.TestCase.assertTrue;
import static org.apache.hadoop.test.TestUtils.LOG_ENTER;
import static org.apache.hadoop.test.TestUtils.LOG_EXIT;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.xml.HasXPath.hasXPath;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class GatewayAdminTopologyFuncTest {

  private static Logger LOG = LoggerFactory.getLogger( GatewayAdminTopologyFuncTest.class );

  public static Enumeration<Appender> appenders;
  public static GatewayConfig config;
  public static GatewayServer gateway;
  public static String gatewayUrl;
  public static String clusterUrl;
  private static GatewayTestDriver driver = new GatewayTestDriver();

  @BeforeClass
  public static void setupSuite() throws Exception {
    //appenders = NoOpAppender.setUp();
    driver.setupLdap(0);
    setupGateway(new GatewayTestConfig());
  }

  @AfterClass
  public static void cleanupSuite() throws Exception {
    gateway.stop();
    driver.cleanup();
    //FileUtils.deleteQuietly( new File( config.getGatewayHomeDir() ) );
    //NoOpAppender.tearDown( appenders );
  }

  public static void setupGateway(GatewayTestConfig testConfig) throws Exception {

    File targetDir = new File( System.getProperty( "user.dir" ), "target" );
    File gatewayDir = new File( targetDir, "gateway-home-" + UUID.randomUUID() );
    gatewayDir.mkdirs();

    config = testConfig;
    testConfig.setGatewayHomeDir( gatewayDir.getAbsolutePath() );

    File topoDir = new File( testConfig.getGatewayTopologyDir() );
    topoDir.mkdirs();

    File deployDir = new File( testConfig.getGatewayDeploymentDir() );
    deployDir.mkdirs();

    File providerConfigDir = new File(testConfig.getGatewayConfDir(), "shared-providers");
    providerConfigDir.mkdirs();

    File descriptorsDir = new File(testConfig.getGatewayConfDir(), "descriptors");
    descriptorsDir.mkdirs();

    File descriptor = new File( topoDir, "admin.xml" );
    FileOutputStream stream = new FileOutputStream( descriptor );
    createKnoxTopology().toStream( stream );
    stream.close();

    File descriptor2 = new File( topoDir, "test-cluster.xml" );
    FileOutputStream stream2 = new FileOutputStream( descriptor2 );
    createNormalTopology().toStream( stream2 );
    stream.close();

    DefaultGatewayServices srvcs = new DefaultGatewayServices();
    Map<String,String> options = new HashMap<>();
    options.put( "persist-master", "false" );
    options.put( "master", "password" );

    try {
      srvcs.init( testConfig, options );
    } catch ( ServiceLifecycleException e ) {
      e.printStackTrace(); // I18N not required.
    }
    gateway = GatewayServer.startGateway( testConfig, srvcs );
    MatcherAssert.assertThat( "Failed to start gateway.", gateway, notNullValue() );

    LOG.info( "Gateway port = " + gateway.getAddresses()[ 0 ].getPort() );

    gatewayUrl = "http://localhost:" + gateway.getAddresses()[0].getPort() + "/" + config.getGatewayPath();
    clusterUrl = gatewayUrl + "/admin";
  }

  private static XMLTag createNormalTopology() {
    XMLTag xml = XMLDoc.newDocument( true )
        .addRoot( "topology" )
        .addTag( "gateway" )
        .addTag( "provider" )
        .addTag( "role" ).addText( "webappsec" )
        .addTag( "name" ).addText( "WebAppSec" )
        .addTag( "enabled" ).addText( "true" )
        .addTag( "param" )
        .addTag( "name" ).addText( "csrf.enabled" )
        .addTag( "value" ).addText( "true" ).gotoParent().gotoParent()
        .addTag( "provider" )
        .addTag( "role" ).addText( "authentication" )
        .addTag( "name" ).addText( "ShiroProvider" )
        .addTag( "enabled" ).addText( "true" )
        .addTag( "param" )
        .addTag( "name" ).addText( "main.ldapRealm" )
        .addTag( "value" ).addText( "org.apache.hadoop.gateway.shirorealm.KnoxLdapRealm" ).gotoParent()
        .addTag( "param" )
        .addTag( "name" ).addText( "main.ldapRealm.userDnTemplate" )
        .addTag( "value" ).addText( "uid={0},ou=people,dc=hadoop,dc=apache,dc=org" ).gotoParent()
        .addTag( "param" )
        .addTag( "name" ).addText( "main.ldapRealm.contextFactory.url" )
        .addTag( "value" ).addText( driver.getLdapUrl() ).gotoParent()
        .addTag( "param" )
        .addTag( "name" ).addText( "main.ldapRealm.contextFactory.authenticationMechanism" )
        .addTag( "value" ).addText( "simple" ).gotoParent()
        .addTag( "param" )
        .addTag( "name" ).addText( "urls./**" )
        .addTag( "value" ).addText( "authcBasic" ).gotoParent().gotoParent()
        .addTag( "provider" )
        .addTag( "role" ).addText( "identity-assertion" )
        .addTag( "enabled" ).addText( "true" )
        .addTag( "name" ).addText( "Default" ).gotoParent()
        .addTag( "provider" )
        .addTag( "role" ).addText( "authorization" )
        .addTag( "enabled" ).addText( "true" )
        .addTag( "name" ).addText( "AclsAuthz" ).gotoParent()
        .addTag( "param" )
        .addTag( "name" ).addText( "webhdfs-acl" )
        .addTag( "value" ).addText( "hdfs;*;*" ).gotoParent()
        .gotoRoot()
        .addTag( "service" )
        .addTag( "role" ).addText( "WEBHDFS" )
        .addTag( "url" ).addText( "http://localhost:50070/webhdfs/v1" ).gotoParent()
        .gotoRoot();
//     System.out.println( "GATEWAY=" + xml.toString() );
    return xml;
  }

  private static XMLTag createKnoxTopology() {
    XMLTag xml = XMLDoc.newDocument( true )
        .addRoot( "topology" )
        .addTag( "gateway" )
        .addTag( "provider" )
        .addTag( "role" ).addText( "authentication" )
        .addTag( "name" ).addText( "ShiroProvider" )
        .addTag( "enabled" ).addText( "true" )
        .addTag( "param" )
        .addTag( "name" ).addText( "main.ldapRealm" )
        .addTag( "value" ).addText( "org.apache.hadoop.gateway.shirorealm.KnoxLdapRealm" ).gotoParent()
        .addTag( "param" )
        .addTag( "name" ).addText( "main.ldapRealm.userDnTemplate" )
        .addTag( "value" ).addText( "uid={0},ou=people,dc=hadoop,dc=apache,dc=org" ).gotoParent()
        .addTag( "param" )
        .addTag( "name" ).addText( "main.ldapRealm.contextFactory.url" )
        .addTag( "value" ).addText( driver.getLdapUrl() ).gotoParent()
        .addTag( "param" )
        .addTag( "name" ).addText( "main.ldapRealm.contextFactory.authenticationMechanism" )
        .addTag( "value" ).addText( "simple" ).gotoParent()
        .addTag( "param" )
        .addTag( "name" ).addText( "urls./**" )
        .addTag( "value" ).addText( "authcBasic" ).gotoParent().gotoParent()
        .addTag("provider")
        .addTag( "role" ).addText( "authorization" )
        .addTag( "name" ).addText( "AclsAuthz" )
        .addTag( "enabled" ).addText( "true" )
        .addTag("param")
        .addTag("name").addText("knox.acl")
        .addTag("value").addText("admin;*;*").gotoParent().gotoParent()
        .addTag("provider")
        .addTag( "role" ).addText( "identity-assertion" )
        .addTag( "enabled" ).addText( "true" )
        .addTag( "name" ).addText( "Default" ).gotoParent()
        .gotoRoot()
        .addTag( "service" )
        .addTag( "role" ).addText( "KNOX" )
        .gotoRoot();
    // System.out.println( "GATEWAY=" + xml.toString() );
    return xml;
  }

  private static XMLTag createProviderConfiguration() {
    XMLTag xml = XMLDoc.newDocument( true )
            .addRoot( "gateway" )
            .addTag( "provider" )
            .addTag( "role" ).addText( "authentication" )
            .addTag( "name" ).addText( "ShiroProvider" )
            .addTag( "enabled" ).addText( "true" )
            .addTag( "param" )
            .addTag( "name" ).addText( "main.ldapRealm" )
            .addTag( "value" ).addText( "org.apache.hadoop.gateway.shirorealm.KnoxLdapRealm" ).gotoParent()
            .addTag( "param" )
            .addTag( "name" ).addText( "main.ldapRealm.userDnTemplate" )
            .addTag( "value" ).addText( "uid={0},ou=people,dc=hadoop,dc=apache,dc=org" ).gotoParent()
            .addTag( "param" )
            .addTag( "name" ).addText( "main.ldapRealm.contextFactory.url" )
            .addTag( "value" ).addText( driver.getLdapUrl() ).gotoParent()
            .addTag( "param" )
            .addTag( "name" ).addText( "main.ldapRealm.contextFactory.authenticationMechanism" )
            .addTag( "value" ).addText( "simple" ).gotoParent()
            .addTag( "param" )
            .addTag( "name" ).addText( "urls./**" )
            .addTag( "value" ).addText( "authcBasic" ).gotoParent().gotoParent()
            .addTag("provider")
            .addTag( "role" ).addText( "authorization" )
            .addTag( "name" ).addText( "AclsAuthz" )
            .addTag( "enabled" ).addText( "true" )
            .addTag("param")
            .addTag("name").addText("knox.acl")
            .addTag("value").addText("admin;*;*").gotoParent().gotoParent()
            .addTag("provider")
            .addTag( "role" ).addText( "identity-assertion" )
            .addTag( "enabled" ).addText( "true" )
            .addTag( "name" ).addText( "Default" ).gotoParent()
            .gotoRoot();
    // System.out.println( "GATEWAY=" + xml.toString() );
    return xml;
  }


  private static String createDescriptor(String clusterName) {
    return createDescriptor(clusterName, null);
  }


  private static String createDescriptor(String clusterName, String providerConfigRef) {
    StringBuilder sb = new StringBuilder();
    if (providerConfigRef == null) {
      providerConfigRef = "sandbox-providers";
    }

    sb.append("{\n");
    sb.append("  \"discovery-type\":\"AMBARI\",\n");
    sb.append("  \"discovery-address\":\"http://c6401.ambari.apache.org:8080\",\n");
    sb.append("  \"discovery-user\":\"ambariuser\",\n");
    sb.append("  \"discovery-pwd-alias\":\"ambari.discovery.password\",\n");
    sb.append("  \"provider-config-ref\":\"");
    sb.append(providerConfigRef);
    sb.append("\",\n");
    sb.append("  \"cluster\":\"");
    sb.append(clusterName);
    sb.append("\",\n");
    sb.append("  \"services\":[\n");
    sb.append("    {\"name\":\"NAMENODE\"},\n");
    sb.append("    {\"name\":\"JOBTRACKER\"},\n");
    sb.append("    {\"name\":\"WEBHDFS\"},\n");
    sb.append("    {\"name\":\"WEBHCAT\"},\n");
    sb.append("    {\"name\":\"OOZIE\"},\n");
    sb.append("    {\"name\":\"WEBHBASE\"},\n");
    sb.append("    {\"name\":\"HIVE\"},\n");
    sb.append("    {\"name\":\"RESOURCEMANAGER\"},\n");
    sb.append("    {\"name\":\"AMBARI\", \"urls\":[\"http://c6401.ambari.apache.org:8080\"]}\n");
    sb.append("  ]\n");
    sb.append("}\n");

    return sb.toString();
  }


  //@Test
  public void waitForManualTesting() throws IOException {
    System.in.read();
  }

  @Test( timeout = TestUtils.LONG_TIMEOUT )
  public void testTopologyCollection() throws ClassNotFoundException {
    LOG_ENTER();

    String username = "admin";
    String password = "admin-password";
    String serviceUrl = clusterUrl + "/api/v1/topologies";
    String href1 = given()
        //.log().all()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .then()
        //.log().all()
        .statusCode(HttpStatus.SC_OK)
        .body("topologies.topology[0].name", not(nullValue()))
        .body("topologies.topology[1].name", not(nullValue()))
        .body("topologies.topology[0].uri", not(nullValue()))
        .body("topologies.topology[1].uri", not(nullValue()))
        .body("topologies.topology[0].href", not(nullValue()))
        .body("topologies.topology[1].href", not(nullValue()))
        .body("topologies.topology[0].timestamp", not(nullValue()))
        .body("topologies.topology[1].timestamp", not(nullValue()))
        .when().get(serviceUrl).thenReturn().getBody().path("topologies.topology.href[1]");

       given()
        //.log().all()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_XML)
        .then()
        //.log().all()
        .body("topologies.topology.href[1]", equalTo(href1))
        .statusCode(HttpStatus.SC_OK)
        .when().get(serviceUrl);


    given()
        //.log().all()
        .auth().preemptive().basic(username, password)
        .then()
        //.log().all()
        .statusCode(HttpStatus.SC_OK)
        .contentType(MediaType.APPLICATION_XML)
        .when().get(serviceUrl);


    given().auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_JSON)
        .then()
        //.log().all()
        .statusCode(HttpStatus.SC_OK)
        .contentType("application/json")
        .body("topology.name", equalTo("test-cluster"))
        .when().get(href1);

    LOG_EXIT();
  }

  @Test( timeout = TestUtils.LONG_TIMEOUT )
  public void testTopologyObject() throws ClassNotFoundException {
    LOG_ENTER();

    String username = "admin";
    String password = "admin-password";
    String serviceUrl = clusterUrl + "/api/v1/topologies";
    String hrefJson = given()
        //.log().all()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_JSON)
        .then()
        //.log().all()
        .statusCode(HttpStatus.SC_OK)
        .when().get(serviceUrl).thenReturn().getBody().path("topologies.topology[1].href");

    String timestampJson = given()
        //.log().all()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_JSON)
        .then()
        //.log().all()
        .statusCode(HttpStatus.SC_OK)
        .contentType("application/json")
        .when().get(serviceUrl).andReturn()
        .getBody().path("topologies.topology[1].timestamp");

        given()
        //.log().all()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_JSON)
        .then()
        //.log().all()
        .statusCode(HttpStatus.SC_OK)
        .body("topology.name", equalTo("test-cluster"))
        .body("topology.timestamp", equalTo(Long.parseLong(timestampJson)))
        .when()
        .get(hrefJson);


    String hrefXml = given()
        //.log().all()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_XML)
        .then()
        //.log().all()
        .statusCode(HttpStatus.SC_OK)
        .when().get(serviceUrl).thenReturn().getBody().path("topologies.topology[1].href");

    given()
        //.log().all()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_XML)
        .then()
        //.log().all()
        .statusCode(HttpStatus.SC_OK)
        .when()
        .get(hrefXml);

    LOG_EXIT();
  }

  @Test( timeout = TestUtils.LONG_TIMEOUT )
  public void testPositiveAuthorization() throws ClassNotFoundException{
    LOG_ENTER();

    String adminUser = "admin";
    String adminPass = "admin-password";
    String url = clusterUrl + "/api/v1/topologies";

    given()
        //.log().all()
        .auth().preemptive().basic(adminUser, adminPass)
        .header("Accept", MediaType.APPLICATION_JSON)
        .then()
        //.log().all()
        .statusCode(HttpStatus.SC_OK)
        .contentType(ContentType.JSON)
        .body("topologies.topology[0].name", not(nullValue()))
        .body("topologies.topology[1].name", not(nullValue()))
        .body("topologies.topology[0].uri", not(nullValue()))
        .body("topologies.topology[1].uri", not(nullValue()))
        .body("topologies.topology[0].href", not(nullValue()))
        .body("topologies.topology[1].href", not(nullValue()))
        .body("topologies.topology[0].timestamp", not(nullValue()))
        .body("topologies.topology[1].timestamp", not(nullValue()))
        .when().get(url);

    LOG_EXIT();
  }

  @Test( timeout = TestUtils.LONG_TIMEOUT )
  public void testNegativeAuthorization() throws ClassNotFoundException{
    LOG_ENTER();

    String guestUser = "guest";
    String guestPass = "guest-password";
    String url = clusterUrl + "/api/v1/topologies";

    given()
        //.log().all()
        .auth().basic(guestUser, guestPass)
        .then()
        //.log().all()
        .statusCode(HttpStatus.SC_FORBIDDEN)
        .when().get(url);

    LOG_EXIT();
  }

  private Topology createTestTopology(){
    Topology topology = new Topology();
    topology.setName("test-topology");

    try {
      topology.setUri(new URI(gatewayUrl + "/" + topology.getName()));
    } catch (URISyntaxException ex) {
      assertThat(topology.getUri(), not(nullValue()));
    }

    Provider identityProvider = new Provider();
    identityProvider.setName("Default");
    identityProvider.setRole("identity-assertion");
    identityProvider.setEnabled(true);

    Provider AuthenicationProvider = new Provider();
    AuthenicationProvider.setName("ShiroProvider");
    AuthenicationProvider.setRole("authentication");
    AuthenicationProvider.setEnabled(true);

    Param ldapMain = new Param();
    ldapMain.setName("main.ldapRealm");
    ldapMain.setValue("org.apache.hadoop.gateway.shirorealm.KnoxLdapRealm");

    Param ldapGroupContextFactory = new Param();
    ldapGroupContextFactory.setName("main.ldapGroupContextFactory");
    ldapGroupContextFactory.setValue("org.apache.hadoop.gateway.shirorealm.KnoxLdapContextFactory");

    Param ldapRealmContext = new Param();
    ldapRealmContext.setName("main.ldapRealm.contextFactory");
    ldapRealmContext.setValue("$ldapGroupContextFactory");

    Param ldapURL = new Param();
    ldapURL.setName("main.ldapRealm.contextFactory.url");
    ldapURL.setValue(driver.getLdapUrl());

    Param ldapUserTemplate = new Param();
    ldapUserTemplate.setName("main.ldapRealm.userDnTemplate");
    ldapUserTemplate.setValue("uid={0},ou=people,dc=hadoop,dc=apache,dc=org");

    Param authcBasic = new Param();
    authcBasic.setName("urls./**");
    authcBasic.setValue("authcBasic");

    AuthenicationProvider.addParam(ldapGroupContextFactory);
    AuthenicationProvider.addParam(ldapMain);
    AuthenicationProvider.addParam(ldapRealmContext);
    AuthenicationProvider.addParam(ldapURL);
    AuthenicationProvider.addParam(ldapUserTemplate);
    AuthenicationProvider.addParam(authcBasic);

    Service testService = new Service();
    testService.setRole("test-service-role");

    topology.addProvider(AuthenicationProvider);
    topology.addProvider(identityProvider);
    topology.addService(testService);
    topology.setTimestamp(System.nanoTime());

    return topology;
  }

  @Test( timeout = TestUtils.LONG_TIMEOUT )
  public void testDeployTopology() throws Exception {
    LOG_ENTER();

    Topology testTopology = createTestTopology();

    String user = "guest";
    String password = "guest-password";

    String url = gatewayUrl + "/" + testTopology.getName() + "/test-service-path/test-service-resource";

    GatewayServices srvs = GatewayServer.getGatewayServices();

    TopologyService ts = srvs.getService(GatewayServices.TOPOLOGY_SERVICE);
    try {
      ts.stopMonitor();

      assertThat( testTopology, not( nullValue() ) );
      assertThat( testTopology.getName(), is( "test-topology" ) );

      given()
          //.log().all()
          .auth().preemptive().basic( "admin", "admin-password" ).header( "Accept", MediaType.APPLICATION_JSON ).then()
          //.log().all()
          .statusCode( HttpStatus.SC_OK ).body( containsString( "ServerVersion" ) ).when().get( gatewayUrl + "/admin/api/v1/version" );

      given()
          //.log().all()
          .auth().preemptive().basic( user, password ).then()
          //.log().all()
          .statusCode( HttpStatus.SC_NOT_FOUND ).when().get( url );

      ts.deployTopology( testTopology );

      given()
          //.log().all()
          .auth().preemptive().basic( user, password ).then()
          //.log().all()
          .statusCode( HttpStatus.SC_OK ).contentType( "text/plain" ).body( is( "test-service-response" ) ).when().get( url ).getBody();

      ts.deleteTopology( testTopology );

      given()
          //.log().all()
          .auth().preemptive().basic( user, password ).then()
          //.log().all()
          .statusCode( HttpStatus.SC_NOT_FOUND ).when().get( url );
    } finally {
      ts.startMonitor();
    }

    LOG_EXIT();
  }

  @Test( timeout = TestUtils.LONG_TIMEOUT )
  public void testDeleteTopology() throws ClassNotFoundException {
    LOG_ENTER();

    Topology test = createTestTopology();

    String username = "admin";
    String password = "admin-password";
    String url = clusterUrl + "/api/v1/topologies/" + test.getName();

    GatewayServices gs = GatewayServer.getGatewayServices();

    TopologyService ts = gs.getService(GatewayServices.TOPOLOGY_SERVICE);

    ts.deployTopology(test);

    given()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_JSON)
        .then()
        //.log().all()
        .statusCode(HttpStatus.SC_OK)
        .contentType(MediaType.APPLICATION_JSON)
        .when().get(url);

    given()
        .auth().preemptive().basic(username, password)
        .then()
        //.log().all()
        .statusCode(HttpStatus.SC_OK)
        .contentType(MediaType.APPLICATION_JSON)
        .when().delete(url);

    given()
        //.log().all()
        .auth().preemptive().basic(username, password)
        .then()
        //.log().all()
        .statusCode(HttpStatus.SC_NO_CONTENT)
        .when().get(url);

    LOG_EXIT();
  }

  @Test( timeout = TestUtils.LONG_TIMEOUT )
  public void testPutTopology() throws Exception {
    LOG_ENTER() ;

    String username = "admin";
    String password = "admin-password";
    String url = clusterUrl + "/api/v1/topologies/test-put";

    String JsonPut =
        given()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_JSON)
        .get(clusterUrl + "/api/v1/topologies/test-cluster")
        .getBody().asString();

    String XML = given()
        //.log().all()
        .auth().preemptive().basic(username, password)
        .contentType(MediaType.APPLICATION_JSON)
        .header("Accept", MediaType.APPLICATION_XML)
        .body(JsonPut)
        .then()
        .statusCode(HttpStatus.SC_OK)
        //.log().all()
        .when().put(url).getBody().asString();

    InputSource source = new InputSource( new StringReader( XML ) );
    Document doc = XmlUtils.readXml( source );

    assertThat( doc, hasXPath( "/topology/gateway/provider[1]/name", containsString( "WebAppSec" ) ) );
    assertThat( doc, hasXPath( "/topology/gateway/provider[1]/param/name", containsString( "csrf.enabled" ) ) );

    given()
            .auth().preemptive().basic(username, password)
            .header("Accept", MediaType.APPLICATION_XML)
            .then()
            .statusCode(HttpStatus.SC_OK)
            .body(equalTo(XML))
            .when().get(url)
            .getBody().asString();

    String XmlPut =
        given()
            .auth().preemptive().basic(username, password)
            .header("Accept", MediaType.APPLICATION_XML)
            .get(clusterUrl + "/api/v1/topologies/test-cluster")
            .getBody().asString();

    String JSON = given()
        //.log().all()
        .auth().preemptive().basic(username, password)
        .contentType(MediaType.APPLICATION_XML)
        .header("Accept", MediaType.APPLICATION_JSON)
        .body(XmlPut)
        .then()
        .statusCode(HttpStatus.SC_OK)
            //.log().all()
        .when().put(url).getBody().asString();

    given()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_JSON)
        .then()
        .statusCode(HttpStatus.SC_OK)
        .body(equalTo(JSON))
        .when().get(url)
        .getBody().asString();

    LOG_EXIT();
  }

  @Test( timeout = TestUtils.LONG_TIMEOUT )
  public void testXForwardedHeaders() {
    LOG_ENTER();

    String username = "admin";
    String password = "admin-password";
    String url = clusterUrl + "/api/v1/topologies";

//    X-Forward header values
    String port = String.valueOf(777);
    String server = "myserver";
    String host = server + ":" + port;
    String proto = "protocol";
    String context = "/mycontext";
    String newUrl = proto + "://" + host + context;
//    String port = String.valueOf(gateway.getAddresses()[0].getPort());

//     Case 1: Add in all x-forward headers (host, port, server, context, proto)
    given()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_XML)
        .header("X-Forwarded-Host", host )
        .header("X-Forwarded-Port", port )
        .header("X-Forwarded-Server", server )
        .header("X-Forwarded-Context", context)
        .header("X-Forwarded-Proto", proto)
        .then()
        .statusCode(HttpStatus.SC_OK)
        .body(containsString(newUrl))
        .body(containsString("test-cluster"))
        .body(containsString("admin"))
        .when().get(url);


//     Case 2: add in x-forward headers (host, server, proto, context)
    given()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_XML)
        .header("X-Forwarded-Host", host )
        .header("X-Forwarded-Server", server )
        .header("X-Forwarded-Context", context )
        .header("X-Forwarded-Proto", proto )
        .then()
        .statusCode(HttpStatus.SC_OK)
        .body(containsString(server))
        .body(containsString(context))
        .body(containsString(proto))
        .body(containsString(host))
        .body(containsString("test-cluster"))
        .body(containsString("admin"))
        .when().get(url);

//     Case 3: add in x-forward headers (host, proto, port, context)
    given()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_XML)
        .header("X-Forwarded-Host", host )
        .header("X-Forwarded-Port", port )
        .header("X-Forwarded-Context", context )
        .header("X-Forwarded-Proto", proto)
        .then()
        .statusCode(HttpStatus.SC_OK)
        .body(containsString(host))
        .body(containsString(port))
        .body(containsString(context))
        .body(containsString(proto))
        .body(containsString("test-cluster"))
        .body(containsString("admin"))
        .when().get(url);

//     Case 4: add in x-forward headers (host, proto, port, context) no port in host.
    given()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_XML)
        .header("X-Forwarded-Host", server)
        .header("X-Forwarded-Port", port)
        .header("X-Forwarded-Context", context)
        .header("X-Forwarded-Proto", proto)
        .then()
        .statusCode(HttpStatus.SC_OK)
        .body(containsString(server))
        .body(containsString(port))
        .body(containsString(context))
        .body(containsString(proto))
        .body(containsString("test-cluster"))
        .body(containsString("admin"))
        .when().get(url);

//     Case 5: add in x-forward headers (host, port)
    given()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_XML)
        .header("X-Forwarded-Host", host )
        .header("X-Forwarded-Port", port )
        .then()
        .statusCode(HttpStatus.SC_OK)
        .body(containsString(host))
        .body(containsString(port))
        .body(containsString("test-cluster"))
        .body(containsString("admin"))
        .when().get(url);

//     Case 6: Normal Request
    given()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_XML)
        .then()
        .statusCode(HttpStatus.SC_OK)
        .body(containsString(url))
        .body(containsString("test-cluster"))
        .body(containsString("admin"))
        .when().get(url);

    LOG_EXIT();
  }

  @Test( timeout = TestUtils.LONG_TIMEOUT )
  public void testGatewayPathChange() throws Exception {
    LOG_ENTER();
    String username = "admin";
    String password = "admin-password";
    String url = clusterUrl + "/api/v1/topologies";

//     Case 1: Normal Request (No Change in gateway.path). Ensure HTTP OK resp + valid URL.
    given()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_XML)
        .then()
        .statusCode(HttpStatus.SC_OK)
        .body(containsString(url + "/test-cluster"))
        .when().get(url);


//     Case 2: Change gateway.path to another String. Ensure HTTP OK resp + valid URL.
   try {
     gateway.stop();

     GatewayTestConfig conf = new GatewayTestConfig();
     conf.setGatewayPath("new-gateway-path");
     setupGateway(conf);

     String newUrl = clusterUrl + "/api/v1/topologies";

     given()
         .auth().preemptive().basic(username, password)
         .header("Accept", MediaType.APPLICATION_XML)
         .then()
         .statusCode(HttpStatus.SC_OK)
         .body(containsString(newUrl + "/test-cluster"))
         .when().get(newUrl);
   } catch(Exception e){
     fail(e.getMessage());
   }
    finally {
//        Restart the gateway with old settings.
       gateway.stop();
      setupGateway(new GatewayTestConfig());
    }

    LOG_EXIT();
  }


  @Test( timeout = TestUtils.LONG_TIMEOUT )
  public void testProviderConfigurationCollection() throws Exception {
    LOG_ENTER();

    final String username = "admin";
    final String password = "admin-password";
    final String serviceUrl = clusterUrl + "/api/v1/providerconfig";

    final File sharedProvidersDir = new File(config.getGatewayConfDir(), "shared-providers");
    final List<String> configNames = Arrays.asList("sandbox-providers", "custom-providers");
    final List<String> configFileNames = Arrays.asList(configNames.get(0) + ".xml", configNames.get(1) + ".xml");

    // Request a listing of all the provider configs with an INCORRECT Accept header
    given()
      .auth().preemptive().basic(username, password)
      .header("Accept", MediaType.APPLICATION_XML)
      .then()
      .statusCode(HttpStatus.SC_NOT_ACCEPTABLE)
      .when().get(serviceUrl);

    // Request a listing of all the provider configs (with the CORRECT Accept header)
    ResponseBody responseBody = given()
                                  .auth().preemptive().basic(username, password)
                                  .header("Accept", MediaType.APPLICATION_JSON)
                                  .then()
                                  .statusCode(HttpStatus.SC_OK)
                                  .contentType(MediaType.APPLICATION_JSON)
                                  .when().get(serviceUrl).body();
    List<String> items = responseBody.path("items");
    assertTrue("Expected no items since the shared-providers dir is empty.", items.isEmpty());

    // Manually write a file to the shared-providers directory
    File providerConfig = new File(sharedProvidersDir, configFileNames.get(0));
    FileOutputStream stream = new FileOutputStream(providerConfig);
    createProviderConfiguration().toStream(stream);
    stream.close();

    // Request a listing of all the provider configs
    responseBody = given()
                      .auth().preemptive().basic(username, password)
                      .header("Accept", MediaType.APPLICATION_JSON)
                      .then()
                      .statusCode(HttpStatus.SC_OK)
                      .contentType(MediaType.APPLICATION_JSON)
                      .when().get(serviceUrl).body();
    items = responseBody.path("items");
    assertEquals("Expected items to include the new file in the shared-providers dir.", 1, items.size());
    assertEquals(configFileNames.get(0), responseBody.path("items[0].name"));
    String href1 = responseBody.path("items[0].href");

    // Manually write another file to the shared-providers directory
    File anotherProviderConfig = new File(sharedProvidersDir, configFileNames.get(1));
    stream = new FileOutputStream(anotherProviderConfig);
    createProviderConfiguration().toStream(stream);
    stream.close();

    // Request a listing of all the provider configs
    responseBody = given()
                      .auth().preemptive().basic(username, password)
                      .header("Accept", MediaType.APPLICATION_JSON)
                      .then()
                      .statusCode(HttpStatus.SC_OK)
                      .contentType(MediaType.APPLICATION_JSON)
                      .when().get(serviceUrl).body();
    items = responseBody.path("items");
    assertEquals(2, items.size());
    String pcOne = responseBody.path("items[0].name");
    String pcTwo = responseBody.path("items[1].name");
    assertTrue(configFileNames.contains(pcOne));
    assertTrue(configFileNames.contains(pcTwo));

    // Request a specific provider configuration with an INCORRECT Accept header
    given()
      .auth().preemptive().basic(username, password)
      .header("Accept", MediaType.APPLICATION_JSON)
      .then()
      .statusCode(HttpStatus.SC_NOT_ACCEPTABLE)
      .when().get(href1).body();

    // Request a specific provider configuration (with the CORRECT Accept header)
    responseBody = given()
                      .auth().preemptive().basic(username, password)
                      .header("Accept", MediaType.APPLICATION_XML)
                      .then()
                      .statusCode(HttpStatus.SC_OK)
                      .contentType(MediaType.APPLICATION_XML)
                      .when().get(href1).body();
    String sandboxProvidersConfigContent = responseBody.asString();

    // Parse the result, to make sure it's at least valid XML
    XmlUtils.readXml(new InputSource(new StringReader(sandboxProvidersConfigContent)));

    providerConfig.delete();
    anotherProviderConfig.delete();

    // Request a specific provider configuration, which does NOT exist
    given()
      .auth().preemptive().basic(username, password)
      .header("Accept", MediaType.APPLICATION_XML)
      .then()
      .statusCode(HttpStatus.SC_NOT_FOUND)
      .when().get(serviceUrl + "/not-a-real-provider-config");

    LOG_EXIT();
  }


  @Test( timeout = TestUtils.LONG_TIMEOUT )
  public void testPutProviderConfiguration() throws Exception {
    LOG_ENTER();

    final String username = "admin";
    final String password = "admin-password";
    final String serviceUrl = clusterUrl + "/api/v1/providerconfig";

    final String newProviderConfigName     = "new-provider-config";
    final String newProviderConfigFileName = newProviderConfigName + ".xml";

    XMLTag newProviderConfigXML = createProviderConfiguration();

    // Attempt to PUT a provider config with an INCORRECT Content-type header
    given()
        .auth().preemptive().basic(username, password)
        .header("Content-type", MediaType.APPLICATION_JSON)
        .body(newProviderConfigXML.toBytes("utf-8"))
        .then()
        .statusCode(HttpStatus.SC_UNSUPPORTED_MEDIA_TYPE)
        .when().put(serviceUrl + "/" + newProviderConfigName);

    // Attempt to PUT a provider config with the CORRECT Content-type header
    given()
        .auth().preemptive().basic(username, password)
        .header("Content-type", MediaType.APPLICATION_XML)
        .body(newProviderConfigXML.toBytes("utf-8"))
        .then()
        .statusCode(HttpStatus.SC_CREATED)
        .when().put(serviceUrl + "/" + newProviderConfigName);

    // Verify that the provider configuration was written to the expected location
    File newProviderConfigFile =
                  new File(new File(config.getGatewayConfDir(), "shared-providers"), newProviderConfigFileName);
    assertTrue(newProviderConfigFile.exists());

    // Request a listing of all the provider configs to further verify the PUT
    ResponseBody responseBody = given()
                                  .auth().preemptive().basic(username, password)
                                  .header("Accept", MediaType.APPLICATION_JSON)
                                  .then()
                                  .statusCode(HttpStatus.SC_OK)
                                  .contentType(MediaType.APPLICATION_JSON)
                                  .when().get(serviceUrl).body();
    List<String> items = responseBody.path("items");
    assertEquals(1, items.size());
    assertEquals(newProviderConfigFileName, responseBody.path("items[0].name"));
    String href = responseBody.path("items[0].href");

    // Get the new provider config content
    responseBody = given()
                      .auth().preemptive().basic(username, password)
                      .header("Accept", MediaType.APPLICATION_XML)
                      .then()
                      .statusCode(HttpStatus.SC_OK)
                      .contentType(MediaType.APPLICATION_XML)
                      .when().get(href).body();
    String configContent = responseBody.asString();

    // Parse the result, to make sure it's at least valid XML
    XmlUtils.readXml(new InputSource(new StringReader(configContent)));

    // Manually delete the provider config
    newProviderConfigFile.delete();

    LOG_EXIT();
  }


  @Test( timeout = TestUtils.LONG_TIMEOUT )
  public void testDeleteProviderConfiguration() throws Exception {
    LOG_ENTER();

    final String username = "admin";
    final String password = "admin-password";
    final String serviceUrl = clusterUrl + "/api/v1/providerconfig";

    final File sharedProvidersDir = new File(config.getGatewayConfDir(), "shared-providers");

    // Manually add two provider config files to the shared-providers directory
    File providerConfigOneFile = new File(sharedProvidersDir, "deleteme-one-config.xml");
    FileOutputStream stream = new FileOutputStream(providerConfigOneFile);
    createProviderConfiguration().toStream(stream);
    stream.close();
    assertTrue(providerConfigOneFile.exists());

    File providerConfigTwoFile = new File(sharedProvidersDir, "deleteme-two-config.xml");
    stream = new FileOutputStream(providerConfigTwoFile);
    createProviderConfiguration().toStream(stream);
    stream.close();
    assertTrue(providerConfigTwoFile.exists());

    // Request a listing of all the provider configs
    ResponseBody responseBody = given()
                                  .auth().preemptive().basic(username, password)
                                  .header("Accept", MediaType.APPLICATION_JSON)
                                  .then()
                                  .statusCode(HttpStatus.SC_OK)
                                  .contentType(MediaType.APPLICATION_JSON)
                                  .when().get(serviceUrl).body();
    List<String> items = responseBody.path("items");
    assertEquals(2, items.size());
    String name1 = responseBody.path("items[0].name");
    String href1 = responseBody.path("items[0].href");
    String name2 = responseBody.path("items[1].name");
    String href2 = responseBody.path("items[1].href");

    // Delete one of the provider configs
    responseBody = given()
                    .auth().preemptive().basic(username, password)
                    .header("Accept", MediaType.APPLICATION_JSON)
                    .then()
                    .statusCode(HttpStatus.SC_OK)
                    .contentType(MediaType.APPLICATION_JSON)
                    .when().delete(href1).body();
    String deletedMsg = responseBody.path("deleted");
    assertEquals("provider config " + FilenameUtils.getBaseName(name1), deletedMsg);
    assertFalse((new File(sharedProvidersDir, name1).exists()));

    assertTrue((new File(sharedProvidersDir, name2).exists()));
    // Delete the other provider config
    responseBody = given()
                    .auth().preemptive().basic(username, password)
                    .header("Accept", MediaType.APPLICATION_JSON)
                    .then()
                    .statusCode(HttpStatus.SC_OK)
                    .contentType(MediaType.APPLICATION_JSON)
                    .when().delete(href2).body();
    deletedMsg = responseBody.path("deleted");
    assertEquals("provider config " + FilenameUtils.getBaseName(name2), deletedMsg);
    assertFalse((new File(sharedProvidersDir, name2).exists()));

    // Attempt to delete a provider config that does not exist
    given()
      .auth().preemptive().basic(username, password)
      .header("Accept", MediaType.APPLICATION_JSON)
      .then()
      .statusCode(HttpStatus.SC_OK)
      .when().delete(serviceUrl + "/does-not-exist");

    LOG_EXIT();
  }


  @Test( timeout = TestUtils.LONG_TIMEOUT )
  public void testDescriptorCollection() throws Exception {
    LOG_ENTER();

    final String username = "admin";
    final String password = "admin-password";
    final String serviceUrl = clusterUrl + "/api/v1/descriptors";

    final File descriptorsDir = new File(config.getGatewayConfDir(), "descriptors");
    final List<String> clusterNames        = Arrays.asList("clusterOne", "clusterTwo");
    final List<String> descriptorNames     = Arrays.asList("test-descriptor-one", "test-descriptor-two");
    final List<String> descriptorFileNames = Arrays.asList(descriptorNames.get(0) + ".json",
                                                           descriptorNames.get(1) + ".json");

    // Request a listing of all the descriptors with an INCORRECT Accept header
    given()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_XML)
        .then()
        .statusCode(HttpStatus.SC_NOT_ACCEPTABLE)
        .when().get(serviceUrl);

    // Request a listing of all the descriptors (with the CORRECT Accept header)
    ResponseBody responseBody = given()
                                  .auth().preemptive().basic(username, password)
                                  .header("Accept", MediaType.APPLICATION_JSON)
                                  .then()
                                  .statusCode(HttpStatus.SC_OK)
                                  .contentType(MediaType.APPLICATION_JSON)
                                  .when().get(serviceUrl).body();
    List<String> items = responseBody.path("items");
    assertTrue("Expected no items since the descriptors dir is empty.", items.isEmpty());

    // Manually write a file to the descriptors directory
    File descriptorOneFile = new File(descriptorsDir, descriptorFileNames.get(0));
    FileUtils.write(descriptorOneFile, createDescriptor(clusterNames.get(0)));

    // Request a listing of all the descriptors
    responseBody = given()
                    .auth().preemptive().basic(username, password)
                    .header("Accept", MediaType.APPLICATION_JSON)
                    .then()
                    .statusCode(HttpStatus.SC_OK)
                    .contentType(MediaType.APPLICATION_JSON)
                    .when().get(serviceUrl).body();
    items = responseBody.path("items");
    assertEquals("Expected items to include the new file in the shared-providers dir.", 1, items.size());
    assertEquals(descriptorFileNames.get(0), responseBody.path("items[0].name"));
    String href1 = responseBody.path("items[0].href");

    // Manually write another file to the descriptors directory
    File descriptorTwoFile = new File(descriptorsDir, descriptorFileNames.get(1));
    FileUtils.write(descriptorTwoFile, createDescriptor(clusterNames.get(1)));

    // Request a listing of all the descriptors
    responseBody = given()
                    .auth().preemptive().basic(username, password)
                    .header("Accept", MediaType.APPLICATION_JSON)
                    .then()
                    .statusCode(HttpStatus.SC_OK)
                    .contentType(MediaType.APPLICATION_JSON)
                    .when().get(serviceUrl).body();
    items = responseBody.path("items");
    assertEquals(2, items.size());
    String descOne = responseBody.path("items[0].name");
    String descTwo = responseBody.path("items[1].name");
    assertTrue(descriptorFileNames.contains(descOne));
    assertTrue(descriptorFileNames.contains(descTwo));

    // Request a specific descriptor with an INCORRECT Accept header
    given()
        .auth().preemptive().basic(username, password)
        .header("Accept", MediaType.APPLICATION_XML)
        .then()
        .statusCode(HttpStatus.SC_NOT_ACCEPTABLE)
        .when().get(href1).body();

    // Request a specific descriptor (with the CORRECT Accept header)
    responseBody = given()
                    .auth().preemptive().basic(username, password)
                    .header("Accept", MediaType.APPLICATION_JSON)
                    .then()
                    .statusCode(HttpStatus.SC_OK)
                    .contentType(MediaType.APPLICATION_JSON)
                    .when().get(href1).body();
    String cluster = responseBody.path("cluster");
    assertEquals(cluster, clusterNames.get(0));

    // Request a specific descriptor, which does NOT exist
    given()
      .auth().preemptive().basic(username, password)
      .header("Accept", MediaType.APPLICATION_JSON)
      .then()
      .statusCode(HttpStatus.SC_NOT_FOUND)
      .when().get(serviceUrl + "/not-a-real-descriptor").body();

    descriptorOneFile.delete();
    descriptorTwoFile.delete();

    LOG_EXIT();
  }


  @Test( timeout = TestUtils.LONG_TIMEOUT )
  public void testPutDescriptor() throws Exception {
    LOG_ENTER();

    final String username = "admin";
    final String password = "admin-password";
    final String serviceUrl = clusterUrl + "/api/v1/descriptors";

    final String clusterName           = "test-cluster";
    final String newDescriptorName     = "new-descriptor";
    final String newDescriptorFileName = newDescriptorName + ".json";

    String newDescriptorJSON = createDescriptor(clusterName);

    // Attempt to PUT a descriptor with an INCORRECT Content-type header
    given()
      .auth().preemptive().basic(username, password)
      .header("Content-type", MediaType.APPLICATION_XML)
      .body(newDescriptorJSON.getBytes("utf-8"))
      .then()
      .statusCode(HttpStatus.SC_UNSUPPORTED_MEDIA_TYPE)
      .when().put(serviceUrl + "/" + newDescriptorName);

    // Attempt to PUT a descriptor with the CORRECT Content-type header
    given()
      .auth().preemptive().basic(username, password)
      .header("Content-type", MediaType.APPLICATION_JSON)
      .body(newDescriptorJSON.getBytes("utf-8"))
      .then()
      .statusCode(HttpStatus.SC_CREATED)
      .when().put(serviceUrl + "/" + newDescriptorName);

    // Verify that the descriptor was written to the expected location
    File newDescriptorFile =
            new File(new File(config.getGatewayConfDir(), "descriptors"), newDescriptorFileName);
    assertTrue(newDescriptorFile.exists());

    // Request a listing of all the descriptors to verify the PUT
    ResponseBody responseBody = given()
                                  .auth().preemptive().basic(username, password)
                                  .header("Accept", MediaType.APPLICATION_JSON)
                                  .then()
                                  .statusCode(HttpStatus.SC_OK)
                                  .contentType(MediaType.APPLICATION_JSON)
                                  .when().get(serviceUrl).body();
    List<String> items = responseBody.path("items");
    assertEquals(1, items.size());
    assertEquals(newDescriptorFileName, responseBody.path("items[0].name"));
    String href = responseBody.path("items[0].href");

    // Get the new descriptor content
    responseBody = given()
                    .auth().preemptive().basic(username, password)
                    .header("Accept", MediaType.APPLICATION_JSON)
                    .then()
                    .statusCode(HttpStatus.SC_OK)
                    .contentType(MediaType.APPLICATION_JSON)
                    .when().get(href).body();
    String cluster = responseBody.path("cluster");
    assertEquals(clusterName, cluster);

    // Manually delete the descriptor
    newDescriptorFile.delete();

    LOG_EXIT();
  }


  @Test( timeout = TestUtils.LONG_TIMEOUT )
  public void testDeleteDescriptor() throws Exception {
    LOG_ENTER();

    final String username = "admin";
    final String password = "admin-password";
    final String serviceUrl = clusterUrl + "/api/v1/descriptors";

    final File descriptorsDir = new File(config.getGatewayConfDir(), "descriptors");

    // Manually add two descriptor files to the descriptors directory
    File descriptorOneFile = new File(descriptorsDir, "deleteme-one.json");
    FileUtils.writeStringToFile(descriptorOneFile, createDescriptor("clusterOne"));
    assertTrue(descriptorOneFile.exists());

    File descriptorTwoFile = new File(descriptorsDir, "deleteme-two.json");
    FileUtils.writeStringToFile(descriptorTwoFile, createDescriptor("clusterTwo"));
    assertTrue(descriptorTwoFile.exists());

    // Request a listing of all the descriptors
    ResponseBody responseBody = given()
                                  .auth().preemptive().basic(username, password)
                                  .header("Accept", MediaType.APPLICATION_JSON)
                                  .then()
                                  .statusCode(HttpStatus.SC_OK)
                                  .contentType(MediaType.APPLICATION_JSON)
                                  .when().get(serviceUrl).body();
    List<String> items = responseBody.path("items");
    assertEquals(2, items.size());
    String name1 = responseBody.path("items[0].name");
    String href1 = responseBody.path("items[0].href");
    String name2 = responseBody.path("items[1].name");
    String href2 = responseBody.path("items[1].href");

    // Delete one of the descriptors
    responseBody = given()
                    .auth().preemptive().basic(username, password)
                    .header("Accept", MediaType.APPLICATION_JSON)
                    .then()
                    .statusCode(HttpStatus.SC_OK)
                    .contentType(MediaType.APPLICATION_JSON)
                    .when().delete(href1).body();
    String deletedMsg = responseBody.path("deleted");
    assertEquals("descriptor " + FilenameUtils.getBaseName(name1), deletedMsg);
    assertFalse((new File(descriptorsDir, name1).exists()));

    assertTrue((new File(descriptorsDir, name2).exists()));
    // Delete the other descriptor
    responseBody = given()
                    .auth().preemptive().basic(username, password)
                    .header("Accept", MediaType.APPLICATION_JSON)
                    .then()
                    .statusCode(HttpStatus.SC_OK)
                    .contentType(MediaType.APPLICATION_JSON)
                    .when().delete(href2).body();
    deletedMsg = responseBody.path("deleted");
    assertEquals("descriptor " + FilenameUtils.getBaseName(name2), deletedMsg);
    assertFalse((new File(descriptorsDir, name2).exists()));

    // Attempt to delete a descriptor that does not exist
    given()
      .auth().preemptive().basic(username, password)
      .header("Accept", MediaType.APPLICATION_JSON)
      .then()
      .statusCode(HttpStatus.SC_OK)
      .when().delete(serviceUrl + "/does-not-exist");

    LOG_EXIT();
  }


}
