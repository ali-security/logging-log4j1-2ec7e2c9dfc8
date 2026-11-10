/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.net;

import junit.framework.TestCase;

import javax.jms.Topic;
import javax.jms.TopicConnection;
import javax.jms.TopicConnectionFactory;
import javax.jms.TopicSession;
import javax.jms.TopicSubscriber;
import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.OperationNotSupportedException;
import javax.naming.spi.InitialContextFactory;
import javax.naming.spi.InitialContextFactoryBuilder;
import javax.naming.spi.NamingManager;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Hashtable;
import java.util.Vector;

/**
 * Checks that {@link JMSSink} only performs JNDI lookups of names in the
 * java: namespace, so that a TopicConnectionFactoryBindingName or a
 * TopicBindingName pointing to an attacker controlled LDAP/RMI/DNS service
 * cannot be used to make it fetch and deserialize remote objects
 * (CVE-2022-23302).
 */
public class JMSSinkTest extends TestCase {

  static final String TCF_NAME = "java:comp/env/jms/TopicConnectionFactory";
  static final String TOPIC_NAME = "java:comp/env/jms/Topic";

  static final String[] MALICIOUS_NAMES = {
    "ldap://127.0.0.1:1389/Exploit",
    "rmi://127.0.0.1:1099/Exploit",
    "dns://127.0.0.1/Exploit",
    "jms/Exploit"
  };

  /** Objects served by the in-memory naming context, keyed by JNDI name. */
  static final Hashtable bindings = new Hashtable();

  /** Every name looked up in the in-memory naming context. */
  static final Vector lookups = new Vector();

  /** Every method invoked on the JMS objects served by the naming context. */
  static final Vector jmsCalls = new Vector();

  private static boolean builderInstalled = false;

  public JMSSinkTest(String name) {
    super(name);
  }

  protected void setUp() throws Exception {
    installInitialContextFactoryBuilder();
    reset();
  }

  protected void tearDown() {
    reset();
  }

  public void testJavaNamespaceBindingsAreLookedUp() {
    bindJmsProvider(TCF_NAME, TOPIC_NAME);

    new JMSSink(TCF_NAME, TOPIC_NAME, "user", "password");

    assertEquals(2, lookups.size());
    assertEquals(TCF_NAME, lookups.elementAt(0));
    assertEquals(TOPIC_NAME, lookups.elementAt(1));
    assertTrue(jmsCalls.contains("TopicConnectionFactory.createTopicConnection"));
    assertTrue(jmsCalls.contains("TopicSession.createSubscriber"));
    assertTrue(jmsCalls.contains("TopicSubscriber.setMessageListener"));
  }

  public void testTopicConnectionFactoryBindingNameOutsideJavaNamespaceIsNotLookedUp() {
    for (int i = 0; i < MALICIOUS_NAMES.length; i++) {
      String maliciousName = MALICIOUS_NAMES[i];
      reset();
      // the attacker controlled service would serve a connection factory
      bindJmsProvider(maliciousName, TOPIC_NAME);

      new JMSSink(maliciousName, TOPIC_NAME, "user", "password");

      assertFalse("JNDI lookup performed for " + maliciousName,
                  lookups.contains(maliciousName));
      assertTrue("Unexpected JNDI lookups " + lookups, lookups.isEmpty());
      assertTrue("Object served for " + maliciousName + " was used: " + jmsCalls,
                 jmsCalls.isEmpty());
    }
  }

  public void testTopicBindingNameOutsideJavaNamespaceIsNotLookedUp() {
    for (int i = 0; i < MALICIOUS_NAMES.length; i++) {
      String maliciousName = MALICIOUS_NAMES[i];
      reset();
      // the attacker controlled service would serve the topic
      bindJmsProvider(TCF_NAME, maliciousName);

      new JMSSink(TCF_NAME, maliciousName, "user", "password");

      assertFalse("JNDI lookup performed for " + maliciousName,
                  lookups.contains(maliciousName));
      assertEquals(1, lookups.size());
      assertEquals(TCF_NAME, lookups.elementAt(0));
      assertFalse("Object served for " + maliciousName + " was used: " + jmsCalls,
                  jmsCalls.contains("TopicSession.createSubscriber"));
    }
  }

  private static void reset() {
    bindings.clear();
    lookups.clear();
    jmsCalls.clear();
  }

  /**
   * Binds a minimal JMS provider: a connection factory under
   * <code>tcfName</code> and a topic under <code>topicName</code>.
   */
  private static void bindJmsProvider(String tcfName, String topicName) {
    TopicSubscriber subscriber = (TopicSubscriber) newProxy(TopicSubscriber.class,
        new JmsHandler("TopicSubscriber"));
    TopicSession session = (TopicSession) newProxy(TopicSession.class,
        new JmsHandler("TopicSession").returning("createSubscriber", subscriber));
    TopicConnection connection = (TopicConnection) newProxy(TopicConnection.class,
        new JmsHandler("TopicConnection").returning("createTopicSession", session));
    TopicConnectionFactory factory = (TopicConnectionFactory) newProxy(TopicConnectionFactory.class,
        new JmsHandler("TopicConnectionFactory").returning("createTopicConnection", connection));
    Topic topic = (Topic) newProxy(Topic.class, new JmsHandler("Topic"));

    bindings.put(tcfName, factory);
    bindings.put(topicName, topic);
  }

  /**
   * Makes every {@link javax.naming.InitialContext} created in this JVM
   * delegate to an in-memory naming context. With a builder installed,
   * InitialContext hands every name, ldap://, rmi:// and dns:// URLs
   * included, to that context instead of the JDK URL context factories, so
   * no network request is ever made and each lookup is recorded.
   */
  private static synchronized void installInitialContextFactoryBuilder() throws NamingException {
    if (builderInstalled) {
      return;
    }
    NamingManager.setInitialContextFactoryBuilder(new InitialContextFactoryBuilder() {
      public InitialContextFactory createInitialContextFactory(Hashtable environment) {
        return new InitialContextFactory() {
          public Context getInitialContext(Hashtable env) {
            return (Context) newProxy(Context.class, new NamingContextHandler());
          }
        };
      }
    });
    builderInstalled = true;
  }

  static Object newProxy(Class type, InvocationHandler handler) {
    return Proxy.newProxyInstance(JMSSinkTest.class.getClassLoader(),
                                  new Class[] { type }, handler);
  }

  static Object invokeObjectMethod(Object proxy, Method method, Object[] args) {
    String name = method.getName();
    if ("equals".equals(name)) {
      return Boolean.valueOf(proxy == args[0]);
    }
    if ("hashCode".equals(name)) {
      return new Integer(System.identityHashCode(proxy));
    }
    return "proxy@" + Integer.toHexString(System.identityHashCode(proxy));
  }

  /** In-memory naming context recording every lookup. */
  static class NamingContextHandler implements InvocationHandler {
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      if (method.getDeclaringClass() == Object.class) {
        return invokeObjectMethod(proxy, method, args);
      }
      String methodName = method.getName();
      if ("lookup".equals(methodName)) {
        String name = String.valueOf(args[0]);
        lookups.addElement(name);
        Object bound = bindings.get(name);
        if (bound == null) {
          throw new NameNotFoundException(name);
        }
        return bound;
      }
      if ("getEnvironment".equals(methodName)) {
        return new Hashtable();
      }
      if ("close".equals(methodName)) {
        return null;
      }
      throw new OperationNotSupportedException(methodName);
    }
  }

  /** JMS object recording every call made on it. */
  static class JmsHandler implements InvocationHandler {
    private final String type;
    private final Hashtable results = new Hashtable();

    JmsHandler(String type) {
      this.type = type;
    }

    JmsHandler returning(String methodName, Object result) {
      results.put(methodName, result);
      return this;
    }

    public Object invoke(Object proxy, Method method, Object[] args) {
      if (method.getDeclaringClass() == Object.class) {
        return invokeObjectMethod(proxy, method, args);
      }
      jmsCalls.addElement(type + "." + method.getName());
      return results.get(method.getName());
    }
  }
}
