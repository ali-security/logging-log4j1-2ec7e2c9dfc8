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

package org.apache.log4j;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

import junit.framework.TestCase;


/**
 * Regression tests for DLL preloading (sonatype-2010-0053).
 *
 * The removed NTEventLogAppender loaded its native library by bare name
 * through System.loadLibrary, so any library with a matching name found
 * on the library search path (PATH, working directory, java.library.path)
 * was loaded into the JVM.  These tests plant such libraries in a
 * directory on java.library.path and check that log4j never loads them.
 */
public class NativeLibraryPreloadTest extends TestCase {

  /**
   * Name of the appender that loaded a native library from the search path.
   */
  private static final String NT_APPENDER = "org.apache.log4j.nt.NTEventLogAppender";

  /**
   * System property naming a directory on java.library.path where the
   * test may plant libraries; set by the NativeLibraryPreload Ant target.
   */
  private static final String PRELOAD_DIR_PROPERTY = "log4j.test.preload.dir";

  /**
   * Libraries planted for the current test.
   */
  private File[] planted = new File[0];

  /**
   * Create new instance of NativeLibraryPreloadTest.
   * @param testName test name
   */
  public NativeLibraryPreloadTest(final String testName) {
    super(testName);
  }

  /**
   * Plants libraries named like the NTEventLogAppender native library.
   * @throws IOException if a library cannot be written
   */
  protected void setUp() throws IOException {
    String dirName = System.getProperty(PRELOAD_DIR_PROPERTY);
    if (dirName == null || dirName.length() == 0) {
      return;
    }
    File dir = new File(dirName);
    dir.mkdirs();
    String[] names = new String[] {
        System.mapLibraryName("NTEventLogAppender." + System.getProperty("os.arch")),
        System.mapLibraryName("NTEventLogAppender")
    };
    planted = new File[names.length];
    for (int i = 0; i < names.length; i++) {
      planted[i] = new File(dir, names[i]);
      FileOutputStream os = new FileOutputStream(planted[i]);
      try {
        os.write("planted library, not a real native image".getBytes());
      } finally {
        os.close();
      }
    }
  }

  /**
   * Removes planted libraries and resets configuration.
   */
  protected void tearDown() {
    for (int i = 0; i < planted.length; i++) {
      if (planted[i] != null) {
        planted[i].delete();
      }
    }
    planted = new File[0];
    LogManager.resetConfiguration();
  }

  /**
   * The appender class that loads a native library by bare name must not
   * be available, so loading it cannot pull a planted library into the JVM.
   */
  public void testNTEventLogAppenderNotAvailable() {
    try {
      Class.forName(NT_APPENDER, true, NativeLibraryPreloadTest.class.getClassLoader());
      fail(NT_APPENDER + " is still available");
    } catch (ClassNotFoundException expected) {
    } catch (LinkageError e) {
      fail(NT_APPENDER + " loaded a native library from the library search path: " + e);
    }
  }

  /**
   * Configuring the appender by class name must not load a native library
   * from the search path; the appender is rejected instead.
   */
  public void testConfiguredNTEventLogAppenderDoesNotLoadLibrary() {
    Properties props = new Properties();
    props.put("log4j.rootLogger", "DEBUG, NT");
    props.put("log4j.appender.NT", NT_APPENDER);
    try {
      PropertyConfigurator.configure(props);
    } catch (LinkageError e) {
      fail("Configuring " + NT_APPENDER
          + " loaded a native library from the library search path: " + e);
    }
    assertNull(Logger.getRootLogger().getAppender("NT"));
  }
}
