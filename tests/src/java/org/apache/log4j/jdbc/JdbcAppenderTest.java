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
package org.apache.log4j.jdbc;
import junit.framework.TestCase;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.xml.XLevel;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class JdbcAppenderTest extends TestCase{
    // Closing the last connection to "in-memory h2" removes the database
    // So we keep the connection during the test
    // The logger opens its own connection
    Connection con;

    Logger logger = Logger.getLogger(JdbcAppenderTest.class);

	
    public void setUp() throws SQLException {
	try {
        // Explicitly load the H2 driver
        Class.forName("org.h2.Driver");
    } catch (ClassNotFoundException e) {
        throw new RuntimeException("H2 Driver not found in classpath", e);
    }

	con = DriverManager.getConnection("jdbc:h2:mem:test_db");
	Statement st = con.createStatement();
	try {
	    st.execute(
		    "create table logs(level varchar(100),location varchar(100),message varchar(100),message2 varchar(100))");
	} finally {
	    st.close();
	}
    }

    public void tearDown() throws SQLException {
	LogManager.shutdown();
	con.close();
    }

    public void testVerifyJdbcBufferSize1() throws SQLException {
	PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");


	String oldThreadName = Thread.currentThread().getName();
	try {
	    Thread.currentThread().setName("main");
	    logger.debug("message with ' quote");
	    assertEquals("batchSize=1, so messages should be added immediately",
		    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n",
		    joinSorted(getMessagesFromDababase()));

	    logger.fatal("message with \" quote");

	    assertEquals("batchSize=1, so two messages should be in DB after two logging calls",
		    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
			    + "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL message with \" quote\n",
		    joinSorted(getMessagesFromDababase()));
	} finally {
	    Thread.currentThread().setName(oldThreadName);
	}
    }

    public void testVerifyJdbcBufferSize2() throws SQLException {
	PropertyConfigurator.configure("input/jdbc_h2_bufferSize2.properties");

	String oldThreadName = Thread.currentThread().getName();
	try {
	    Thread.currentThread().setName("main");
	    logger.log(XLevel.TRACE, "xtrace message");
	    logger.debug("message with ' quote");
	    logger.info("message with \" quote");
	    logger.warn("?");
	    // bufferSize=2, so this messsage won't yet be stored to the db
	    logger.error("m4");

	    assertEquals(
		    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
			    + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n"
			    + "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n"
			    + "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
		    joinSorted(getMessagesFromDababase()));

	    logger.fatal("m5");

	    assertEquals("Logging m5 message should trigger buffer flush for both m4 and m5",
		    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
			    + "ERROR; org.apache.log4j.jdbc.JdbcAppenderTest; m4;  org.apache.log4j.jdbc.JdbcAppenderTest ERROR m4\n"
			    + "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; m5;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL m5\n"
			    + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n"
			    + "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n"
			    + "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
		    joinSorted(getMessagesFromDababase()));
	} finally {
	    Thread.currentThread().setName(oldThreadName);
	}
    }

    private static String joinSorted(List list) {
	Collections.sort(list);
	StringBuilder sb = new StringBuilder();
	for (int i = 0; i < list.size(); i++) {
		String s = (String) list.get(i);
	    sb.append(s).append('\n');
	}
	return sb.toString();
    }

    private List getMessagesFromDababase() throws SQLException {
	List res = new ArrayList();
	PreparedStatement ps = con.prepareStatement("select level,location,message,message2 from logs");
	ResultSet rs = ps.executeQuery();
	try {
	    while (rs.next()) {
		res.add(rs.getString(1) + "; " + rs.getString(2) + "; " + rs.getString(3) + "; " + rs.getString(4));
	    }
	} finally {
	    rs.close();
	}
	return res;
    }
}
