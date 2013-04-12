package org.marl.hobes.test;

import java.net.MalformedURLException;
import java.net.URL;

import org.marl.hobes.HobesTransportException;

public class TestPreferences {

	public static TestObjectType getTestObject(){
		return new TestObjectType("hobes",69);
	}
	
	public static URL getEchoEndpointUrl() throws HobesTransportException{
		try {
			return new URL(ECHO_ENDPOINT_URL);
		}
		catch (MalformedURLException e) {
			throw new HobesTransportException(ECHO_ENDPOINT_URL, e);
		}
	}
	
	public static URL getTestDesUrl() throws HobesTransportException{
		try {
			return new URL(TEST_DES_ENDPOINT_URL);
		}
		catch (MalformedURLException e) {
			throw new HobesTransportException(TEST_DES_ENDPOINT_URL, e);
		}
	}
	
	static final String ECHO_ENDPOINT_URL = "http://localhost:8080/hobes-www/echo";
	static final String TEST_DES_ENDPOINT_URL = "http://localhost:8080/hobes-www/test-des";
		
}
