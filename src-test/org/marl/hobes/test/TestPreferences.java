package org.marl.hobes.test;

import java.net.MalformedURLException;
import java.net.URL;

import org.marl.hobes.HobesException;
import org.marl.hobes.HobesTransportException;

public class TestPreferences {

	public static TestObjectType getTestObject(){
		return new TestObjectType("hobes",69);
	}
	
	public static URL getRawEchoUrl() throws HobesException{
		try {
			return new URL(RAW_ECHO_URL);
		}
		catch (MalformedURLException e) {
			throw new HobesTransportException(RAW_ECHO_URL, e);
		}
	}
	public static URL getDesEchoUrl() throws HobesException{
		try {
			return new URL(DES_ECHO_URL);
		}
		catch (MalformedURLException e) {
			throw new HobesTransportException(DES_ECHO_URL, e);
		}
	}
	public static URL getDhHandshakeUrl() throws HobesException{
		try {
			return new URL(DH_HANDSHAKE_URL);
		}
		catch (MalformedURLException e) {
			throw new HobesTransportException(DH_HANDSHAKE_URL, e);
		}
	}
	public static URL getDhxEchoUrl() throws HobesException{
		try {
			return new URL(DH_ECHO_URL);
		}
		catch (MalformedURLException e) {
			throw new HobesTransportException(DH_ECHO_URL, e);
		}
	}
	
	static final String DH_HANDSHAKE_URL = "http://localhost:8080/hobes-www/dhx-dh";

	static final String DH_ECHO_URL = "http://localhost:8080/hobes-www/dhx-echo";
	
	static final String RAW_ECHO_URL = "http://localhost:8080/hobes-www/raw-echo";

	static final String DES_ECHO_URL = "http://localhost:8080/hobes-www/des-echo";

}
