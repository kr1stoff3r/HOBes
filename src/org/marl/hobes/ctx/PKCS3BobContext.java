package org.marl.hobes.ctx;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Properties;

import org.marl.hobes.HobesDataException;
import org.marl.hobes.HobesException;
import org.marl.hobes.HobesSecurityException;
import org.marl.hobes.HobesTransportException;
import org.marl.hobes.ObjectBus;
import org.marl.hobes.SourcedObject;
import org.marl.hobes.secrets.PKCS3Bob;

public class PKCS3BobContext implements Serializable {
	private static final long serialVersionUID = 1L;

	private HashMap<String,PKCS3Bob> channels;
	private Properties ctxConfig;

	/**
	 * @param pPath
	 * @throws HobesTransportException
	 * @throws HobesDataException
	 * @throws HobesSecurityException
	 */
	public PKCS3BobContext(String pPath) throws HobesTransportException,
			HobesDataException, HobesSecurityException {
		
		this.channels = new HashMap<String,PKCS3Bob>(); 
		this.ctxConfig = new Properties();
		InputStream is;
		try{
			if (pPath != null){
				is = new FileInputStream(pPath);
			}
			else {
				is = PKCS3BobContext.class.getClassLoader().getResourceAsStream("org/marl/hobes/ctx/bob.properties");
			}
			this.ctxConfig.load(is);
			is.close();
		}
		catch(IOException e){
			throw new HobesDataException(pPath, e);
		}
	}

	public Object onRequest(InputStream httpInStream, 
			OutputStream httpOutStream,
			boolean isSilentModeFlag) throws HobesException {
		
		SourcedObject request = ObjectBus.readWithSource(httpInStream);
		if (request.getPayload() instanceof byte[]){
			// we assume (re)configuring the channel
			byte[] aliceEncodedPV = (byte[]) request.getPayload();
			PKCS3Bob channel = new PKCS3Bob(request.getSource());
			channel.protocolPhaseI();
			ObjectBus.write(httpOutStream, channel.getPublicValue());
			channel.protocolPhaseII(aliceEncodedPV);
			
			if (this.channels.containsKey(channel.getId())){
				this.channels.remove(channel.getId());
			}
			this.channels.put(channel.getId(), channel);
			
			return channel;
		}
		else{
			// we assume sealed payload
			PKCS3Bob channel = this.channels.get(request.getSource());
			if (channel == null){
				throw new HobesSecurityException("Undefined channel: "+request.getSource());
			}
			Object plainRequest = channel.decipher(request.getPayload());
			
			Class<? extends HobesCommand> cmdClass = findCommandType(plainRequest);
			Constructor<? extends HobesCommand> constructor;
			try {
				constructor = cmdClass.getConstructor(new Class[] {});
				HobesCommand cmd = constructor.newInstance(new Object[] {});
				Object result = cmd.execute(request.getSource(), plainRequest);
				
				if (! isSilentModeFlag){
					channel.write(httpOutStream, plainRequest);
				}
				
				return new HobesResponse(request.getSource(),
						plainRequest,
						cmdClass,
						result);
			} 
			catch (NoSuchMethodException e) {
				throw new HobesDataException(e);
			}
			catch (SecurityException e) {
				throw new HobesSecurityException(e);
			} 
			catch (InstantiationException e) {
				throw new HobesDataException(e);
			} 
			catch (IllegalAccessException e) {
				throw new HobesDataException(e);
			} 
			catch (IllegalArgumentException e) {
				throw new HobesDataException(e);
			} 
			catch (InvocationTargetException e) {
				throw new HobesDataException(e);
			} 
		}
	}
	
	protected Class<? extends HobesCommand> findCommandType(Object request)
			throws HobesDataException{
		Class<?> requestType = request.getClass();
		String cmdClassName = this.ctxConfig.getProperty(requestType.getName());
		
		while ((cmdClassName == null) && (!requestType.equals(Object.class))){
			requestType = requestType.getSuperclass();
			cmdClassName = this.ctxConfig.getProperty(requestType.getName());
		}
		if (cmdClassName == null){
			throw new HobesDataException(request.getClass().getName());
		}
		
		try{
			return (Class<? extends HobesCommand>) PKCS3BobContext.class.getClassLoader().loadClass(cmdClassName);
		}
		catch (ClassNotFoundException e) {
			throw new HobesDataException(cmdClassName);
		} 
	}
}
