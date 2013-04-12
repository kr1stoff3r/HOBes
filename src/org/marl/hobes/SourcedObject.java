/*
This file is part of HOBes.

HOBes is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

HOBes is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with HOBes.  If not, see <http://www.gnu.org/licenses/>.
 
*/
package org.marl.hobes;

/**
 *  Associates an object message, referenced as the <i>payload</i>, to its source.
 * <p>The source, for example a mobile device, denotes the entity that 
 * initially <code>write</code> the object to the bus.
 * <p>This allows the transport and communication layers to implement
 * pre/post processing (filtering,cryptography,decoration) based on a particular issuer.
 * This is essential for example for stealth channels.
 * 
 * @author chris
 */
public class SourcedObject {

	/** Identifier for an anonymous guest source. */
	public static final String GUEST_ID = "urn:org.marl.hobes.uiid#foobar";

	private String sourceId;
	protected Object payload;
	
	/** 
	 * Associates a source and an object.
	 * 
	 * @param sourceId The source identifier.
	 * @param payload The transported payload.
	 */
	public SourcedObject(String sourceId, Object payload) {
		super();
		this.sourceId = sourceId;
		this.payload = payload;
	}
	
	public String getSource() {
		return sourceId;
	}
	public Object getPayload() {
		return payload;
	}

	/** 
	 * Answers whether this payload has an anonymous source.
	 * 
	 * @return That's it.
	 */
	public boolean isAnonymous(){
		return GUEST_ID.equals(getSource());
	}
}
