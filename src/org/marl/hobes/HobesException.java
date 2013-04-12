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

/** HOBes code should throw only this kind of exception.
 * 
 * @author chris
 *
 */
public class HobesException extends Exception {
	private static final long serialVersionUID = 1L;

	public HobesException() {
		super();
	}

	public HobesException(String message, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public HobesException(String message, Throwable cause) {
		super(message, cause);
	}

	public HobesException(String message) {
		super(message);
	}

	public HobesException(Throwable cause) {
		super(cause);
	}
}
