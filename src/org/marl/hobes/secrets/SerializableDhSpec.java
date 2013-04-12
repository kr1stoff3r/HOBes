package org.marl.hobes.secrets;

import java.io.Serializable;
import java.math.BigInteger;

import javax.crypto.spec.DHParameterSpec;

/** 
 * An envelop to enable standard <code>DHParameterSpec</code>
 * de/serialization.
 * 
 * @author chris
 */
public class SerializableDhSpec implements Serializable {
	private static final long serialVersionUID = 1L;
	
	private BigInteger p;
	private BigInteger g;
	private int l;
	
	/** 
	 * Creates a serializable DH specification from a standard
	 * <code>DHParameterSpec</code>.
	 *  
	 * @param dhspec The standard specification.
	 */
	public SerializableDhSpec(DHParameterSpec dhspec){
		this.p = dhspec.getP();
		this.g = dhspec.getG();
		this.l = dhspec.getL();
	}

	/** Answsers the prime modulus.
	 * 
	 * @return P.
	 */
	public BigInteger getP() {
		return p;
	}
	public void setP(BigInteger p) {
		this.p = p;
	}
	
	/** Answers the base generator.
	 * 
	 * @return G.
	 */
	public BigInteger getG() {
		return g;
	}
	public void setG(BigInteger g) {
		this.g = g;
	}

	/** Answers the size in bits of the random exponent.
	 * 
	 * @return l.
	 */
	public int getL() {
		return l;
	}
	public void setL(int l) {
		this.l = l;
	}
	
	/** Creates a standard DH specification based on
	 * this one.
	 * 
	 * @return A standard specification.
	 */
	public DHParameterSpec asStandardSpec(){
		return new DHParameterSpec(getP(), getG(), getL());
	}
	
}
