package org.marl.hobes.test;

import java.io.Serializable;

public class TestObjectType implements Serializable {
	private static final long serialVersionUID = 1L;
	private String name;
	private int number;
	public TestObjectType(String name, int number) {
		super();
		this.name = name;
		this.number = number;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public int getNumber() {
		return number;
	}
	public void setNumber(int number) {
		this.number = number;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this.name == null){
			return obj == null;
		}
		if (obj instanceof TestObjectType){
			TestObjectType other = (TestObjectType)obj;
			return (this.name.equals(other.getName()) 
					&& this.number == other.getNumber());
		}
		return false;
	}
	
	
}