package com.cigital.wbsa.test;

import java.security.SecureRandom;
import java.util.Random;

public class RandomTest {
	private Random unsafeRandom = new Random();
	
	static public SecureRandom safeRandom = new SecureRandom();

	public void unsafeRandom() {
		byte[] randomBuffer = new byte[100];
		unsafeRandom.nextBytes(randomBuffer);
		safeRandom.nextBytes(randomBuffer);

		double randomDouble;
		randomDouble = Math.random();
		randomDouble = unsafeRandom.nextGaussian();
		randomDouble = safeRandom.nextGaussian();

		float randomFloat;
		randomFloat = unsafeRandom.nextFloat();
		randomFloat = safeRandom.nextFloat();

		double randomGaussian;
		randomGaussian = unsafeRandom.nextGaussian();
		randomGaussian = safeRandom.nextGaussian();

		int randomInt;
		randomInt = unsafeRandom.nextInt();
		randomInt = safeRandom.nextInt();
		randomInt = unsafeRandom.nextInt(1024);
		randomInt = safeRandom.nextInt(1024);
		
		long randomLong;
		randomLong = unsafeRandom.nextLong();
		randomLong = safeRandom.nextLong();
	}

}
