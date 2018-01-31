#include "stdafx.h"
#include "BigInt.h"
#include <iostream>
#include <string>
#include <time.h>

const int PRIME_LENGTH = 20;
const int COPRIME = 65537;

// Creates a random number, not my class, inherited from BigInt
BigInt MakeRandom(BigInt &number, unsigned long int digitCount)
{
	srand(time(NULL));

	// The new number will be created using a string object and later converted into a BigInt
	std::string newNum;
	newNum.resize(digitCount);

	unsigned long int tempDigitCount(0);

	// Generate random digits
	while (tempDigitCount < digitCount)
	{
		unsigned long int newRand(std::rand());

		// 10 is chosen to skip the first digit, because it might be statistically <= n, where n is the first digit of RAND_MAX
		while (newRand >= 10)
		{
			newNum[tempDigitCount++] = (newRand % 10) + '0';
			newRand /= 10;
			if (tempDigitCount == digitCount)
				break;
		}
	}

	// Make sure the leading digit is not zero
	if (newNum[0] == '0')
		newNum[0] = (std::rand() % 9) + 1 + '0';
	number = newNum;
	return number;
}

// Creates a random number, not my class, inherited from BigInt
BigInt makeRandom(BigInt &number, const BigInt &top)
{
	// Randomly select the number of digits for the random number
	unsigned long int newDigitCount = (rand() % top.Length()) + 1;
	MakeRandom(number, newDigitCount);

	// Make sure number < top
	while (number >= top)
		MakeRandom(number, newDigitCount);
	return number;
}

// A Miller Rabin primality test that checks to see if a number is prime ,larger value of z increases accuracy of test

bool isPrime(BigInt &n, int z)
{
	BigInt d = n - 1;
	BigInt two = 2;
	BigInt m;
	BigInt k = 1;
	BigInt remainder;
	BigInt a;
	BigInt x;
	int i = 0;

	// Generates the largest number than can express d as 2k·d
	while (remainder.EqualsZero())
	{
		m = n / two.GetPower(k);
		remainder = m % two;
		k++;
	}

	while (i < z)
	{
		i++;
		BigInt b = makeRandom(a, d - 1);
		x = b.GetPowerMod(d, n);
		if (x == 1 || x == d)
			continue;
		for (int j = 0; j < k - 1; j++)
		{
			x = x.GetPowerMod(two, n);
			if (x == 1)
			{
				// Number is definitely not prime
				return false;
			}
			if (x == d)
				continue;
		}
		// Number is definitely not prime
		return false;
	}

	// Number is probably prime
	return true;
}

// Function that generates the prime number
BigInt primeGeneration(BigInt prime)
{
	BigInt c;

	// If the number is even make it odd
	if (prime % 2 == BigIntZero)
	{
		prime = prime + BigIntOne;
	}

	bool test = isPrime(prime, 40);

	// If the number generated is not prime but odd add two to the number and recheck
	while (test == false)
	{
		prime = prime + 2;
		std::cout << prime << "\n";
		bool test = isPrime(prime, 40);

		if (test == true)
		{
			break;
		}
	}
	return prime;
}

// Calculates the modular multiplicative inverse of e and the totient
BigInt modMultiInverse(BigInt e, BigInt totient)
{
	BigInt b0 = totient, t, q;
	BigInt x0 = BigIntZero, x1 = BigIntOne;
	if (totient == 1) std::cout << BigIntOne << "\n";
	while (e > 1) {
		q = e / totient;
		t = totient, totient = e % totient, e = t;
		t = x0, x0 = x1 - q * x0, x1 = t;
	}
	if (x1 < BigIntZero) x1 += b0;

	return x1;
}

//Encryption method, uses the coprime and the product of the two keys to encrypt
BigInt encryption(BigInt encodedmessage, BigInt coprime, BigInt n)
{
	std::string ciphertext = encodedmessage.GetPowerMod(coprime, n);
	std::cout << ciphertext;
	return ciphertext;
}

// A more efficient way of decrypting; using the Chinese Remainder Theorem
BigInt chineseRemainderTheorem(BigInt d, BigInt p, BigInt q, BigInt c, BigInt e, BigInt n)
{
	BigInt dp = d % (p - 1);
	BigInt dq = d % (q - 1);
	BigInt cTwo = modMultiInverse(p, q);
	BigInt cDp = c.GetPowerMod(dp, p);
	BigInt cDq = c.GetPowerMod(dq, q);
	BigInt u = ((cDq - cDp)*(cTwo) % q);

	//sometimes u is negative which will give an incorrect answer, to make it positive but to keep the mod ratio we add q to it
	if (u < BigIntZero)
	{
		u = u + q;
	}

	return cDp + (u*p);
}

int main()
{
	// Used to seed for the MakeRandom function
	srand(time(NULL));

	BigInt i;
	BigInt p;
	BigInt q;
	BigInt n;
	BigInt d;

	// Coprime is constant and this is a common coprime to use
	BigInt coprime = COPRIME;
	BigInt totient;

	// Generate the first random number to use in the primeGeneration function
	BigInt m = MakeRandom(i, PRIME_LENGTH);

	time_t keyStart, keyEnd;
	time_t encryptionStart, encryptionEnd;
	time_t decryptionStart, decryptionEnd;
	time_t programStart, programEnd;
	time(&keyStart);
	p = primeGeneration(m);

	// Reseed to prevent duplicate primes
	m = MakeRandom(i, PRIME_LENGTH);
	std::cout << "first prime number is:" << "\n";
	std::cout << p << "\n";
	q = primeGeneration(m);
	std::cout << "second prime number is:" << "\n";
	std::cout << q << "\n";
	time(&keyEnd);
	float keyDif = difftime(keyEnd, keyStart);
	std::cout << "\n";
	printf("Elasped time for key generation is %.2lf seconds.\n", keyDif);

	// Generate other figures needed for encryption and decryption
	n = p * q;
	std::cout << n << "\n";
	totient = (p - 1) * (q - 1);
	std::cout << totient << "\n";
	d = modMultiInverse(coprime, totient);
	std::cout << d << "\n";

	std::string plaintext;

	std::cout << "Please enter the string you wish to encrypt:\n";
	getline(std::cin, plaintext);
	time(&programStart);
	BigInt* encode = new BigInt[plaintext.size()];
	BigInt* encrypted = new BigInt[plaintext.size()];
	BigInt* decrypted = new BigInt[plaintext.size()];
	std::string* decode = new std::string[plaintext.size()];

	std::cout << "Encoded string is \n";

	// Encode string to ASCII characters
	for (int i = 0; i < plaintext.size(); i++)
	{
		encode[i] = (BigInt)plaintext[i];
		std::cout << encode[i];
	}

	std::cout << "\n Encrypted string is \n";

	time(&encryptionStart);

	for (int i = 0; i < plaintext.size(); i++)
	{
		encrypted[i] = encryption(encode[i], coprime, n);
	}

	time(&encryptionEnd);

	float encryptionDif = difftime(encryptionEnd, encryptionStart);
	std::cout << "\n";
	printf("Elasped time for encryption is %.2lf seconds.\n", encryptionDif);
	std::cout << "\n Decrypted string is \n";
	time(&decryptionStart);

	for (int i = 0; i < plaintext.size(); i++)
	{
		decrypted[i] = chineseRemainderTheorem(d, p, q, encrypted[i], coprime, n);
		std::cout << decrypted[i];
	}
	time(&decryptionEnd);
	float decryptionDif = difftime(decryptionEnd, decryptionStart);
	std::cout << "\n";
	printf("Elasped time for decryption is %.2lf seconds.\n", decryptionDif);

	// clean up dymanic arrays created earlier
	delete[]encode;
	delete[]encrypted;
	delete[]decrypted;
	delete[]decode;
	time(&programEnd);
	float programDif = difftime(programEnd, programStart);
	std::cout << "\n";
	printf("Elasped time for the program is %.2lf seconds.\n", programDif);
}