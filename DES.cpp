/**
 * DES (Data Encryption Standard) Implementation in C++
 *
 * Purpose:
 * This program implements the DES algorithm, a symmetric-key block cipher that
 * encrypts/decrypts 64-bit data blocks using a 56-bit key (with 8 parity bits).
 *
 * Key Components:
 * - Encryption/Decryption: Supports both operations using 16-round Feistel structure
 * - Subkey Generation: Derives 16 subkeys from the main key
 * - S-Boxes/Permutations: Core components for confusion and diffusion
 *
 * Library Usage:
 * <iostream>    : For input/output operations
 * <string>      : For string manipulation and storage
 * <cmath>       : For bitwise operations (pow in S-box lookup)
 * <stdexcept>   : For exception handling (invalid hex input)
 * <algorithm>   : For reverse() in decryption and all_of() in input validation
 * <functional>  : For predicate functions in input validation
 * <vector>      : For using vectors and vectors methods
 
 * Usage Example:
 * 1. Select operation (encrypt/decrypt)
 * 2. Input 16-character hex string (plaintext/ciphertext)
 * 3. Input 16-character hex key
 *
 * Security Note:
 * DES is considered insecure for modern applications (use AES instead).

==================================================================================================================
==================================================================================================================

 * ===================== DES IMPLEMENTATION FUNCTION SUMMARY =====================
 *
 * CORE CLASS:
 *   DES_Encryption - Handles DES encryption/decryption
 *     - encrypt(plaintext, key)  : Returns ciphertext (16 hex chars)
 *     - decrypt(ciphertext, key) : Returns plaintext (16 hex chars)
 *
 * PRIVATE HELPER METHODS (DES_Encryption):
 *   - shift_bit(s, n)          : Circular-shifts string 's' left by 'n' bits
 *   - expand_R(r32)            : Expands 32-bit block to 48-bit using E-table
 *   - xor_add(s1, s2)          : Bitwise XOR of two binary strings
 *   - get_element_from_box(s,k): Returns 4-bit S-box substitution for 6-bit input 's' (box 'k')
 *   - generate_subkeys(key, decrypt) : Generates 16 subkeys (reversed if decrypt=true)
 *   - process_des(input, key_48)    : Core DES round operations (16 Feistel rounds)
 *
 * BINARY/HEX CONVERSION HELPERS:
 *   - Bin_to_Hex(s)  : Converts binary string to hex (e.g., "1101" -> "D")
 *   - Hex_to_Bin(s)  : Converts hex string to binary (e.g., "A" -> "1010")
 *   - Dec_to_Bin(n)  : Converts decimal (0-15) to 4-bit binary (e.g., 5 -> "0101")
 *
 * VALIDATION:
 *   - validate_hex_input(input, len) : Checks if 'input' is valid hex of length 'len'
 *
 * CONSTANT TABLES:
 *   - pc_1, pc_2      : Key permutation tables
 *   - IP_t, P_1       : Initial/Final permutations
 *   - E_t             : Expansion table
 *   - S[8][4][16]     : S-box substitutions
 *   - P               : Permutation after S-boxes
 *   - num_leftShift[] : Key shift schedule
 * ===============================================================================
 */




#include <iostream>
#include <string>
#include <cmath>
#include <stdexcept>
#include <algorithm>
#include <functional>
#include <vector>
using namespace std;

// Helper function declarations
string Bin_to_Hex(const string& s);
string Hex_to_Bin(const string& s);
string Dec_to_Bin(int n);
bool validate_hex_input(const string& input, size_t expected_length);

class DES_Encryption
{
private:
	// Constants regarding the keys
	const int pc_1[56] = { 57 ,49 ,41 ,33 ,25 ,17 ,9  ,
				1  ,58 ,50 ,42 ,34 ,26 ,18 ,
				10 ,2  ,59 ,51 ,43 ,35 ,27 ,
				19 ,11 ,3  ,60 ,52 ,44 ,36 ,
				63 ,55 ,47 ,39 ,31 ,23 ,15 ,
				7  ,62 ,54 ,46 ,38 ,30 ,22 ,
				14 ,6  ,61 ,53 ,45 ,37 ,29 ,
				21 ,13 ,5  ,28 ,20 ,12 ,4 };

	const int num_leftShift[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 }; // number of bits to shift for each iteration

	const int pc_2[48] = { 14 ,17 ,11 ,24 ,1  ,5  ,
				3  ,28 ,15 ,6  ,21 ,10 ,
				23 ,19 ,12 ,4  ,26 ,8  ,
				16 ,7  ,27 ,20 ,13 ,2  ,
				41 ,52 ,31 ,37 ,47 ,55 ,
				30 ,40 ,51 ,45 ,33 ,48 ,
				44 ,49 ,39 ,56 ,34 ,53 ,
				46 ,42 ,50 ,36 ,29 ,32 };

	// Constants regarding the plain text
	const int IP_t[64] = { 58 ,50 ,42 ,34 ,26 ,18 ,10 ,2 ,  // intital permutation table
				60 ,52 ,44 ,36 ,28 ,20 ,12 ,4 ,
				62 ,54 ,46 ,38 ,30 ,22 ,14 ,6 ,
				64 ,56 ,48 ,40 ,32 ,24 ,16 ,8 ,
				57 ,49 ,41 ,33 ,25 ,17 ,9  ,1 ,
				59 ,51 ,43 ,35 ,27 ,19 ,11 ,3 ,
				61 ,53 ,45 ,37 ,29 ,21 ,13 ,5 ,
				63 ,55 ,47 ,39 ,31 ,23 ,15 ,7 };

	const int E_t[48] = { 32 ,1  ,2  ,3  ,4  ,5  , // expantion table
				4  ,5  ,6  ,7  ,8  ,9  ,
				8  ,9  ,10 ,11 ,12 ,13 ,
				12 ,13 ,14 ,15 ,16 ,17 ,
				16 ,17 ,18 ,19 ,20 ,21 ,
				20 ,21 ,22 ,23 ,24 ,25 ,
				24 ,25 ,26 ,27 ,28 ,29 ,
				28 ,29 ,30 ,31 ,32 ,1 };

	const int S[8][4][16] = {                        // S-box
		{
			{ 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
			{ 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
			{ 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
			{ 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }
		},
		{
			{ 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
			{ 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
			{ 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
			{ 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 }
		},
		{
			{ 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
			{ 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
			{ 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
			{ 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }
		},
		{
			{ 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
			{ 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
			{ 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
			{ 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }
		},
		{
			{ 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
			{ 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
			{ 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
			{ 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }
		},
		{
			{ 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
			{ 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
			{ 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
			{ 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }
		},
		{
			{ 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 },
			{ 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 },
			{ 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 },
			{ 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 }
		},
		{
			{ 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
			{ 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
			{ 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
			{ 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
		}
	};

	const int P[32] = { 16 ,7  ,20 ,21 ,
				29 ,12 ,28 ,17 ,
				1  ,15 ,23 ,26 ,
				5  ,18 ,31 ,10 ,
				2  ,8  ,24 ,14 ,
				32 ,27 ,3  ,9  ,
				19 ,13 ,30 ,6  ,
				22 ,11 ,4  ,25 };

	const int P_1[64] = { 40 ,8  ,48 ,16 ,56 ,24 ,64 ,32 ,
				39 ,7  ,47 ,15 ,55 ,23 ,63 ,31 ,
				38 ,6  ,46 ,14 ,54 ,22 ,62 ,30 ,
				37 ,5  ,45 ,13 ,53 ,21 ,61 ,29 ,
				36 ,4  ,44 ,12 ,52 ,20 ,60 ,28 ,
				35 ,3  ,43 ,11 ,51 ,19 ,59 ,27 ,
				34 ,2  ,42 ,10 ,50 ,18 ,58 ,26 ,
				33 ,1  ,41 ,9  ,49 ,17 ,57 ,25 };

	// Helper methods
	string shift_bit(const string& s, int n) const
	{
		if (s.empty() || n <= 0) return s;

		string k;
		k.reserve(s.size());

		for (int i = n; i < s.size(); i++)
			k += s[i];

		for (int i = 0; i < n; i++)
			k += s[i];

		return k;
	}

	string expand_R(const string& r32) const
	{
		string r;
		r.reserve(48);
		for (int j = 0; j < 48; j++)
		{
			r += r32[E_t[j] - 1];
		}
		return r;
	}

	string xor_add(const string& s1, const string& s2) const
	{
		string result;
		result.reserve(s1.size());
		for (int j = 0; j < s1.size(); j++) {
			result += (s1[j] != s2[j]) ? '1' : '0';
		}
		return result;
	}

	string get_element_from_box(const string& s, int k) const
	{
		int dec1 = (s[0] - '0') * 2 + (s[5] - '0');
		int dec2 = 0, pwr = 0;

		for (int i = s.size() - 2; i >= 1; i--)
		{
			dec2 += (s[i] - '0') * pow(2, pwr++);
		}

		return Dec_to_Bin(S[k][dec1][dec2]);
	}

	// Generate subkeys for encryption or decryption
	vector<string> generate_subkeys(const string& key, bool decrypt = false) const
	{
		string key_64 = Hex_to_Bin(key);
		string key_56;
		key_56.reserve(56);

		// Apply permutation choice 1
		for (int i = 0; i < 56; i++)
			key_56 += key_64[pc_1[i] - 1];

		string key_firstHalf = key_56.substr(0, 28);
		string key_secondHalf = key_56.substr(28, 28);

		vector<string> L_key(16), R_key(16);

		// Generate all subkeys through shifting
		L_key[0] = shift_bit(key_firstHalf, num_leftShift[0]);
		R_key[0] = shift_bit(key_secondHalf, num_leftShift[0]);

		for (int i = 1; i < 16; i++)
		{
			L_key[i] = shift_bit(L_key[i - 1], num_leftShift[i]);
			R_key[i] = shift_bit(R_key[i - 1], num_leftShift[i]);
		}

		vector<string> keys_56(16), key_48(16);

		// Combine halves to form 56-bit keys
		for (int i = 0; i < 16; i++)
		{
			keys_56[i] = L_key[i] + R_key[i];
		}

		// Apply permutation choice 2 to get 48-bit keys
		for (int i = 0; i < 16; i++)
		{
			key_48[i].reserve(48);
			for (int j = 0; j < 48; j++)
				key_48[i] += keys_56[i][pc_2[j] - 1];
		}

		// For decryption, reverse the order of subkeys
		if (decrypt)
		{
			reverse(key_48.begin(), key_48.end());
		}

		return key_48;
	}

	// Common processing for both encryption and decryption
	string process_des(const string& input, const vector<string>& key_48) const
	{
		string input_64 = Hex_to_Bin(input);

		// Initial permutation
		string IP;
		IP.reserve(64);
		for (int i = 0; i < 64; i++)
			IP += input_64[IP_t[i] - 1];

		string L = IP.substr(0, 32);
		string R = IP.substr(32, 32);

		vector<string> L_32(16), R_32(16);
		vector<string> R_48(16), R_xor_K(16), s_1(16), P_R(16);
		vector<vector<string>> s(16, vector<string>(8));

		// First round
		R_48[0] = expand_R(R);
		R_xor_K[0] = xor_add(R_48[0], key_48[0]);

		for (int j = 0; j < 48; j += 6)  //Groub the result of xor in 6-groups
		{
			for (int k = j; k < j + 6 && k < R_xor_K[0].size(); k++)
				s[0][j / 6] += R_xor_K[0][k];
		}

		s_1[0].clear();
		for (int j = 0; j < 8; j++)
			s_1[0] += get_element_from_box(s[0][j], j); //s-l stores the result of s-boxes

		P_R[0].clear();
		for (int j = 0; j < 32; j++)
			P_R[0] += s_1[0][P[j] - 1];

		L_32[0] = R;
		R_32[0] = xor_add(P_R[0], L);

		// Remaining rounds
		for (int i = 1; i < 16; i++)
		{
			L_32[i] = R_32[i - 1];
			R_48[i] = expand_R(R_32[i - 1]);
			R_xor_K[i] = xor_add(R_48[i], key_48[i]);

			// Clear previous values
			for (int j = 0; j < 8; j++)
				s[i][j].clear();

			for (int j = 0; j < 48; j += 6) //group each 6 bits in 2d vector
			{
				for (int k = j; k < j + 6 && k < R_xor_K[i].size(); k++)
					s[i][j / 6] += R_xor_K[i][k];
			}

			s_1[i].clear();
			for (int j = 0; j < 8; j++)  //get values from s-box [CONVERT 6-BITS TO 4-BITS]
				s_1[i] += get_element_from_box(s[i][j], j);

			P_R[i].clear();
			for (int j = 0; j < 32; j++)
				P_R[i] += s_1[i][P[j] - 1];

			R_32[i] = xor_add(P_R[i], L_32[i - 1]);
		}

		// Final permutation (reverse of initial)
		string result_bin;
		string RL = R_32[15] + L_32[15];  // Note the swap for final permutation

		result_bin.reserve(64);
		for (int i = 0; i < 64; i++)
			result_bin += RL[P_1[i] - 1];

		return Bin_to_Hex(result_bin);
	}

public:
	// Encrypt plaintext using DES algorithm
	string encrypt(const string& plain_txt, const string& key) const
	{
		try {
			vector<string> key_48 = generate_subkeys(key, false);
			return process_des(plain_txt, key_48);
		}
		catch (const exception& e) {
			cerr << "Encryption error: " << e.what() << endl;
			return "";
		}
	}

	// Decrypt ciphertext using DES algorithm
	string decrypt(const string& cipher_txt, const string& key) const
	{
		try {
			vector<string> key_48 = generate_subkeys(key, true);
			return process_des(cipher_txt, key_48);
		}
		catch (const exception& e) {
			cerr << "Decryption error: " << e.what() << endl;
			return "";
		}
	}
};

int main()
{
	DES_Encryption DES;

	string plain_txt, key, cipher_txt;
	char operation;

	cout << "Select operation (e for encrypt, d for decrypt): ";
	cin >> operation;

	if (operation == 'e' || operation == 'E') {
		cout << "Enter PLAIN TEXT of EXACTLY 16 characters written in hexadecimal: ";
		while (!validate_hex_input(plain_txt, 16)) {
			cin >> plain_txt;
			if (!validate_hex_input(plain_txt, 16))
				cout << "Invalid input, try again: ";
		}

		cout << "Enter a KEY of EXACTLY 16 characters written in hexadecimal: ";
		while (!validate_hex_input(key, 16)) {
			cin >> key;
			if (!validate_hex_input(key, 16))
				cout << "Invalid input, try again: ";
		}

		cipher_txt = DES.encrypt(plain_txt, key);
		cout << "Encrypted text: " << cipher_txt << endl;
	}
	else if (operation == 'd' || operation == 'D') {
		cout << "Enter CIPHER TEXT of EXACTLY 16 characters written in hexadecimal: ";
		while (!validate_hex_input(cipher_txt, 16)) {
			cin >> cipher_txt;
			if (!validate_hex_input(cipher_txt, 16))
				cout << "Invalid input, try again: ";
		}

		cout << "Enter a KEY of EXACTLY 16 characters written in hexadecimal: ";
		while (!validate_hex_input(key, 16)) {
			cin >> key;
			if (!validate_hex_input(key, 16))
				cout << "Invalid input, try again: ";
		}

		plain_txt = DES.decrypt(cipher_txt, key);
		cout << "Decrypted text: " << plain_txt << endl;
	}
	else {
		cout << "Invalid operation selected." << endl;
	}

	return 0;
}

// Helper function implementations
string Bin_to_Hex(const string& s)
{
	string hex;
	hex.reserve(s.size() / 4);

	for (size_t i = 0; i < s.size(); i += 4)
	{
		string k = s.substr(i, 4);

		if (k == "0000") hex += '0';
		else if (k == "0001") hex += '1';
		else if (k == "0010") hex += '2';
		else if (k == "0011") hex += '3';
		else if (k == "0100") hex += '4';
		else if (k == "0101") hex += '5';
		else if (k == "0110") hex += '6';
		else if (k == "0111") hex += '7';
		else if (k == "1000") hex += '8';
		else if (k == "1001") hex += '9';
		else if (k == "1010") hex += 'A';
		else if (k == "1011") hex += 'B';
		else if (k == "1100") hex += 'C';
		else if (k == "1101") hex += 'D';
		else if (k == "1110") hex += 'E';
		else if (k == "1111") hex += 'F';
	}
	return hex;
}

string Hex_to_Bin(const string& s)
{
	string bin;
	bin.reserve(s.size() * 4);

	for (size_t i = 0; i < s.size(); i++)
	{
		switch (toupper(s[i]))
		{
		case '0': bin += "0000"; break;
		case '1': bin += "0001"; break;
		case '2': bin += "0010"; break;
		case '3': bin += "0011"; break;
		case '4': bin += "0100"; break;
		case '5': bin += "0101"; break;
		case '6': bin += "0110"; break;
		case '7': bin += "0111"; break;
		case '8': bin += "1000"; break;
		case '9': bin += "1001"; break;
		case 'A': bin += "1010"; break;
		case 'B': bin += "1011"; break;
		case 'C': bin += "1100"; break;
		case 'D': bin += "1101"; break;
		case 'E': bin += "1110"; break;
		case 'F': bin += "1111"; break;
		default: throw runtime_error("Invalid hex character: " + string(1, s[i]));
		}
	}
	return bin;
}

string Dec_to_Bin(int n)
{
	string bin;

	if (n == 0) return "0000";

	while (n > 0)
	{
		bin = char(n % 2 + '0') + bin;
		n /= 2;
	}

	while (bin.size() < 4)
		bin = '0' + bin;

	return bin;
}

bool validate_hex_input(const string& input, size_t expected_length)
{
	if (input.size() != expected_length)
		return false;

	return all_of(input.begin(), input.end(), [](char c) { //lambda
		return (c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'f') ||
			(c >= 'A' && c <= 'F');
		});
}
