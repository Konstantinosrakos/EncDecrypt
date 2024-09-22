#pragma once
#include <vector>
#include <string>

class Password
{
public:
	Password(const std::string& password);

	Password(const std::string& password,
			const std::vector<unsigned char>& salt,
			const std::vector<unsigned char>& iv);

	const std::vector<unsigned char>& getSalt() const;

	const std::vector<unsigned char>& getKey() const;
private:
	std::string password_;
	std::string info_;
	std::string digestAlgorithm_;
	std::vector<unsigned char> salt_;
	std::vector<unsigned char> iv_;
	std::vector<unsigned char> key_;

	const int salt_length_ = 16;
	const int key_length_ = 32;
	const int iterations_ = 10000;


	void generateSalt();
	void generateInfo();
	void deriveKey();
	void deriveKey(const std::vector<unsigned char>& salt, const std::vector<unsigned char>& iv);
	void generateDigest(const std::string& algorithm);
};
