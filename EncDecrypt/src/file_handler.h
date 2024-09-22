#pragma once
#include <vector>
#include <string>


std::vector<unsigned char> readFile(const std::string& filepath);
void writeFile(const std::string& filepath, std::vector<unsigned char>& data);