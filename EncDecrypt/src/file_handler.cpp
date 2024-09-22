#include "file_handler.h"
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <iostream>

using std::ifstream;
using std::ofstream;
using std::vector;
using std::string;
using std::ios;
using std::runtime_error;
using std::istreambuf_iterator;

vector<unsigned char> readFile(const string& filepath) {
    ifstream file(filepath, std::ios::binary);

    if (!file) {
        throw runtime_error("Error opening file for reading: " + filepath);
    }

    vector<unsigned char> data((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());

    if (file.bad()) {
        throw runtime_error("Error reading file: " + filepath);
    }

    return data;
}

void writeFile(const string& filepath, vector<unsigned char>& data) {
    ofstream file(filepath, std::ios::binary);

    if (!file) {
        throw runtime_error("Error opening file for writing: " + filepath);
    }

    std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(file));

    if (!file) {
        throw runtime_error("Error writing to file: " + filepath);
    }
}
