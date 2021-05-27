#pragma once
#include "../utils/xxhash.hpp"
#include <Windows.h>
#include <memory>
#include <vector>

struct hash_data
{
	std::uint32_t chunk;
	std::size_t chunk_size;
	std::uint32_t hash;
};

class memory_checker
{
public:
	memory_checker();

	void hash();
	void start();

private:
	std::vector<hash_data> data;
	std::uint16_t seed;
};
