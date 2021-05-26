#pragma once
#include "../utils/xxhash.hpp"
#include <Windows.h>
#include <memory>
#include <vector>

struct hash_data
{
	std::uint32_t function;
	std::size_t size;
	std::uint32_t hash;
};

class memory_checker
{
public:
	memory_checker();

	void hash(const std::uintptr_t function);
	void start();

private:
	std::size_t calculate_function_size(const std::uintptr_t function);

	std::vector<hash_data> data;
	std::uint16_t seed;
};
