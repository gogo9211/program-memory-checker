#include "mc.hpp"
#include "../utils/encrypt.hpp"
#include "../utils/import.hpp"
#include <ctime>
#include <thread>

memory_checker::memory_checker()
{
	std::srand(std::time(nullptr));

	this->seed = static_cast<std::uint16_t>(1 + (std::rand() % 0x1000));
}

void memory_checker::hash(const std::uintptr_t function) 
{
	std::uint16_t size = this->calculate_function_size(function);
	std::uint32_t hash = XXHash32::hash(reinterpret_cast<void*>(function), size, this->seed);

	this->data.push_back({ function, size, hash });
}

void memory_checker::start()
{
	std::thread([&]()
	{
		while (true)
		{
			for (const auto& hash_data : this->data)
			{
				std::uint32_t hash = XXHash32::hash(reinterpret_cast<void*>(hash_data.function), hash_data.size, this->seed);

				const auto random_junk = 5 + std::rand();

				switch (random_junk)
				{
					case 0:
					case 1:
					case 3:
					case 4:
					case 5: std::exit(0); break;

					default:
					{
						if (hash_data.hash != hash)
						    LI_FN(printf).cached()(xorstr_("memory anomaly detected at function: 0x%X\n"), hash_data.function);
					}
				}
			}
			LI_FN(Sleep)(1000);
		}
	}).detach();
}

std::size_t memory_checker::calculate_function_size(const std::uintptr_t function)
{
	auto bytes = reinterpret_cast<std::uint8_t*>(function);

	do
		bytes += 0x10;
	while (!(*reinterpret_cast<std::uint16_t*>(bytes) == 0x8B55 && bytes[2] == 0xEC));

	return reinterpret_cast<std::size_t>(bytes) - function;
}
