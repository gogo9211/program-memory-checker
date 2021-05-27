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

void memory_checker::hash() 
{
	HMODULE module = LI_FN(GetModuleHandleA).cached()(0);
	IMAGE_DOS_HEADER* const dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
	IMAGE_NT_HEADERS* const nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<BYTE*>(dos_header) + dos_header->e_lfanew);

	std::size_t chunk_size = 0x300;
	std::uint32_t text = nt_headers->OptionalHeader.ImageBase + nt_headers->OptionalHeader.BaseOfCode;
	const std::uint32_t text_size = nt_headers->OptionalHeader.SizeOfCode;
	const std::uint32_t text_end = text + text_size;

	while (true)
	{
		if (text + chunk_size > text_end)
		{
			chunk_size = text_end - text;

			if (chunk_size == 0) { break; }

			const std::uint32_t hash = XXHash32::hash(reinterpret_cast<void*>(text), chunk_size, this->seed);
			this->data.push_back({ text, chunk_size, hash });

			break;
		}

		const std::uint32_t hash = XXHash32::hash(reinterpret_cast<void*>(text), chunk_size, this->seed);
		this->data.push_back({ text, chunk_size, hash });

		text += chunk_size;
	}
}

void memory_checker::start()
{
	std::thread([&]()
	{
		while (true)
		{
			for (const hash_data& data : this->data)
			{
				const std::uint32_t hash = XXHash32::hash(reinterpret_cast<void*>(data.chunk), data.chunk_size, this->seed);

				const std::uint32_t random_junk = 5 + LI_FN(rand).cached()();

				switch (random_junk)
				{
					case 0:
					case 1:
					case 3:
					case 4:
					case 5: std::exit(0); break;

					default:
					{
						if (data.hash != hash)
						    LI_FN(printf).cached()(xorstr_("memory anomaly detected at chunk: 0x%X\n"), data.chunk);
					}
				}
			}
			LI_FN(Sleep).cached()(1000);
		}
	}).detach();
}
