#pragma once

#include <string>
#include <vector>

#include <libcdoc/cdoc.h>

class DDOCReader
{
public:
	struct File
	{
		std::string name, mime;
		std::vector<uint8_t> data;
	};
	static int parse(libcdoc::DataSource *src, libcdoc::MultiDataConsumer *dst);

	static std::vector<File> files(const std::vector<uint8_t> &data);
};
