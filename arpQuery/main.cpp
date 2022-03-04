#include <TermAPI.hpp>
#include <palette.hpp>
#include <str.hpp>
#include <strmath.hpp>
#include <process.hpp>

#include "tokenizer.hpp"

#include <fileio.hpp>

int main(const int argc, char** argv)
{
	enum class COLOR {
		NONE,
	};
	term::palette<COLOR> color{
		std::make_pair(COLOR::NONE, color::white),

	};
	try {
		//end temp section
		std::stringstream buffer{};
		if (process::exec(&buffer, "arp -a", process::Mode::TEXT | process::Mode::READ) == 0) {
			const auto arpTable{ arp::Parser{ arp::Tokenizer(std::move(buffer)).tokenize() }.parse() };

			std::cout << arpTable << std::endl;
		}
		else throw make_exception("Command \"arp -a\" failed:  Non-Zero Return Code!");
		return 0;
	} catch (const std::exception& ex) {
		std::cerr << color.get_error() << ex.what() << std::endl;
	} catch (...) {
		std::cerr << color.get_crit() << "An undefined exception occurred!" << std::endl;
	}
	return 1;
}
