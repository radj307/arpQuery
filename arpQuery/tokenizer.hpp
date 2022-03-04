#pragma once
#include "arpTable.hpp"

#include <TokenRedux.hpp>

namespace arp {

	enum class Lexeme : unsigned char {
		NONE,
		LETTER,
		DIGIT,
		WHITESPACE,
		PERIOD,
		PUNCT,
		DASH,
	};

	struct LexemeDict : token::base::LexemeDictBase<Lexeme> {
		Lexeme char_to_lexeme(const char& c) const noexcept override
		{
			if (std::isdigit(c))
				return Lexeme::DIGIT;
			else if (std::isalpha(c) || c == '_') // allow underscores to be letters
				return Lexeme::LETTER;
			switch (c) {
			case '.': return Lexeme::PERIOD;
			case '-': return Lexeme::DASH;
			case '\t': [[fallthrough]];
			case '\v': [[fallthrough]];
			case '\r': [[fallthrough]];
			case '\n': [[fallthrough]];
			case ' ': return Lexeme::WHITESPACE;
			default:
				return ispunct(c) ? Lexeme::PUNCT : Lexeme::NONE;
			}
		}
	};

	enum class TokenType : unsigned char {
		NONE,
		END,
		NET_ADDRESS,
		MAC_ADDRESS,
		WORD,
		NUMBER,
		TRIPLEDASH,
		PUNCT,
	};

	inline std::string tokenTypeToString(const TokenType& t)
	{
		switch (t) {
		case TokenType::NONE:
			return "(null)";
		case TokenType::END:
			return "(eof)";
		case TokenType::NET_ADDRESS:
			return "Network Address";
		case TokenType::MAC_ADDRESS:
			return "MAC Address";
		case TokenType::WORD:
			return "Word";
		case TokenType::NUMBER:
			return "Number";
		default:
			return{};
		}
	}

	inline std::ostream& operator<<(std::ostream& os, const TokenType& t)
	{
		return os << tokenTypeToString(t);
	}

	using Token = token::base::TokenBase<TokenType>;

	class Tokenizer : token::base::TokenizerBase<Lexeme, LexemeDict, TokenType, Token> {
		Token getNextToken(const char& c) override
		{
			std::string s; //< used to pass data between case labels when falling through

			switch (get_lexeme(c)) {
			case Lexeme::DIGIT: {
				if (str::tolower(peek()) == 'x')
					if (s = str::stringify(c, getsimilar(Lexeme::LETTER, Lexeme::DIGIT)); str::ishex(s))
						return Token{ s, TokenType::NUMBER };
				// else
				[[fallthrough]];
			}
			case Lexeme::LETTER:
				if (s.empty())
					s = str::stringify(c, getsimilar(Lexeme::LETTER, Lexeme::DIGIT, Lexeme::PERIOD, Lexeme::DASH));

				if (std::all_of(s.begin(), s.end(), isalpha))
					return Token{ s, TokenType::WORD };
				else if (std::all_of(s.begin(), s.end(), [](auto&& ch) {return isdigit(ch) || ch == '.'; }))
					return Token{ s, TokenType::NET_ADDRESS };
				else if (std::all_of(s.begin(), s.end(), [](auto&& ch) { return ch == '-' || isdigit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'); }))
					return Token{ s, TokenType::MAC_ADDRESS };
				return Token{ s, TokenType::NONE };
			case Lexeme::DASH:
				rollback();
				if (getline_and_match(3ull, "---", s))
					return Token{ s, TokenType::TRIPLEDASH };
				rollback();
				return Token{ c, TokenType::PUNCT };
			case Lexeme::PUNCT:
				return Token{ c, TokenType::PUNCT };
			case Lexeme::NONE: [[fallthrough]];
			default:
				break;
			}
			return Token{ c, TokenType::NONE };
		}
	public:
		Tokenizer(std::stringstream&& ss) : TokenizerBase<Lexeme, LexemeDict, TokenType, Token>(std::move(ss), Lexeme::WHITESPACE) {}
		Tokenizer(std::vector<std::string> const& strvec) : TokenizerBase<Lexeme, LexemeDict, TokenType, Token>(std::move([](auto&& strvec) -> std::stringstream { std::stringstream ss; for (const auto& s : strvec) ss << ' ' << s; return std::move(ss); }(strvec)), Lexeme::WHITESPACE) {}
		/**
		 * @brief				Tokenize overload that provides the EOF token for you.
		 * @param reserve_sz	Expand the vector's capacity by this number of elements each time the capacity limit is reached.
		 * @returns				std::vector<TokenT>
		 */
		[[nodiscard]] std::vector<TokenT> tokenize(const size_t& reserve_sz = 64ull)
		{
			return TokenizerBase::tokenize(TokenType::END, reserve_sz);
		}
	};

	class Parser : public token::base::IteratingParserBase<ArpTable, TokenType, Token> {
	public:
		Parser(TokenCont&& tkns) : token::base::IteratingParserBase<ArpTable, TokenType, Token>(std::move(tkns)) {}
		Parser(const TokenCont& tkns) : token::base::IteratingParserBase<ArpTable, TokenType, Token>(tkns) {}

		OutputT parse() override
		{
			OutputT table;
			std::string gateway, index;

			std::vector<ArpTableEntry> entries;
			std::string ip, mac;
			AddressType type;

			const auto& insert_entry{ [&ip, &mac, &type, &entries]() {
				if (ip.empty() || mac.empty() || type == AddressType::NONE)
					return;
				entries.emplace_back(ArpTableEntry(ip, mac, type));
				// reset variables
				ip = mac = "";
				type = AddressType::NONE;
			} };
			const auto& insert_interface{ [&table, &gateway, &index, &entries, &insert_entry]() {
				insert_entry();
				if (gateway.empty() || index.empty())
					return;

				entries.shrink_to_fit();
				table.emplace_back(Interface(gateway, index, entries));

				gateway = index = "";
				entries.clear();
			} };

			while (hasMore()) {
				const Token tkn{ *getNext() };

				switch (tkn.type) {
				case TokenType::NET_ADDRESS:
					if (peekNext()->type == TokenType::TRIPLEDASH) {
						insert_interface();
						gateway = tkn.str;
					}
					else if (ip.empty())
						ip = tkn.str;
					else throw make_exception("Parser::parse() failed:  Unmatched IP address: \"", tkn.str, '\"');
					break;
				case TokenType::MAC_ADDRESS:
					mac = tkn.str;
					break;
				case TokenType::NUMBER:
					if (peekLast()->type == TokenType::TRIPLEDASH)
						index = tkn.str;
					else throw make_exception("Parser::parse() failed:  Illegal number appearance \"", tkn.str, "\"!");
				case TokenType::WORD:
					if (peekLast()->type == TokenType::MAC_ADDRESS) {
						if (str::equalsAny(tkn.str, "dynamic"))
							type = AddressType::DYNAMIC;
						else if (str::equalsAny(tkn.str, "static"))
							type = AddressType::STATIC;
						else throw make_exception("Parser::parse() failed:  Unrecognized Address Type \"", tkn.str, '\"');
						insert_entry();
					} // else ignore
					break;
				case TokenType::END:
					insert_interface();
					return table;
				case TokenType::PUNCT: [[fallthrough]];
				default:
					break;
				}
			}

			return table;
		}
	};
}
