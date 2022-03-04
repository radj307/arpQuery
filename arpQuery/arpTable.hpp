#pragma once
#include <string>
#include <vector>

enum class AddressType : unsigned char {
	NONE = 0,
	DYNAMIC = 1,
	STATIC = 2
};

[[nodiscard]] inline std::string AddressTypeToString(const AddressType& addrType) noexcept
{
	switch (addrType) {
	case AddressType::DYNAMIC:
		return "dynamic";
	case AddressType::STATIC:
		return "static";
	case AddressType::NONE: [[fallthrough]];
	default:
		return "(null)";
	}
}
[[nodiscard]] inline AddressType StringToAddressType(std::string strType) noexcept
{
	strType = str::tolower(strType);
	if (strType == "dynamic")
		return AddressType::DYNAMIC;
	else if (strType == "static")
		return AddressType::STATIC;
	else
		return AddressType::NONE;
}

struct ArpTableEntry {
	// @brief	IP Address
	std::string netaddr;
	// @brief	MAC Address
	std::string physaddr;
	// @brief	DHCP/Static IP
	AddressType type;

	ArpTableEntry(const std::string& network_address, const std::string& physical_address, const AddressType& address_type) : netaddr{ network_address }, physaddr{ physical_address }, type{ address_type } {}
	ArpTableEntry(const std::string& network_address, const std::string& physical_address, const std::string& address_type) : netaddr{ network_address }, physaddr{ physical_address }, type{ StringToAddressType(address_type) } {}

	std::string IPAddress() const { return netaddr; }
	std::string MACAddress() const { return physaddr; }

};

struct Interface {
	std::string gateway;
	size_t index;
	std::vector<ArpTableEntry> entries;

	Interface(const std::string& gateway_address, const size_t& index, const std::vector<ArpTableEntry>& entries) : gateway{ gateway_address }, index{ index }, entries{ entries } {}
	Interface(const std::string& gateway_address, const std::string& index, const std::vector<ArpTableEntry>& entries) : gateway{ gateway_address }, index{ static_cast<size_t>(str::toBase10(index, 16)) }, entries{ entries } {}
};

struct ArpTable {
	using container = std::vector<Interface>;
	using iterator = container::iterator;
	using const_iterator = container::const_iterator;
	container interfaces;

	ArpTable() = default;

	WINCONSTEXPR auto begin() const { return interfaces.begin(); }
	WINCONSTEXPR auto end() const { return interfaces.end(); }
	auto at(const size_t& pos) const { return interfaces.at(pos); }
	WINCONSTEXPR auto empty() const { return interfaces.empty(); }
	WINCONSTEXPR void reserve(const size_t& size) { interfaces.reserve(size); }
	WINCONSTEXPR auto capacity() const { return interfaces.capacity(); }

	std::optional<Interface> get(const std::function<bool(Interface)>& pred) const
	{
		for (const auto& it : interfaces)
			if (pred(it))
				return it;
		return std::nullopt;
	}
	std::optional<Interface> get(const std::string& addr) const
	{
		return get([&addr](auto&& i) {
			return i.gateway == addr;
		});
	}
	std::optional<Interface> get(const size_t& interfaceIndex) const
	{
		return get([&interfaceIndex](auto&& i) {
			return i.index == interfaceIndex;
		});
	}

	auto insert(const const_iterator& it, auto&& iface)
	{
		static_assert(std::same_as<std::remove_cvref_t<decltype(iface)>, Interface>, "Cannot insert non-Interface type to the arp table.");
		return interfaces.insert(it, std::forward<decltype(iface)>(iface));
	}
	auto emplace_back(auto&& iface)
	{
		static_assert(std::same_as<std::remove_cvref_t<decltype(iface)>, Interface>, "Cannot append non-Interface type to the arp table.");
		return interfaces.emplace_back(std::forward<decltype(iface)>(iface));
	}

	friend std::ostream& operator<<(std::ostream& os, const ArpTable& arp)
	{
		const size_t column_width{ 22ull };

		const auto& printColumnHeader{ [&column_width, &os]() { os << "  " << "Internet Address" << indent(column_width, 16) << "Physical Address" << indent(column_width, 16) << "Type" << '\n'; } };
		const auto& printColumn{ [&column_width, &os](const ArpTableEntry& entry) { 
			os 
				<< "  " << entry.netaddr
				<< indent(column_width, entry.netaddr.size()) << entry.physaddr
				<< indent(column_width, entry.physaddr.size()) << AddressTypeToString(entry.type) << '\n';
		} };

		for (const auto& it : arp.interfaces) {
			os << "Interface: " << it.gateway << " --- 0x" << str::fromBase10(it.index, 16) << '\n';
			printColumnHeader();

			for (const auto& entry : it.entries)
				printColumn(entry);

			os << '\n';
		}
		return os;
	}
};

