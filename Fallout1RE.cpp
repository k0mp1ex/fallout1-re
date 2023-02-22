#include <Windows.h>
#include <TlHelp32.h>

#include <format>
#include <functional>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

template <class... Args>
void Print(const std::string_view text, Args&&... args) {
    std::cout << std::vformat(text, std::make_format_args(args...)) << std::endl;
}

constexpr auto PROCESS_NAME = L"falloutwHR.exe";

namespace RE {
    DWORD GetProcId(const wchar_t* procName) {
        DWORD  procId = 0;
        HANDLE hSnap = (CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 procEntry;
            procEntry.dwSize = sizeof(procEntry);
            if (Process32First(hSnap, &procEntry)) {
                do {
                    if (!_wcsicmp(procEntry.szExeFile, procName)) {
                        procId = procEntry.th32ProcessID;
                        break;
                    }
                } while (Process32Next(hSnap, &procEntry));
            }
        }
        CloseHandle(hSnap);
        return procId;
    }

    uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName) {
        uintptr_t modBaseAddr = 0;
        HANDLE    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 modEntry;
            modEntry.dwSize = sizeof(modEntry);
            if (Module32First(hSnap, &modEntry)) {
                do {
                    if (!_wcsicmp(modEntry.szModule, modName)) {
                        modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                        break;
                    }
                } while (Module32Next(hSnap, &modEntry));
            }
        }
        CloseHandle(hSnap);
        return modBaseAddr;
    }

    uintptr_t FindDMAAddy(HANDLE hProc, uintptr_t ptr, std::vector<unsigned int> offsets) {
        uintptr_t addr = ptr;
        int       out;
        for (unsigned int i = 0; i < offsets.size(); ++i) {
            ReadProcessMemory(hProc, (BYTE*)addr, &out, sizeof(out), 0);
            addr = out + offsets[i];
        }
        return addr;
    }
}

namespace Fallout1 {
    HANDLE    _handle = nullptr;
    DWORD     GetProcID() { return RE::GetProcId(PROCESS_NAME); }
    uintptr_t GetModuleBaseAddress() { return RE::GetModuleBaseAddress(GetProcID(), PROCESS_NAME); }
    void      UsingProcess(std::function<void()> func) {
        _handle = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetProcID());
        func();
        CloseHandle(_handle);
    }
    uintptr_t GetAddress(unsigned int baseAddress, std::vector<unsigned int> offsets = {}) {
        return RE::FindDMAAddy(_handle, GetModuleBaseAddress() + baseAddress, offsets);
    }

    struct Item {
        char _unk1[0x3C];                      //0x00 => padding to skip unknown data and match alignment (0x3C from beginning of struct)
        int ammo;                              //0x3C
        char _unk2[0x64 - sizeof(int) - 0x3C]; //0x40 => padding to skip unknown data and match alignment (0x64 from beginning of struct, 0x64 - sizeof(int ammo) - 0x3C from beginning of struct)
        int prototypeID;                       //0x64
    };

    struct InventoryItem {
        Item* item; //4 byte size pointer (important to build as 32-bit). As a pointer we'll need to use ReadProcessMemory later to read the value it points to
        int count;  //4 byte size int (0x8 from beginning of struct)
    };

    struct Inventory {
        InventoryItem items[6]; //6 is the max amount of items in inventory (not equipped slots)
    };

    void ShowPlayer() {
        UsingProcess([&]() {
            char playerName[12];  //falloutwHR.exe + 16BF1C
            uintptr_t playerNameAddress = GetAddress(0x16BF1C);
            ReadProcessMemory(_handle, (BYTE*)playerNameAddress, &playerName, sizeof(playerName), nullptr);
            Print("Player name: {}", playerName);

            int playerAge;        //falloutwHR.exe + 1076C8
            uintptr_t playerAgeAddress = GetAddress(0x1076C8);
            ReadProcessMemory(_handle, (BYTE*)playerAgeAddress, &playerAge, sizeof(playerAge), nullptr);
            Print("Player age: {}", playerAge);

            int playerHitPoints;  //falloutwHR.exe + 105708
            uintptr_t playerHitPointsAddress = GetAddress(0x105708);
            ReadProcessMemory(_handle, (BYTE*)playerHitPointsAddress, &playerHitPoints, sizeof(playerHitPoints), nullptr);
            Print("Player hit points: {}", playerHitPoints);

            int playerCharacterPoints;        //falloutwHR.exe + 10502C
            uintptr_t playerCharacterPointsAddress = GetAddress(0x10502C);
            ReadProcessMemory(_handle, (BYTE*)playerCharacterPointsAddress, &playerCharacterPoints, sizeof(playerCharacterPoints), nullptr);
            Print("Player character points: {}", playerCharacterPoints);
            });
    }

    void ShowItem(Item* item) {
        Print("item->ammo = {}", item->ammo);
        Print("item->prototypeID = {:08}", item->prototypeID); //it's still a decimal value, just formatting with zero padding
    }

    int GetNumberOfItemsInInventory() {
        int result{};
        UsingProcess([&]() {
            uintptr_t ptr = GetAddress(0x19CE50, { 0x0 }); //offset 0x0 just to dereference 0x19CE50 using ReadProcessMemory inside FindDMAAddy
            ReadProcessMemory(_handle, (BYTE*)ptr, &result, sizeof(result), nullptr);
            });
        return result;
    }

    void ShowInventory() {
        int itemCount = GetNumberOfItemsInInventory();
        Print("Item count in inventory: {}", itemCount);

        UsingProcess([&]() {
            uintptr_t inventoryAddress = GetAddress(0x19CE50, { 0x8, 0x0 });
            Print("inventoryAddress: 0x{:08x}", inventoryAddress);
            Print("--------------");

            Inventory inv; //falloutwHR.exe + 19CE50
            ReadProcessMemory(_handle, (BYTE*)inventoryAddress, &inv, sizeof(inv), nullptr);
            Print("sizeof(Inventory): {}", sizeof(Inventory));

            Print("[Items in inventory not equipped]");
            for (int i {}; i < itemCount; ++i) {
                Print("inv.items[{}].count = {}", i, inv.items[i].count);
                Print("inv.items[{}].item = 0x{:08x}", i, (uintptr_t)inv.items[i].item);

                //inv.items[i].item is a pointer, we need ReadProcessMemory again to access the region it points to and store it in => Item item
                //we will need to use ReadProcessMemory everytime we need to dereference a pointer
                //IF we were inside the same process, we would have access to all its memory so we could just dereference the pointer and access all its values right away
                Item item;
                ReadProcessMemory(_handle, (BYTE*)(inv.items[i].item), &item, sizeof(item), nullptr);
                ShowItem(&item);

                Print("--------------");
            }

            Print("[Items equipped in inventory]");

            Print("[Slot 1]");
            uintptr_t itemEquipped1Address = GetAddress(0x19CF10, { 0x0 }); //offset 0x0 just to dereference 0x19CF10 using ReadProcessMemory inside FindDMAAddy
            if (itemEquipped1Address) {
                Item itemEquipped1;   //falloutwHR.exe + 19CF10
                ReadProcessMemory(_handle, (BYTE*)itemEquipped1Address, &itemEquipped1, sizeof(itemEquipped1), nullptr);
                ShowItem(&itemEquipped1);
            }

            Print("--------------");

            Print("[Slot 2]");
            uintptr_t itemEquipped2Address = GetAddress(0x19CF1C, { 0x0 }); //offset 0x0 just to dereference 0x19CF1C using ReadProcessMemory inside FindDMAAddy
            if (itemEquipped2Address) {
                Item itemEquipped2;   //falloutwHR.exe + 19CF1C
                ReadProcessMemory(_handle, (BYTE*)itemEquipped2Address, &itemEquipped2, sizeof(itemEquipped2), nullptr);
                ShowItem(&itemEquipped2);
            }
            });
    }
}

int main() {
    Fallout1::ShowPlayer();
    Fallout1::ShowInventory();
    return 0;
}
