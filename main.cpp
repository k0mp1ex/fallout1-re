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
            ReadProcessMemory(hProc, (BYTE*)addr, &out, sizeof(out), nullptr);
            addr = out + offsets[i];
        }
        return addr;
    }

    void PatchEx(BYTE* dst, BYTE* src, unsigned int size, HANDLE hProcess) {
        DWORD oldProtect;
        VirtualProtectEx(hProcess, dst, size, PAGE_EXECUTE_READWRITE, &oldProtect);
        WriteProcessMemory(hProcess, dst, src, size, nullptr);
        VirtualProtectEx(hProcess, dst, size, oldProtect, &oldProtect);
    }

    void NopEx(BYTE* dst, unsigned int size, HANDLE hProcess) {
        BYTE* nopArray = new BYTE[size];
        memset(nopArray, 0x90, size); //0x90 = NOP

        PatchEx(dst, nopArray, size, hProcess);
        delete[] nopArray;
    }
}

namespace Fallout1 {
    constexpr auto PROCESS_NAME = L"falloutwHR.exe";
    HANDLE    _handle = nullptr;
    DWORD     GetProcID() { return RE::GetProcId(PROCESS_NAME); }
    void      UsingProcess(std::function<void()> func) {
        _handle = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetProcID());
        func();
        CloseHandle(_handle);
    }
    template <typename T>
    bool ResolveIntoVariable(uintptr_t baseAddress, std::vector<unsigned int> offsets, T* value) {
        uintptr_t address = RE::FindDMAAddy(_handle, baseAddress, offsets);
        if (address) {
            ReadProcessMemory(_handle, (BYTE*)address, value, sizeof(T), nullptr);
        }
        return address;
    }
    template <typename T>
    bool ResolveFromBaseModuleIntoVariable(uintptr_t baseAddress, std::vector<unsigned int> offsets, T* value) {
        return ResolveIntoVariable(RE::GetModuleBaseAddress(GetProcID(), PROCESS_NAME) + baseAddress, offsets, value);
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
        char playerName[12];  //falloutwHR.exe + 16BF1C
        ResolveFromBaseModuleIntoVariable(0x16BF1C, {}, &playerName);
        Print("Player name: {}", playerName);

        int playerAge;        //falloutwHR.exe + 1076C8
        ResolveFromBaseModuleIntoVariable(0x1076C8, {}, &playerAge);
        Print("Player age: {}", playerAge);

        int playerHitPoints;  //falloutwHR.exe + 105708
        ResolveFromBaseModuleIntoVariable(0x105708, {}, &playerHitPoints);
        Print("Player hit points: {}", playerHitPoints);

        int playerCharacterPoints; //falloutwHR.exe + 10502C
        ResolveFromBaseModuleIntoVariable(0x10502C, {}, &playerCharacterPoints);
        Print("Player character points: {}", playerCharacterPoints);
    }

    void ShowItem(Item* item) {
        //be aware, the item we have here is inside our own process memory and it was read from the game process using ReadProcessMemory
        //it won't have the same address as the original inv.items[i].item!
        Print("item->ammo = {}", item->ammo);
        Print("item->prototypeID = {:08}", item->prototypeID); //it's still a decimal value, just formatting with zero padding
    }

    int GetNumberOfItemsInInventory() {
        int result {};
        ResolveFromBaseModuleIntoVariable(0x19CE50, { 0x0 }, &result);
        return result;
    }

    void ShowInventory() {
        int itemCount = GetNumberOfItemsInInventory();
        Print("Item count in inventory: {}", itemCount);

        Inventory inv; //falloutwHR.exe + 19CE50
        if (ResolveFromBaseModuleIntoVariable(0x19CE50, { 0x8, 0x0 }, &inv)) {
            Print("[Items in inventory not equipped]");

            for (int i{}; i < itemCount; ++i) {
                Print("inv.items[{}].count = {}", i, inv.items[i].count);
                Print("inv.items[{}].item = 0x{:08x}", i, reinterpret_cast<uintptr_t>(inv.items[i].item));

                //inv.items[i].item is a pointer, we need ReadProcessMemory again to access the region it points to and store it in => Item item
                //we will need to use ReadProcessMemory everytime we need to dereference a pointer
                //IF we were inside the same process, we would have access to all its memory so we could just dereference the pointer and access all its values right away
                Item item;
                //here we already have the "final" pointer, no need to add the base module address to it
                if (ResolveIntoVariable(reinterpret_cast<uintptr_t>(inv.items[i].item), {}, &item)) {
                    ShowItem(&item);
                }

                Print("--------------");
            }

            Print("[Items equipped in inventory]");

            Print("[Slot 1]");

            Item itemEquipped1;   //falloutwHR.exe + 19CF10
            if (ResolveFromBaseModuleIntoVariable(0x19CF10, { 0x0 }, &itemEquipped1)) { //offset 0x0 just to dereference 0x19CF10 using ReadProcessMemory inside FindDMAAddy
                ShowItem(&itemEquipped1);
            }

            Print("--------------");

            Print("[Slot 2]");
            Item itemEquipped2;   //falloutwHR.exe + 19CF1C
            if (ResolveFromBaseModuleIntoVariable(0x19CF1C, { 0x0 }, &itemEquipped2)) { //offset 0x0 just to dereference 0x19CF1C using ReadProcessMemory inside FindDMAAddy
                ShowItem(&itemEquipped2);
            }
        }
    }

    void PatchInfiniteHitPoints() {
        static bool hookedHitPoints {};
        hookedHitPoints = !hookedHitPoints;
        Print("Infinite Hit Points State: {}", hookedHitPoints ? "ON" : "OFF");

        BYTE* instructionAddress = (BYTE*)RE::GetModuleBaseAddress(GetProcID(), PROCESS_NAME) + 0x27D29;
        if (hookedHitPoints) {
            RE::NopEx(instructionAddress, 3, _handle);
        }
        else {
            RE::PatchEx(instructionAddress, (BYTE*)"\x89\x53\x2C", 3, _handle);
        }
    }

    void Welcome() {
        Print("====================");
        Print("[Let's RE Fallout!]");
        Print("Press <INSERT> to toggle 'Infinite Hit Points' ON/OFF");
        Print("Press <HOME> to show player's inventory and general info");
        Print("Press <END> to quit");
        Print("====================");
    }

    void MainLoop() {
        UsingProcess([&]() {
            DWORD dwExit = 0;

            while (GetExitCodeProcess(_handle, &dwExit) && dwExit == STILL_ACTIVE) {
                if (GetAsyncKeyState(VK_END) & 1) {
                    return;
                }

                if (GetAsyncKeyState(VK_HOME) & 1) {
                    ShowPlayer();
                    ShowInventory(); //we need to open inventory first
                    Print("-----------------");
                }

                if (GetAsyncKeyState(VK_INSERT) & 1) {
                    PatchInfiniteHitPoints();
                }

                Sleep(10);
            }
        });
    }

}

int main() {
    Fallout1::Welcome();
    Fallout1::MainLoop();
    return 0;
}
