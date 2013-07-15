#include <iostream>
#include <Windows.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <fcntl.h>
#include <io.h>
#include <set>
#include <map>
#include <vector>
#include <algorithm>
#include <time.h>
#include <sstream>

using namespace std;

void CreateDebugConsole()
{
	HANDLE lStdHandle = 0;
	int hConHandle = 0;
	FILE *fp = 0;
	AllocConsole();
	lStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	hConHandle = _open_osfhandle(PtrToUlong(lStdHandle), _O_TEXT);
	SetConsoleTitle(L"Cube World Mod");
	SetConsoleTextAttribute(lStdHandle, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	system("cls");
	fp = _fdopen(hConHandle, "w");
	*stdout = *fp;
	setvbuf(stdout, NULL, _IONBF, 0);
}

DWORD GetModuleSize(LPSTR strModuleName)
{
	MODULEENTRY32	lpme = { 0 };
	DWORD			dwSize = 0;
	DWORD			PID = GetCurrentProcessId();
	BOOL			isMod = 0;
	char			chModName[256];

	strcpy_s(chModName, strModuleName);
	_strlwr_s(chModName);

	HANDLE hSnapshotModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	if (hSnapshotModule)
	{
		lpme.dwSize = sizeof(lpme);
		isMod = Module32First(hSnapshotModule, &lpme);
		while (isMod)
		{
			char *str = new char[4046];
			wcstombs(str, lpme.szExePath, sizeof(lpme.szExePath));
			if (strcmp(_strlwr(str), chModName))
			{
				dwSize = (DWORD) lpme.modBaseSize;
				CloseHandle(hSnapshotModule);
				return dwSize;
			}
			isMod = Module32Next(hSnapshotModule, &lpme);
		}
	}
	CloseHandle(hSnapshotModule);

	return 0;
}


DWORD FindPattern(DWORD start_offset, DWORD size, BYTE* pattern, char mask [])
{

	DWORD pos = 0;
	int searchLen = strlen(mask) - 1;
	for (DWORD retAddress = start_offset; retAddress < start_offset + size; retAddress++)
	{
		if (*(BYTE*) retAddress == pattern[pos] || mask[pos] == '?'){
			if (mask[pos + 1] == '\0')
				return (retAddress - searchLen);
			pos++;
		}
		else
			pos = 0;
	}
	return NULL;
}


void MakeJMP(BYTE *pAddress, DWORD dwJumpTo, DWORD dwLen)
{
	DWORD dwOldProtect, dwBkup, dwRelAddr;
	VirtualProtect(pAddress, dwLen, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	dwRelAddr = (DWORD) (dwJumpTo - (DWORD) pAddress) - 5;
	*pAddress = 0xE9;
	*((DWORD *) (pAddress + 0x1)) = dwRelAddr;
	for (DWORD x = 0x5; x < dwLen; x++) *(pAddress + x) = 0x90;
	VirtualProtect(pAddress, dwLen, dwOldProtect, &dwBkup);

	return;

}

DWORD draw_player_internal = FindPattern(reinterpret_cast<DWORD>(GetModuleHandle(NULL)), GetModuleSize("Cube.exe"),
	reinterpret_cast<PBYTE>("\xF3\x0F\x10\x82\x6C\x01\x00\x00"),
	"xxxxxxxx");

DWORD draw_player_JMP_back = (draw_player_internal + 6);


DWORD examine_prompt_internal = FindPattern(reinterpret_cast<DWORD>(GetModuleHandle(NULL)), GetModuleSize("Cube.exe"),
	reinterpret_cast<PBYTE>("\x8B\x0A\x49\x83\xF9\x4C"),
	"xxxxxx");

DWORD examine_prompt_JMP_back = examine_prompt_internal + 5;

DWORD push_examine = FindPattern(reinterpret_cast<DWORD>(GetModuleHandle(NULL)), GetModuleSize("Cube.exe"),
	reinterpret_cast<PBYTE>("\x8B\x8F\xAC\x08\x80\x00\x8D\x84\x24\x3C\x22\x00\x00\x50"),
	"xxxxxxxxxxxxxx");


DWORD draw_location_string = FindPattern(reinterpret_cast<DWORD>(GetModuleHandle(NULL)), GetModuleSize("Cube.exe"),
	reinterpret_cast<PBYTE>("\x55\x8B\xEC\x8B\x45\x0C\x83\x78\x14\x08\x8B\x48\x10\x72\x02\x8B\x00\x51\x8B\x4D\x08\x50\xFF\x71\x10\x6A\x00\xE8\xD0\x72\xFD\xFF\xF7\xD8\x1B\xC0\xF7\xD8\x5D\xC3"),
	"xxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxx");

DWORD draw_location_JMP_back = draw_location_string + 17 + 5;

DWORD push_nothing_special = FindPattern(reinterpret_cast<DWORD>(GetModuleHandle(NULL)), GetModuleSize("Cube.exe"),
	reinterpret_cast<PBYTE>("\x89\x45\xE4\x8D\x45\xD4\x50\x83\xEC\x18\x8B\xCC"),
	"xxxxxxxxxxxx");

DWORD load_world = FindPattern(reinterpret_cast<DWORD>(GetModuleHandle(NULL)), GetModuleSize("Cube.exe"),
	reinterpret_cast<PBYTE>("\x50\xFF\xB1\x50\x0A\x80\x00\x81\xC1\xE4\x02\x00\x00"),
	"xxxxxxxxxxxxx");

DWORD load_world_JMP_back = load_world + 5;

DWORD push_nothing_special_JMP_back = push_nothing_special + 5 + 0x0A;

DWORD dialogue_bubble_JMP_back_dialogue;
DWORD dialogue_bubble_JMP_back_no_dialogue;


DWORD oldeax;
DWORD oldecx;
DWORD oldedx;
DWORD oldebx;
DWORD oldesp;
DWORD oldebp;
DWORD oldesi;
DWORD oldedi;


typedef unsigned __int64 QWORD;

PVOID* p_player_base = NULL;

PVOID* p_item_base = NULL;

wchar_t* location_string = NULL;

struct location {
	bool city_district;
	bool trade_district;
	bool merchant;
	QWORD x;
	QWORD z;
	QWORD y;
};
map<wstring, location> cities;
typedef pair <wstring, location> City_Pair;
int city_travel_index = 0;

map<QWORD, wstring> traders;
typedef pair <QWORD, wstring> Trader_Pair;
wstring travel_target;

wchar_t last_str[32] = {0};
wchar_t last_city[32] = {0};
bool in_outer_city = false;
bool in_city_district = false;
bool in_trade_district = false;
bool in_city = false;

bool last_inspected_trader = false;
bool disable_trader_dialogue = false;

DWORD current_seed = -1;

wchar_t prompt[64] = { 0 };
/*int hashCode(wstring str) {
	int hashcode = 0;
	for (int i = str.length() - 1; i >= 0; i--)
		hashcode = 31 * hashcode + str[i];
	return hashcode;
}*/

void sanity_check(const location* loc, const wchar_t* stage, const wchar_t* city){
	DWORD x = loc->x & (DWORD) - 1;
	DWORD x_chunk = loc->x >> 32;
	DWORD z = loc->z & (DWORD) - 1;
	DWORD z_chunk = loc->z >> 32;
	DWORD y = loc->y & (DWORD) - 1;
	DWORD y_chunk = loc->y >> 32;
	printf("Chunks: %d, %d, %d\n", x_chunk, z_chunk, y_chunk);

	if (x_chunk > 255 || x_chunk < 1 || z_chunk > 255 || z_chunk < 1 || y_chunk > 2){
		wchar_t string[512];
		wsprintf(string, L"Chunk location sanity check failed.\nMod is refusing to start for this world, world-%d.sav needs to contain valid data or be deleted.\n\nPlease contact the mod developer.\n\nInformation:\nStage: %s\nCity: %s\nSeed: %d", current_seed, stage, city, current_seed);
		MessageBox(
			NULL,
			string,
			L"Assertion failed",
			MB_ICONEXCLAMATION | MB_OK
			);
		exit(-1);
	}
	
}

location* get_location(){
	QWORD player_x = *((QWORD*) p_player_base + 0x2);
	QWORD player_z = *((QWORD*) p_player_base + 0x3);
	QWORD player_y = *((QWORD*) p_player_base + 0x4);

	location* loc = new location;
	loc->x = player_x;
	loc->z = player_z;
	loc->y = player_y;
	loc->city_district = in_city_district;
	loc->trade_district = in_trade_district;

	return loc;
}


void serialize(){
	wchar_t filename[32];
	wsprintf(filename, L"world-%d.sav", current_seed);

	wprintf(L"Serializing to %s\n", filename);

	byte data[50000]; // should support ~1000 cities
	byte* data_c = data;
	wcscpy((wchar_t*) data_c, last_city);
	data_c += wcslen(last_city) * 2;
	*data_c = 0;
	data_c++;
	*data_c = 0;
	data_c++;
	for (map<wstring, location>::iterator it = cities.begin(); it != cities.end(); ++it) {
		wstring city = it->first;
		location loc = it->second;

		wcscpy((wchar_t*) data_c, city.c_str());
		data_c += wcslen(city.c_str())*2;
		*data_c = 0;
		data_c++;
		*data_c = 0;
		data_c++;

		*((QWORD*) data_c) = loc.x;
		data_c += sizeof(QWORD);
		*((QWORD*) data_c) = loc.z;
		data_c += sizeof(QWORD);
		*((QWORD*) data_c) = loc.y;
		data_c += sizeof(QWORD);

		*data_c = loc.city_district;
		data_c++;
		*data_c = loc.trade_district;
		data_c++;
	}


	HANDLE hFile = CreateFile(
		filename,				// name of the write
		GENERIC_WRITE,		    // open for writing
		0,                      // do not share
		NULL,                   // default security
		CREATE_ALWAYS,          // overwrite
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);
	DWORD dwBytesWritten = 0;
	bool bErrorFlag = WriteFile(
		hFile,							// open file handle
		data,							// start of data to write
		data_c - data,					// number of bytes to write
		&dwBytesWritten,				// number of bytes that were written
		NULL);							// no overlapped structure
	CloseHandle(hFile);

}

void deserialize(){
	wchar_t filename[32];
	wsprintf(filename, L"world-%d.sav", current_seed);

	wprintf(L"Deserializing from %s\n", filename);


	byte data[50000]; // should support ~1000 cities
	byte* data_c = data;
	DWORD  dwBytesRead = 0;
	HANDLE hFile = CreateFile(
		filename,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	printf("Got handle\n");
	bool b = ReadFile(
		hFile,
		data,
		5000 - 1,
		&dwBytesRead,
		NULL
		);
	printf("%d\n", dwBytesRead);
	printf("%d\n", b);
	if (b && (data_c - data) < dwBytesRead){
		wchar_t* data_s = (wchar_t*) data_c;
		wcscpy_s(last_city, data_s);
		data_c += wcslen(last_city) * 2;
		data_c += 2;
	}
	while (b && (data_c - data) < dwBytesRead){
		location loc;

		wchar_t city[32];
		wchar_t* data_s = (wchar_t*) data_c;
		wcscpy_s(city, data_s);
		data_c += wcslen(city) * 2;
		data_c += 2;

		loc.x = *((QWORD*) data_c);
		data_c += sizeof(QWORD);
		loc.z = *((QWORD*) data_c);
		data_c += sizeof(QWORD);
		loc.y = *((QWORD*) data_c);
		data_c += sizeof(QWORD);

		loc.city_district = *data_c;
		data_c++;
		loc.trade_district = *data_c;
		data_c++;

		sanity_check(&loc, L"deserialize", city);

		cities.insert(City_Pair(city, loc));
		wprintf(L"Loaded city %s\n", city);

	}
	CloseHandle(hFile);

}

bool on_ground(){
	if (p_player_base){
		byte flags = *((byte*) (p_player_base) + 0x5C);
		return flags & 1;
	}
	return false;
}

bool update_next_ground = false;
void on_draw_location(){
	if (p_player_base && update_next_ground && in_city && on_ground()){
		update_next_ground = false;
		wprintf(L"Updating '%s' to a location on the ground\n", last_city);
		cities[last_city] = *get_location();
		serialize();
	}
	if (wcscmp(last_str, location_string) && *((BYTE*) location_string) != 0x00 && p_player_base){

		wcsncpy(last_str, location_string, 32);

		in_outer_city = wcsstr(location_string, L"City");
		in_city_district = wcsstr(location_string, L"District");
		in_city = in_outer_city || in_city_district;
		in_trade_district = wcsstr(location_string, L"Trade District");

		if (in_outer_city){
			wchar_t* city = location_string;
			wcsncpy(last_city, city, 32);
		}
		if (!on_ground()){
			update_next_ground = true;
		} 
		else if (p_player_base &&(in_outer_city || in_city_district) && wcslen(last_city) > 0){
				wprintf(L"In city %s\n", last_city);

				srand(time(NULL));
				city_travel_index = rand()+1;

				location* loc = get_location();

				map<wstring, location>::iterator it = cities.find(last_city);
				if (it == cities.end()){
					wprintf(L"Inserting city '%s' into map\n", last_city);
					cities.insert(City_Pair(last_city, *loc));
					for (map<wstring, location>::iterator it = cities.begin(); it != cities.end(); ++it) {
						wprintf(L"\t%s\n", it->first);
					}

					/* 
					A new city has been found, so reset the traders destinations 
					so that they can include the new city
					*/
					traders.clear();
					serialize();
					sanity_check(loc, L"Save new city", travel_target.c_str());
				}
				else if (loc->trade_district){
					if (!it->second.trade_district){
						/*
						We are in a trade district, but the saved location is not.
						Update the saved location
						*/
						wprintf(L"Updating city '%s' to point to a trade district\n", last_city);
						cities[last_city] = *loc;
						serialize();
					}
				}
				else if (loc->city_district){
					if (!it->second.city_district){
						/*
						We are in a city district, but the saved location is not.
						Update the saved location
						*/
						wprintf(L"Updating city '%s' to point to a city district\n", last_city);
						cities[last_city] = *loc;
						serialize();
					}
				}
				else {
					delete loc;
				}
			}
	}


	__asm
	{
		
			mov eax, [oldeax]
			mov ecx, [oldecx]
			mov edx, [oldedx]
			mov ebx, [oldebx]
			mov esp, [oldesp]
			mov ebp, [oldebp]
			mov esi, [oldesi]
			mov edi, [oldedi]

			PUSH    ECX
			MOV     ECX, DWORD PTR SS : [EBP + 8]
			PUSH    EAX
			PUSH    DWORD PTR DS : [ECX + 10]
						
			jmp[draw_location_JMP_back]
	}
}

__declspec(naked) void draw_location_asm(){
	__asm
	{
			
			mov [oldeax], eax
			mov [oldecx], ecx
			mov [oldedx], edx
			mov [oldebx], ebx
			mov [oldesp], esp
			mov [oldebp], ebp
			mov [oldesi], esi
			mov [oldedi], edi

			mov[location_string], eax

			jmp on_draw_location
	}
}

wchar_t* inspect_dialogue = L"There is nothing special";
wchar_t* no_cities_dialogue = L"I'll only take you to cities you have already been to";
wchar_t traveled_dialogue[64];
wchar_t* dialogue = inspect_dialogue;

void on_push_nothing_special(){
		
	map<wstring, location>::iterator it = cities.find(travel_target);
	if (it != cities.end() && last_inspected_trader && wcslen(last_city) > 0){

		printf("Teleporting...\n");
		wcsncpy(traveled_dialogue, L"You have arrived in", 32);
		wcsncat(traveled_dialogue, travel_target.c_str(), 32);
		disable_trader_dialogue = true;

		location loc = it->second;
		sanity_check(&loc, L"Teleport", travel_target.c_str());
		*((QWORD*) p_player_base + 0x2) = loc.x;
		*((QWORD*) p_player_base + 0x3) = loc.z;
		*((QWORD*) p_player_base + 0x4) = loc.y;

		wcsncpy(last_city, travel_target.c_str(), 32);
		serialize();
	}
	else if (last_inspected_trader){
		dialogue = no_cities_dialogue;
	}
	else {
		dialogue = inspect_dialogue;
	}

	__asm
	{
		
			mov eax, [oldeax]
			mov ecx, [oldecx]
			mov edx, [oldedx]
			mov ebx, [oldebx]
			mov esp, [oldesp]
			mov ebp, [oldebp]
			mov esi, [oldesi]
			mov edi, [oldedi]

			MOV     ECX, ESP
			PUSH[dialogue]
			
			jmp[push_nothing_special_JMP_back]
	}
}

__declspec(naked) void push_nothing_special_asm()
{
	__asm
	{
			
			mov [oldeax], eax
			mov [oldecx], ecx
			mov [oldedx], edx
			mov [oldebx], ebx
			mov [oldesp], esp
			mov [oldebp], ebp
			mov [oldesi], esi
			mov [oldedi], edi

			jmp on_push_nothing_special
	}
}

QWORD last_item_hash;

void on_examine_prompt(){

	QWORD item_x = *((QWORD*) p_item_base + 0x1);
	QWORD item_z = *((QWORD*) p_item_base + 0x2);
	QWORD item_y = *((QWORD*) p_item_base + 0x3);

	QWORD item_hash = item_x ^ item_z ^ item_y;
	if (item_hash != last_item_hash)
	{
		last_item_hash = item_hash;

		byte id = *((byte*) p_item_base);
		printf("%x\n", id);

		if (id == 0x15 || id == 0x16 || id == 0x17)
		{
			last_inspected_trader = true;



			/*
			Teleporting to stalls is the optimal way to travel
			*/
			if (p_player_base && wcslen(last_city) > 0){
				location* loc = get_location();
				if (!loc->merchant){
					loc->city_district = true;
					loc->trade_district = true;
					loc->merchant = true;
					wprintf(L"Updating city '%s' to point to a merchant\n", last_city);
					cities[last_city] = *loc;
					serialize();
				}
			}

			

			vector<wstring> city_vector;
			for (map<wstring, location>::iterator it = cities.begin(); it != cities.end(); ++it) {
				city_vector.push_back(it->first);
			}

			city_vector.erase(remove(city_vector.begin(), city_vector.end(), wstring(last_city)), city_vector.end());
			for (auto i : city_vector) {
				wprintf(L"\t%s\n", i);
			}

			if (city_vector.size() > 0 && wcslen(last_city) > 0)
			{
				/*
					If there is no last_city then we have just
					loaded the game into a city, so we dissalow
					fast-travel to the city we are in
				*/

				map<QWORD, wstring>::iterator it = traders.find(item_hash);
				if (it == traders.end()){
					printf("New trader\n");

					travel_target = city_vector[++city_travel_index % city_vector.size()];
					traders.insert(Trader_Pair(item_hash, travel_target));
				}
				else {
					travel_target = it->second;
				}


				wcsncpy(prompt, L"[R] Travel to ", 64);
				wcscat(prompt, travel_target.c_str());
				wprintf(L"%s\n", prompt);
				DWORD dwOldProtect, dwBkup;
				VirtualProtect((BYTE*) (push_examine), 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
				*((DWORD *) ((BYTE*) (push_examine) + 0x1)) = (intptr_t) (&prompt);
				VirtualProtect((BYTE*) (push_examine), 5, dwOldProtect, &dwBkup);

			}
			else 
			{
				wcsncpy(prompt, L"[R] Travel", 64);
				DWORD dwOldProtect, dwBkup;
				VirtualProtect((BYTE*) (push_examine), 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
				*((DWORD *) ((BYTE*) (push_examine) + 0x1)) = (intptr_t) (&prompt);
				VirtualProtect((BYTE*) (push_examine), 5, dwOldProtect, &dwBkup);
			}

		}
		else {
			if (last_inspected_trader){
				wcsncpy(prompt, L"[R] Inspect", 64);
				DWORD dwOldProtect, dwBkup;
				VirtualProtect((BYTE*) (push_examine), 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
				*((DWORD *) ((BYTE*) (push_examine) + 0x1)) = (intptr_t) (&prompt);
				VirtualProtect((BYTE*) (push_examine), 5, dwOldProtect, &dwBkup);
			}
			last_inspected_trader = false;

		}
	}

		
	__asm
	{
		
			mov eax, [oldeax]
			mov ecx, [oldecx]
			mov edx, [oldedx]
			mov ebx, [oldebx]
			mov esp, [oldesp]
			mov ebp, [oldebp]
			mov esi, [oldesi]
			mov edi, [oldedi]

			MOV     ECX, DWORD PTR DS : [EDX]
			DEC     ECX
			CMP     ECX, 0x4C

			jmp[examine_prompt_JMP_back]
	}
}

__declspec(naked) void examine_prompt_asm(){
		__asm
		{
				mov [oldeax], eax
				mov [oldecx], ecx
				mov [oldedx], edx
				mov [oldebx], ebx
				mov [oldesp], esp
				mov [oldebp], ebp
				mov [oldesi], esi
				mov [oldedi], edi

				mov[p_item_base], edx

				jmp on_examine_prompt
		}
}

PVOID* old_p_player_base;
time_t last = 0;

void on_draw_player(){
		
	if (old_p_player_base != p_player_base){
		printf("Found player: %x\n", p_player_base);
		printf("Name:%s\n\n", (wchar_t*) ((p_player_base + 0x45a)));
	}
	
	old_p_player_base = p_player_base;

	__asm
	{
			
			mov eax, [oldeax]	
			mov ecx, [oldecx]
			mov edx, [oldedx]
			mov ebx, [oldebx]
			mov esp, [oldesp]
			mov ebp, [oldebp]
			mov esi, [oldesi]
			mov edi, [oldedi]

			MOVSS XMM0, DWORD PTR DS : [EDX + 0x16C]

			jmp[draw_player_JMP_back]
	}
}

__declspec(naked) void on_draw_player_asm(){
	__asm
	{
			
			mov [oldeax], eax
			mov [oldecx], ecx
			mov [oldedx], edx
			mov [oldebx], ebx
			mov [oldesp], esp
			mov [oldebp], ebp
			mov [oldesi], esi
			mov [oldedi], edi

			mov[p_player_base], edx
	
			jmp on_draw_player
	}
}



__declspec(naked) void dialogue_bubble_asm()
{
	__asm
	{
			LEA     EAX, DWORD PTR SS : [EBP - 0x1C]
			LEA     ECX, DWORD PTR DS : [EDI + 0x160]

		    cmp byte ptr ss:[disable_trader_dialogue], 0x00
			mov byte ptr ss:[disable_trader_dialogue], 0x00
			jnz NO_DIALOGUE // taken if disable_trader_dialogue == true

			PUSH EAX
			jmp [dialogue_bubble_JMP_back_dialogue] // taken if disable_trader_dialogue == false

		NO_DIALOGUE:
			jmp [dialogue_bubble_JMP_back_no_dialogue]
	}
}

void on_load_world(){

	printf("Loading world with seed: %d\n", current_seed);
	deserialize();

	__asm
	{
		mov eax, [oldeax]
		mov ecx, [oldecx]
		mov edx, [oldedx]
		mov ebx, [oldebx]
		mov esp, [oldesp]
		mov ebp, [oldebp]
		mov esi, [oldesi]
		mov edi, [oldedi]

		PUSH    EAX								// world name
		PUSH    DWORD PTR DS : [ECX + 0x800A50]	// seed

		jmp[load_world_JMP_back]
	}
}

__declspec(naked) void load_world_asm(){
	__asm
	{
		mov [oldeax], eax
		mov [oldecx], ecx
		mov [oldedx], edx
		mov [oldebx], ebx
		mov [oldesp], esp
		mov [oldebp], ebp
		mov [oldesi], esi
		mov [oldedi], edi

		mov eax, DWORD PTR DS : [ECX + 0x800A50]
		mov[current_seed], eax
		
		jmp on_load_world
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{

		CreateDebugConsole();

		DWORD cube_base = (DWORD) GetModuleHandle(L"Cube.exe");
		
		if (draw_player_internal)
		{
			printf("Found drawing opcodes: %x\n", draw_player_internal);
			MakeJMP((BYTE*) (draw_player_internal), (DWORD) on_draw_player_asm, 0x8);
		}
		else {
			printf("drawing code not found\n");
		}

		if (examine_prompt_internal)
		{
			printf("Found view element opcodes: %x\n", draw_player_internal);
			MakeJMP((BYTE*) (examine_prompt_internal), (DWORD) examine_prompt_asm, 0x6);
		}
		else {
			printf("view element code not found\n");
		}
		if (push_examine){
			push_examine += 36;
			printf("Found view push examine : %x\n", push_examine);
		}
		else {
			printf("push examine not found\n");
		}
		if (draw_location_string){
			printf("draw location found\n");
			draw_location_string += 17;
			MakeJMP((BYTE*) (draw_location_string), (DWORD) draw_location_asm, 0x8);
		}
		else {
			printf("draw location not found\n");
		}
		if (push_nothing_special){
			printf("push nothing special found\n");
			push_nothing_special += 0x0A;
			MakeJMP((BYTE*) (push_nothing_special), (DWORD) push_nothing_special_asm, 0x7);

			/*
				Patch the code that displays the text window, so we can disable this on teleport
			*/
			dialogue_bubble_JMP_back_dialogue = push_nothing_special + 0x3f;
			dialogue_bubble_JMP_back_no_dialogue = push_nothing_special + 0x46;
			MakeJMP((BYTE*) (push_nothing_special + 0x37), (DWORD) dialogue_bubble_asm, 0xA);

		}
		else {
			printf("push nothing special not found\n");
		}

		if (load_world){
			MakeJMP((BYTE*) (load_world), (DWORD) load_world_asm, 0x7);
		}
	
	}
	
	return TRUE;
}