#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <fcntl.h>
#include <io.h>
#include <set>
#include <map>
#include <vector>
#include <algorithm>
#include <time.h>

using namespace std;

wstring ExePath() {
	wchar_t buffer[MAX_PATH];
	GetModuleFileName(NULL, buffer, MAX_PATH);
	string::size_type pos = wstring(buffer).find_last_of(L"\\/");
	return wstring(buffer).substr(0, pos).append(L"\\");
}

void move_old_saves(){
	CreateDirectory((ExePath().append(L"fast-travel/").c_str()), NULL);
	struct _wfinddata_t dirFile;
	long hFile;
	if ((hFile = _wfindfirst(ExePath().append(L"*.sav").c_str(), &dirFile)) != -1)
	{
		wprintf(L"Moving saves from the main directory: %s\n", ExePath());
		do{
			wstring file = ExePath().append(dirFile.name);
			wstring dest = ExePath().append(L"fast-travel\\").append(dirFile.name);
			wprintf(L"Moving %s -> %s\n", file.c_str(), dest.c_str());
			MoveFile(file.c_str(), dest.c_str());
			
		} while (_wfindnext(hFile, &dirFile) == 0);
		_findclose(hFile);
	}

}


void CreateDebugConsole()
{
	HANDLE lStdHandle = 0;
	int hConHandle = 0;
	FILE *fp = 0;
	AllocConsole();
	lStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	hConHandle = _open_osfhandle(PtrToUlong(lStdHandle), _O_TEXT);
	SetConsoleTitle(L"Fast Travel Mod");
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
	reinterpret_cast<PBYTE>("\xFF\xB0\x90\x01\x00\x00\x8D\x84\x24\x60\x09\x00\x00"),
	"xxxxxxxxxxxxx");

DWORD draw_player_JMP_back = draw_player_internal + 5;


DWORD examine_prompt_internal = FindPattern(reinterpret_cast<DWORD>(GetModuleHandle(NULL)), GetModuleSize("Cube.exe"),
	reinterpret_cast<PBYTE>("\x8B\x0A\x49\x83\xF9\x4C"),
	"xxxxxx");

DWORD examine_prompt_JMP_back = examine_prompt_internal + 5;

DWORD push_examine = examine_prompt_internal + 0x3BD;


DWORD draw_location = FindPattern(reinterpret_cast<DWORD>(GetModuleHandle(NULL)), GetModuleSize("Cube.exe"),
	reinterpret_cast<PBYTE>("\x55\x8B\xEC\x8B\x45\x0C\x83\x78\x14\x08\x8B\x48\x10\x72\x02\x8B\x00\x51\x8B\x4D\x08\x50\xFF\x71\x10\x6A\x00\xE8\xD0\x72\xFD\xFF\xF7\xD8\x1B\xC0\xF7\xD8\x5D\xC3"),
	"xxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxx");

DWORD draw_location_JMP_back;

DWORD original_draw_call = FindPattern(reinterpret_cast<DWORD>(GetModuleHandle(NULL)), GetModuleSize("Cube.exe"),
	reinterpret_cast<PBYTE>("\x55\x8B\xEC\x8B\x55\x08\x8B\xC1\x8B\x48\x10\x3B\xCA"),
	"xxxxxxxxxxxxx");

DWORD push_nothing_special = FindPattern(reinterpret_cast<DWORD>(GetModuleHandle(NULL)), GetModuleSize("Cube.exe"),
	reinterpret_cast<PBYTE>("\x89\x45\xE4\x8D\x45\xD4\x50\x83\xEC\x18\x8B\xCC"),
	"xxxxxxxxxxxx");

DWORD push_nothing_special_JMP_back = push_nothing_special + 5 + 0x0A;

DWORD load_world = FindPattern(reinterpret_cast<DWORD>(GetModuleHandle(NULL)), GetModuleSize("Cube.exe"),
	reinterpret_cast<PBYTE>("\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\xF0\x00\x00\x00"),
	"xxxxxxxxxxxxx");

DWORD load_world_JMP_back = load_world + 5;

DWORD key_press = FindPattern(reinterpret_cast<DWORD>(GetModuleHandle(NULL)), GetModuleSize("Cube.exe"),
	reinterpret_cast<PBYTE>("\x83\xC0\xF7\x83\xF8\x67"),
	"xxxxxx");

DWORD key_press_jmp_back = key_press + 5;



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

HINSTANCE hinst;

struct location {
	byte city_district;
	byte trade_district;
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

HHOOK hhk;

bool do_town_portal = false;

bool last_inspected_trader = false;
bool disable_trader_dialogue = false;

bool update_next_ground = false;

bool in_city_district = false;
bool in_trade_district = false;

wchar_t* p_location_internal = NULL;
wchar_t* current_city = NULL;
wchar_t* current_district = NULL;

wchar_t* last_city = NULL;

DWORD current_seed = -1;


int portal_base_cost = 0;
int portal_level_cost = 0;
int town_portal_base_cost = 0;
int town_portal_level_cost = 0;


wchar_t prompt[64] = { 0 };

void debug_location(location loc){
	DWORD x = loc.x & (DWORD) - 1;
	DWORD x_chunk = loc.x >> 32;
	DWORD z = loc.z & (DWORD) - 1;
	DWORD z_chunk = loc.z >> 32;
	DWORD y = loc.y & (DWORD) - 1;
	DWORD y_chunk = loc.y >> 32;

	printf("X: %d, %d\tZ: %d, %d\tY: %d, %d\n", x, x_chunk, z, z_chunk, y, y_chunk);
}

void fail(wchar_t* opcodes)
{
	wchar_t string[256];
	wsprintf(string, L"Failed to find %s opcodes\n", opcodes);
	wprintf(string);
	fflush(stdout);
	MessageBox(
		NULL,
		string,
		L"Opcode hot-replace failed",
		MB_ICONEXCLAMATION | MB_OK
		);
	exit(-1);
}

void sanity_check(const location* loc, const wchar_t* stage, const wchar_t* city){
	DWORD x = loc->x & (DWORD) - 1;
	DWORD x_chunk = loc->x >> 32;
	DWORD z = loc->z & (DWORD) - 1;
	DWORD z_chunk = loc->z >> 32;
	DWORD y = loc->y & (DWORD) - 1;
	DWORD y_chunk = loc->y >> 32;

	if (x_chunk > 255 || x_chunk < 1 || z_chunk > 255 || z_chunk < 1 || y_chunk > 2){
		wchar_t string[512];
		wsprintf(string, L"Chunk location sanity check failed.\nMod is refusing to start for this world, \\fast-travel\\world-%d.sav needs to contain valid data or be deleted.\n\nPlease contact the mod developer.\n\nInformation:\nStage: %s\nCity: %s\nSeed: %d\n", current_seed, stage, city, current_seed);
		printf("Location:\n\tX: %d, %d\n\tZ: %d, %d\n\tY: %d, %d\n", x_chunk, x, z_chunk, z, y_chunk, y);
		wprintf(string);
		fflush(stdout);
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
	wchar_t filename[256];
	wsprintf(filename, L"%sfast-travel\\world-%d.sav", ExePath().c_str(), current_seed);

	wprintf(L"Serializing to %s\n", filename);
	fflush(stdout);

	byte data[50000]; // should support ~1000 cities
	byte* data_c = data;

	if (last_city){
		wcscpy((wchar_t*) data_c, last_city);
		data_c += wcslen(last_city) * 2;
	}
	*data_c = 0;
	data_c++;
	*data_c = 0;
	data_c++;
	for (map<wstring, location>::iterator it = cities.begin(); it != cities.end(); ++it) {
		wstring city = it->first;
		location loc = it->second;

		wcscpy((wchar_t*) data_c, city.c_str());
		data_c += wcslen(city.c_str()) * 2;
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
		false);							// no overlapped structure
	CloseHandle(hFile);
	fflush(stdout);

}

void deserialize(){
	wchar_t filename[256];
	wsprintf(filename, L"%sfast-travel\\world-%d.sav", ExePath().c_str(), current_seed);

	wprintf(L"Deserializing from %s\n", filename);
	fflush(stdout);

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
		false
		);
	printf("%d\n", dwBytesRead);
	printf("%d\n", b);
	if (b && (data_c - data) < dwBytesRead){
		if (*data_c){
			// If not \0, then a valid string was written
			last_city = new wchar_t[32];
			wcsncpy(last_city, (wchar_t*) data_c, 32);
			data_c += wcslen(last_city) * 2;
			wprintf(L"Loaded last_city = %s\n", last_city);
		}
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
	fflush(stdout);

}

bool on_ground(){
	if (p_player_base){
		byte flags = *((byte*) (p_player_base) + 0x5C);
		return flags & 1;
	}
	return false;
}

unsigned int draw_location_cycle = 0;

unsigned int last_no_city_cycle = 0;
unsigned int last_no_district_cycle = 0;


void on_draw_location(){
	if (p_player_base && ++draw_location_cycle % 1024 < 4){
		//printf("%d    -   update\n", time(NULL));
		if (update_next_ground && p_player_base && current_city && on_ground()){
			update_next_ground = false;
			wprintf(L"Updating '%s' to a location on the ground\n", current_city);
			location loc = *get_location();
			cities[current_city] = loc;
			serialize();
			sanity_check(&loc, L"Update city to ground level", travel_target.c_str());
			fflush(stdout);
		}
		bool location_changed = false;
		if (p_location_internal && wcsstr(p_location_internal, L"City"))
		{
			last_no_city_cycle = 0;
			last_no_district_cycle++;
			if (!current_city || wcscmp(current_city, p_location_internal)){
				wprintf(L"current_city changed from %s to %s\n", current_city, p_location_internal);
				fflush(stdout);
				if (!current_city){
					current_city = new wchar_t[32];
				}
				wcsncpy(current_city, p_location_internal, 32);

				if (!last_city){
					last_city = new wchar_t[32];
				}
				wcsncpy(last_city, current_city, 32);
				serialize();

				location_changed = true;
			}
		}
		else if (p_location_internal && wcsstr(p_location_internal, L"District"))
		{
			last_no_district_cycle = 0;
			last_no_city_cycle++;
			if (!current_district || wcscmp(current_district, p_location_internal)){
				wprintf(L"current_district changed from %s to %s\n", current_district, p_location_internal);
				fflush(stdout);
				if (!current_district)
				{
					current_district = new wchar_t[32];
				}
				wcsncpy(current_district, p_location_internal, 32);
				location_changed = true;

			}
			in_city_district = true;
			in_trade_district = wcsstr(p_location_internal, L"Trade District");
		}
		else if (current_district && last_no_district_cycle > 16)
		{
			last_no_district_cycle = 0;
			wprintf(L"current_district changed from %s to null\n", current_district);
			delete current_district;
			current_district = NULL;
			in_city_district = in_trade_district = false;
			location_changed = true;
		}
		else if (current_city && last_no_city_cycle > 16)
		{
			last_no_city_cycle = 0;
			wprintf(L"current_city changed from %s to null\n", current_city);
			delete current_city;
			current_city = NULL;
			in_city_district = in_trade_district = false;
			location_changed = true;
		}
		else
		{
			last_no_city_cycle++;
			last_no_district_cycle++;
		}
		if (location_changed){
			wprintf(L"Location Changed!\n\tcurrent_city = '%s'\n\tcurrent_district = '%s'\n\tin_city_district = %s\n\tin_trade_district = %s\n\tlast_city = '%s'\n\n",
				current_city, current_district, (in_city_district) ? L"true" : L"false", (in_trade_district) ? L"true" : L"false", last_city);
			fflush(stdout);
			srand(time(NULL));
			city_travel_index = rand() + 1;

			if (current_city)
			{
				location* loc = get_location();
				wstring city = wstring(current_city);
				map<wstring, location>::iterator it = cities.find(city);
				if (it == cities.end()){
					wprintf(L"Inserting city '%s' into map. Current cities: ", city);
					cities.insert(City_Pair(city, *loc));
					for (map<wstring, location>::iterator it = cities.begin(); it != cities.end(); ++it) {
						wprintf(L"%s, ", it->first);
					}
					printf("\n");

					/*
					A new city has been found, so reset the traders destinations
					so that they can include the new city
					*/
					traders.clear();
					serialize();
					sanity_check(loc, L"Save new city", city.c_str());
					if (!on_ground()){
						update_next_ground = true;
					}
					fflush(stdout);
				}
				else if (loc->trade_district){
					if (!it->second.trade_district){
						/*
						We are in a trade district, but the saved location is not.
						Update the saved location
						*/
						wprintf(L"Updating '%s' to point to a trade district\n", city);
						cities[city] = *loc;
						serialize();
						sanity_check(loc, L"Update city to trade district", city.c_str());
						if (!on_ground()){
							update_next_ground = true;
						}
						fflush(stdout);
					}
				}
				else if (loc->city_district){
					if (!it->second.city_district){
						/*
						We are in a city district, but the saved location is not.
						Update the saved location
						*/
						wprintf(L"Updating '%s' to point to a city district\n", city);
						cities[city] = *loc;
						serialize();
						sanity_check(loc, L"Update city to any district", city.c_str());
						if (!on_ground()){
							update_next_ground = true;
						}
						fflush(stdout);
					}
				}
				else {
					delete loc;
				}
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

			call[original_draw_call]
			NEG     EAX
			SBB     EAX, EAX
			NEG     EAX
			POP     EBP
			RETN
	}
}

__declspec(naked) void draw_location_asm(){
	__asm
	{
			mov[oldeax], eax
			mov[oldecx], ecx
			mov[oldedx], edx
			mov[oldebx], ebx
			mov[oldesp], esp
			mov[oldebp], ebp
			mov[oldesi], esi
			mov[oldedi], edi

			mov[p_location_internal], eax

			jmp on_draw_location
	}
}

wchar_t* inspect_dialogue = L"There is nothing special";
wchar_t* no_cities_dialogue = L"I'll only take you to cities you have already been to";
wchar_t* cant_afford = L"Come back when you have enough money";
wchar_t* dialogue = inspect_dialogue;

void on_push_nothing_special(){

	map<wstring, location>::iterator it = cities.find(travel_target);
	printf("Checking if teleporting is allowed\n\tfound player: %s\n\tfound target city: %s\n\tlast examined trader: %s\n\tin a known city: %s\n\n",
		(p_player_base) ? "true" : "false", (it != cities.end()) ? "true" : "false", (last_inspected_trader) ? "true" : "false", (current_city) ? "true" : "false");
	if (p_player_base && it != cities.end() && last_inspected_trader && current_city){

		DWORD level = (DWORD) *(p_player_base + (0x190 / 4));
		DWORD* money = (DWORD*) (p_player_base + (0x1304 / 4));
		int cost = portal_base_cost + portal_level_cost * level;

		if (*money >= cost){
			*money = *money - cost;

			wprintf(L"Teleporting from '%s' to '%s'\n", current_city, travel_target);

			printf("Current location: ");
			location* dloc = get_location();
			debug_location(*dloc);
			delete dloc;

			disable_trader_dialogue = true;
			fflush(stdout);
			location loc = it->second;
			sanity_check(&loc, L"Teleport", travel_target.c_str());

			wcsncpy(current_city, travel_target.c_str(), 32);
			if (!last_city){
				last_city = new wchar_t[32];
			}
			wcsncpy(last_city, travel_target.c_str(), 32);

			printf("Teleporting to: ");
			debug_location(loc);
			fflush(stdout);

			*((QWORD*) p_player_base + 0x2) = loc.x;
			*((QWORD*) p_player_base + 0x3) = loc.z;
			*((QWORD*) p_player_base + 0x4) = loc.y;



			printf("Teleport done\n");

			printf("Current location: ");
			dloc = get_location();
			debug_location(*dloc);
			delete dloc;
		}
		else {
			printf("Can't afford to teleport with only %d. Need %d\n", *money, cost);
			dialogue = cant_afford;
		}

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

			mov[oldeax], eax
			mov[oldecx], ecx
			mov[oldedx], edx
			mov[oldebx], ebx
			mov[oldesp], esp
			mov[oldebp], ebp
			mov[oldesi], esi
			mov[oldedi], edi

			jmp on_push_nothing_special
	}
}

QWORD last_item_hash = -1;

void on_examine_prompt(){

	QWORD item_x = *((QWORD*) p_item_base + 0x1);
	QWORD item_z = *((QWORD*) p_item_base + 0x2);
	QWORD item_y = *((QWORD*) p_item_base + 0x3);

	QWORD item_hash = item_x*31 + item_z*31 + item_y*31 + (current_city==NULL);
	if (item_hash != last_item_hash)
	{

		last_item_hash = item_hash;

		byte id = *((byte*) p_item_base);
		printf("%x\n", id);

		if ((id == 0x15 || id == 0x16 || id == 0x17) && current_city)
		{
			last_inspected_trader = true;

			DWORD level = (DWORD) *(p_player_base + (0x190 / 4));
			DWORD money = (DWORD) *(p_player_base + (0x1304 / 4));
			int cost = portal_base_cost + portal_level_cost * level;

			/*
			Teleporting to stalls is the optimal way to travel
			*/
			if (p_player_base && current_city && on_ground()){
				if (cities[wstring(current_city)].trade_district != 2){
					location* loc = get_location();
					loc->city_district = true;
					loc->trade_district = 2;
					wprintf(L"Updating '%s' to point to a merchant\n", current_city);
					cities[wstring(current_city)] = *loc;
					serialize();
				}
			}

			vector<wstring> city_vector;
			for (map<wstring, location>::iterator it = cities.begin(); it != cities.end(); ++it) {
				city_vector.push_back(it->first);
			}

			printf("Possible targets:");
			city_vector.erase(remove(city_vector.begin(), city_vector.end(), wstring(current_city)), city_vector.end());
			for (auto i : city_vector) {
				wprintf(L"%s, ", i);
			}
			wprintf(L"\nExcluded targets: %s\n", current_city);
			fflush(stdout);
			if (city_vector.size() > 0 && current_city)
			{
				/*
				If there is no current_city then we have just
				loaded the game into a city, so we dissalow
				fast-travel to the city we are in
				*/

				map<QWORD, wstring>::iterator it = traders.find(item_hash);
				if (it == traders.end()){
					travel_target = city_vector[++city_travel_index % city_vector.size()];
					wprintf(L"New trader %llu. Target = '%s'\n", item_hash, travel_target);
					fflush(stdout);
					traders.insert(Trader_Pair(item_hash, travel_target));
				}
				else {
					travel_target = it->second;
					wprintf(L"Already have a trader %llu. Target = '%s'\n", item_hash, travel_target);
				}


				wsprintf(prompt, L"[R] Travel to %s\n{ %dG %dS %dC }", travel_target.c_str(), cost / 10000, (cost % 10000) / 100, cost % 100);
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
		fflush(stdout);
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
		mov[oldeax], eax
			mov[oldecx], ecx
			mov[oldedx], edx
			mov[oldebx], ebx
			mov[oldesp], esp
			mov[oldebp], ebp
			mov[oldesi], esi
			mov[oldedi], edi

			mov[p_item_base], edx

			jmp on_examine_prompt
	}
}

PVOID* old_p_player_base;
bool in = false;
void on_draw_player(){

	if (old_p_player_base != p_player_base){
		printf("Found player: %x\n", p_player_base);
		printf("Name: %s\n", (wchar_t*) ((p_player_base + 0x45a)));
		old_p_player_base = p_player_base;
		fflush(stdout);
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

			PUSH    DWORD PTR DS : [EAX + 0x190]

			jmp[draw_player_JMP_back]
	}
}

__declspec(naked) void on_draw_player_asm(){
	__asm
	{

			mov[oldeax], eax
			mov[oldecx], ecx
			mov[oldedx], edx
			mov[oldebx], ebx
			mov[oldesp], esp
			mov[oldebp], ebp
			mov[oldesi], esi
			mov[oldedi], edi

			mov[p_player_base], eax

			jmp on_draw_player
	}
}

__declspec(naked) void dialogue_bubble_asm()
{
	__asm
	{
			LEA     EAX, DWORD PTR SS : [EBP - 0x1C]
			LEA     ECX, DWORD PTR DS : [EDI + 0x160]

			cmp byte ptr ss : [disable_trader_dialogue], 0x00
			mov byte ptr ss : [disable_trader_dialogue], 0x00
			jnz NO_DIALOGUE // taken if disable_trader_dialogue == true

			PUSH EAX
			jmp[dialogue_bubble_JMP_back_dialogue] // taken if disable_trader_dialogue == false

		NO_DIALOGUE :
			jmp[dialogue_bubble_JMP_back_no_dialogue]
	}
}

void on_load_world(){

	printf("Loading world with seed: %d\nClearing world specific data\n", current_seed);

	if (last_city){
		delete last_city;
	}
	last_city = NULL;
	if (current_city){
		delete current_city;
	}
	current_city = NULL;
	if (current_district){
		delete current_district;
	}
	current_district = NULL;

	p_location_internal = NULL;
	in_city_district = false;
	in_trade_district = false;
	do_town_portal = false;
	update_next_ground = false;

	cities.clear();
	traders.clear();

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

			MOV EAX, DWORD PTR FS : [0]

			jmp[load_world_JMP_back]
	}
}

__declspec(naked) void load_world_asm(){
	__asm
	{
			mov[oldeax], eax
			mov[oldecx], ecx
			mov[oldedx], edx
			mov[oldebx], ebx
			mov[oldesp], esp
			mov[oldebp], ebp
			mov[oldesi], esi
			mov[oldedi], edi

			mov eax, dword ptr ss : [ESP + 0x10]
			mov[current_seed], eax

			jmp on_load_world
	}
}

DWORD last_key = 0;

void on_key_press(){

	if (last_key == 'J'){
		printf("Town portal spell hit\n");

		DWORD level = (DWORD) *(p_player_base + (0x190 / 4));
		DWORD* money = (DWORD*) (p_player_base + (0x1304 / 4));
		int cost = town_portal_base_cost + town_portal_level_cost * level;

		if (last_city){
			if (*money >= cost){
				*money = *money - cost;
				wprintf(L"Teleporting to city '%s'\n", last_city);

				map<wstring, location>::iterator it = cities.find(wstring(last_city));
				if (it == cities.end()){
					printf("city not found in map\n");
					return;
				}

				printf("Current location: ");
				location* dloc = get_location();
				debug_location(*dloc);
				delete dloc;

				fflush(stdout);
				location loc = it->second;
				sanity_check(&loc, L"Teleport", last_city);

				if (!current_city){
					current_city = new wchar_t[32];
				}
				wcsncpy(current_city, last_city, 32);

				printf("Teleporting to: ");
				debug_location(loc);
				fflush(stdout);

				*((QWORD*) p_player_base + 0x2) = loc.x;
				*((QWORD*) p_player_base + 0x3) = loc.z;
				*((QWORD*) p_player_base + 0x4) = loc.y;

				printf("Teleport done\n");

				printf("Current location: ");
				dloc = get_location();
				debug_location(*dloc);
				delete dloc;


				fflush(stdout);
				serialize();
			}
			else {
				printf("Can't afford to use town portal with only %d. Need %d\n", *money, cost);
			}
		}
		else {
			printf("No last city\n");
		}
		fflush(stdout);
	}


	__asm{

		mov eax, [oldeax]
		mov ecx, [oldecx]
		mov edx, [oldedx]
		mov ebx, [oldebx]
		mov esp, [oldesp]
		mov ebp, [oldebp]
		mov esi, [oldesi]
		mov edi, [oldedi]

		ADD EAX, -9
		CMP EAX, 67

		jmp [key_press_jmp_back];
	}
}

__declspec(naked) void key_press_asm(){
	__asm
	{

		mov[oldeax], eax
		mov[oldecx], ecx
		mov[oldedx], edx
		mov[oldebx], ebx
		mov[oldesp], esp
		mov[oldebp], ebp
		mov[oldesi], esi
		mov[oldedi], edi

		mov [last_key], esi

		jmp on_key_press

	}

}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{

		hinst = hModule;
		//CreateDebugConsole();
		freopen("fast travel.log", "a", stdout);

		move_old_saves();

		portal_base_cost = GetPrivateProfileInt(L"portals", L"base_cost", 0, L".\\fast-travel.ini");
		portal_level_cost = GetPrivateProfileInt(L"portals", L"cost_per_level", 0, L".\\fast-travel.ini");
		town_portal_base_cost = GetPrivateProfileInt(L"town-portal", L"base_cost", 0, L".\\fast-travel.ini");
		town_portal_level_cost = GetPrivateProfileInt(L"town-portal", L"cost_per_level", 0, L".\\fast-travel.ini");

		printf("Loaded settings\n\tportal_base_cost: %d\n\tportal_level_cost: %d\n\ttown_portal_base_cost: %d\n\ttown_portal_level_cost: %d\n",
			portal_base_cost, portal_level_cost, town_portal_base_cost, town_portal_level_cost);

		printf("%d\n", GetLastError());

		DWORD cube_base = (DWORD) GetModuleHandle(L"Cube.exe");

		if (draw_player_internal)
		{
			printf("Found drawing opcodes: %x\n", draw_player_internal);
			MakeJMP((BYTE*) (draw_player_internal), (DWORD) on_draw_player_asm, 0x6);
		}
		else {
			fail(L"draw_player_internal");
		}

		if (examine_prompt_internal)
		{
			printf("Found examine prompt opcodes: %x\n", examine_prompt_internal);
			MakeJMP((BYTE*) (examine_prompt_internal), (DWORD) examine_prompt_asm, 0x6);
			printf("\t and found push examine opcodes: %x\n", push_examine);
		}
		else {
			fail(L"examine_prompt_internal");
		}
		if (draw_location)
		{
			draw_location += 0x1B;
			draw_location_JMP_back = draw_location + 5;
			printf("Found draw location : %x\n", draw_location);

			if (original_draw_call){
				printf("Found original_draw_call : %x\n", original_draw_call);
			}
			else {
				fail(L"original_draw_call");
			}

			//(BYTE *pAddress, DWORD dwJumpTo, DWORD dwLen)
			BYTE *pAddress = (BYTE*) draw_location;
			DWORD dwJumpTo = (DWORD) draw_location_asm;
			DWORD dwLen = 7;
			DWORD dwOldProtect, dwBkup, dwRelAddr;
			VirtualProtect(pAddress, dwLen, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			dwRelAddr = (DWORD) (dwJumpTo - (DWORD) pAddress) - 5;
			*pAddress = 0xE9;
			*((DWORD *) (pAddress + 0x1)) = dwRelAddr;
			for (DWORD x = 0x5; x < dwLen; x++) *(pAddress + x) = 0x90;
			VirtualProtect(pAddress, dwLen, dwOldProtect, &dwBkup);

		}
		else {
			fail(L"draw_location");
		}
		if (push_nothing_special){
			push_nothing_special += 0x0A;
			printf("Found PUSH nothing special : %x \n", push_nothing_special);

			MakeJMP((BYTE*) (push_nothing_special), (DWORD) push_nothing_special_asm, 0x7);

			//	Patch the code that displays the text window, so we can disable this on teleport

			dialogue_bubble_JMP_back_dialogue = push_nothing_special + 0x3f;
			dialogue_bubble_JMP_back_no_dialogue = push_nothing_special + 0x46;
			MakeJMP((BYTE*) (push_nothing_special + 0x37), (DWORD) dialogue_bubble_asm, 0xA);

		}
		else {
			fail(L"push_nothing_special");
		}

		if (load_world){
			printf("Found load word %x\n", load_world);
			MakeJMP((BYTE*) (load_world), (DWORD) load_world_asm, 0x6);
		}
		else {
			fail(L"load_world");
		}

		if (key_press){
			printf("Found keypress default %x\n", key_press);
			MakeJMP((BYTE*) key_press, (DWORD) key_press_asm, 6);
		}
		else {
			fail(L"keypress default");
		}


		fflush(stdout);

	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH)
	{
		//printf("Unhooking keyboard\n");
		//typedef void (*Uninstall)();
		//Uninstall uninstall = (Uninstall) GetProcAddress(hinst, "uninstall");
		//uninstall();


		printf("Exiting... closing stdout\n");
		fclose(stdout);
		exit(0);
	}

	return TRUE;
}
