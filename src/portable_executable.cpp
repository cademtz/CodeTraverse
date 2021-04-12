#include "../include/codetraverse/portable_executable.h"

#if defined(_WIN64)
	#define NATIVE_64BIT 1
#else
	#define NATIVE_64BIT 0
#endif

CPortableExecutable::CPortableExecutable(char* FileData, size_t FileLen, size_t SizeLimitKB)
	: m_file(FileData), m_filelen(FileLen), m_sizelimit(SizeLimitKB * 1024)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)FileData;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_SECTION_HEADER		sect;
	PIMAGE_IMPORT_DESCRIPTOR	iid;
	PIMAGE_EXPORT_DIRECTORY		ied;
	PIMAGE_FUNCTION_ENTRY		ife;
	size_t iid_off, ied_off, exc_off;

	if (sizeof(*dos) > FileLen ||
		dos->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	nt = (PIMAGE_NT_HEADERS)(FileData + dos->e_lfanew);

	if (!IsInFileBounds(nt, sizeof(IMAGE_NT_HEADERS64) - sizeof(IMAGE_OPTIONAL_HEADER64)) ||
		nt->Signature != IMAGE_NT_SIGNATURE)
		return;

	if (!IsInFileBounds(&nt->OptionalHeader, sizeof(nt->OptionalHeader.Magic)))
		return;

	m_opthedr = CNtOptionalHeader(&nt->OptionalHeader);

	if (!IsInFileBounds(&nt->OptionalHeader, m_opthedr.SizeOfOptHeader()) ||
		!m_opthedr.IsValid() ||
		!IsSafeSize(m_opthedr.SizeOfHeaders()) ||
		!IsSafeSize(m_opthedr.SizeOfImage()))
		return;

	m_imgbase = m_opthedr.ImageBase();
	m_imglen = m_opthedr.SizeOfImage();

	iid_off = m_opthedr.DataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	ied_off = m_opthedr.DataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	exc_off = m_opthedr.DataDirectory()[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;

	if (m_opthedr.AddressOfEntryPoint() && !IsSafeRva(m_opthedr.AddressOfEntryPoint()))
		return;

	sect = (PIMAGE_SECTION_HEADER)((char*)nt + m_opthedr.SizeOfNtHeader());

	for (size_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) // Safety-check sections
	{
		if (!IsInFileBounds(&sect[i], sizeof(sect[i])) ||
			!IsSafeRva(sect[i].VirtualAddress, sect[i].SizeOfRawData))
			return;
	}

	m_valid		= true;
	m_64bit		= m_opthedr.IsHeader64();
	m_filehedr	= &nt->FileHeader;

	// Map image internally to make it friendly for disassembly and RVAs
	m_img		= (char*)VirtualAlloc(0, m_imglen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	iid		= (PIMAGE_IMPORT_DESCRIPTOR)(m_img + iid_off);
	ied		= (PIMAGE_EXPORT_DIRECTORY)(m_img + ied_off);

	if (m_opthedr.AddressOfEntryPoint())
		m_codeEntry = m_img + m_opthedr.AddressOfEntryPoint();

	memcpy(m_img, dos, m_opthedr.SizeOfHeaders());
	for (size_t i = 0; i < nt->FileHeader.NumberOfSections; ++i)
		memcpy(m_img + sect[i].VirtualAddress, FileData + sect[i].PointerToRawData, sect[i].SizeOfRawData);

	// Relocate pointers
	PerformReloc((uint64_t)m_img, m_imgbase);

	// List all imports
	if (iid_off && IsSafeRva(iid_off))
	{
		while (IsInBounds(iid, sizeof(iid)) && iid->Characteristics)
		{
			CImageThunkData original(m_img + iid->OriginalFirstThunk, m_64bit);
			CImageThunkData first(m_img + iid->FirstThunk, m_64bit);
			char* libname = m_img + iid->Name;

			if (!IsSafeRva(iid->OriginalFirstThunk, original.Size()) ||
				!IsSafeRva(iid->FirstThunk, first.Size()) ||
				!IsSafeStr(libname))
				continue; // Bad pointer(s)

			m_imports.push_back({ 0 });
			auto& lib = m_imports.back();

			lib.libname = libname;

			while (IsInBounds(original.Thunk(), original.Size()) &&
				IsInBounds(first.Thunk(), first.Size()) &&
				original.Data())
			{
				if (original.Data() & (original.IsThunk64() ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32))
					lib.locs.push_back({ 0, original.Data() & 0xFFFF, first.Thunk() });
				else
				{
					PIMAGE_IMPORT_BY_NAME name = (PIMAGE_IMPORT_BY_NAME)(m_img + original.Data());
					if (IsSafeStr(name->Name))
						lib.locs.push_back({ name->Name, 0, first.Thunk() });
				}

				++original, ++first;
			}
			iid++;
		}
	}

	// List all exports
	if (ied_off && IsSafeRva(ied_off))
	{
		size_t count	= (size_t)ied->NumberOfNames;
		DWORD* funcs	= (DWORD*)(m_img + ied->AddressOfFunctions);
		DWORD* names	= (DWORD*)(m_img + ied->AddressOfNames);
		WORD* ords		= (WORD*)(m_img + ied->AddressOfNameOrdinals);

		// Safety check name and ordinal bounds beforehand
		if (IsInBounds(ords, count * sizeof(ords[0])) && IsInBounds(names, count * sizeof(names[0])))
		{
			for (size_t i = 0; i < count; i++)
			{
				PE_LocName exp	= { 0 };
				DWORD* rva		= &funcs[ords[i]];
				char* name		= m_img + (UINT_PTR)names[i];

				if (!IsInBounds(rva, sizeof(*rva)) || !IsSafeRva(*rva) || !IsSafeStr(name))
					continue;

				exp.ordinal	= ords[i];
				exp.name	= name;
				exp.loc		= m_img + *rva;
				m_exports.push_back(exp);
			}
		}
	}

	// List all exception/runtime routines
	// Structs vary between machines. x64 is the only target right now.
	if (exc_off && IsSafeRva(exc_off) &&
		(nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
			nt->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64))
	{
		ife = (IMAGE_FUNCTION_ENTRY*)(m_img + exc_off);

		for (; IsInBounds(ife, sizeof(*ife)) && ife->StartingAddress; ++ife)
		{
			if (IsSafeRva(ife->StartingAddress))
				m_routines.push_back(m_img + ife->StartingAddress);
		}
	}
}

CPortableExecutable::~CPortableExecutable()
{
	if (m_img)
		VirtualFree(m_img, 0, MEM_FREE);
}

void CPortableExecutable::WriteMappedToFile()
{
	const IMAGE_DOS_HEADER* dos = (PIMAGE_DOS_HEADER)m_img;
	const IMAGE_NT_HEADERS* nt = (PIMAGE_NT_HEADERS)(m_img + dos->e_lfanew);
	const IMAGE_SECTION_HEADER* sect;

	// Temporarily reverse relocations
	// TODO: Support rebasing? Probably not that useful.
	PerformReloc(m_imgbase, (uint64_t)m_img);

	// Write DOS, NT, and section headers back
	memcpy(m_file, m_img, m_opthedr.SizeOfHeaders());

	sect = (PIMAGE_SECTION_HEADER)((char*)nt + m_opthedr.SizeOfNtHeader());

	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		void* src = m_img + sect[i].VirtualAddress;
		DWORD size = sect[i].SizeOfRawData;

		if (!IsInBounds(src, size) || (size_t)sect[i].PointerToRawData + size > m_filelen)
			continue; // Image or file address out of bounds

		memcpy(m_file + sect[i].PointerToRawData, src, sect[i].SizeOfRawData);
	}

	// Fix relocations again
	PerformReloc((uint64_t)m_img, m_imgbase);
}

void CPortableExecutable::PerformReloc(uint64_t NewBase, uint64_t OldBase)
{
	const IMAGE_DATA_DIRECTORY*	ibr_dir;
	PIMAGE_BASE_RELOCATION		ibr;
	size_t		ibr_off;
	uint64_t	delta;

	ibr_dir = &m_opthedr.DataDirectory()[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	ibr_off = ibr_dir->VirtualAddress;
	ibr = (PIMAGE_BASE_RELOCATION)(m_img + ibr_off);

	if (!ibr_off)
		return;

	delta = NewBase - OldBase;

	while (IsInBounds(ibr, sizeof(ibr)) &&
		IsInBounds(ibr, ibr->SizeOfBlock) && // Safety check ibr struct, then full ibr block
		ibr->VirtualAddress)
	{
		size_t count = (ibr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		WORD* list = (WORD*)(ibr + 1);

		for (size_t i = 0; i < count; i++)
		{
			void* ptr = (void*)(m_img + ((uintptr_t)ibr->VirtualAddress + (list[i] & 0xFFF)));
			switch ((list[i] >> 12) & 0xF)
			{
			case IMAGE_REL_BASED_LOW:
				if (IsInBounds(ptr, sizeof(WORD)))
					*(WORD*)ptr += LOWORD(delta);
				break;
			case IMAGE_REL_BASED_HIGH:
				if (IsInBounds(ptr, sizeof(WORD)))
					*(WORD*)ptr += HIWORD(delta);
				break;
			case IMAGE_REL_BASED_DIR64:
				if (IsInBounds(ptr, sizeof(uint64_t)))
				{
					if (!NATIVE_64BIT && m_64bit)
						;
					else *(uint64_t*)ptr += delta;
				}
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				if (IsInBounds(ptr, sizeof(DWORD)))
				{
					if (NATIVE_64BIT && !m_64bit)
						; // Leave unchanged. This way, (ptr - imagebase) can indicate a valid offset
					else *(DWORD*)ptr += (DWORD)delta;
				}
				break;
			}
		}

		ibr = (PIMAGE_BASE_RELOCATION)((char*)ibr + ibr->SizeOfBlock);
	}
}

CNtOptionalHeader::CNtOptionalHeader(const void* pOptionalHeader)
{
	WORD magic = *(const WORD*)pOptionalHeader;
	if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		m_64bit = true, m_hdr64 = (const IMAGE_OPTIONAL_HEADER64*)pOptionalHeader;
	else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		m_64bit = false, m_hdr32 = (const IMAGE_OPTIONAL_HEADER32*)pOptionalHeader;
	else
		return;

	m_valid = true;
}
