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
	size_t iid_off, ied_off;

	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	nt = (PIMAGE_NT_HEADERS)(FileData + dos->e_lfanew);

	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return;

	m_opthedr = CNtOptionalHeader(&nt->OptionalHeader);

	if (!m_opthedr.IsValid() ||
		!IsSafeSize(m_opthedr.SizeOfHeaders()) ||
		!IsSafeSize(m_opthedr.SizeOfImage()))
		return;

	iid_off = m_opthedr.DataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	ied_off = m_opthedr.DataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	if ((iid_off && !IsSafeSize(iid_off)) ||
		(ied_off && !IsSafeSize(ied_off)))
		return;

	if (m_opthedr.AddressOfEntryPoint() && !IsSafeSize(m_opthedr.AddressOfEntryPoint()))
		return;

	m_valid		= true;
	m_64bit		= m_opthedr.IsHeader64();
	m_filehedr	= &nt->FileHeader;

	// Map image internally to make it friendly for disassembly and RVAs
	m_imgbase	= m_opthedr.ImageBase();
	m_imglen	= m_opthedr.SizeOfImage();
	m_img		= (char*)VirtualAlloc(0, m_imglen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	sect	= (PIMAGE_SECTION_HEADER)((char*)nt + m_opthedr.SizeOfNtHeader());
	iid		= (PIMAGE_IMPORT_DESCRIPTOR)(m_img + iid_off);
	ied		= (PIMAGE_EXPORT_DIRECTORY)(m_img + ied_off);
	if (m_opthedr.AddressOfEntryPoint())
		m_codeEntry = m_img + m_opthedr.AddressOfEntryPoint();

	memcpy(m_img, dos, m_opthedr.SizeOfHeaders());
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
		memcpy(m_img + sect[i].VirtualAddress, FileData + sect[i].PointerToRawData, sect[i].SizeOfRawData);

	// Relocate pointers
	PerformReloc((uint64_t)m_img, m_imgbase);

	// List all imports
	if (iid_off)
	{
		while (iid->Characteristics)
		{
			CImageThunkData original(m_img + iid->OriginalFirstThunk, m_opthedr.IsHeader64());
			CImageThunkData first(m_img + iid->FirstThunk, m_opthedr.IsHeader64());
			char* libname = m_img + iid->Name;

			m_imports.push_back({ 0 });
			auto& lib = m_imports.back();

			lib.libname = libname;

			for (; original.Data(); ++original, ++first)
			{
				void* addr = first.Thunk();

				if (original.Data() & (original.IsThunk64() ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32))
					lib.locs.push_back({ 0, original.Data() & 0xFFFF, addr });
				else
				{
					PIMAGE_IMPORT_BY_NAME name = (PIMAGE_IMPORT_BY_NAME)(m_img + original.Data());
					if (!IsInBounds(name->Name))
						DebugBreak();
					lib.locs.push_back({ name->Name, 0, addr });
				}
			}
			iid++;
		}
	}

	// List all exports
	if (ied_off)
	{
		const IMAGE_DATA_DIRECTORY* dir = &m_opthedr.DataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT];
		DWORD* funcs	= (DWORD*)(m_img + ied->AddressOfFunctions);
		DWORD* names	= (DWORD*)(m_img + ied->AddressOfNames);
		WORD* ords		= (WORD*)(m_img + ied->AddressOfNameOrdinals);

		for (size_t i = 0; i < ied->NumberOfNames; i++)
		{
			PE_LocName exp	= { 0 };
			size_t rva		= funcs[ords[i]];
			char* name		= m_img + (UINT_PTR)names[i];
			char* loc		= m_img + rva;

			if (rva >= (size_t)dir->VirtualAddress && rva <= (size_t)dir->VirtualAddress + dir->Size)
				continue; // Forwarded export

			exp.name = name;
			exp.loc = loc;
			m_exports.push_back(exp);
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

	// Write DOS, NT, and section headers back
	memcpy(m_file, m_img, m_opthedr.SizeOfHeaders());

	sect = (PIMAGE_SECTION_HEADER)((char*)nt + m_opthedr.SizeOfNtHeader());

	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		void* src = m_img + sect[i].VirtualAddress;
		DWORD size = sect[i].SizeOfRawData;

		if (!IsInBounds(src, size) || sect[i].PointerToRawData + size > m_filelen);
			continue; // Image or file address out of bounds

		memcpy(m_file + sect[i].PointerToRawData, src, sect[i].SizeOfRawData);
	}
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

	if (!ibr_off || !IsInBounds(m_img + ibr_off, ibr_dir->Size))
		return;

	delta = NewBase - OldBase;

	for (auto reloc = ibr; reloc->VirtualAddress; reloc = (PIMAGE_BASE_RELOCATION)((char*)reloc + reloc->SizeOfBlock))
	{
		size_t count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		WORD* list = (WORD*)(reloc + 1);
		for (size_t i = 0; i < count; i++)
		{
			void* ptr = (void*)(m_img + ((uintptr_t)reloc->VirtualAddress + (list[i] & 0xFFF)));
			switch ((list[i] >> 12) & 0xF)
			{
			case IMAGE_REL_BASED_LOW: *(WORD*)ptr += LOWORD(delta); break;
			case IMAGE_REL_BASED_HIGH: *(WORD*)ptr += HIWORD(delta); break;
			case IMAGE_REL_BASED_DIR64:
				if (!NATIVE_64BIT && m_64bit)
					;
				else *(uint64_t*)ptr += delta;
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				if (NATIVE_64BIT && !m_64bit)
					; // Leave unchanged. This way, a pointer can be distinguished if (ptr - imagebase) is a valid offset
				else *(DWORD*)ptr += (DWORD)delta;
				break;
			}
		}
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
