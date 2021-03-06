#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stddef.h>
#include <list>

typedef struct _pe_locname
{
	char* name;		// - If import: NULL if ordinal is set
	WORD ordinal;	// - If import: NULL if name is set
	void* loc;		// - If import: Location of the pointer. Not the actual code/data pointed to.
} PE_LocName;

typedef struct _pe_import
{
	char* libname;
	std::list<PE_LocName> locs;
} PE_Import;

class CNtOptionalHeader
{
public:
	CNtOptionalHeader() { }
	CNtOptionalHeader(const void* pOptionalHeader);

	inline bool IsValid() const { return m_valid; }
	inline bool IsHeader64() const { return m_64bit; }
	size_t SizeOfNtHeader() const {
		return m_64bit ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32);
	}
	size_t SizeOfOptHeader() const {
		return m_64bit ? sizeof(*m_hdr64) : sizeof(*m_hdr32);
	}

	DWORD AddressOfEntryPoint() const {
		return m_64bit ? m_hdr64->AddressOfEntryPoint : m_hdr32->AddressOfEntryPoint;
	}
	DWORD BaseOfCode() const {
		return m_64bit ? m_hdr64->BaseOfCode : m_hdr32->BaseOfCode;
	}
	DWORD SizeOfCode() const {
		return m_64bit ? m_hdr64->SizeOfCode : m_hdr32->SizeOfCode;
	}
	DWORD SizeOfHeaders() const {
		return m_64bit ? m_hdr64->SizeOfHeaders : m_hdr32->SizeOfHeaders;
	}
	DWORD SizeOfImage() const {
		return m_64bit ? m_hdr64->SizeOfImage : m_hdr32->SizeOfImage;
	}
	uint64_t ImageBase() const {
		return m_64bit ? m_hdr64->ImageBase : m_hdr32->ImageBase;
	}
	const IMAGE_DATA_DIRECTORY* DataDirectory() const {
		return m_64bit ? m_hdr64->DataDirectory : m_hdr32->DataDirectory;
	}

private:
	union {
		const IMAGE_OPTIONAL_HEADER64* m_hdr64;
		const IMAGE_OPTIONAL_HEADER32* m_hdr32;
	};

	bool m_valid = false;
	bool m_64bit = false;
};

class CPortableExecutable
{
public:
	/**
	* @brief	Constructs a mapped PE from file data with a size-limit (in KB) allowed for mapping
	* @see		IsValid()
	* 
	* @param	FileData	Pointer to editable raw file data
	* @see		WriteMappedToFile()
	* @param	FileLen		Length of raw file data
	* @param	SizeLimitKB	Limit (in KB) allowed to allocate for mapping. Invalidates PE if too large
	*/
	CPortableExecutable(char* FileData, size_t FileLen, size_t SizeLimitKB = 1024 * 40);
	CPortableExecutable() { }
	~CPortableExecutable();

	inline bool IsValid() const		{ return m_valid; }
	inline bool Is64bit() const		{ return m_64bit; }

	/**
	* @brief	Pointer to unmapped file data. Call WriteFile
	* @see		WriteMappedToFile()
	*/
	inline char* FileData() const	{ return m_file; }
	inline size_t FileLen() const	{ return m_filelen; }

	/** @brief	Pointer to mapped image data */
	inline char* ImgData() const	{ return m_img; }
	inline size_t ImgLen() const	{ return m_imglen; }
	inline char* RawEnd() const		{ return m_img + m_imglen; }
	inline bool IsInBounds(const void* Loc, size_t Size = 0) const {
		return Loc >= m_img && Loc <= RawEnd() - Size;
	}
	inline bool IsInFileBounds(const void* Loc, size_t Size = 0) const {
		return Loc >= m_file && Loc <= m_file + m_filelen - Size;
	}

	inline uint64_t ImageBase() const	{ return m_imgbase; }
	inline void* CodeEntry() const		{ return m_codeEntry; }
	inline const std::list<PE_LocName>& Exports() const		{ return m_exports; }
	inline const std::list<PE_Import>& Imports() const		{ return m_imports; }
	/**@brief Comes from exception handler directory, but holds other runtime methods too */
	inline const std::list<void*>& Routines() const			{ return m_routines; }
	inline const CNtOptionalHeader& OptionalHeader() const	{ return m_opthedr; }
	inline const IMAGE_FILE_HEADER* FileHeader() const		{ return m_filehedr; }

	/** @brief	Writes all mapped headers and sections back to unmapped file data */
	void WriteMappedToFile();

private:
	template <class T = size_t>
	inline bool IsSafeSize(T Size) const { return Size > 0 && Size < m_sizelimit; }
	template <class T = uint64_t>
	inline bool IsSafeRva(T Rva, size_t Size = 1) const { return (uint64_t)Rva + Size <= m_imglen; }
	inline bool IsSafeStr(const char* Str) const {
		for (; IsInBounds(Str) && *Str; ++Str);
		return IsInBounds(Str) && *Str == 0;
	}

	void PerformReloc(uint64_t NewBase, uint64_t OldBase);

	bool		m_valid		= false;
	bool		m_64bit		= false;
	char*		m_img		= 0;
	char*		m_file		= 0;
	size_t		m_imglen	= 0;
	size_t		m_filelen	= 0;
	uint64_t	m_imgbase	= 0;
	size_t		m_sizelimit	= 0;

	void*					m_codeEntry	= 0;
	IMAGE_FILE_HEADER*		m_filehedr	= 0;
	std::list<PE_LocName>	m_exports;
	std::list<PE_Import>	m_imports;
	std::list<void*>		m_routines;
	CNtOptionalHeader		m_opthedr;
};

class CImageThunkData
{
public:
	CImageThunkData(void* Thunk, bool Is64bit) : m_64bit(Is64bit) {
		if (m_64bit) m_thunk._64 = (IMAGE_THUNK_DATA64*)Thunk;
		else m_thunk._32 = (IMAGE_THUNK_DATA32*)Thunk;
	}

	inline bool IsThunk64() const { return m_64bit; }

	CImageThunkData Next() const {
		return m_64bit ? CImageThunkData(m_thunk._64 + 1, m_64bit) : CImageThunkData(m_thunk._32 + 1, m_64bit);
	}
	uint64_t Data() const {
		return m_64bit ? m_thunk._64->u1.AddressOfData : m_thunk._32->u1.AddressOfData;
	}
	size_t Size() const { return m_64bit ? sizeof(uint64_t) : sizeof(uint32_t); }
	void* Thunk() const { return *(void**)&m_thunk; }

	CImageThunkData& operator++()
	{
		if (m_64bit) m_thunk._64++;
		else m_thunk._32++;
		return *this;
	}

private:
	union {
		PIMAGE_THUNK_DATA32 _32;
		PIMAGE_THUNK_DATA64 _64;
	} m_thunk;

	bool m_64bit;
};