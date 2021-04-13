#pragma once
#include <functional>
#include <stdint.h>
#include <list>
#include <map>
#include <stack>
#include <vector>

enum ETraverseUserCode;
class CTraverse;

typedef std::stack<const void*, std::vector<const void*>> branches_t;
typedef std::function
	<ETraverseUserCode(CTraverse* Code, const void*& BranchAddr, bool IsMem)>
	ct_onbranch_t;

enum ETraverseUserCode
{
	TraverseUserCode_Continue = 0,	// - Resume, running any default operations
	TraverseUserCode_Handled,		// - Return without running the default operation
	TraverseUserCode_Break,			// - Stop and fail the current operation
};

enum ETraverseDataType
{
	TraverseDataType_None,
	TraverseDataType_String,
	TraverseDataType_Pointer,
	TraverseDataType_Int8,
	TraverseDataType_Int16,
	TraverseDataType_Int32,
	TraverseDataType_Int64,
};

enum ETraversePageFlag
{
	TraversePageFlag_Code	= (1 << 0),
	TraversePageFlag_Read	= (1 << 1),
	TraversePageFlag_Write	= (1 << 2),
};

typedef struct _traverse_page
{
	uint64_t	len;
	const char*	loc;
	uint8_t		flags; // - ORed values from ETraversePageFlag
} TraversePage;

typedef struct _traverse_data
{
	const void*	loc;
	const char*	name;	// - Optional
	std::list<const void*> refs;
	uint8_t		type;	// - Value from ETraverseDataType

	inline void AddRef(const void* InstructionLoc) {
		if (std::find(refs.begin(), refs.end(), InstructionLoc) == refs.end())
			refs.push_back(InstructionLoc);
	}
} TraverseData;

typedef struct _traverse_block
{
	const char*	loc;
	const char*	name;	// - Optional
	const void* _block1, * _block2;
	uint64_t	len;
} TraverseBlock;

typedef struct _traverse_func
{
	uint64_t	len;	// - Span from lowest to highest address. May encompass unrelated bytes
	const char* entry;	// - Entry point. May not be the lowest address belonging to it
	const char* low;	// - Lowest code address of func code. Useful for copying all bytes
	const char* name;	// - Optional
	std::list<TraverseBlock*> blocks;
} TraverseFunc;

class CTraverse
{
public:
	/**
	* @brief	Constructs a new code traverser that can explore sections of x86 or AMD64 machine code.
	*			Analyzing 32-bit code on 64-bit (or backwards) requires a BaseAddr to correct for pointers
	* @param	RuntimeAddr	Base address of code at runtime
	* @param	BaseAddr	Base address of code that its native arch expects
	* @param	Is64bit		Indicates that the data contains AMD64 machine code
	* @see		SetBaseAddr()
	*/
	CTraverse(const void* RuntimeAddr, uint64_t BaseAddr, bool Is64bit);
	CTraverse() { }

	/** @brief	Callback determines what to do with the location pointed to by a branch (jump/call).
	*			By setting this callback, it can help CodeTraverse ignore, name, and redirect branching code.
	*			By default, CodeTraverse will assume all branching code points to more code.
	*			CodeTraverse won't know which code is imported, has names, or isn't worth exploring.
	* @param	Code		The calling CTraverse instance
	* @param	RuntimeAddr	Location of code that caused the branch in logic
	* @param	BranchAddr	A reference to the address that CodeTraverse will attempt to explore
	* @param	IsMem		Indicates that BranchAddr is a pointer to memory that will be de-referenced
	* @return	A value from ETraverseUserCode
	* @see		ETraverseUserCode
	*/
	ct_onbranch_t m_onbranch = 0;

	inline std::list<TraversePage>&		Pages()		{ return m_pages; }
	inline std::list<TraverseBlock>&	Blocks()	{ return m_blocks; }
	inline std::list<TraverseFunc>&		Funcs()		{ return m_funcs; }
	inline std::map<uint64_t, TraverseData>& Data()	{ return m_data; }

	/**
	* @brief	Adds (or overwrites) a page, making its memory visible to the traverser
	* @param	Loc		Address of valid memory
	* @param	Len		Length of memory
	* @param	Flags	Page/protection flags. Values ORed from ETraversePageFlag enum
	*/
	void AddPage(const void* Loc, uint64_t Len, uint8_t Flags);

	/**
	* @brief	Finds and edits the page Loc points at, returning it afterwards.
	* @param	Loc		Address of memory within a page
	* @param	Flags	New flags to assign to page. ORed values from ETraversePageFlag.
	* @return	On success: The found TraversePage. On failure: NULL
	* @see		TraversePage
	*/
	TraversePage* SetPageFlags(const void* Loc, uint8_t Flags);

	/**
	* @param	Loc		Address of memory within a page
	* @return	The found TraversePage. NULL if not found.
	*/
	const TraversePage* FindPage(const void* Loc) const;
	inline TraversePage* FindPage(const void* Loc) {
		return (TraversePage*)((const CTraverse*)this)->FindPage(Loc);
	}

	/**
	* @brief	Traverses the start of a function and recurses undiscovered branching calls.
	*			This will not affect existing functions
	* @param	Entry	Entry point of function code
	* @return	NULL on failure
	*/
	TraverseFunc* Traverse_Func(const void* Entry);


	/**
	* @brief	Finds an existing function from any pointer over its region
	* @see		Fund_FuncAt
	* @param	Loc		Points in region belonging to a function's code
	* @return	NULL on failure
	*/
	TraverseFunc* Find_Func(const void* Loc);

	/**
	* @brief	Finds an existing function by entry point.
	* @see		Find_Func()
	* @param	Entry	Possible entry point of an existing function
	* @return	NULL on failure
	*/
	TraverseFunc* Find_FuncAt(const void* Entry);


	/**
	* @brief	Traverses the start of a code block
	*			Any new blocks are appended to a list and their pointer returned.
	* @param	Block	Start location of code
	* @return	NULL on failure
	*/
	TraverseBlock* Traverse_Block(const void* Block);

	/**
	* @brief	Finds an existing block from any pointer over its region.
	* @see		Find_BlockAt()
	* @param	Loc		Points in region belonging to a block of code
	* @return	NULL on failure
	*/
	TraverseBlock* Find_Block(const void* Loc);

	/**
	* @brief	Finds an existing block by start address.
	* @see		Find_Block()
	* @param	Start	Points at start location of an existing code block
	* @return	NULL on failure
	*/
	TraverseBlock* Find_BlockAt(const void* Start);

	/**
	* @brief	Recursively appends any not-listed blocks to BlockList starting at Root.
	*			Assumes that if an existing block is listed, none of its children need to be added.
	* @param	Root		The parent block to be searched. Will include itself in list.
	* @param	BlockList	Any list of TraverseBlock*. This method only adds unique pointers.
	* @return	Number of items added to BlockList
	*/
	size_t List_Blocks(TraverseBlock* Root, std::list<TraverseBlock*>& BlockList);

	const char* Read_String(const void* Loc, size_t MaxSize = 0) const;

	/**
	* @brief	Sets the base address property, important for traversing code for different machines.
	*			Printed addresses will be shown relative to BaseAddr.
	* @param	Base	The preferred base address when displaying info
	*/
	void SetBaseAddr(uint64_t Base) { m_baseaddr = Base; }
	inline uint64_t GetBaseAddr() const { return m_baseaddr; }

	template <class TRet = uint64_t, class TLoc>
	inline TRet RealToVirtual(TLoc Loc) const { return (TRet)((uint64_t)Loc - (uint64_t)m_realaddr + m_baseaddr); }
	template <class TRet = const char*, class TLoc>
	inline TRet VirtualToReal(TLoc Loc) const { return (TRet)((uint64_t)Loc - m_baseaddr + (uint64_t)m_realaddr); }

	uint64_t MemAddrToReal(uint64_t Addr) const;

	inline const void* RealAddr() const	{ return m_realaddr; }
	inline uint64_t Len() const		{ return m_len; }

	const TraversePage* IsInBounds(const void* Loc, size_t Size = 0) const;
	const TraversePage* IsInBoundsFlags(const void* Loc, size_t Size, uint8_t Flags) const;
	inline const TraversePage* IsReadable(const void* Loc, size_t Size = 0) const {
		return IsInBoundsFlags(Loc, Size, TraversePageFlag_Read);
	}
	inline const TraversePage* IsCode(const void* Loc, size_t Size = 0) const {
		return IsInBoundsFlags(Loc, Size, TraversePageFlag_Read | TraversePageFlag_Code);
	}

private:
	/**
	* @brief	Traverses the start of a code block, given a disassembler and optional settings.
	* 
	* @param	Result		Pointer to store resulting TraverseBlock data
	* @param	Block		Start location of code
	* @param	De			An initialized ZydisDecoder
	* @param	Ins			Pointer to store a Zydis instruction in (Saves on stack mem)
	* @param	Branches	(Optional) A list to populate with branching calls for more exploring
	* @param	Fmt			(Optional) An initialized ZydisFormatter. Use to spew debug info
	* @return	Indicates success
	*/
	bool _Traverse_Block(
		TraverseBlock* Result,
		const void* Block,
		struct ZydisDecoder_* De,
		struct ZydisDecodedInstruction_* Ins,
		branches_t* Branches = 0,
		struct ZydisFormatter_* Fmt = 0);

	/**
	* @brief	Recurses the start of a code block and all branching blocks (but not branching calls).
	*			New blocks are added to m_blocks, and existing blocks are re-analyzed.
	*			As a side effect, existing blocks will update if their data was edited prior.
	* 
	* @param	BlockList	A list of block pointers to be added to
	* @param	Block		Start location of code
	* @param	De			An initialized ZydisDecoder
	* @param	Ins			Pointer to store a Zydis instruction in (Saves on stack mem)
	* @param	Branches	(Optional) A list to populate with branching calls for more exploring
	* @param	Fmt			(Optional) An initialized ZydisFormatter. Use to spew debug info
	* @return	Indicates success
	* @return	Indicates success
	*/
	bool _Recurse_Blocks(
		std::list<TraverseBlock*>& BlockList,
		const void* Block,
		struct ZydisDecoder_* De,
		struct ZydisDecodedInstruction_* Ins,
		branches_t* Branches = 0,
		struct ZydisFormatter_* Fmt = 0);
	
	/**
	* @brief	Traverses the start of a function, given a disassembler and optional settings.
	*			A new function will be appended to m_func regardless of existing ones.
	* 
	* @param	De			An initialized ZydisDecoder
	* @param	Ins			Pointer to store a Zydis instruction in (Saves on stack mem)
	* @param	Branches	(Optional) A list to populate with branching calls for more exploring
	* @param	Fmt			(Optional) An initialized ZydisFormatter. Use to spew debug info
	* @return	On success: A pointer to a newly appended func in m_funcs. On failure: NULL
	*/
	TraverseFunc* _Traverse_Func(const void* Entry,
		struct ZydisDecoder_* De,
		struct ZydisDecodedInstruction_* Ins,
		branches_t* Branches = 0,
		struct ZydisFormatter_* Fmt = 0);

	/**
	* @brief	Dereferences a real address to another address which may need conversion.
	*			The m_onbranch callback (if set) is called first and can control this output fully,
	*			which can help locate calls to unresolved imports or avoid certain code and data locations.
	* 
	* @param	Addr		Real address to a pointer in traversible region
	* @param	out_Addr	Pointer to copy the result on success. Result must still be safety checked.
	* 
	* @return	TraverseUserCode_Continue:	Success.
	*			TraverseUserCode_Handled:	Success. The user callback fully controlled the output. 
	*			TraverseUserCode_Break:		Failure. Bad address or the user callback wants failure.
	*/
	ETraverseUserCode _DerefAddrToReal(uint64_t Addr, uint64_t* out_Addr);

	uint64_t	m_len		= 0;
	uint64_t	m_baseaddr	= 0;
	const char*	m_realaddr	= 0;
	bool		m_64bit		= false;

	std::list<TraversePage>		m_pages;
	std::list<TraverseBlock>	m_blocks;
	std::list<TraverseFunc>		m_funcs;
	std::map<uint64_t, TraverseData> m_data;
};