#include "../include/codetraverse/traverse.h"
#include <inttypes.h>
#include <algorithm>

#define Zydis_EXPORTS
#define ZYDIS_DISABLE_FORMATTER
#include <Zydis/Zydis.h>

#ifdef CODETRAVERSE_DEBUG
	#include <stdio.h>
	#define CODETRAVERSE_LOGFMT(Fmt, ...) printf(Fmt, __VA_ARGS__)
#else
	#define CODETRAVERSE_LOGFMT(Fmt, ...) ((void)0)
#endif

#if defined(_WIN64)
#define NATIVE_64BIT 1
#else
#define NATIVE_64BIT 0
#endif

CTraverse::CTraverse(const void* RuntimeAddr, uint64_t BaseAddr, bool Is64bit)
	: m_realaddr((const char*)RuntimeAddr), m_baseaddr(BaseAddr), m_64bit(Is64bit)
{
}

void CTraverse::AddPage(const void* Loc, uint64_t Len, uint8_t Flags)
{
	TraversePage newpage;
	const char* endloc = (const char*)Loc + Len;

	for (auto it = m_pages.begin(); it != m_pages.end(); ++it)
	{
		TraversePage& page = *it;
		const char* start = page.loc;
		const char* end = start + page.len;

		// Remove entirely overwritten pages
		if (page.loc >= Loc && end <= endloc)
			it = --m_pages.erase(it);
		else if ((Loc >= start && Loc <= end) || // Overlapping bounds
			(endloc > start && endloc <= end))
		{
			// Merge boundaries of same page types
			if (page.flags == Flags)
			{
				start = std::min(start, (const char*)Loc);
				end = std::max(end, (const char*)Loc + Len);

				Loc = start;
				Len = end - start;
				it = --m_pages.erase(it);
			}
			else // Trim overwritten parts
			{
				if (start >= Loc) // Chop start
					page.loc = endloc, page.len -= endloc - start;
				else if (end <= endloc) // Chop end
					page.len -= end - Loc;
				else // Cellular mitosis
				{
					TraversePage other;
					other.loc = endloc;
					other.len = end - endloc;
					other.flags = page.flags;

					it = m_pages.insert(++it, other);

					page.len -= end - Loc;
				}
			}
		}
	}

	newpage.loc = (const char*)Loc;
	newpage.len = Len;
	newpage.flags = Flags;

	m_pages.push_back(newpage);
}

TraversePage* CTraverse::SetPageFlags(const void* Loc, uint8_t Flags)
{
	if (TraversePage* page = FindPage(Loc))
	{
		page->flags = Flags;
		return page;
	}
	return 0;
}

const TraversePage* CTraverse::FindPage(const void* Loc) const
{
	for (auto& page : m_pages)
		if (Loc >= page.loc && Loc < page.loc + page.len)
			return &page;
	return 0;
}

TraverseFunc* CTraverse::Traverse_Func(const void* Entry)
{
	ZydisDecoder de;
	ZydisDecodedInstruction ins;
	branches_t branches;
	TraverseFunc* func;

	if (func = Find_FuncAt(Entry))
		return func;

	if (ZYAN_FAILED(ZydisDecoderInit(&de,
			m_64bit ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
			m_64bit ? ZYDIS_ADDRESS_WIDTH_64 : ZYDIS_ADDRESS_WIDTH_32)))
	{
		assert(0 && "Failed to initialize Zydis");
		return nullptr;
	}

	if (!(func = _Traverse_Func(Entry, &de, &ins, &branches)))
		return nullptr;

	if (!branches.empty())
	{
		do
		{
			const void* loc = branches.top();
			branches.pop();

			if (!Find_FuncAt(loc)) // New territory
				_Traverse_Func(loc, &de, &ins, &branches);
		} while (!branches.empty());
	}

	return func;
}

TraverseFunc* CTraverse::Find_Func(const void* Loc)
{
	TraverseBlock* found;

	if (!(found = Find_Block(Loc)))
		return 0;

	for (auto& func : m_funcs)
	{
		if (Loc >= func.low && Loc < func.low + func.len)
		{
			for (TraverseBlock* block : func.blocks)
			{
				if (block == found)
					return &func;
			}
		}
	}
	return 0;
}

TraverseFunc* CTraverse::Find_FuncAt(const void* Entry)
{
	for (auto& func : m_funcs)
	{
		if (func.entry == Entry)
			return &func;
	}
	return nullptr;
}

TraverseBlock* CTraverse::Traverse_Block(const void* Block)
{
	ZydisDecoder de;
	ZydisDecodedInstruction ins;
	TraverseBlock block;

	// TODO: Make this update existing block

	if (TraverseBlock* found = Find_BlockAt(Block))
		return found;

	if (ZYAN_FAILED(ZydisDecoderInit(&de,
			m_64bit ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
			m_64bit ? ZYDIS_ADDRESS_WIDTH_64 : ZYDIS_ADDRESS_WIDTH_32)))
	{
		assert(0 && "Failed to initialize Zydis");
		return nullptr;
	}

	if (_Traverse_Block(&block, Block, &de, &ins, 0, 0))
	{
		m_blocks.push_back(block);
		return &m_blocks.back();
	}
	return nullptr;
}

TraverseBlock* CTraverse::Find_Block(const void* Loc)
{
	for (auto& block : m_blocks) // Check single blocks
	{
		if (Loc >= block.loc && Loc < block.loc + block.len)
			return &block;
	}
	return nullptr;
}

TraverseBlock* CTraverse::Find_BlockAt(const void* Start)
{
	auto it = std::find_if(m_blocks.begin(), m_blocks.end(), [Start](TraverseBlock& b) { return b.loc == Start; });
	return it == m_blocks.end() ? 0 : &(*it);
}

size_t CTraverse::List_Blocks(TraverseBlock* Root,	blocklist_t& BlockList)
{
	size_t count = 1;

	if (std::find(BlockList.begin(), BlockList.end(), Root) != BlockList.end())
		return 0;

	BlockList.push_back(Root);
	if (Root->_block1) count += List_Blocks(Root, BlockList);
	if (Root->_block2) count += List_Blocks(Root, BlockList);
	return count;
}

const char* CTraverse::Read_String(const void* Loc, size_t MaxSize) const
{
	const TraversePage* page;
	uintptr_t sizeleft;
	size_t len = 0;

	if (!(page = IsReadable(Loc, 1)))
		return 0;

	sizeleft = page->len - ((uintptr_t)Loc - (uintptr_t)page->loc);
	if (MaxSize == 0 || MaxSize > sizeleft)
		MaxSize = sizeleft;

	for (; len < MaxSize && ((const char*)Loc)[len]; ++len);
	if (len > MaxSize || ((const char*)Loc)[len]) // Exceeds max size or no null-terminator
		return 0;

	return (const char*)Loc;
}

uint64_t CTraverse::MemAddrToReal(uint64_t Addr) const {
	return NATIVE_64BIT && !m_64bit ? VirtualToReal<uint64_t>(Addr) : Addr;
}

const TraversePage* CTraverse::IsInBounds(const void* Loc, size_t Size) const
{
	if (const TraversePage* page = FindPage(Loc))
		if ((const char*)Loc + Size <= page->loc + page->len)
			return page;
	return 0;
}

const TraversePage* CTraverse::IsInBoundsFlags(const void* Loc, size_t Size, uint8_t Flags) const
{
	if (const TraversePage* page = IsInBounds(Loc, Size))
		if (page->flags & Flags)
			return page;
	return 0;
}

bool CTraverse::_Recurse_Blocks(blocklist_t& BlockList,
	const void* Block,
	ZydisDecoder_* De,
	ZydisDecodedInstruction_* Ins,
	branches_t* Branches,
	ZydisFormatter_* Fmt)
{
	TraverseBlock* block = Find_BlockAt(Block);
	if (!block) // Brand new territory
	{
		m_blocks.emplace_back();
		block = &m_blocks.back();
	}
	else if (std::find(BlockList.cbegin(), BlockList.cend(), block) != BlockList.cend())
		return true; // Already visited by this recursion
	else // Was previously discovered somewhere else
	{
		List_Blocks(block, BlockList);
		return true;
	}

	if (!_Traverse_Block(block, Block, De, Ins, Branches, Fmt))
	{
		m_blocks.pop_back();
		return false;
	}

	BlockList.push_back(block);

	if (block->_block1)
		_Recurse_Blocks(BlockList, block->_block1, De, Ins, Branches, Fmt);
	if (block->_block2)
		_Recurse_Blocks(BlockList, block->_block2, De, Ins, Branches, Fmt);
	return true;
}

TraverseFunc* CTraverse::_Traverse_Func(const void* Entry,
	ZydisDecoder_* De,
	ZydisDecodedInstruction_* Ins,
	branches_t* Branches,
	ZydisFormatter_* Fmt)
{
	TraverseFunc* func;
	TraverseBlock* block = 0;

	m_funcs.push_back({ 0 });
	func = &m_funcs.back();

	if (!_Recurse_Blocks(func->blocks, Entry, De, Ins, Branches, Fmt))
	{
		m_funcs.pop_back();
		return nullptr;
	}

	func->entry = (const char*)Entry;
	func->low = (*func->blocks.begin())->loc;

	for (TraverseBlock* block : func->blocks) // Find lowest address
	{
		if (block->loc < func->low)
			func->low = block->loc;
	}
	for (TraverseBlock* block : func->blocks) // Find highest address
	{
		uint64_t len = block->loc + block->len - func->low;
		if (len > func->len)
			func->len = len;
	}
	return func;
}

ETraverseUserCode CTraverse::_DerefAddrToReal(uint64_t Addr, uint64_t* out_Addr)
{
	uint64_t result = Addr;
	ETraverseUserCode code = TraverseUserCode_Continue;

	if (m_onbranch)
		code = m_onbranch(this, *(const void**)&result, true);

	if (code == TraverseUserCode_Break ||
		!IsCode((const void*)result, m_64bit ? sizeof(int64_t) : sizeof(int32_t)))
		return TraverseUserCode_Break;

	if (code != TraverseUserCode_Continue)
		return code;

	// De-reference
	if (m_64bit)
		result = *(uint64_t*)result;
	else result = *(uint32_t*)result;

	if (result)
	{
		if (NATIVE_64BIT != m_64bit)
			result = VirtualToReal<ZyanU64>(result);
		else
			; // WARNING: This expects all pointers are correctly relocated
	}

	*out_Addr = result;
	return TraverseUserCode_Continue;
}

bool CTraverse::_Traverse_Block(TraverseBlock* Result,
	const void* Block,
	ZydisDecoder* De,
	ZydisDecodedInstruction* Ins,
	branches_t* Branches,
	struct ZydisFormatter_* Fmt)
{
	const TraversePage* page = 0;
	uint64_t off;
	ZyanU64 addr;
	bool done = false;

	if (!(page = IsInBounds(Block, 1)))
	{
		CODETRAVERSE_LOGFMT("Given OOB block %" PRIX64 "\n", (uint64_t)Block - (uint64_t)m_realaddr + m_baseaddr);
		return false;
	}

	off = (const char*)Block - page->loc;

	memset(Result, 0, sizeof(*Result));
	Result->loc = (const char*)Block;

	ZyanStatus err;
	while (!done &&
		ZYAN_SUCCESS(err = ZydisDecoderDecodeBuffer(
			De, page->loc + off, page->len - off, Ins)))
	{

#if defined(CODETRAVERSE_DEBUG)
		uint64_t v_addr = RealToVirtual(page->loc + off);
#endif

		switch (Ins->mnemonic)
		{

			// ---------- Control flow ---------- //

		case ZYDIS_MNEMONIC_JMP:
			done = true;

			if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(Ins, &Ins->operands[0], (ZyanU64)page->loc + off, &addr)))
			{
				if (Ins->operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
				{
					if (_DerefAddrToReal(MemAddrToReal(addr), &addr) == TraverseUserCode_Break)
						break;
				}
				if (IsCode((const void*)addr))
					Result->_block1 = (const void*)addr;
			}
			break;
		case ZYDIS_MNEMONIC_JB:
		case ZYDIS_MNEMONIC_JBE:
		case ZYDIS_MNEMONIC_JCXZ:
		case ZYDIS_MNEMONIC_JECXZ:
		case ZYDIS_MNEMONIC_JKNZD:
		case ZYDIS_MNEMONIC_JKZD:
		case ZYDIS_MNEMONIC_JL:
		case ZYDIS_MNEMONIC_JLE:
		case ZYDIS_MNEMONIC_JNB:
		case ZYDIS_MNEMONIC_JNBE:
		case ZYDIS_MNEMONIC_JNL:
		case ZYDIS_MNEMONIC_JNLE:
		case ZYDIS_MNEMONIC_JNO:
		case ZYDIS_MNEMONIC_JNP:
		case ZYDIS_MNEMONIC_JNS:
		case ZYDIS_MNEMONIC_JNZ:
		case ZYDIS_MNEMONIC_JO:
		case ZYDIS_MNEMONIC_JP:
		case ZYDIS_MNEMONIC_JRCXZ:
		case ZYDIS_MNEMONIC_JS:
		case ZYDIS_MNEMONIC_JZ:
			done = true;
			Result->_block1 = page->loc + off + Ins->length;

			if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(Ins, &Ins->operands[0], (ZyanU64)page->loc + off, &addr)))
			{
				if (IsCode((const void*)addr, 1))
					Result->_block2 = (const void*)addr;
				else
					CODETRAVERSE_LOGFMT("Bad j(c) to %" PRIX64 "\n", v_addr);
			}
			break;
		case ZYDIS_MNEMONIC_RET:
			done = true;
			break;
		case ZYDIS_MNEMONIC_CALL:
			if (Branches)
			{
				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(Ins, &Ins->operands[0], (ZyanU64)page->loc + off, &addr)))
				{
					if (Ins->operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
					{
						if (_DerefAddrToReal(MemAddrToReal(addr), &addr) == TraverseUserCode_Break)
							break;
					}
					if (IsCode((const void*)addr))
						Branches->push((const void*)addr);
				}
			}
			break;

			// ---------- Const data ---------- //

		default:
			// Abusing the f(reak) out of ZydisCalcAbsoluteAddress on every single opcode
			for (ZyanU8 i = 0; i < Ins->operand_count; i++)
			{
				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(Ins, &Ins->operands[i], (ZyanU64)page->loc + off, &addr)))
				{
					if (Ins->operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
						addr = MemAddrToReal(addr);
				}
				else if (Ins->operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
					addr = MemAddrToReal(Ins->operands[i].imm.value.u);
				else
					continue;

				if (IsReadable((const void*)addr, 1))
				{
					TraverseData* data;
					auto it = m_data.find(addr);
					if (it == m_data.end())
					{
						data = &(m_data[addr] = { 0 });
						data->loc = (const char*)addr;
						data->type = TraverseDataType_None;
					}
					else
						data = &(*it).second;

					data->AddRef(page->loc + off);
				}
			}
		}

		off += Ins->length;
	}

	err = ZYAN_STATUS_CODE(err);
	if (err != ZYAN_STATUS_CODE(ZYAN_STATUS_SUCCESS) &&
		err != ZYAN_STATUS_CODE(ZYAN_STATUS_TRUE))
		CODETRAVERSE_LOGFMT("Exited block %" PRIX64 " with error 0x%X\n", RealToVirtual(page->loc + off), (uint32_t)err);

	if (page->loc + off == Block)
		return false; // No instructions disassembled

	Result->len = off - (uint64_t)((const char*)Block - page->loc);
	return true;
}
