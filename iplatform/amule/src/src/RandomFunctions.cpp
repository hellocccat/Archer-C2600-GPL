//
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2011 aMule Team ( admin@amule.org / http://www.amule.org )
//
// Any parts of this program derived from the xMule, lMule or eMule project,
// or contributed by third-party developers are copyrighted by their
// respective authors.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA
//

// The backtrace functions contain modified code from libYaMa, (c) Venkatesha Murthy G.
// You can check libYaMa at http://personal.pavanashree.org/libyama/

#include "RandomFunctions.h"	// Interface declarations
#ifndef ENABLE_TOMCRYPT
#include "CryptoPP_Inc.h"	// Needed for Crypto functions
#endif //ENABLE_TOMCRYPT
#include "OtherFunctions.h"

#ifndef ENABLE_TOMCRYPT
static CryptoPP::AutoSeededRandomPool cryptRandomGen;
const CryptoPP::AutoSeededRandomPool& GetRandomPool() { return cryptRandomGen; }
#endif //ENABLE_TOMCRYPT

uint8_t GetRandomUint8()
{
#ifndef ENABLE_TOMCRYPT
	//return cryptRandomGen.GenerateByte();
#else
	uint8_t a;
	if(get_random_fread(&a, 1)){
		//unlucky
		return 0x1;
	}

	return a;
#endif //ENABLE_TOMCRYPT

}

uint16_t GetRandomUint16()
{
#ifndef ENABLE_TOMCRYPT
	return (uint16_t)cryptRandomGen.GenerateWord32(0x0000, 0xFFFF);
#else
	uint8_t a[2];
	if(get_random_fread(a, 2)){
		//unlucky
		return 0x1;
	}

	uint16_t b = *(uint16_t *)a;

	return b;
#endif //ENABLE_TOMCRYPT
}

uint32_t GetRandomUint32()
{
#ifndef ENABLE_TOMCRYPT
	return cryptRandomGen.GenerateWord32();
#else
	
	uint8_t a[4];
	if(get_random_fread(a, 4)){
		//unlucky
		return 0x1;
	}

	uint32_t b = *(uint32_t *)a;

	return b;
#endif //ENABLE_TOMCRYPT
}

uint64_t GetRandomUint64()
{
#ifndef ENABLE_TOMCRYPT
	return ((uint64_t)GetRandomUint32() << 32) + GetRandomUint32();
#else
	uint8_t a[8];
	if(get_random_fread(a, 8)){
		//unlucky
		return 0x1;
	}

	uint64_t b = *(uint64_t *)a;

	return b;
#endif //ENABLE_TOMCRYPT
}

namespace Kademlia {
	CUInt128 GetRandomUint128()
	{
		uint8_t randomBytes[16];
#ifndef ENABLE_TOMCRYPT
		cryptRandomGen.GenerateBlock(randomBytes, 16);
#else
		get_random_fread(randomBytes, 16);
#endif //ENABLE_TOMCRYPT
		return CUInt128(randomBytes);
	}
}

// File_checked_for_headers
