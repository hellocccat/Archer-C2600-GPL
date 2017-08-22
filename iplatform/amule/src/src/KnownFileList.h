//
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2011 aMule Team ( admin@amule.org / http://www.amule.org )
// Copyright (c) 2002-2011 Merkur ( devs@emule-project.net / http://www.emule-project.net )
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
#ifdef ENABLE_KNOWNFILES			
#ifndef KNOWNFILELIST_H
#define KNOWNFILELIST_H


#include "SharedFileList.h" // CKnownFileMap


class CKnownFile;
class CPath;

class CKnownFileList
{
public:
	CKnownFileList();
	~CKnownFileList();
	bool	SafeAddKFile(CKnownFile* toadd, bool afterHashing = false);
	bool	Init();
	void	Save();
	void	Clear();
	CKnownFile* FindKnownFile(
		const CPath& filename,
		time_t in_date,
		uint64 in_size);
	CKnownFile* FindKnownFileByID(const CMD4Hash& hash);
	void	PrepareIndex();
	void	ReleaseIndex();

#if 1 //zengwei add restrict share number
	uint32 GetknownFileMapSize() {wxMutexLocker lock(list_mut); return m_knownFileMap.size();}
#endif //zengwei add restrict share number

	uint16 requested;
	uint32 transferred;
	uint16 accepted;

private:
	wxMutex	list_mut;

	bool	Append(CKnownFile*, bool afterHashing = false);

	CKnownFile *IsOnDuplicates(
		const CPath& filename,
		uint32 in_date,
		uint64 in_size) const;

	bool KnownFileMatches(
		CKnownFile *knownFile,
		const CPath& filename,
		uint32 in_date,
		uint64 in_size) const;

	typedef std::list<CKnownFile*> KnownFileList;
	KnownFileList	m_duplicateFileList;
	CKnownFileMap	m_knownFileMap;
	// The filename "known.met"
	//wxString	m_filename;
	// Speed up shared files reload
	typedef std::multimap<uint32, CKnownFile*> KnownFileSizeMap;
	KnownFileSizeMap * m_knownSizeMap;
	KnownFileSizeMap * m_duplicateSizeMap;
};

#endif // KNOWNFILELIST_H
#endif
// File_checked_for_headers
