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

#include "ClientCreditsList.h"	// Interface declarations


#include <protocol/ed2k/Constants.h>
#include <common/Macros.h>
#include <common/DataFileVersion.h>
#include <common/FileFunctions.h>	// Needed for GetFileSize


#include "GetTickCount.h"	// Needed for GetTickCount
#include "Preferences.h"	// Needed for thePrefs
#include "ClientCredits.h"	// Needed for CClientCredits
#include "amule.h"		// Needed for theApp
#include "CFile.h"		// Needed for CFile
#include "Logger.h"		// Needed for Add(Debug)LogLine
#ifndef ENABLE_TOMCRYPT 
#include "CryptoPP_Inc.h"	// Needed for Crypto functions
#else
#include "tomcrypt.h"
#endif //ENABLE_TOMCRYPT
#include "ClientList.h"

#define CLIENTS_MET_FILENAME		wxT("clients.met")
//#define CLIENTS_MET_BAK_FILENAME	wxT("clients.met.bak")
#define CRYPTKEY_FILENAME		wxT("cryptkey.dat")

CClientCreditsList::CClientCreditsList()
{	
#ifdef ENABLE_TOMCRYPT
	//register tommath desc(LTM)
	register_hash(&sha1_desc);
	register_prng(&sprng_desc);
	ltc_mp = ltm_desc;
#endif //ENABLE_TOMCRYPT

	m_nLastSaved = ::GetTickCount();
	LoadList();	
	InitalizeCrypting();
}


CClientCreditsList::~CClientCreditsList()
{
	DeleteContents(m_mapClients);
#ifndef ENABLE_TOMCRYPT
	delete static_cast<CryptoPP::RSASSA_PKCS1v15_SHA_Signer *>(m_pSignkey);
#endif //ENABLE_TOMCRYPT
}


void CClientCreditsList::LoadList()
{
	CFile file;
	CPath fileName = CPath(theApp->ConfigDir + CLIENTS_MET_FILENAME);

	if (!fileName.FileExists()) {
		return;
	}	
	
	try {
		file.Open(fileName, CFile::read);
	
		if (file.ReadUInt8() != CREDITFILE_VERSION) {
			AddDebugLogLineC( logCredits, wxT("Creditfile is outdated and will be replaced") );
			file.Close();
			return;
		}

#if 0	//no backup
		// everything is ok, lets see if the backup exist...
		CPath bakFileName = CPath(theApp->ConfigDir + CLIENTS_MET_BAK_FILENAME);
	
		bool bCreateBackup = TRUE;
		if (bakFileName.FileExists()) {
			// Ok, the backup exist, get the size
			CFile hBakFile(bakFileName);
			if ( hBakFile.GetLength() > file.GetLength()) {
				// the size of the backup was larger then the
				// org. file, something is wrong here, don't
				// overwrite old backup..
				bCreateBackup = FALSE;
			}
			// else: backup is smaller or the same size as org.
			// file, proceed with copying of file
		}
	
		//else: the backup doesn't exist, create it
		if (bCreateBackup) {
			file.Close(); // close the file before copying
			if (!CPath::CloneFile(fileName, bakFileName, true)) {
				AddDebugLogLineC(logCredits,
					CFormat(wxT("Could not create backup file '%s'")) % fileName);
			}
			// reopen file
			if (!file.Open(fileName, CFile::read)) {
				AddDebugLogLineC( logCredits,
					wxT("Failed to load creditfile") );
				return;
			}

			file.Seek(1);
		}	
#endif	
	
		uint32 count = file.ReadUInt32();

		const uint32 dwExpired = time(NULL) - 12960000; // today - 150 day
		uint32 cDeleted = 0;
		for (uint32 i = 0; i < count; i++){
			CreditStruct* newcstruct = new CreditStruct();

			newcstruct->key					= file.ReadHash();
			newcstruct->uploaded            = file.ReadUInt32();
			newcstruct->downloaded          = file.ReadUInt32();
			newcstruct->nLastSeen           = file.ReadUInt32();
			newcstruct->uploaded            += static_cast<uint64>(file.ReadUInt32()) << 32;
			newcstruct->downloaded          += static_cast<uint64>(file.ReadUInt32()) << 32;
			newcstruct->nReserved3          = file.ReadUInt16();
			newcstruct->nKeySize            = file.ReadUInt8();
			file.Read(newcstruct->abySecureIdent, MAXPUBKEYSIZE);
		
			if ( newcstruct->nKeySize > MAXPUBKEYSIZE ) {
				// Oh dear, this is bad mojo, the file is most likely corrupt
				// We can no longer assume that any of the clients in the file are valid
				// and will have to discard it.
				delete newcstruct;
				
				DeleteContents(m_mapClients);
				
				AddDebugLogLineC( logCredits,
					wxT("WARNING: Corruptions found while reading Creditfile!") );
				return;	
			}
		
			if (newcstruct->nLastSeen < dwExpired){
				cDeleted++;
				delete newcstruct;
				continue;
			}

			CClientCredits* newcredits = new CClientCredits(newcstruct);
			m_mapClients[newcredits->GetKey()] = newcredits;
		}

		AddLogLineN(CFormat(wxPLURAL("Creditfile loaded, %u client is known", "Creditfile loaded, %u clients are known", count - cDeleted)) % (count - cDeleted));
	
		if (cDeleted) {
			AddLogLineN(CFormat(wxPLURAL(" - Credits expired for %u client!", " - Credits expired for %u clients!", cDeleted)) % cDeleted);
		}
	} catch (const CSafeIOException& e) {
		AddDebugLogLineC(logCredits, wxT("IO error while loading clients.met file: ") + e.what());
	}
}


void CClientCreditsList::SaveList()
{
	AddDebugLogLineN( logCredits, wxT("Saved Credit list"));
	m_nLastSaved = ::GetTickCount();

	wxString name(theApp->ConfigDir + CLIENTS_MET_FILENAME);
	CFile file;

	if ( !file.Create(name, true) ) {
		AddDebugLogLineC( logCredits, wxT("Failed to create creditfile") );
		return;
	}
	
	if ( file.Open(name, CFile::write) ) {
		try {
			uint32 count = 0;

			file.WriteUInt8( CREDITFILE_VERSION );
			// Temporary place-holder for number of stucts
			file.WriteUInt32( 0 );

			ClientMap::iterator it = m_mapClients.begin();
			for ( ; it != m_mapClients.end(); ++it ) {	
				CClientCredits* cur_credit = it->second;
		
				if ( cur_credit->GetUploadedTotal() || cur_credit->GetDownloadedTotal() ) {
					const CreditStruct* const cstruct = cur_credit->GetDataStruct();
					file.WriteHash(cstruct->key);
					file.WriteUInt32(static_cast<uint32>(cstruct->uploaded));
					file.WriteUInt32(static_cast<uint32>(cstruct->downloaded));
					file.WriteUInt32(cstruct->nLastSeen);
					file.WriteUInt32(static_cast<uint32>(cstruct->uploaded >> 32));
					file.WriteUInt32(static_cast<uint32>(cstruct->downloaded >> 32));
					file.WriteUInt16(cstruct->nReserved3);
					file.WriteUInt8(cstruct->nKeySize);
					// Doesn't matter if this saves garbage, will be fixed on load.
					file.Write(cstruct->abySecureIdent, MAXPUBKEYSIZE);
					count++;
				}
			}
		
			// Write the actual number of structs
			file.Seek( 1 );
			file.WriteUInt32( count );
		} catch (const CIOFailureException& e) {
			AddDebugLogLineC(logCredits, wxT("IO failure while saving clients.met: ") + e.what());
		}
	} else {
		AddDebugLogLineC(logCredits, wxT("Failed to open existing creditfile!"));
	}
}


CClientCredits* CClientCreditsList::GetCredit(const CMD4Hash& key)
{
	CClientCredits* result;

	ClientMap::iterator it = m_mapClients.find( key );

	
	if ( it == m_mapClients.end() ){
		result = new CClientCredits(key);
		m_mapClients[result->GetKey()] = result;
	} else {
		result = it->second;
	}
	
	result->SetLastSeen();
	
	return result;
}


void CClientCreditsList::Process()
{
//		if (::GetTickCount() - m_nLastSaved > MIN2MS(13)){
//			SaveList();
//		}

	//zengwei add don't save just clean for saving memory after 30min
	if (::GetTickCount() - m_nLastSaved > MIN2MS(30)){

		m_nLastSaved = ::GetTickCount();
		
		ClientMap::iterator it = m_mapClients.begin();
		for ( ; it != m_mapClients.end(); ++it ) {
//				if (m_mapClients.size() <= 100){
//					break;
//				}
			
			CClientCredits* cur_credit = it->second;

			if (!cur_credit){
				break;
			}

			if (theApp->clientlist->IsClientCreditExist((void*)cur_credit)){
				continue;
			}

			//if no download in one hour delete it
			CreditStruct* credit = cur_credit->GetDataStruct();
			if (credit){				
				if ( !(credit->downloaded <= cur_credit->GetCleanTimeDownloaded()
					&& (::GetTickCount() - cur_credit->GetCleanTime()) >= HR2MS(1))
					){

					cur_credit->SetCleanTime(::GetTickCount());
					cur_credit->SetCleanTimeDownloaded(credit->downloaded);
					continue;
				}
				
				delete credit;
			}
			m_mapClients.erase(it);
		}
	}
}


bool CClientCreditsList::CreateKeyPair()
{
#ifndef ENABLE_TOMCRYPT
	try {
		CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> rng;
		CryptoPP::InvertibleRSAFunction privkey;
		privkey.Initialize(rng, RSAKEYSIZE);

		// Nothing we can do against this filename2char :/
		wxCharBuffer filename = filename2char(theApp->ConfigDir + CRYPTKEY_FILENAME);
		CryptoPP::FileSink *fileSink = new CryptoPP::FileSink(filename);
		CryptoPP::Base64Encoder *privkeysink = new CryptoPP::Base64Encoder(fileSink);
		privkey.DEREncode(*privkeysink);
		privkeysink->MessageEnd();

		// Do not delete these pointers or it will blow in your face.
		// cryptopp semantics is giving ownership of these objects.
		//
		// delete privkeysink;
		// delete fileSink;

		AddDebugLogLineN(logCredits, wxT("Created new RSA keypair"));
	} catch(const CryptoPP::Exception& e) {
		AddDebugLogLineC(logCredits,
			wxString(wxT("Failed to create new RSA keypair: ")) +
			wxString(char2unicode(e.what())));
		wxFAIL;
 		return false;
 	}
#else
	int		prng_idx, ret;
	rsa_key	key;

	//init crypt rsa key of libtom
	memset(&key, 0, sizeof(rsa_key));
			
	prng_idx = find_prng("sprng");	
	if (prng_idx == -1) {
		AddLogLineC(CFormat(_("CreateKeyPair find_prng requires sprng")));
		return false;
	}

	//make rsa key
	if (ret=rsa_make_key(NULL, prng_idx, RSAKEYSIZE/8, 17, &key)){
		AddLogLineC(CFormat(_("CreateKeyPair rsa_make_key failed %d")) % ret);
		return false;
	}

	//check
	if (mp_unsigned_bin_size(key.N) != RSAKEYSIZE/8) {
		AddLogLineC(CFormat(_("CreateKeyPair rsa key modulus has %ul bytes need %d bytes")) 
					% mp_unsigned_bin_size(key.N) % (RSAKEYSIZE/8));
		rsa_free(&key);
		return false;
	}

	byte abyMySignKey[MAX_CLIENT_SIGN_KEY_LEN]; //512 enough when 384bits key size
	unsigned long abyMySignKeyLen = MAX_CLIENT_SIGN_KEY_LEN;
	byte base64MySignKey[MAX_CLIENT_BASE64_SIGN_KEY_LEN]; //1024 enough when 384bits key size
	unsigned long base64MySignKeyLen = MAX_CLIENT_BASE64_SIGN_KEY_LEN;

	//get rsa private key
	ret = rsa_der_export(abyMySignKey, &abyMySignKeyLen, 
								PK_PRIVATE, DER_FULL_CODE_TYPE, &key);
	if (ret){
		AddLogLineC(CFormat(_("CreateKeyPair rsa privkey export failed ret = %d")) % ret);
		rsa_free(&key);
		return false;	
	}

	//a little diffrent with cryptopp, just no LFRF after 72 bytes in libtomcrypt
	//it is ok when decode use libtomcrypt 
	ret = base64_encode(abyMySignKey, abyMySignKeyLen, 
								base64MySignKey, &base64MySignKeyLen);
	if (ret){
		AddLogLineC(CFormat(_("CreateKeyPair rsa privkey base64 encode failed ret = %d")) % ret);
		rsa_free(&key);
		return false;	
	}

	//write to file
	try{
		CFile preffile;
		wxString fullpath(theApp->ConfigDir + CRYPTKEY_FILENAME);

		if (!wxFileExists(fullpath)) {
			preffile.Create(fullpath);
		}

		if (preffile.Open(fullpath, CFile::read_write)) {
			preffile.Write(base64MySignKey, base64MySignKeyLen);
			preffile.Flush();
			preffile.Close();
		}
	} catch(const CMuleException& e){
		AddDebugLogLineC(logCredits, wxT("Failure while write priv key to file: ") + e.what());
		rsa_free(&key);
		wxFAIL;
		return false;			
	}
	
	AddDebugLogLineN(logCredits, wxT("Created new RSA keypair"));
	rsa_free(&key);
#endif //ENABLE_TOMCRYPT
 	return true;
}


void CClientCreditsList::InitalizeCrypting()
{
	m_nMyPublicKeyLen = 0;
	memset(m_abyMyPublicKey,0,MAX_CLIENT_PUB_KEY_LEN); // not really needed; better for debugging tho
#ifndef ENABLE_TOMCRYPT
	m_pSignkey = NULL;
#else
	m_nMySignKeyLen = 0;
	memset(m_abyMySignKey,0,MAX_CLIENT_SIGN_KEY_LEN); // not really needed; better for debugging tho
#endif //ENABLE_TOMCRYPT

	if (!thePrefs::IsSecureIdentEnabled()) {
		AddDebugLogLineC(logCredits, wxT("Secure identity disabled."));
		return;
	}

#ifndef ENABLE_TOMCRYPT
	try {
		// check if keyfile is there
 		if (wxFileExists(theApp->ConfigDir + CRYPTKEY_FILENAME)) {
			off_t keySize = CPath::GetFileSize(theApp->ConfigDir + CRYPTKEY_FILENAME);
			
			if (keySize == wxInvalidOffset) {
				AddDebugLogLineC(logCredits, wxT("Cannot access 'cryptkey.dat', please check permissions."));
				return;
			} else if (keySize == 0) {
				AddDebugLogLineC(logCredits, wxT("'cryptkey.dat' is empty, recreating keypair."));
				CreateKeyPair();
 			}
 		} else {
			AddLogLineN(_("No 'cryptkey.dat' file found, creating.") );
 			CreateKeyPair();
 		}
			
 		// load private key
 		CryptoPP::FileSource filesource(filename2char(theApp->ConfigDir + CRYPTKEY_FILENAME), true, new CryptoPP::Base64Decoder);
 		m_pSignkey = new CryptoPP::RSASSA_PKCS1v15_SHA_Signer(filesource);
 		// calculate and store public key
		CryptoPP::RSASSA_PKCS1v15_SHA_Verifier pubkey(*static_cast<CryptoPP::RSASSA_PKCS1v15_SHA_Signer *>(m_pSignkey));
		CryptoPP::ArraySink asink(m_abyMyPublicKey, MAX_CLIENT_PUB_KEY_LEN);
 		pubkey.DEREncode(asink);
 		m_nMyPublicKeyLen = asink.TotalPutLength();
 		asink.MessageEnd();
	} catch (const CryptoPP::Exception& e) {
		delete static_cast<CryptoPP::RSASSA_PKCS1v15_SHA_Signer *>(m_pSignkey);
		m_pSignkey = NULL;
		
		AddDebugLogLineC(logCredits,
			wxString(wxT("Error while initializing encryption keys: ")) +
			wxString(char2unicode(e.what())));
 	}
#else
	size_t keySize;
	byte abyBaseSignKey[MAX_CLIENT_BASE64_SIGN_KEY_LEN];
	memset(abyBaseSignKey, 0, MAX_CLIENT_BASE64_SIGN_KEY_LEN);

	// check if keyfile is there
	if (wxFileExists(theApp->ConfigDir + CRYPTKEY_FILENAME)) {
		keySize = CPath::GetFileSize(theApp->ConfigDir + CRYPTKEY_FILENAME);	
		if (keySize == wxInvalidOffset) {
			AddDebugLogLineC(logCredits, wxT("Cannot access 'cryptkey.dat', please check permissions."));
			return;
		} else if (keySize == 0 || keySize >= MAX_CLIENT_BASE64_SIGN_KEY_LEN) {
			AddDebugLogLineC(logCredits, wxT("'cryptkey.dat' is empty or exceed max, recreating keypair."));
			CPath::RemoveFile(CPath(theApp->ConfigDir + CRYPTKEY_FILENAME));
			CreateKeyPair();
		}
	} else {
		AddDebugLogLineC(logCredits, wxT("No 'cryptkey.dat' file found, creating.") );
		CreateKeyPair();
	}
	
	// load private key
	try {
		CFile preffile;		
		wxString fullpath(theApp->ConfigDir + CRYPTKEY_FILENAME);
		keySize = CPath::GetFileSize(theApp->ConfigDir + CRYPTKEY_FILENAME);
		//verify keysize again to ensure stability, never happen
		if (keySize == 0 || keySize >= MAX_CLIENT_BASE64_SIGN_KEY_LEN) {
			AddLogLineC(CFormat(_("'cryptkey.dat' is empty or exceed max(%d), bad process and return.")) % keySize);
			return;
		}
		
		if (preffile.Open(fullpath, CFile::read)) {
			preffile.Read(abyBaseSignKey, keySize);
			preffile.Close();
		}
	} catch (const CIOFailureException& e) {
		AddDebugLogLineC(logCredits, wxT("IO failure while getting priv key: ") + e.what());
		return;
	} catch (const CEOFException& e){
		AddDebugLogLineC(logCredits, wxT("EOF exception while getting priv key: ") + e.what());
		return; 		
	} catch (const CMuleException& e){
		AddDebugLogLineC(logCredits, wxT("Other exception while getting priv key: ") + e.what());
		return; 		
	}
	
	int ret, prng_idx;
	unsigned long signkeylen;
	rsa_key key;

	//init crypt var of libtom
	memset(&key, 0, sizeof(rsa_key));

	signkeylen = MAX_CLIENT_SIGN_KEY_LEN;
	ret = base64_decode(abyBaseSignKey, keySize, m_abyMySignKey, &signkeylen);
	if (signkeylen == 0 || ret != CRYPT_OK){
		AddDebugLogLineC(logCredits, wxT("'cryptkey.dat' data format error."));
		return;
	}
		
	//Read the file	
	prng_idx = find_prng("sprng");	
	if (prng_idx == -1) {
		AddDebugLogLineC(logCredits, wxT("Get KeyPair find_prng requires sprng"));
		return;
	}

	//import rsa private key
	ret = rsa_der_import(m_abyMySignKey, signkeylen, 
								PK_PRIVATE, DER_FULL_CODE_TYPE, &key);
	if (ret){
		AddLogLineC(CFormat(_("Get KeyPair rsa signkey import failed ret = %d")) % ret);
		return;	
	}	
	
	//get rsa pub key
	unsigned long pubkeylen = MAX_CLIENT_PUB_KEY_LEN;
	ret = rsa_der_export(m_abyMyPublicKey, &pubkeylen, 
							PK_PUBLIC, DER_FULL_CODE_TYPE, &key);
	if (ret){
		AddLogLineC(CFormat(_("Get rsa pubkey export failed ret = %d")) % ret);
		rsa_free(&key);
		return;	
	}
	
	m_nMySignKeyLen = signkeylen;
	m_nMyPublicKeyLen = pubkeylen;
	AddDebugLogLineN(logCredits, wxT("Get RSA keypair success"));
	rsa_free(&key);
		
#endif //ENABLE_TOMCRYPT
}


uint8 CClientCreditsList::CreateSignature(CClientCredits* pTarget, byte* pachOutput, uint8 nMaxSize, uint32 ChallengeIP, uint8 byChaIPKind, void* sigkey)
{	
#ifndef ENABLE_TOMCRYPT
	CryptoPP::RSASSA_PKCS1v15_SHA_Signer* signer =
		static_cast<CryptoPP::RSASSA_PKCS1v15_SHA_Signer *>(sigkey);
	// signer param is used for debug only
	if (signer == NULL)
		signer = static_cast<CryptoPP::RSASSA_PKCS1v15_SHA_Signer *>(m_pSignkey);

	// create a signature of the public key from pTarget
	wxASSERT( pTarget );
	wxASSERT( pachOutput );
	
	if ( !CryptoAvailable() ) {
 		return 0;
	}
	
	try {		
		CryptoPP::SecByteBlock sbbSignature(signer->SignatureLength());
		CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> rng;
		byte abyBuffer[MAXPUBKEYSIZE+9];
		uint32 keylen = pTarget->GetSecIDKeyLen();
		memcpy(abyBuffer,pTarget->GetSecureIdent(),keylen);
		// 4 additional bytes random data send from this client
		uint32 challenge = pTarget->m_dwCryptRndChallengeFrom;
		wxASSERT ( challenge != 0 );		
		PokeUInt32(abyBuffer+keylen,challenge);
		
		uint16 ChIpLen = 0;
		if ( byChaIPKind != 0){
			ChIpLen = 5;
			PokeUInt32(abyBuffer+keylen+4, ChallengeIP);
			PokeUInt8(abyBuffer+keylen+4+4,byChaIPKind);
		}
 		signer->SignMessage(rng, abyBuffer ,keylen+4+ChIpLen , sbbSignature.begin());
 		CryptoPP::ArraySink asink(pachOutput, nMaxSize);
 		asink.Put(sbbSignature.begin(), sbbSignature.size());
		
		return asink.TotalPutLength();			
	} catch (const CryptoPP::Exception& e) {
		AddDebugLogLineC(logCredits, wxString(wxT("Error while creating signature: ")) + wxString(char2unicode(e.what())));
		wxFAIL;
		
		return 0;
 	}
#else
	rsa_key privKey;
	int hash_idx, prng_idx, ret;
	unsigned long  len;
	
	hash_idx = find_hash("sha1");
	prng_idx = find_prng("sprng");
	if (hash_idx == -1 || prng_idx == -1) {
	   AddLogLineC(CFormat(_("CreateSignature requires SHA1 and sprng")));
	   return 0;
	}

	// create a signature of the public key from pTarget
	wxASSERT( pTarget );
	wxASSERT( pachOutput );
	
	if ( !CryptoAvailable() ) {
		AddDebugLogLineC(logCredits, wxT("Crypt is not available."));
 		return 0;
	}

	unsigned long signkeylen = m_nMySignKeyLen;
	ret = rsa_der_import(m_abyMySignKey, signkeylen, 
							PK_PRIVATE, DER_FULL_CODE_TYPE, &privKey);
	if (ret){
		AddLogLineC(CFormat(_("CreateSignature rsa_der_import failed ret =%d")) % ret);
		return 0;
	}
	
	//if fail bellow, must free the privKey memory 
	byte abyBuffer[MAXPUBKEYSIZE+9];
	uint32 keylen = pTarget->GetSecIDKeyLen();
	memcpy(abyBuffer,pTarget->GetSecureIdent(),keylen);
	// 4 additional bytes random data send from this client
	uint32 challenge = pTarget->m_dwCryptRndChallengeFrom;
	if (challenge == 0){
		rsa_free(&privKey);
		return 0;
	}

	PokeUInt32(abyBuffer+keylen,challenge);
	
	uint16 ChIpLen = 0;
	if ( byChaIPKind != 0){
		ChIpLen = 5;
		PokeUInt32(abyBuffer+keylen+4, ChallengeIP);
		PokeUInt8(abyBuffer+keylen+4+4,byChaIPKind);
	}
	
	//get the message hash
	hash_state hs;
	unsigned char hash[SHA1_HASH_SIZE];
	sha1_init(&hs);
	unsigned long keylen_l = keylen+4+ChIpLen;
	sha1_process(&hs, abyBuffer, keylen_l);
	sha1_done(&hs, hash);

	//create signature
	len = nMaxSize;
	ret = rsa_sign_hash_ex(hash, SHA1_HASH_SIZE, pachOutput, &len, 
							LTC_LTC_PKCS_1_V1_5, NULL, prng_idx, hash_idx, 8, &privKey);
	if (ret){
		AddLogLineC(CFormat(_("CreateSignature rsa_sign_hash_ex failed ret =%d")) % ret);
		rsa_free(&privKey);
		return 0;
	}
	
	rsa_free(&privKey);
	return len;			
#endif //ENABLE_TOMCRYPT

}

void CClientCreditsList::PrintClientCreditsList()
{
	AddLogLineN(CFormat(_("Show ClientCreditsList map client size %d"))% GetMapClientSize());
}

#if 0
#ifdef ENABLE_TOMCRYPT
int zw_rsa_verify_hash_ex(const unsigned char *sig,      unsigned long siglen,
                       const unsigned char *hash,     unsigned long hashlen,
                             int            padding,
                             int            hash_idx, unsigned long saltlen,
                             int           *stat,     rsa_key      *key)
{
  unsigned long modulus_bitlen, modulus_bytelen, x;
  int           err;
  unsigned char *tmpbuf;
  int i, j;

  LTC_ARGCHK(hash  != NULL);
  LTC_ARGCHK(sig   != NULL);
  LTC_ARGCHK(stat  != NULL);
  LTC_ARGCHK(key   != NULL);

  /* default to invalid */
  *stat = 0;

  /* valid padding? */

  if ((padding != LTC_LTC_PKCS_1_V1_5) &&
      (padding != LTC_LTC_PKCS_1_PSS)) {
    return CRYPT_PK_INVALID_PADDING;
  }

  if (padding == LTC_LTC_PKCS_1_PSS) {
    /* valid hash ? */
    if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
       return err;
    }
  }

  /* get modulus len in bits */
  modulus_bitlen = mp_count_bits( (key->N));

  /* outlen must be at least the size of the modulus */
  modulus_bytelen = mp_unsigned_bin_size( (key->N));
  if (modulus_bytelen != siglen) {
     return CRYPT_INVALID_PACKET;
  }

  /* allocate temp buffer for decoded sig */
  tmpbuf = (unsigned char *)XMALLOC(siglen);
  if (tmpbuf == NULL) {
     return CRYPT_MEM;
  }

  /* RSA decode it  */
  x = siglen;
  if ((err = ltc_mp.rsa_me(sig, siglen, tmpbuf, &x, PK_PUBLIC, key)) != CRYPT_OK) {
     XFREE(tmpbuf);
     return err;
  }

  /* make sure the output is the right size */
  if (x != siglen) {
     XFREE(tmpbuf);
     return CRYPT_INVALID_PACKET;
  }

  if (padding == LTC_LTC_PKCS_1_PSS) {
    /* PSS decode and verify it */
    err = pkcs_1_pss_decode(hash, hashlen, tmpbuf, x, saltlen, hash_idx, modulus_bitlen, stat);
  } else {
    /* LTC_PKCS #1 v1.5 decode it */
    unsigned char *out;
    unsigned long outlen, loid[16];
    int           decoded;
    ltc_asn1_list digestinfo[2], siginfo[2];

    /* not all hashes have OIDs... so sad */
    if (hash_descriptor[hash_idx].OIDlen == 0) {
       err = CRYPT_INVALID_ARG;
       goto bail_2;
    }

    /* allocate temp buffer for decoded hash */
    outlen = ((modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0)) - 3;
    out    = (unsigned char *)XMALLOC(outlen);
    if (out == NULL) {
      err = CRYPT_MEM;
      goto bail_2;
    }

    if ((err = pkcs_1_v1_5_decode(tmpbuf, x, LTC_LTC_PKCS_1_EMSA, modulus_bitlen, out, &outlen, &decoded)) != CRYPT_OK) {
      XFREE(out);       
      goto bail_2;
    }

	printf("der code len %d (\n", outlen);
	for (i=0; i<outlen; i++){
		printf("0x%02x,", *(out+i));
	}	
	printf(" )\n");
	
	
    /* now we must decode out[0...outlen-1] using ASN.1, test the OID and then test the hash */
    /* construct the SEQUENCE 
      SEQUENCE {
         SEQUENCE {hashoid OID
                   blah    NULL
         }
         hash    OCTET STRING 
      }
   */
    LTC_SET_ASN1(digestinfo, 0, LTC_ASN1_OBJECT_IDENTIFIER, loid, sizeof(loid)/sizeof(loid[0]));
    LTC_SET_ASN1(digestinfo, 1, LTC_ASN1_NULL,              NULL,                          0);
    LTC_SET_ASN1(siginfo,    0, LTC_ASN1_SEQUENCE,          digestinfo,                    2);
    LTC_SET_ASN1(siginfo,    1, LTC_ASN1_OCTET_STRING,      tmpbuf,                        siglen);
   
    if ((err = der_decode_sequence(out, outlen, siginfo, 2)) != CRYPT_OK) {
       XFREE(out);
       goto bail_2;
    }

    /* test OID */
	unsigned long *tmp;
	printf("input hash id(%d): ( ", digestinfo[0].size);
	tmp = (unsigned long *)digestinfo[0].data;
	for (i=0; i<digestinfo[0].size; i++){
		printf("0x%02x,", *(tmp+i));
	}	
	printf(" )\n");

	printf("std hash id(%d): ( ", hash_descriptor[hash_idx].OIDlen);
	for (i=0; i<hash_descriptor[hash_idx].OIDlen; i++){
		printf("0x%02x,", hash_descriptor[hash_idx].OID[i]);
	}	
	printf(" )\n");

	printf("input hash len(%d): ( ",siginfo[1].size );
	for (i=0; i<siginfo[1].size; i++){
		printf("0x%02x,", *((unsigned char *)siginfo[1].data+i));
	}	
	printf(" )\n");

	printf("std hash len(%d): ( ",hashlen);
	for (i=0; i<hashlen; i++){
		printf("0x%02x,", hash[i]);
	}	
	printf(" )\n");

	
    if ((digestinfo[0].size == hash_descriptor[hash_idx].OIDlen) &&
        (XMEMCMP(digestinfo[0].data, hash_descriptor[hash_idx].OID, sizeof(unsigned long) * 
hash_descriptor[hash_idx].OIDlen) == 0) &&
        (siginfo[1].size == hashlen) &&
        (XMEMCMP(siginfo[1].data, hash, hashlen) == 0)) {
       *stat = 1;
    }

#ifdef LTC_CLEAN_STACK
    zeromem(out, outlen);
#endif
    XFREE(out);
  }

bail_2:
#ifdef LTC_CLEAN_STACK
  zeromem(tmpbuf, siglen);
#endif
  XFREE(tmpbuf);
  return err;
}
#endif //ENABLE_TOMCRYPT
#endif

bool CClientCreditsList::VerifyIdent(CClientCredits* pTarget, const byte* pachSignature, uint8 nInputSize, uint32 dwForIP, uint8 byChaIPKind)
{
	wxASSERT( pTarget );
	wxASSERT( pachSignature );
	if ( !CryptoAvailable() ){
		pTarget->SetIdentState(IS_NOTAVAILABLE);
		return false;
	}
	bool bResult;
#ifndef ENABLE_TOMCRYPT
	try {
		CryptoPP::StringSource ss_Pubkey((byte*)pTarget->GetSecureIdent(),pTarget->GetSecIDKeyLen(),true,0);
		CryptoPP::RSASSA_PKCS1v15_SHA_Verifier pubkey(ss_Pubkey);

#endif //ENABLE_TOMCRYPT
	// 4 additional bytes random data send from this client +5 bytes v2
	byte abyBuffer[MAXPUBKEYSIZE+9];
	memcpy(abyBuffer,m_abyMyPublicKey,m_nMyPublicKeyLen);
	uint32 challenge = pTarget->m_dwCryptRndChallengeFor;
	wxASSERT ( challenge != 0 );
	PokeUInt32(abyBuffer+m_nMyPublicKeyLen, challenge);
	
	// v2 security improvments (not supported by 29b, not used as default by 29c)
	uint8 nChIpSize = 0;
	if (byChaIPKind != 0){
		nChIpSize = 5;
		uint32 ChallengeIP = 0;
		switch (byChaIPKind) {
			case CRYPT_CIP_LOCALCLIENT:
				ChallengeIP = dwForIP;
				break;
			case CRYPT_CIP_REMOTECLIENT:
				// Ignore local ip...
				if (!theApp->GetPublicIP(true)) {
					if (::IsLowID(theApp->GetED2KID())){
						AddDebugLogLineN(logCredits, wxT("Warning: Maybe SecureHash Ident fails because LocalIP is unknown"));
						// Fallback to local ip...
						ChallengeIP = theApp->GetPublicIP();
					} else {
						ChallengeIP = theApp->GetED2KID();
					}
				} else {
					ChallengeIP = theApp->GetPublicIP();
				}
				break;
			case CRYPT_CIP_NONECLIENT: // maybe not supported in future versions
				ChallengeIP = 0;
				break;
		}
		PokeUInt32(abyBuffer+m_nMyPublicKeyLen+4, ChallengeIP);
		PokeUInt8(abyBuffer+m_nMyPublicKeyLen+4+4, byChaIPKind);
	}
	//v2 end
	
#ifndef ENABLE_TOMCRYPT
		bResult = pubkey.VerifyMessage(abyBuffer, m_nMyPublicKeyLen+4+nChIpSize, pachSignature, nInputSize);
	printf("bResult = %d\n", bResult);
#else
	
	int hash_idx, prng_idx, stat, ret;
	rsa_key pubKey;

	hash_idx = find_hash("sha1");
	prng_idx = find_prng("sprng");
	if (hash_idx == -1 || prng_idx == -1) {
		AddLogLineC(CFormat(_("VerifyIdent requires SHA1 and sprng")));
		pTarget->SetIdentState(IS_NOTAVAILABLE);
		return false;
	}

	//import the pubkey
	ret = rsa_der_import(pTarget->GetSecureIdent(), (unsigned long)pTarget->GetSecIDKeyLen(), 
										PK_PUBLIC, DER_FULL_CODE_TYPE, &pubKey);
	if (ret){
		AddLogLineC(CFormat(_("VerifyIdent rsa_der_import failed ret =%d")) % ret);
		pTarget->SetIdentState(IS_NOTAVAILABLE);
		return false;
	}

	//get the message hash
	hash_state hs;
	unsigned char hash[SHA1_HASH_SIZE];
	sha1_init(&hs);
	unsigned long keylen_l= m_nMyPublicKeyLen+4+nChIpSize;
	sha1_process(&hs, abyBuffer, keylen_l);
	sha1_done(&hs, hash);

	//verify signature
	ret = rsa_verify_hash_ex(pachSignature, nInputSize, hash, SHA1_HASH_SIZE, 
								LTC_LTC_PKCS_1_V1_5, hash_idx, 8, &stat, &pubKey);
	if (ret == CRYPT_OK && stat == 1){
		//AddDebugLogLineC(logCredits, CFormat(_("VerifyIdent rsa_verify_hash_ex ok\n")));
		bResult = true;
	}else{	
		AddDebugLogLineC(logCredits, CFormat(_("VerifyIdent rsa_verify_hash_ex failed ret=%d\n")) % ret);
		bResult = false;
	}
		
#endif //ENABLE_TOMCRYPT
#ifndef ENABLE_TOMCRYPT
	} catch (const CryptoPP::Exception& e) {
		AddDebugLogLineC(logCredits, wxString(wxT("Error while verifying identity: ")) + wxString(char2unicode(e.what())));
 		bResult = false;
 	}
#endif //ENABLE_TOMCRYPT

	if (!bResult){
		if (pTarget->GetIdentState() == IS_IDNEEDED)
			pTarget->SetIdentState(IS_IDFAILED);
	} else {
		pTarget->Verified(dwForIP);
	}

#ifdef ENABLE_TOMCRYPT
	rsa_free(&pubKey);
#endif //ENABLE_TOMCRYPT
	return bResult;
}


bool CClientCreditsList::CryptoAvailable() const
{
#ifndef ENABLE_TOMCRYPT
	return m_nMyPublicKeyLen > 0 && m_pSignkey != NULL;
#else
	return m_nMyPublicKeyLen > 0 && m_nMySignKeyLen > 0;
#endif //ENABLE_TOMCRYPT
}

#ifdef _DEBUG
#ifndef ENABLE_TOMCRYPT
bool CClientCreditsList::Debug_CheckCrypting(){
	// create random key
	CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> rng;

	CryptoPP::RSASSA_PKCS1v15_SHA_Signer priv(rng, 384);
	CryptoPP::RSASSA_PKCS1v15_SHA_Verifier pub(priv);

	byte abyPublicKey[80];
	CryptoPP::ArraySink asink(abyPublicKey, 80);
	pub.DEREncode(asink);
	int8 PublicKeyLen = asink.TotalPutLength();
	asink.MessageEnd();
	uint32 challenge = rand();
	// create fake client which pretends to be this emule
	CreditStruct* newcstruct = new CreditStruct();
	CClientCredits newcredits(newcstruct);
	newcredits.SetSecureIdent(m_abyMyPublicKey,m_nMyPublicKeyLen);
	newcredits.m_dwCryptRndChallengeFrom = challenge;
	// create signature with fake priv key
	byte pachSignature[200];
	memset(pachSignature,0,200);
	uint8 sigsize = CreateSignature(&newcredits,pachSignature,200,0,false, &priv);


	// next fake client uses the random created public key
	CreditStruct* newcstruct2 = new CreditStruct();
	CClientCredits newcredits2(newcstruct2);
	newcredits2.m_dwCryptRndChallengeFor = challenge;

	// if you uncomment one of the following lines the check has to fail
	//abyPublicKey[5] = 34;
	//m_abyMyPublicKey[5] = 22;
	//pachSignature[5] = 232;

	newcredits2.SetSecureIdent(abyPublicKey,PublicKeyLen);

	//now verify this signature - if it's true everything is fine
	return VerifyIdent(&newcredits2,pachSignature,sigsize,0,0);
}
#endif
#endif
// File_checked_for_headers
