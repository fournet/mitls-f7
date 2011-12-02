// This is the main DLL file.

#include "stdafx.h"

#include "ManagedRC4.h"
#pragma comment(lib, "advapi32.lib")

using namespace ManagedRC4;

bool RC4Native::ImportKey( BYTE* pKeyData, unsigned long cbKeyData )
{
   bool fRet = false;
   BYTE* pbKeyBlob;
   static const PUBLICKEYSTRUC pks = { PLAINTEXTKEYBLOB, CUR_BLOB_VERSION , 0, CALG_RC4 };

   // Assume enough room for a 128-bit key
   size_t cbAlloc = 20 + sizeof(PUBLICKEYSTRUC);
   
   pbKeyBlob = new BYTE[cbAlloc];

   ZeroMemory(pbKeyBlob, cbAlloc);

   // Set the PUBLICKEYSTRUC part of the header
   *(reinterpret_cast<PUBLICKEYSTRUC*>(pbKeyBlob)) = pks;
   // Copy in the key data
   memcpy_s(pbKeyBlob + sizeof(PUBLICKEYSTRUC) + sizeof(DWORD), cbKeyData, pKeyData, cbKeyData);
   // Set the size of the key data in bytes
   DWORD* pcbKeyData = reinterpret_cast<DWORD*>(pbKeyBlob + sizeof(PUBLICKEYSTRUC));

   // This step makes explicit what the Microsoft implementation of RC4 is really doing, unless
   // CRYPT_NO_SALT flag is set. Essentially, there's a 128-bit key, just that the last 88 bits
   // are all 0. Unfortunately, there is no standard for RC4, which is part of why this happens.
   if( cbKeyData == 5 )
      *pcbKeyData = 16;
   else
      *pcbKeyData = cbKeyData;

   fRet = !!CryptImportKey( m_CryptProv, pbKeyBlob, static_cast<DWORD>(cbAlloc), NULL, 0, &m_CryptKey );
   delete[] pbKeyBlob;

#ifdef _DEBUG
   if( !fRet )
   {
      DWORD err = GetLastError();
   }
#endif

   return fRet;
}

void RC4Native::Release()
{
   if( m_CryptKey != NULL )
      CryptDestroyKey( m_CryptKey );
   if( m_CryptProv != NULL )
      CryptReleaseContext( m_CryptProv, 0 );

   m_CryptKey = NULL;
   m_CryptProv = NULL;
}

