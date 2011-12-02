// ManagedRC4.h

#pragma once

using namespace System;

namespace ManagedRC4 {

   class RC4Native
   {
   public:
      RC4Native() : m_CryptProv(NULL), m_CryptKey(NULL)
      {
      }
      ~RC4Native() { this->Release(); }

      // Use this to call CryptImportKey
      bool Init( BYTE* pKeyData, unsigned long cbData )
      {
         return AcquireContext() && ImportKey( pKeyData, cbData );
      }

      bool Encrypt( BYTE* pData, unsigned long cbData)
      {
         DWORD dwDataLen = cbData;
         if(!CryptEncrypt( m_CryptKey, NULL, FALSE, 0, pData, &dwDataLen, cbData))
         {
            return false;
         }

         if(dwDataLen != cbData)
               return false;

         return true;
      }

      bool Decrypt( BYTE* pData, unsigned long cbData)
      {
         DWORD dwDataLen = cbData;
         return !!CryptDecrypt( m_CryptKey, NULL, FALSE, 0, pData, &dwDataLen );
      }

      void Release();

   private:

      bool ImportKey( BYTE* pKeyData, unsigned long cbKeyData );

      bool AcquireContext()
      {
         return !!CryptAcquireContext(&m_CryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
      }

      HCRYPTPROV m_CryptProv;
      HCRYPTKEY  m_CryptKey;
   };
	
   public ref class RC4
	{
   public:
      RC4() : m_RC4Native(NULL) {}
      ~RC4() { delete m_RC4Native; }

      void Init( array<byte>^ data, unsigned int cbData )
      {
         // This should throw on failure
         m_RC4Native = new RC4Native;
         pin_ptr<byte> pPin = &data[0];
         byte* pData = pPin;

         if( !m_RC4Native->Init( pData, cbData ) )
         {
            delete m_RC4Native;
            m_RC4Native = NULL;
            throw gcnew System::Exception("Cannot initialize RC4 encryption");
         }
      }

      void Encrypt( array<byte>^ data, unsigned long cbData )
      {
         if( m_RC4Native == NULL )
            throw gcnew System::Exception("Class not initialized");

         // pin the incoming array
         pin_ptr<byte> pPin = &data[0];
         // Now map it to a native type
         byte* pData = pPin;
         if(!m_RC4Native->Encrypt(pData, cbData))
            throw gcnew System::Exception("Cannot encrypt data");
      }

      void Decrypt( array<byte>^ data, unsigned long cbData )
      {
         if( m_RC4Native == NULL )
            throw gcnew System::Exception("Class not initialized");

         pin_ptr<byte> pPin = &data[0];
         byte* pData = pPin;
         if(!m_RC4Native->Decrypt(pData, cbData))
            throw gcnew System::Exception("Cannot decrypt data");
      }

   private:
      RC4Native* m_RC4Native;
		
	};
} // namespace
