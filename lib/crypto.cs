using System;
using System.Runtime.InteropServices;

namespace lib
{
	/// <summary>
	/// TweetNaCl
	/// </summary>
	public static class crypto
	{
		private static readonly UnmanagedLibrary NativeLib;

		private const string LibraryName = "tweetnacl";

		static crypto()
		{
			NativeLib = Platform.LoadUnmanagedLibrary(LibraryName);
		}

		/* randombytes
		[DllImport(LibraryName, EntryPoint = "randombytes", CallingConvention = CallingConvention.Cdecl)]
		private static extern void randombytes(byte[] buffer, long bufferLength);
		public delegate void randombytes_delegate(byte[] buffer, long bufferLength);
		public static readonly randombytes_delegate random = randombytes; /**/

		// crypto_box
		[DllImport(LibraryName, EntryPoint = "crypto_box", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_box(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] publicKey, byte[] secretKey);
		public delegate Int32 crypto_box_delegate(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] publicKey, byte[] secretKey);
		public static readonly crypto_box_delegate box = crypto_box;

		// crypto_box_open
		[DllImport(LibraryName, EntryPoint = "crypto_box_open", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_box_open(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] publicKey, byte[] secretKey);
		public delegate Int32 crypto_box_open_delegate(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] publicKey, byte[] secretKey);
		public static readonly crypto_box_open_delegate box_open = crypto_box_open;

		// crypto_box_publickey
		[DllImport(LibraryName, EntryPoint = "crypto_box_publickey", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_box_publickey(byte[] publicKey, byte[] secretKey);
		public delegate Int32 crypto_box_publickey_delegate(byte[] publicKey, byte[] secretKey);
		public static readonly crypto_box_publickey_delegate box_publickey = crypto_box_publickey;

		/* crypto_box_keypair
		[DllImport(LibraryName, EntryPoint = "crypto_box_keypair", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_box_keypair(byte[] publicKey, byte[] secretKey);
		public delegate Int32 crypto_box_keypair_delegate(byte[] publicKey, byte[] secretKey);
		public static readonly crypto_box_keypair_delegate box_keypair = crypto_box_keypair; /**/

		// crypto_box_beforenm
		[DllImport(LibraryName, EntryPoint = "crypto_box_beforenm", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_box_beforenm(byte[] k, byte[] publicKey, byte[] secretKey);
		public delegate Int32 crypto_box_beforenm_delegate(byte[] k, byte[] publicKey, byte[] secretKey);
		public static readonly crypto_box_beforenm_delegate box_beforenm = crypto_box_beforenm;

		// crypto_box_afternm
		[DllImport(LibraryName, EntryPoint = "crypto_box_afternm", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_box_afternm(byte[] cipher, byte[] message, Int32 messageLength, byte[] nonce, byte[] key);
		public delegate Int32 crypto_box_afternm_delegate(byte[] cipher, byte[] message, Int32 messageLength, byte[] nonce, byte[] key);
		public static readonly crypto_box_afternm_delegate box_afternm = crypto_box_afternm;

		// crypto_box_open_afternm
		[DllImport(LibraryName, EntryPoint = "crypto_box_open_afternm", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_box_open_afternm(byte[] message, byte[] cipher, Int32 cipherLength, byte[] nonce, byte[] key);
		public delegate Int32 crypto_box_open_afternm_delegate(byte[] message, byte[] cipher, Int32 cipherLength, byte[] nonce, byte[] key);
		public static readonly crypto_box_open_afternm_delegate box_open_afternm = crypto_box_open_afternm;


		// crypto_core_salsa20
		[DllImport(LibraryName, EntryPoint = "crypto_core_salsa20", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_core_salsa20(byte[] o, byte[] i, byte[] k, byte[] c);
		public delegate Int32 crypto_core_delegate(byte[] o, byte[] i, byte[] k, byte[] c);
		public static readonly crypto_core_delegate core_salsa20 = crypto_core_salsa20;

		// crypto_core_hsalsa20
		[DllImport(LibraryName, EntryPoint = "crypto_core_hsalsa20", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_core_hsalsa20(byte[] o, byte[] i, byte[] k, byte[] c);
		// public delegate Int32 crypto_core_hsalsa20_delegate(byte[] o, byte[] i, byte[] k, byte[] c);
		public static readonly crypto_core_delegate core_hsalsa20 = crypto_core_hsalsa20;


		// crypto_hashblocks_sha512
		[DllImport(LibraryName, EntryPoint = "crypto_hashblocks_sha512", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_hashblocks_sha512(byte[] buffer, byte[] message, long length);
		public delegate Int32 crypto_hashblocks_delegate(byte[] buffer, byte[] message, long length);
		public static readonly crypto_hashblocks_delegate hashblocks_sha512 = crypto_hashblocks_sha512;

		// crypto_hashblocks_sha256
		[DllImport(LibraryName, EntryPoint = "crypto_hashblocks_sha256", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_hashblocks_sha256(byte[] buffer, byte[] message, long length);
		// public delegate Int32 crypto_hashblocks_delegate(byte[] buffer, byte[] message, long length);
		public static readonly crypto_hashblocks_delegate hashblocks_sha256 = crypto_hashblocks_sha256;


		// crypto_hash_sha512
		[DllImport(LibraryName, EntryPoint = "crypto_hash_sha512", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_hash_sha512(byte[] buffer, byte[] message, long length);
		public delegate Int32 crypto_hash_delegate(byte[] buffer, byte[] message, long length);
		public static readonly crypto_hash_delegate hash_sha512 = crypto_hash_sha512;

		// crypto_hash_sha256
		[DllImport(LibraryName, EntryPoint = "crypto_hash_sha256", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_hash_sha256(byte[] buffer, byte[] message, long length);
		// public delegate Int32 crypto_hash_delegate(byte[] buffer, byte[] message, long length);
		public static readonly crypto_hash_delegate hash_sha256 = crypto_hash_sha256;


		// crypto_onetimeauth
		[DllImport(LibraryName, EntryPoint = "crypto_onetimeauth", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_onetimeauth(byte[] buffer, byte[] message, long messageLength, byte[] key);
		public delegate Int32 crypto_onetimeauth_delegate(byte[] buffer, byte[] message, long messageLength, byte[] key);
		public static readonly crypto_onetimeauth_delegate onetimeauth = crypto_onetimeauth;

		// crypto_onetimeauth_verify
		[DllImport(LibraryName, EntryPoint = "crypto_onetimeauth_verify", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_onetimeauth_verify(byte[] signature, byte[] message, long messageLength, byte[] key);
		public delegate Int32 crypto_onetimeauth_verify_delegate(byte[] signature, byte[] message, long messageLength, byte[] key);
		public static readonly crypto_onetimeauth_verify_delegate onetimeauth_verify = crypto_onetimeauth_verify;


		// crypto_scalarmult
		[DllImport(LibraryName, EntryPoint = "crypto_scalarmult", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_scalarmult(byte[] q, byte[] n, byte[] p);
		public delegate Int32 crypto_scalarmult_delegate(byte[] q, byte[] n, byte[] p);
		public static readonly crypto_scalarmult_delegate scalarmult = crypto_scalarmult;

		// crypto_scalarmult_base
		[DllImport(LibraryName, EntryPoint = "crypto_scalarmult_base", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_scalarmult_base(byte[] q, byte[] n);
		public delegate Int32 crypto_scalarmult_base_delegate(byte[] q, byte[] n);
		public static readonly crypto_scalarmult_base_delegate scalarmult_base = crypto_scalarmult_base;


		// crypto_secretbox
		[DllImport(LibraryName, EntryPoint = "crypto_secretbox", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_secretbox(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);
		public delegate Int32 crypto_secretbox_delegate(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);
		public static readonly crypto_secretbox_delegate secretbox = crypto_secretbox;

		// crypto_secretbox_open
		[DllImport(LibraryName, EntryPoint = "crypto_secretbox_open", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_secretbox_open(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] key);
		public delegate Int32 crypto_secretbox_open_delegate(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] key);
		public static readonly crypto_secretbox_open_delegate secretbox_open = crypto_secretbox_open;


		// crypto_sign
		[DllImport(LibraryName, EntryPoint = "crypto_sign", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_sign(byte[] buffer, ref long bufferLength, byte[] message, long messageLength, byte[] key);
		public delegate Int32 crypto_sign_delegate(byte[] buffer, ref long bufferLength, byte[] message, long messageLength, byte[] key);
		public static readonly crypto_sign_delegate sign = crypto_sign;

		// crypto_sign_open
		[DllImport(LibraryName, EntryPoint = "crypto_sign_open", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_sign_open(byte[] buffer, ref long bufferLength, byte[] signedMessage, long signedMessageLength, byte[] key);
		public delegate Int32 crypto_sign_open_delegate(byte[] buffer, ref long bufferLength, byte[] signedMessage, long signedMessageLength, byte[] key);
		public static readonly crypto_sign_open_delegate sign_open = crypto_sign_open;

		/* crypto_sign_keypair
		[DllImport(LibraryName, EntryPoint = "crypto_sign_keypair", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_sign_keypair(byte[] publicKey, byte[] secretKey);
		public delegate Int32 crypto_sign_keypair_delegate(byte[] publicKey, byte[] secretKey);
		public static readonly crypto_sign_keypair_delegate sign_keypair = crypto_sign_keypair; /**/

		// crypto_sign_publickey
		[DllImport(LibraryName, EntryPoint = "crypto_sign_publickey", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_sign_publickey(byte[] publicKey, byte[] secretKey);
		public delegate Int32 crypto_sign_publickey_delegate(byte[] publicKey, byte[] secretKey);
		public static readonly crypto_sign_publickey_delegate sign_publickey = crypto_sign_publickey;


		// crypto_stream_xsalsa20
		[DllImport(LibraryName, EntryPoint = "crypto_stream_xsalsa20", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_stream_xsalsa20(byte[] message, long messageLength, byte[] buffer, byte[] nonce, byte[] key);
		public delegate Int32 crypto_stream_delegate(byte[] message, long messageLength, byte[] buffer, byte[] nonce, byte[] key);
		public static readonly crypto_stream_delegate stream_xsalsa20 = crypto_stream_xsalsa20;

		// crypto_stream_xsalsa20_xor
		[DllImport(LibraryName, EntryPoint = "crypto_stream_xsalsa20_xor", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_stream_xsalsa20_xor(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);
		public delegate Int32 crypto_stream_xor_delegate(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);
		public static readonly crypto_stream_xor_delegate stream_xsalsa20_xor = crypto_stream_xsalsa20_xor;

		// crypto_stream_salsa20
		[DllImport(LibraryName, EntryPoint = "crypto_stream_salsa20", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_stream_salsa20(byte[] message, long messageLength, byte[] buffer, byte[] nonce, byte[] key);
		// public delegate Int32 crypto_stream_delegate(byte[] message, long messageLength, byte[] buffer, byte[] nonce, byte[] key);
		public static readonly crypto_stream_delegate stream_salsa20 = crypto_stream_salsa20;

		// crypto_stream_salsa20_xor
		[DllImport(LibraryName, EntryPoint = "crypto_stream_salsa20_xor", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_stream_salsa20_xor(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);
		// public delegate Int32 crypto_stream_xor_delegate(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);
		public static readonly crypto_stream_xor_delegate stream_salsa20_xor = crypto_stream_salsa20_xor;


		// crypto_verify_16
		[DllImport(LibraryName, EntryPoint = "crypto_verify_16", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_verify_16(byte[] x, byte[] y);
		public delegate Int32 crypto_verify_delegate(byte[] x, byte[] y);
		public static readonly crypto_verify_delegate verify_16 = crypto_verify_16;

		// crypto_verify_32
		[DllImport(LibraryName, EntryPoint = "crypto_verify_32", CallingConvention = CallingConvention.Cdecl)]
		private static extern Int32 crypto_verify_32(byte[] x, byte[] y);
		// public delegate Int32 crypto_verify_delegate(byte[] x, byte[] y);
		public static readonly crypto_verify_delegate verify_32 = crypto_verify_32;
	}
}
