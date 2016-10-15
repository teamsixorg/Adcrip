using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace Adcrip
{
	public enum CryptProvider
	{
		Rijndael,
		RC2,
		DES,
		TripleDES
	}
	
	public class Adcrip
	{
        private string _key = string.Empty;
        private CryptProvider _cryptProvider;
        private SymmetricAlgorithm _algorithm;
        private void SetIV()
        {
            switch (_cryptProvider)
            {
                case CryptProvider.Rijndael:
                    _algorithm.IV = new byte[] { 0xf, 0x6f, 0x13, 0x2e, 0x35, 0xc2, 0xcd, 0xf9, 0x5, 0x46, 0x9c, 0xea, 0xa8, 0x4b, 0x73, 0xcc };
                    break;
                default:
                    _algorithm.IV = new byte[] { 0xf, 0x6f, 0x13, 0x2e, 0x35, 0xc2, 0xcd, 0xf9 };
                    break;
            }
        }
        public string Key
        {
            get { return _key; }
            set { _key = value; }
        }
        public Adcrip()
        {
            _algorithm = new RijndaelManaged();
            _algorithm.Mode = CipherMode.CBC;
            _cryptProvider = CryptProvider.Rijndael;
        }
        public Adcrip(CryptProvider cryptProvider)
             {     
                    switch(cryptProvider)
                    {
                           case CryptProvider.Rijndael:
                                  _algorithm = new RijndaelManaged();
                                 _cryptProvider = CryptProvider.Rijndael;
                                  break;
                           case CryptProvider.RC2:
                                  _algorithm = new RC2CryptoServiceProvider();
                                  _cryptProvider = CryptProvider.RC2;
                                  break;
                           case CryptProvider.DES:
                                  _algorithm = new DESCryptoServiceProvider();
                                  _cryptProvider = CryptProvider.DES;
                                  break;
                           case CryptProvider.TripleDES:
                                  _algorithm = new TripleDESCryptoServiceProvider();
                                  _cryptProvider = CryptProvider.TripleDES;
                                  break;
                    }
                    _algorithm.Mode = CipherMode.CBC;
             }
        public virtual byte[] GetKey()
        {
            string salt = string.Empty;
            if (_algorithm.LegalKeySizes.Length > 0)
            {
                int keySize = _key.Length * 8;
                int minSize = _algorithm.LegalKeySizes[0].MinSize;
                int maxSize = _algorithm.LegalKeySizes[0].MaxSize;
                int skipSize = _algorithm.LegalKeySizes[0].SkipSize;
                if (keySize > maxSize)
                {
                    _key = _key.Substring(0, maxSize / 8);
                }
                else if (keySize < maxSize)
                {
                    int validSize = (keySize <= minSize) ? minSize : (keySize - keySize % skipSize) + skipSize;
                    if (keySize < validSize)
                    {
                        _key = _key.PadRight(validSize / 8, '*');
                    }
                }
            }
            PasswordDeriveBytes key = new PasswordDeriveBytes(_key, ASCIIEncoding.ASCII.GetBytes(salt));
            return key.GetBytes(_key.Length);
        }
        public virtual string Encrypt(string texto)
        {
            byte[] plainByte = Encoding.UTF8.GetBytes(texto);
            byte[] keyByte = GetKey();
            _algorithm.Key = keyByte;
            SetIV();
            ICryptoTransform cryptoTransform = _algorithm.CreateEncryptor();
            MemoryStream _memoryStream = new MemoryStream();
            CryptoStream _cryptoStream = new CryptoStream(_memoryStream, cryptoTransform, CryptoStreamMode.Write);
            _cryptoStream.Write(plainByte, 0, plainByte.Length);
            _cryptoStream.FlushFinalBlock();
            byte[] cryptoByte = _memoryStream.ToArray();
            return Convert.ToBase64String(cryptoByte, 0, cryptoByte.GetLength(0));
        }
        public virtual string Decrypt(string textoCriptografado)
        {
            byte[] cryptoByte = Convert.FromBase64String(textoCriptografado);
            byte[] keyByte = GetKey();
            _algorithm.Key = keyByte;
            SetIV();
            ICryptoTransform cryptoTransform = _algorithm.CreateDecryptor();
            try
            {
                MemoryStream _memoryStream = new MemoryStream(cryptoByte, 0, cryptoByte.Length);
                CryptoStream _cryptoStream = new CryptoStream(_memoryStream, cryptoTransform, CryptoStreamMode.Read);
                StreamReader _streamReader = new StreamReader(_cryptoStream);
                return _streamReader.ReadToEnd();
            }
            catch
            {
                return null;
            }
        }
    }
	
	class Criptografia
	{
		string Metodo;
		string Texto;
		string Arquivo;
		string Chave;
		string Resultado;
		
		public Criptografia DoTexto(string Texto)
		{
			this.Texto = Texto;
			return this;
		}
		
		public Criptografia DoArquivo(string Arquivo)
		{
			this.Arquivo = Arquivo;
			return this;
		}
		
		public Criptografia ComChave(string Chave)
		{
			this.Chave = Chave;
			return this;
		}
		
		public Criptografia NoMetodo(string Metodo)
		{
			this.Metodo = Metodo;
			return this;
		}
		
		public string GerarRetorno()
		{
			CryptProvider MetodoAssimetrico = new CryptProvider();
	
			// Seleção do método de criptografia.
			#region
			
			switch(Metodo)
			{
				case "DES":
					MetodoAssimetrico = CryptProvider.DES;
					break;
				case "RC2":
					MetodoAssimetrico = CryptProvider.RC2;
					break;
				case "Rijndael":
					MetodoAssimetrico = CryptProvider.Rijndael;
					break;
				case "TripleDES":
					MetodoAssimetrico = CryptProvider.TripleDES;
					break;
			}
			
			#endregion
			
			// Criptografia assimétrica.
			#region
			
			if(MetodoAssimetrico != null)
			{
				Adcrip Crip = new Adcrip(MetodoAssimetrico);
				Crip.Key = Chave;
			
				if(string.IsNullOrEmpty(Texto) == false)
				{
					Resultado = Crip.Encrypt(Texto);
				}
				else if(string.IsNullOrEmpty(Arquivo) == false)
				{
					List<string> NovoTexto = new List<string>();
					StreamReader TextoArquivo = new StreamReader(Arquivo);
					while(!TextoArquivo.EndOfStream)
					{
						string LinhaAtual = TextoArquivo.ReadLine();
						if(string.IsNullOrEmpty(LinhaAtual) == false)
						{
							NovoTexto.Add(Crip.Encrypt(LinhaAtual));
						}
						else
						{
							NovoTexto.Add("");
						}
					}		
					TextoArquivo.Close();
					TextoArquivo.Dispose();
			
					string path = Path.GetDirectoryName(Arquivo) + @"\" + Path.GetFileNameWithoutExtension(Arquivo) + "_Crip" + Path.GetExtension(Arquivo);
					StreamWriter EscritaNovoArq = new StreamWriter(path);
					for(int c = 0; c >= NovoTexto.Count; c++)
					{
						string ct = NovoTexto[c].ToString();
						EscritaNovoArq.WriteLine(ct);
					}
					EscritaNovoArq.Close();
					EscritaNovoArq.Dispose();
					
					Resultado = path;
				}
			}
			
			#endregion
			
			// Retorno e limpeza da função.
			#region
			
			return Resultado;
			Metodo = null;
			Texto = null;
			Arquivo = null;
			Chave = null;
			Resultado = null;
			
			#endregion
		}
	}
	
	class Descriptografia
	{
		string Metodo;
		string Texto;
		string Arquivo;
		string Chave;
		string Resultado;
		
		public Descriptografia DoTexto(string Texto)
		{
			this.Texto = Texto;
			return this;
		}
		
		public Descriptografia DoArquivo(string Arquivo)
		{
			this.Arquivo = Arquivo;
			return this;
		}
		
		public Descriptografia ComChave(string Chave)
		{
			this.Chave = Chave;
			return this;
		}
		
		public Descriptografia NoMetodo(string Metodo)
		{
			this.Metodo = Metodo;
			return this;
		}
		
		public string GerarRetorno()
		{
			CryptProvider MetodoAssimetrico = new CryptProvider();
			
			// Seleção do metodo de criptografia.
			#region
			
			switch(Metodo)
			{
				case "DES":
					MetodoAssimetrico = CryptProvider.DES;
					break;
				case "RC2":
					MetodoAssimetrico = CryptProvider.RC2;
					break;
				case "Rijndael":
					MetodoAssimetrico = CryptProvider.Rijndael;
					break;
				case "TripleDES":
					MetodoAssimetrico = CryptProvider.TripleDES;
					break;
			}
			
			#endregion
			
			// Criptografia assimétrica.
			#region
			
			Adcrip Decrip = new Adcrip(MetodoAssimetrico);
			Decrip.Key = Chave;
			if(string.IsNullOrEmpty(Texto) == false)
			{
				Resultado = Decrip.Decrypt(Texto);
			}
			else if(string.IsNullOrEmpty(Arquivo) == false)
			{
				List<string> NovoTexto = new List<string>();
				StreamReader TextoArquivo = new StreamReader(Arquivo);
				while(!TextoArquivo.EndOfStream)
				{
					string LinhaAtual = TextoArquivo.ReadLine();
					if(string.IsNullOrEmpty(LinhaAtual) == false)
					{
						NovoTexto.Add(Decrip.Decrypt(LinhaAtual));
					}
					else
					{
						NovoTexto.Add("");
					}
				}
				TextoArquivo.Close();
				TextoArquivo.Dispose();
				
				string path = Path.GetDirectoryName(Arquivo) + @"\" + Path.GetFileNameWithoutExtension(Arquivo) + "_Decrip" + Path.GetExtension(Arquivo);
				StreamWriter EscritaNovoArq = new StreamWriter(path);
				for(int c = 0; c >= NovoTexto.Count; c++)
				{
					string ct = NovoTexto[c].ToString();
					EscritaNovoArq.WriteLine(ct);
				}
				EscritaNovoArq.Close();
				EscritaNovoArq.Dispose();
				
				Resultado = path;
			}
			
			#endregion
			
			// Retorno e limpeza da função.
			#region
			
			return Resultado;
			Metodo = null;
			Texto = null;
			Arquivo = null;
			Chave = null;
			Resultado = null;
			
			#endregion
		}
	}
}