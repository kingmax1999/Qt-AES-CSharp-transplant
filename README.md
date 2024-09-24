# C# AES
Small and portable AES encryption class for C#.
Native support for all key sizes - 128/192/256 bits - ECB, CBC, CFB and OFB modes for all key sizes
partial AES-NI support

Although C# comes with a built-in AES encryption library that is quite convenient to use, utilizing library functions can be a happy thing for hackers. By using native code for compilation, along with code obfuscation techniques for C# programs, the security of the application can be greatly enhanced. I would like to thank the original project author for making it easy for us to obtain the C# version of the code. I hope this is useful for everyone.
## Usage

### Available Methods
```

```

#### AES Levels
The class supports all AES key lenghts

* AES_128
* AES_192
* AES_256

#### Modes
The class supports the following operating modes

* ECB
* CBC
* CFB
* OFB

#### Padding
By default the padding method is `ISO`, however, the class supports:

* ZERO
* PKCS7
* ISO

### Example

Just add C#AES.cs to your c# project is enough. The c++ files is only FYI.
Sample code using a 128bit key in ECB mode
```
     private string decryptText(string encryptedText)
        {
            string key = "8fa99e94fada9527"; // 16 bytes(AES-128)
            string iv = "8fa99e94fada9527";  //  (IV)
                                           
            CSharpAESEncryption encryption = new CSharpAESEncryption(CSharpAESEncryption.Aes.AES_128, CSharpAESEncryption.Mode.ECB, CSharpAESEncryption.Padding.PKCS7);
           
            byte[] decodedCiphertext = Convert.FromBase64String(encryptedText);  //base64 decode
            byte[] decrypted = encryption.decode(decodedCiphertext, System.Text.Encoding.UTF8.GetBytes(key), System.Text.Encoding.UTF8.GetBytes(iv));//
            byte[] paddingRemoved = encryption.removePadding(decrypted);
            string plainText = Encoding.UTF8.GetString(paddingRemoved);
            return plainText;
        }
```


## Dependencies


No OpenSSL required.

## Contact
Question or suggestions are welcome!
Please use the GitHub issue tracking to report suggestions or issues.

## License
This software is provided under the [UNLICENSE](http://unlicense.org/)

## Known Issues
Please take a look at the list of currently open issues
