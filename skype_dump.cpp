/**
 *  The MIT License:
 *
 *  Copyright (c) 2012 Kevin Devine
 *
 *  Permission is hereby granted,  free of charge,  to any person obtaining a 
 *  copy of this software and associated documentation files (the "Software"),
 *  to deal in the Software without restriction,  including without limitation 
 *  the rights to use,  copy,  modify,  merge,  publish,  distribute,  
 *  sublicense,  and/or sell copies of the Software,  and to permit persons to 
 *  whom the Software is furnished to do so,  subject to the following 
 *  conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS",  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED,  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,  DAMAGES OR OTHER
 *  LIABILITY,  WHETHER IN AN ACTION OF CONTRACT,  TORT OR OTHERWISE,  
 *  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
 *  OTHER DEALINGS IN THE SOFTWARE.
 */

#include <string>
#include <cstdio>
#include <stdint.h>

#define _WIN32_IE 0x0500

#include <windows.h>
#include <wincrypt.h>
#include <Shlwapi.h>
#include <Shlobj.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Shell32.lib")

#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/aes.h>

#include <libxml/xmlreader.h>

#define MAX_SALT_LEN 64
#define MAX_HASH_LEN 16

/**
 *
 *  Obtain, decrypt and return pointer to unique salt
 *  return NULL if unable to read
 *
 *  caller should free memory afterwards with LocalFree()
 *
 */
PBYTE GetSalt(DWORD &cbSalt) {
    BYTE aBlob[2048];
    DWORD cbSize = sizeof(aBlob);
    const char skype_path[] = "Software\\Skype\\ProtectedStorage";
    
    LSTATUS lStatus = SHGetValue(HKEY_CURRENT_USER, skype_path, 
        "0", 0, aBlob, &cbSize);
      
    if (lStatus != ERROR_SUCCESS) {
      printf("\n  Unable to open skype key : %08x", lStatus);
      return NULL;
    }

    DATA_BLOB in, out;
    
    in.pbData = aBlob;
    in.cbData = cbSize;
    
    if (CryptUnprotectData(&in, NULL, NULL, NULL, 
        NULL, 0, &out)) {
      cbSalt = out.cbData;
      return out.pbData;
    } else {
      printf("\n  Unable to decrypt skype entry.");
    }
    return NULL;
}

/**
 *
 *  Obtain path to config.xml and read Credentials* value
 *  return pointer to binary or NULL if couldn't be read
 * 
 *  caller should free memory pointer with LocalFree()
 *
 */
bool GetCredentials(BYTE ciphertext[], std::string config_xml) {    
    bool bFound = false;
    
    // try open config.xml
    xmlTextReaderPtr reader;
    reader = xmlReaderForFile(config_xml.c_str(), NULL, 0);
    
    // tested with Credentials2 or Credentials3
    const xmlChar *credentials; 
    credentials = (const xmlChar*)"Credentials";

    if (reader != NULL) {
    
      // while nodes are available
      while (xmlTextReaderRead(reader) == 1) {
        // get name
        const xmlChar *name;
        name = xmlTextReaderConstName(reader);
        if (name == NULL) continue;

        // equal to credentials we're searching for?
        if (xmlStrncmp(credentials, name, xmlStrlen(credentials)) == 0) {

          // read the next value
          if (xmlTextReaderRead(reader) == 1) {
            const xmlChar *value;
            value = xmlTextReaderConstValue(reader);
            
            for (int i = 0;i < 16;i++) {
              sscanf((const char*)&value[i * 2], "%02x", &ciphertext[i]);
            }
            bFound = true;
            break;
          }
        }
      }
      xmlFreeTextReader(reader);
    }
    xmlCleanupParser();
    return bFound;
}

/**
 *
 *  Decrypt the ciphertext to reveval MD5 hash of users password
 *
 */
void DecryptHash(PBYTE pbCipherText, PBYTE pbSalt, DWORD cbSalt) {
    
    SHA_CTX ctx;
    AES_KEY key;
    
    uint8_t dgst[40], buffer[AES_BLOCK_SIZE];
    
    memset(&buffer, 0, sizeof(buffer));
    
    // use counter mode + SHA-1 to generate key
    for (ULONG i = 0;i < 2;i++) {
        ULONG ulIndex = _byteswap_ulong(i);
          
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, &ulIndex, sizeof(ulIndex));
        SHA1_Update(&ctx, pbSalt, cbSalt);
        SHA1_Final(&dgst[i*20], &ctx);
    }
    
    AES_set_encrypt_key(dgst, 256, &key);
    AES_encrypt(buffer, buffer, &key);
    
    printf("\n  MD5 hash = ");
    
    // decrypt MD5 hash with XOR
    for (int i = 0;i < 16;i++) {
        printf("%02x", pbCipherText[i] ^ buffer[i]);
    }
    printf("\n");
}

/**
 *
 *  Initial info found in http://www.recon.cx/en/f/vskype-part2.pdf
 *
 */
void GenHash(const char *id, const char *pwd) {
    MD5_CTX ctx;
    const char *skype = "\nskyper\n";
    uint8_t dgst[32];
    
    MD5_Init(&ctx);
    MD5_Update(&ctx, id, strlen(id));
    MD5_Update(&ctx, skype, strlen(skype));
    MD5_Update(&ctx, pwd, strlen(pwd));
    MD5_Final(dgst, &ctx);

    printf("\n  Login ID = %s"
           "\n  Password = %s"
           "\n  MD5 hash = ", id, pwd);
    
    for (int i = 0;i < 16;i++) {
        printf("%02x", dgst[i]);
    }
    printf("\n");
}

/**
 *
 *  Try to retrieve path of config.xml from current users profile
 *
 */
bool GetXMLPath(std::string &AppData) {
    WIN32_FIND_DATA wfd;
    HANDLE hFind = FindFirstFile((AppData + "\\*.*").c_str(), &wfd);
    bool bFound = false;
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                std::string name = wfd.cFileName;
                
                if (name != "." && name != "..") {
                    std::string path = AppData + "\\" + name + "\\config.xml";            
                    DWORD dwAttributes = GetFileAttributes(path.c_str());
                    
                    if (dwAttributes != INVALID_FILE_ATTRIBUTES) {
                        AppData = path;
                        bFound = true;
                        break;
                    }
                }
            }
        } while (FindNextFile(hFind, &wfd));
        FindClose(hFind);
    }
    return bFound;
}

void exit_app(const char exit_msg[]) {
    printf("%s\n  Press any key to continue . . .", exit_msg);
    fgetc(stdin);
    exit(0);
}

int main(int argc, char *argv[]) {
    puts("\n  Skype Hash Dumper v1.0"
         "\n  Copyright (c) 2012 Kevin Devine\n");
    
    std::string config_xml;

    // try to retrieve the path if no parameters specified
    if (argc == 1) {
      CHAR lpszPath[MAX_PATH];
      
      if (!SHGetSpecialFolderPath(NULL, lpszPath, 
          CSIDL_APPDATA, FALSE)) {
        exit_app("  Unable to determine \"Application Data\" folder\n");
      }
      config_xml = lpszPath;
      config_xml += "\\Skype";
      
      if (!GetXMLPath(config_xml)) {
        exit_app("  Unable to locate config.xml\n");
      }
      
    // else if we have just 1 argument, assume it's path of config.xml
    } else if (argc == 2) {
      config_xml = argv[1];
      
    // else if 2 arguments, treat as username + password combination
    } else if (argc == 3) {
        GenHash(argv[1], argv[2]);   
        exit_app("");
    // else show arguments 
    } else {
      exit_app("\n  Usage: skype_dump <config.xml> | <username> <password>\n");
    }
    
    // try read the salt value first
    DWORD cbSalt = 0;
    PBYTE pbSalt = NULL;
    
    pbSalt = GetSalt(cbSalt);
    
    if (pbSalt != NULL) {
      BYTE ciphertext[MAX_HASH_LEN];
      
      if (GetCredentials(ciphertext, config_xml)) {
        DecryptHash(ciphertext, pbSalt, cbSalt);
      } else {
        printf("\n  Unable to obtain encrypted hash from config.xml");
      }
    } else {
      printf("\n  Unable to obtain salt.");
    }
    exit_app("");
    return 0;
}
