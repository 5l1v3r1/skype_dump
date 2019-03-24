

Skype Hash Dumper v1.0
http://www.insecurety.net/
Dec 2012


[ What is it?

  The code demonstrates decryption of the MD5 password hash stored in Skype 
  configuration file on Windows... 
  
  The Linux version doesn't encrypt at all.

  Although the plaintext password can't be recovered using this tool, (which some may
  say is useless) In combination with a password cracker, it's possible to recover
  the plaintext.
 
  I haven't provided a password cracker but the algorithm is included for reference
  which you can try out by supplying username and password parameters like:
  
    skype_dump username password
  
  John The Ripper does in fact have a module available for those 
  interested and perhaps some other tools exist I'm not aware of.
  
  
[ Building

  If you want to compile your own exe from source, here are the steps using 
  OpenSSL and LibXML2
  Your version of libraries may differ and this is only a rough guide.
 
  1) Download and extract LibXML2 sources somewhere (I'm using C:\ here)
  2) Start a visual studio command prompt and drop into source directory.

       cd C:\libxml2-2.9.0\win32
    
  3) Edit C:\libxml2-2.9.0\win32\configure.js so that cruntime="/MT" instead of "/MD"
     and from command line run the configure script before finally building with nmake.
 
       cscript configure.js xml_debug=no iconv=no ftp=no http=no zlib=no lzma=no debug=no writer=no static=yes prefix=C:\libxml2-2.9.0
       nmake -f Makefile.msvc all

  4) Download and extract OpenSSL sources
  5) Start a visual studio command prompt and drop into the source directory to configure and build.
    
       cd C:\openssl-1.0.1c
       perl Configure VC-WIN32 no-asm --prefix=C:\openssl-1.0.1c
       ms\do_ms.bat
       nmake -f ms\nt.mak
 
  6) Compile skype_dump.cpp using the static libraries.
      
       cl /GS- /Oy /O1 /Os skype_dump.cpp /I C:\openssl-1.0.1c\inc32 /I C:\libxml2-2.9.0\include c:\openssl-1.0.1c\out32\libeay32.lib C:\libxml2-2.9.0\win32\bin.msvc\libxml2_a.lib


[ Pre-Compiled binaries

  Igor Zlatkovic has already provided pre-compiled binaries/libaries if you 
  would prefer to use those. Initially, I compiled with his libraries which 
  needed both iconv and zlib.

  You'll find everything you need here: ftp://ftp.zlatkovic.com/libxml/
  
  
[ And finally...

  If you have further questions, post it in the comments section 
  of article that discusses the algorithm in detail: http://insecurety.net/?p=427
  
  Best Regards,
  
  .dietrich