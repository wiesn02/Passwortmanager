
# Password Manager

## Description

The Repository divides into two parts:

A simple terminal-based password manager written in c. Easy to use and self-explanatory. Securely store and manage your passwords locally.
Precompiled executables and the source code (in the `src_c` folder) are provided for this application. The folder `SBOM` contains the Software Bills of Materials for the password manager written in c.

and

The source code for the same password manager that was migrated to the language rust using the LLM Claude Sonnet 4.5, located in the folder `src_rust`.

## Installation

To use the Password Manager, follow these steps:

### Clone the repository:

	git clone <repo-url>

### Then you can either A) use precompiled executables or B) compile the project yourself

#### A) Use precompiled executables
`Passwortmanager_Windows.exe` for Windows platforms
or
`./Passwordmanager_Linux` for Linux platforms


#### B) Compiling the Project yourself using the source code found in the src_c folder.
Below are two example commands for compiling: for Windows platforms using Microsoft Visual Studio and for Linux platforms using gcc.
These drop-in commands ensure hardened compiling following the OWASP Cheatsheet for c-based toolchain hardening: https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html

Using MSVS on Windows:

	cl main.c userSession.c helperFunctions.c db.c crypto.c sqlite3.c /DSODIUM_STATIC /I libsodium\include libsodium\x64\static\libsodium.lib /Fe:Passwortmanager_Windows.exe ^
	/W4 /sdl /GS /DYNAMICBASE /D_CRT_SECURE_NO_WARNINGS /guard:cf /O2 /link /NXCOMPAT

Using gcc on Linux:

	gcc main.c userSession.c helperFunctions.c db.c crypto.c sqlite3.c -DSODIUM_STATIC -I libsodium/include -L libsodium/x64/static -lsodium -o Passwortmanager_Linux \
	-Wall -Wextra -Wformat -Wformat-security -Werror=format-security -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2 -fPIE -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack


Note: For compiling using any other compination of platform and compiler, you will need to adapt the compilation command to your specific compiler or platform.


### The vault folder:

Your encrypted password will be stored here. If it doesnt exist, the manager will create it.

### Run the executable

Enjoy securely managing your passwords!