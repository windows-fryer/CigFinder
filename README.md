# Information
- Despite using the YARA/IDA signature format, there's a requirement of double wildcards. Signatures also must not have any whitespace. An example of a signature can be `C9 ?? ?? ?? ?? FF`. 
- This was built with use inside of Win32 applications.
- This will **only** scan the .text section of the specified module.
