# Reverse Engineering Challenge: **sneek3rs l33t VM**

Welcome to the **sneek3rs l33t VM** reverse engineering challenge! In this CTF, you'll be tasked with analyzing a binary file to uncover hidden secrets.

---

## Challenge Overview

### Files Provided

- **`challenge`** - The compiled binary you’ll be analyzing.
- **`source.c`** - The obfuscated source code used to generate the binary, though it does not contain the actual keys or encrypted flag. The obfuscation is intended to add complexity and challenge your code analysis skills.

The objective of this challenge is to reverse engineer the binary and determine the correct sequence or inputs needed to reveal the hidden flag.

### Objective

Using static and dynamic analysis tools, reverse engineer the binary to extract the encrypted flag. The binary and source code may employ a range of obfuscation techniques, and the flag might be revealed only after satisfying specific conditions.

### Skills Tested

This challenge will test your understanding and skills in:

- Assembly language and binary analysis
- Static and dynamic analysis
- Reverse engineering techniques
- Obfuscation and anti-debugging methods
- Virtual machine analysis

---

## Getting Started

1. **Examine the Source Code**: Although `source.c` doesn’t contain the key or flag, it can give you insight into the structure of the program and where secrets might be hidden. The source is obfuscated, so be prepared to analyze complex code flows.

2. **Analyze the Binary**: Use tools like **Ghidra**, **IDA Pro**, or **Radare2** for static analysis. **GDB** or **x64dbg** can be used for dynamic analysis if needed.

3. **Identify Key Functions**: Look for functions that may contain encryption/decryption logic or flag verification mechanisms. Pay close attention to any routines that handle strings, check values, or perform calculations, as they could be related to revealing the flag.

4. **Bypass or Solve Checks**: The binary may have checks in place to prevent easy access to the flag. You may need to bypass these checks by:
   - Understanding the logic and supplying the correct inputs.
   - Patching or modifying the binary to circumvent certain restrictions.
   - Using a debugger to set breakpoints and observe the behavior of the program in real-time.

5. **Retrieve the Flag**: The goal is to retrieve and decrypt (if necessary) the flag hidden within the binary. Once obtained, the flag should be in the standard format, e.g., `flag{your_flag_here}`.

---

## Rules and Guidelines

- **No Brute Force**: This challenge is designed for reverse engineering, so brute-forcing inputs may lead to incorrect or unexpected results. Analyze the binary and find the logical solution.
- **Sharing and Editing**: Participants are encouraged to share solutions, hints, writeups, and even this CTF itself! Feel free to modify, improve, or adapt it as you like.

---

### License

This challenge is intended for educational purposes. Redistribution, modification, and use of this material are permitted and encouraged.
