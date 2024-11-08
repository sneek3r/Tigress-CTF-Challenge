# Reverse Engineering Challenge: **sneekers l33t VM**

Can't be bothered to do a full README so Enjoy ChatGPT's README :)

Welcome to the **sneekers l33t VM** reverse engineering challenge! In this CTF, you'll be tasked with analyzing a binary file to uncover hidden secrets.

---

## Challenge Overview

### Files Provided

- **`challenge`** - The compiled binary you’ll be analyzing.
- **`source.c`** - The source code used to generate the binary, though it does not contain the actual keys or encrypted flag.

The objective of this challenge is to reverse engineer the binary and determine the correct sequence or inputs needed to reveal the hidden flag.

### Objective

Using static and dynamic analysis tools, reverse engineer the binary to extract the encrypted flag. The binary may employ a range of obfuscation techniques, and the flag might be revealed only after satisfying specific conditions.

### Skills Tested

This challenge will test your understanding and skills in:

- Assembly language and binary analysis
- Static and dynamic analysis
- Reverse engineering techniques
- Obfuscation and anti-debugging methods

---

## Getting Started

1. **Examine the Source Code**: Although `source.c` doesn’t contain the key or flag, it can give you insight into the structure of the program and where secrets might be hidden.
  
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
- **No Sharing Solutions**: This is a solo challenge, so please do not share solutions or hints with other participants.
- **Respect the Tools**: Use appropriate reverse engineering tools and refrain from automated or aggressive methods that may hinder your progress.

---

## Recommended Tools

- **Ghidra**, **IDA Pro**, **Radare2** - for static analysis and decompilation.
- **GDB**, **x64dbg** - for dynamic analysis and debugging.
- **objdump**, **strings**, **objcopy** - for initial exploration and binary inspection.
- **Hex Editor** - for manual analysis and patching if necessary.

---

## Hints

1. **Understand the Obfuscation**: The binary might use simple or complex obfuscation techniques. Analyzing control flow and identifying unusual patterns in the assembly could help.
2. **Look for Hidden Data**: Important information might be hidden within sections of the binary, such as `.rodata`, or it could be generated at runtime.
3. **Pay Attention to Conditionals**: Specific branches or conditions may need to be met to reveal the flag. Look for conditional jumps and logical comparisons in the assembly.

---

## Submission

Submit the flag once you've retrieved it. The format for the flag will be `flag{your_flag_here}`.

Good luck, and happy reversing!

---

### License

This challenge is intended solely for educational purposes. Unauthorized redistribution or use of this material outside the CTF is prohibited.
