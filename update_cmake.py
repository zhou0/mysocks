import sys
import re

with open("CMakeLists.txt", "r") as f:
    lines = f.readlines()

# 1. Update cmake_minimum_required
lines[0] = "cmake_minimum_required(VERSION 3.5)\n"

# 2. Remove macros use_c99 and use_c11 (lines 13-33)
del lines[12:33]

# 3. Add C standard settings after project(mysocks)
for i, line in enumerate(lines):
    if "project(mysocks)" in line:
        lines.insert(i + 1, "set(CMAKE_C_STANDARD 11)\nset(CMAKE_C_STANDARD_REQUIRED OFF)\n")
        break

# 4. Remove redundant include_directories call (lines 46-47 original, now shifted)
# We look for the one with the newline typo.
i = 0
while i < len(lines):
    if "include_directories" in lines[i] and "OpenSSL_1_1_0/in" in lines[i]:
        del lines[i:i+2]
        continue
    i += 1

# 5. Replace set_target_properties with target_compile_definitions
for i in range(len(lines)):
    if "set_target_properties" in lines[i] and "COMPILE_FLAGS" in lines[i]:
        m = re.search(r"set_target_properties\s*\(\s*([^ ]+)\s*PROPERTIES\s*COMPILE_FLAGS\s*\"-DWITH_([^\"]+)\"\s*\)", lines[i])
        if m:
            lines[i] = f"target_compile_definitions( {m.group(1)} PRIVATE WITH_{m.group(2)} )\n"

# 6. Remove manual compiler checks (at the end)
for i, line in enumerate(lines):
    if 'if("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")' in line:
        start_idx = i
        break
else:
    start_idx = -1

if start_idx != -1:
    # Find the corresponding endif()
    # Looking at the file, it ends before enable_testing()
    for j in range(start_idx, len(lines)):
        if "enable_testing()" in lines[j]:
            end_idx = j
            break
    else:
        end_idx = len(lines)
    del lines[start_idx:end_idx]

with open("CMakeLists.txt", "w") as f:
    f.writelines(lines)
