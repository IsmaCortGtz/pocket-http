#!/usr/bin/env python3

import os
import re
from pathlib import Path


# ======== CONFIGURATION ========

output_header = os.path.join("dist", "pockethttp.hpp")
output_cpp = os.path.join("dist", "pockethttp.cpp")

main_header = os.path.join("include", "pockethttp", "pockethttp.hpp")

include_regex = re.compile(r'^\s*#\s*include\s*"(.+?)"')


# ======== SCRIPT ========


headers = []


def extract_include(line):
  match = include_regex.match(line)
  if match:
    return match.group(1).replace(".hpp", "")
  return None


def list_files():
  headers = []
  with open(main_header, "r") as f:
    for line in f:
      file_path = extract_include(line)
      if file_path:
        headers.append(file_path)
  return headers


def process_file(file_path):
  new_lines = []
  with open(file_path, "r") as f:
    for line in f:
      include = extract_include(line)
      if include:
        if include in headers:
          new_lines.append(f'// #include "{include}.hpp"\n')
        else:
          new_lines.extend(process_file(os.path.join("include", include + ".hpp")))
      else:
        new_lines.append(line)
  return new_lines


def generate_header():
  merged_header = "// Auto-generated merged header" + os.linesep + os.linesep
  
  for header in headers:
    res = process_file(os.path.join("include", header + ".hpp"))
    merged_header += "// " + header + ".hpp" + os.linesep + "".join(res) + os.linesep + os.linesep

  file_path = Path(output_header)
  file_path.parent.mkdir(parents=True, exist_ok=True)
  with open(output_header, "w") as f:
    f.write(merged_header)


def generate_cpp():
  merged_cpp = "// Auto-generated merged cpp" + os.linesep
  merged_cpp += f'#include "{os.path.basename(output_header)}"' + os.linesep + os.linesep
  
  for header in headers:
    if not os.path.exists(os.path.join(header.replace("pockethttp", "src", 1) + ".cpp")):
      continue

    res = process_file(os.path.join(header.replace("pockethttp", "src", 1) + ".cpp"))
    merged_cpp += "// " + header + ".cpp" + os.linesep + "".join(res) + os.linesep + os.linesep

  file_path = Path(output_cpp)
  file_path.parent.mkdir(parents=True, exist_ok=True)
  with open(output_cpp, "w") as f:
    f.write(merged_cpp)


headers = list_files()
generate_header()
generate_cpp()


# ========================