/*
 * Copyright 2016 WebAssembly Community Group participants
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "option-parser.h"
#include "stream.h"
#include "writer.h"
#include "binary-reader.h"
#include "binary-reader-objdump.h"
#include "literal.h"
#include "vector.h"

#define PROGRAM_NAME "wasm2s"

#define NOPE HasArgument::No
#define YEP HasArgument::Yes

using namespace wabt;

namespace wabt {
  extern Result s_binary(const void* data,
                         size_t size,
                         BinaryReader* reader,
                         uint32_t num_function_passes,
                         const ReadBinaryOptions* options);
};

int main(int argc, char** argv) {
  init_stdio();

  void* void_data;
  size_t size;
  Result result = read_file(argv[1], &void_data, &size);
  if (WABT_FAILED(result))
    return result != Result::Ok;

  uint8_t* data = static_cast<uint8_t*>(void_data);

  BinaryReader reader;
  WABT_ZERO_MEMORY(reader);
  ReadBinaryOptions read_options = WABT_READ_BINARY_OPTIONS_DEFAULT;
  read_options.read_debug_names = true;
  return s_binary(data, size, &reader, 1, &read_options) != Result::Ok;
}
