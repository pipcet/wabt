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

#include "binary-reader-objdump.h"

#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>

#include <vector>

#include "binary-reader-nop.h"
#include "literal.h"

namespace wabt {

namespace {

typedef std::vector<uint32_t> Uint32Vector;

class BinaryReaderObjdumpBase : public BinaryReaderNop {
 public:
  BinaryReaderObjdumpBase(const uint8_t* data,
                          size_t size,
                          ObjdumpOptions* options);

  virtual Result OnRelocCount(uint32_t count,
                              BinarySection section_code,
                              StringSlice section_name);
  virtual Result OnReloc(RelocType type,
                         uint32_t offset,
                         uint32_t index,
                         int32_t addend);

 protected:
  bool ShouldPrintDetails();
  void PrintDetails(const char* fmt, ...);

  ObjdumpOptions* options = nullptr;
  const uint8_t* data = nullptr;
  size_t size = 0;
  bool print_details = false;
  BinarySection reloc_section = BinarySection::Invalid;
  uint32_t section_starts[kBinarySectionCount];
};

BinaryReaderObjdumpBase::BinaryReaderObjdumpBase(const uint8_t* data,
                                                 size_t size,
                                                 ObjdumpOptions* options)
    : options(options), data(data), size(size) {
  WABT_ZERO_MEMORY(section_starts);
}

bool BinaryReaderObjdumpBase::ShouldPrintDetails() {
  if (options->mode != ObjdumpMode::Details)
    return false;
  return print_details;
}

void WABT_PRINTF_FORMAT(2, 3)
    BinaryReaderObjdumpBase::PrintDetails(const char* fmt, ...) {
  if (!ShouldPrintDetails())
    return;
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

Result BinaryReaderObjdumpBase::OnRelocCount(uint32_t count,
                                             BinarySection section_code,
                                             StringSlice section_name) {
  reloc_section = section_code;
  PrintDetails("  - section: %s\n", get_section_name(section_code));
  return Result::Ok;
}

Result BinaryReaderObjdumpBase::OnReloc(RelocType type,
                                        uint32_t offset,
                                        uint32_t index,
                                        int32_t addend) {
  uint32_t total_offset =
      section_starts[static_cast<size_t>(reloc_section)] + offset;
  PrintDetails("   - %-18s idx=%#-4x addend=%#-4x offset=%#x(file=%#x)\n",
               get_reloc_type_name(type), index, addend, offset, total_offset);
  return Result::Ok;
}

class BinaryReaderObjdumpPrepass : public BinaryReaderObjdumpBase {
 public:
  BinaryReaderObjdumpPrepass(const uint8_t* data,
                             size_t size,
                             ObjdumpOptions* options);

  virtual Result OnFunctionName(uint32_t function_index,
                                StringSlice function_name);
  virtual Result OnReloc(RelocType type,
                         uint32_t offset,
                         uint32_t index,
                         int32_t addend);
};

BinaryReaderObjdumpPrepass::BinaryReaderObjdumpPrepass(const uint8_t* data,
                                                       size_t size,
                                                       ObjdumpOptions* options)
    : BinaryReaderObjdumpBase(data, size, options) {}

Result BinaryReaderObjdumpPrepass::OnFunctionName(uint32_t index,
                                                  StringSlice name) {
  if (options->mode == ObjdumpMode::Prepass) {
    options->function_names.resize(index + 1);
    options->function_names[index] = string_slice_to_string(name);
  } else {
    PrintDetails(" - func[%d] " PRIstringslice "\n", index,
                 WABT_PRINTF_STRING_SLICE_ARG(name));
  }
  return Result::Ok;
}

Result BinaryReaderObjdumpPrepass::OnReloc(RelocType type,
                                           uint32_t offset,
                                           uint32_t index,
                                           int32_t addend) {
  BinaryReaderObjdumpBase::OnReloc(type, offset, index, addend);
  if (reloc_section == BinarySection::Code) {
    options->code_relocations.emplace_back(type, offset, index, addend);
  }
  return Result::Ok;
}

class BinaryReaderObjdump : public BinaryReaderObjdumpBase {
 public:
  BinaryReaderObjdump(const uint8_t* data,
                      size_t size,
                      ObjdumpOptions* options);

  virtual Result BeginModule(uint32_t version);
  virtual Result EndModule();

  virtual Result BeginSection(BinarySection section_type, uint32_t size);

  virtual Result BeginCustomSection(uint32_t size, StringSlice section_name);

  virtual Result OnTypeCount(uint32_t count);
  virtual Result OnType(uint32_t index,
                        uint32_t param_count,
                        Type* param_types,
                        uint32_t result_count,
                        Type* result_types);

  virtual Result OnImportCount(uint32_t count);
  virtual Result OnImportFunc(uint32_t import_index,
                              StringSlice module_name,
                              StringSlice field_name,
                              uint32_t func_index,
                              uint32_t sig_index);
  virtual Result OnImportTable(uint32_t import_index,
                               StringSlice module_name,
                               StringSlice field_name,
                               uint32_t table_index,
                               Type elem_type,
                               const Limits* elem_limits);
  virtual Result OnImportMemory(uint32_t import_index,
                                StringSlice module_name,
                                StringSlice field_name,
                                uint32_t memory_index,
                                const Limits* page_limits);
  virtual Result OnImportGlobal(uint32_t import_index,
                                StringSlice module_name,
                                StringSlice field_name,
                                uint32_t global_index,
                                Type type,
                                bool mutable_);

  virtual Result OnFunctionCount(uint32_t count);
  virtual Result OnFunction(uint32_t index, uint32_t sig_index);

  virtual Result OnTableCount(uint32_t count);
  virtual Result OnTable(uint32_t index,
                         Type elem_type,
                         const Limits* elem_limits);

  virtual Result OnMemoryCount(uint32_t count);
  virtual Result OnMemory(uint32_t index, const Limits* limits);

  virtual Result OnGlobalCount(uint32_t count);
  virtual Result BeginGlobal(uint32_t index, Type type, bool mutable_);

  virtual Result OnExportCount(uint32_t count);
  virtual Result OnExport(uint32_t index,
                          ExternalKind kind,
                          uint32_t item_index,
                          StringSlice name);

  virtual Result OnFunctionBodyCount(uint32_t count);
  virtual Result BeginFunctionBody(uint32_t index);

  virtual Result OnOpcode(Opcode Opcode);
  virtual Result OnOpcodeBare();
  virtual Result OnOpcodeUint32(uint32_t value);
  virtual Result OnOpcodeUint32Uint32(uint32_t value, uint32_t value2);
  virtual Result OnOpcodeUint64(uint64_t value);
  virtual Result OnOpcodeF32(uint32_t value);
  virtual Result OnOpcodeF64(uint64_t value);
  virtual Result OnOpcodeBlockSig(uint32_t num_types, Type* sig_types);

  virtual Result OnBrTableExpr(uint32_t num_targets,
                               uint32_t* target_depths,
                               uint32_t default_target_depth);
  virtual Result OnEndExpr();
  virtual Result OnEndFunc();

  virtual Result OnElemSegmentCount(uint32_t count);
  virtual Result BeginElemSegment(uint32_t index, uint32_t table_index);
  virtual Result OnElemSegmentFunctionIndex(uint32_t index,
                                            uint32_t func_index);

  virtual Result OnDataSegmentCount(uint32_t count);
  virtual Result BeginDataSegment(uint32_t index, uint32_t memory_index);
  virtual Result OnDataSegmentData(uint32_t index,
                                   const void* data,
                                   uint32_t size);

  virtual Result OnFunctionName(uint32_t function_index,
                                StringSlice function_name);
  virtual Result OnLocalName(uint32_t function_index,
                             uint32_t local_index,
                             StringSlice local_name);

  virtual Result OnInitExprF32ConstExpr(uint32_t index, uint32_t value);
  virtual Result OnInitExprF64ConstExpr(uint32_t index, uint64_t value);
  virtual Result OnInitExprGetGlobalExpr(uint32_t index, uint32_t global_index);
  virtual Result OnInitExprI32ConstExpr(uint32_t index, uint32_t value);
  virtual Result OnInitExprI64ConstExpr(uint32_t index, uint64_t value);

 private:
  Result OnCount(uint32_t count);
  void LogOpcode(const uint8_t* data, size_t data_size, const char* fmt, ...);

  Stream* out_stream = nullptr;
  Opcode current_opcode = Opcode::Unreachable;
  size_t current_opcode_offset = 0;
  size_t last_opcode_end = 0;
  int indent_level = 0;
  bool header_printed = false;
  int section_found = false;
  uint32_t next_reloc = 0;
};

BinaryReaderObjdump::BinaryReaderObjdump(const uint8_t* data,
                                         size_t size,
                                         ObjdumpOptions* options)
    : BinaryReaderObjdumpBase(data, size, options),
      out_stream(init_stdout_stream()) {}

Result BinaryReaderObjdump::BeginSection(BinarySection section_code,
                                         uint32_t size) {
  section_starts[static_cast<size_t>(section_code)] = state->offset;

  const char* name = get_section_name(section_code);

  bool section_match =
      !options->section_name || !strcasecmp(options->section_name, name);
  if (section_match)
    section_found = true;

  switch (options->mode) {
    case ObjdumpMode::Prepass:
      break;
    case ObjdumpMode::Headers:
      printf("%9s start=%#010" PRIzx " end=%#010" PRIzx " (size=%#010x) ", name,
             state->offset, state->offset + size, size);
      break;
    case ObjdumpMode::Details:
      if (section_match) {
        if (section_code != BinarySection::Code)
          printf("%s:\n", name);
        print_details = true;
      } else {
        print_details = false;
      }
      break;
    case ObjdumpMode::RawData:
      if (section_match) {
        printf("\nContents of section %s:\n", name);
        write_memory_dump(out_stream, data + state->offset, size, state->offset,
                          PrintChars::Yes, nullptr, nullptr);
      }
      break;
    case ObjdumpMode::Disassemble:
      break;
  }
  return Result::Ok;
}

Result BinaryReaderObjdump::BeginCustomSection(uint32_t size,
                                               StringSlice section_name) {
  PrintDetails(" - name: \"" PRIstringslice "\"\n",
               WABT_PRINTF_STRING_SLICE_ARG(section_name));
  if (options->mode == ObjdumpMode::Headers) {
    printf("\"" PRIstringslice "\"\n",
           WABT_PRINTF_STRING_SLICE_ARG(section_name));
  }
  return Result::Ok;
}

Result BinaryReaderObjdump::OnCount(uint32_t count) {
  if (options->mode == ObjdumpMode::Headers) {
    printf("count: %d\n", count);
  }
  return Result::Ok;
}

Result BinaryReaderObjdump::BeginModule(uint32_t version) {
  if (options->print_header) {
    const char* basename = strrchr(options->infile, '/');
    if (basename)
      basename++;
    else
      basename = options->infile;
    printf("%s:\tfile format wasm %#08x\n", basename, version);
    header_printed = true;
  }

  switch (options->mode) {
    case ObjdumpMode::Headers:
      printf("\n");
      printf("Sections:\n\n");
      break;
    case ObjdumpMode::Details:
      printf("\n");
      printf("Section Details:\n\n");
      break;
    case ObjdumpMode::Disassemble:
      printf("\n");
      printf("Code Disassembly:\n\n");
      break;
    case ObjdumpMode::RawData:
    case ObjdumpMode::Prepass:
      break;
  }

  return Result::Ok;
}

Result BinaryReaderObjdump::EndModule() {
  if (options->section_name) {
    if (!section_found) {
      printf("Section not found: %s\n", options->section_name);
      return Result::Error;
    }
  }

  return Result::Ok;
}

Result BinaryReaderObjdump::OnOpcode(Opcode opcode) {
  if (options->mode != ObjdumpMode::Disassemble)
    return Result::Ok;

  if (options->debug) {
    const char* opcode_name = get_opcode_name(opcode);
    printf("on_opcode: %#" PRIzx ": %s\n", state->offset, opcode_name);
  }

  if (last_opcode_end) {
    if (state->offset != last_opcode_end + 1) {
      uint8_t missing_opcode = data[last_opcode_end];
      const char* opcode_name =
          get_opcode_name(static_cast<Opcode>(missing_opcode));
      fprintf(stderr, "warning: %#" PRIzx " missing opcode callback at %#" PRIzx
                      " (%#02x=%s)\n",
              state->offset, last_opcode_end + 1, data[last_opcode_end],
              opcode_name);
      return Result::Error;
    }
  }

  current_opcode_offset = state->offset;
  current_opcode = opcode;
  return Result::Ok;
}

#define IMMEDIATE_OCTET_COUNT 9

void BinaryReaderObjdump::LogOpcode(const uint8_t* data,
                                    size_t data_size,
                                    const char* fmt,
                                    ...) {
  size_t offset = current_opcode_offset;

  // Print binary data
  printf(" %06" PRIzx ": %02x", offset - 1,
         static_cast<unsigned>(current_opcode));
  for (size_t i = 0; i < data_size && i < IMMEDIATE_OCTET_COUNT;
       i++, offset++) {
    printf(" %02x", data[offset]);
  }
  for (size_t i = data_size + 1; i < IMMEDIATE_OCTET_COUNT; i++) {
    printf("   ");
  }
  printf(" | ");

  // Print disassemble
  int indent_level = this->indent_level;
  if (current_opcode == Opcode::Else)
    indent_level--;
  for (int j = 0; j < indent_level; j++) {
    printf("  ");
  }

  const char* opcode_name = get_opcode_name(current_opcode);
  printf("%s", opcode_name);
  if (fmt) {
    printf(" ");
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
  }

  printf("\n");

  last_opcode_end = current_opcode_offset + data_size;

  if (options->relocs) {
    if (next_reloc < options->code_relocations.size()) {
      Reloc* reloc = &options->code_relocations[next_reloc];
      size_t code_start =
          section_starts[static_cast<size_t>(BinarySection::Code)];
      size_t abs_offset = code_start + reloc->offset;
      if (last_opcode_end > abs_offset) {
        if (reloc->type == RelocType::FuncIndexLEB) {
          if (reloc->index < options->function_names.size() &&
              !options->function_names[reloc->index].empty())
            printf("           %06" PRIzx ": %-18s func[%d] = <%s>", abs_offset,
                   get_reloc_type_name(reloc->type), reloc->index,
                   options->function_names[reloc->index].c_str());
          else
            printf("           %06" PRIzx ": %-18s %d", abs_offset,
                   get_reloc_type_name(reloc->type), reloc->index);
        } else
          printf("           %06" PRIzx ": %-18s %d", abs_offset,
                 get_reloc_type_name(reloc->type), reloc->index);
        switch (reloc->type) {
          case RelocType::MemoryAddressLEB:
          case RelocType::MemoryAddressSLEB:
          case RelocType::MemoryAddressI32:
            printf(" + %d", reloc->addend);
            break;
          default:
            break;
        }
        printf("\n");
        next_reloc++;
      }
    }
  }
}

Result BinaryReaderObjdump::OnOpcodeBare() {
  if (options->mode != ObjdumpMode::Disassemble)
    return Result::Ok;
  LogOpcode(data, 0, nullptr);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnOpcodeUint32(uint32_t value) {
  if (options->mode != ObjdumpMode::Disassemble)
    return Result::Ok;
  size_t immediate_len = state->offset - current_opcode_offset;
  LogOpcode(data, immediate_len, "%#x", value);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnOpcodeUint32Uint32(uint32_t value,
                                                 uint32_t value2) {
  if (options->mode != ObjdumpMode::Disassemble)
    return Result::Ok;
  size_t immediate_len = state->offset - current_opcode_offset;
  LogOpcode(data, immediate_len, "%lu %lu", value, value2);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnOpcodeUint64(uint64_t value) {
  if (options->mode != ObjdumpMode::Disassemble)
    return Result::Ok;
  size_t immediate_len = state->offset - current_opcode_offset;
  LogOpcode(data, immediate_len, "%d", value);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnOpcodeF32(uint32_t value) {
  if (options->mode != ObjdumpMode::Disassemble)
    return Result::Ok;
  size_t immediate_len = state->offset - current_opcode_offset;
  char buffer[WABT_MAX_FLOAT_HEX];
  write_float_hex(buffer, sizeof(buffer), value);
  LogOpcode(data, immediate_len, buffer);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnOpcodeF64(uint64_t value) {
  if (options->mode != ObjdumpMode::Disassemble)
    return Result::Ok;
  size_t immediate_len = state->offset - current_opcode_offset;
  char buffer[WABT_MAX_DOUBLE_HEX];
  write_double_hex(buffer, sizeof(buffer), value);
  LogOpcode(data, immediate_len, buffer);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnBrTableExpr(uint32_t num_targets,
                                          uint32_t* target_depths,
                                          uint32_t default_target_depth) {
  if (options->mode != ObjdumpMode::Disassemble)
    return Result::Ok;
  size_t immediate_len = state->offset - current_opcode_offset;
  /* TODO(sbc): Print targets */
  LogOpcode(data, immediate_len, nullptr);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnEndFunc() {
  if (options->mode != ObjdumpMode::Disassemble)
    return Result::Ok;
  LogOpcode(nullptr, 0, nullptr);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnEndExpr() {
  if (options->mode != ObjdumpMode::Disassemble)
    return Result::Ok;
  indent_level--;
  assert(indent_level >= 0);
  LogOpcode(nullptr, 0, nullptr);
  return Result::Ok;
}

const char* type_name(Type type) {
  switch (type) {
    case Type::I32:
      return "i32";

    case Type::I64:
      return "i64";

    case Type::F32:
      return "f32";

    case Type::F64:
      return "f64";

    default:
      assert(0);
      return "INVALID TYPE";
  }
}

Result BinaryReaderObjdump::OnOpcodeBlockSig(uint32_t num_types,
                                             Type* sig_types) {
  if (num_types)
    LogOpcode(data, 1, "%s", type_name(*sig_types));
  else
    LogOpcode(data, 1, nullptr);
  indent_level++;
  return Result::Ok;
}

Result BinaryReaderObjdump::OnTypeCount(uint32_t count) {
  return OnCount(count);
}

Result BinaryReaderObjdump::OnType(uint32_t index,
                                   uint32_t param_count,
                                   Type* param_types,
                                   uint32_t result_count,
                                   Type* result_types) {
  if (!ShouldPrintDetails())
    return Result::Ok;
  printf(" - [%d] (", index);
  for (uint32_t i = 0; i < param_count; i++) {
    if (i != 0) {
      printf(", ");
    }
    printf("%s", type_name(param_types[i]));
  }
  printf(") -> ");
  if (result_count)
    printf("%s", type_name(result_types[0]));
  else
    printf("nil");
  printf("\n");
  return Result::Ok;
}

Result BinaryReaderObjdump::OnFunctionCount(uint32_t count) {
  return OnCount(count);
}

Result BinaryReaderObjdump::OnFunction(uint32_t index, uint32_t sig_index) {
  PrintDetails(" - func[%d] sig=%d\n", index, sig_index);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnFunctionBodyCount(uint32_t count) {
  return OnCount(count);
}

Result BinaryReaderObjdump::BeginFunctionBody(uint32_t index) {
  if (options->mode == ObjdumpMode::Disassemble) {
    if (index < options->function_names.size() &&
        !options->function_names[index].empty())
      printf("%06" PRIzx " <%s> = func[%d]:\n", state->offset,
             options->function_names[index].c_str(), index);
    else
      printf("%06" PRIzx " func[%d]:\n", state->offset, index);
  }

  last_opcode_end = 0;
  return Result::Ok;
}

Result BinaryReaderObjdump::OnImportCount(uint32_t count) {
  return OnCount(count);
}

Result BinaryReaderObjdump::OnImportFunc(uint32_t import_index,
                                         StringSlice module_name,
                                         StringSlice field_name,
                                         uint32_t func_index,
                                         uint32_t sig_index) {
  PrintDetails(" - func[%d] sig=%d <- " PRIstringslice "." PRIstringslice "\n",
               func_index, sig_index, WABT_PRINTF_STRING_SLICE_ARG(module_name),
               WABT_PRINTF_STRING_SLICE_ARG(field_name));
  return Result::Ok;
}

Result BinaryReaderObjdump::OnImportTable(uint32_t import_index,
                                          StringSlice module_name,
                                          StringSlice field_name,
                                          uint32_t table_index,
                                          Type elem_type,
                                          const Limits* elem_limits) {
  PrintDetails(" - " PRIstringslice "." PRIstringslice
               " -> table elem_type=%s init=%" PRId64 " max=%" PRId64 "\n",
               WABT_PRINTF_STRING_SLICE_ARG(module_name),
               WABT_PRINTF_STRING_SLICE_ARG(field_name),
               get_type_name(elem_type), elem_limits->initial,
               elem_limits->max);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnImportMemory(uint32_t import_index,
                                           StringSlice module_name,
                                           StringSlice field_name,
                                           uint32_t memory_index,
                                           const Limits* page_limits) {
  PrintDetails(" - " PRIstringslice "." PRIstringslice " -> memory\n",
               WABT_PRINTF_STRING_SLICE_ARG(module_name),
               WABT_PRINTF_STRING_SLICE_ARG(field_name));
  return Result::Ok;
}

Result BinaryReaderObjdump::OnImportGlobal(uint32_t import_index,
                                           StringSlice module_name,
                                           StringSlice field_name,
                                           uint32_t global_index,
                                           Type type,
                                           bool mutable_) {
  PrintDetails(" - global[%d] %s mutable=%d <- " PRIstringslice
               "." PRIstringslice "\n",
               global_index, get_type_name(type), mutable_,
               WABT_PRINTF_STRING_SLICE_ARG(module_name),
               WABT_PRINTF_STRING_SLICE_ARG(field_name));
  return Result::Ok;
}

Result BinaryReaderObjdump::OnMemoryCount(uint32_t count) {
  return OnCount(count);
}

Result BinaryReaderObjdump::OnMemory(uint32_t index,
                                     const Limits* page_limits) {
  PrintDetails(" - memory[%d] pages: initial=%" PRId64, index,
               page_limits->initial);
  if (page_limits->has_max)
    PrintDetails(" max=%" PRId64, page_limits->max);
  PrintDetails("\n");
  return Result::Ok;
}

Result BinaryReaderObjdump::OnTableCount(uint32_t count) {
  return OnCount(count);
}

Result BinaryReaderObjdump::OnTable(uint32_t index,
                                    Type elem_type,
                                    const Limits* elem_limits) {
  PrintDetails(" - table[%d] type=%s initial=%" PRId64, index,
               get_type_name(elem_type), elem_limits->initial);
  if (elem_limits->has_max)
    PrintDetails(" max=%" PRId64, elem_limits->max);
  PrintDetails("\n");
  return Result::Ok;
}

Result BinaryReaderObjdump::OnExportCount(uint32_t count) {
  return OnCount(count);
}

Result BinaryReaderObjdump::OnExport(uint32_t index,
                                     ExternalKind kind,
                                     uint32_t item_index,
                                     StringSlice name) {
  PrintDetails(" - %s[%d] ", get_kind_name(kind), item_index);
  PrintDetails(PRIstringslice, WABT_PRINTF_STRING_SLICE_ARG(name));
  PrintDetails("\n");
  return Result::Ok;
}

Result BinaryReaderObjdump::OnElemSegmentFunctionIndex(uint32_t index,
                                                       uint32_t func_index) {
  PrintDetails("  - func[%d]\n", func_index);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnElemSegmentCount(uint32_t count) {
  return OnCount(count);
}

Result BinaryReaderObjdump::BeginElemSegment(uint32_t index,
                                             uint32_t table_index) {
  PrintDetails(" - segment[%d] table=%d\n", index, table_index);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnGlobalCount(uint32_t count) {
  return OnCount(count);
}

Result BinaryReaderObjdump::BeginGlobal(uint32_t index,
                                        Type type,
                                        bool mutable_) {
  PrintDetails(" - global[%d] %s mutable=%d", index, get_type_name(type),
               mutable_);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnInitExprF32ConstExpr(uint32_t index,
                                                   uint32_t value) {
  char buffer[WABT_MAX_FLOAT_HEX];
  write_float_hex(buffer, sizeof(buffer), value);
  PrintDetails(" - init f32=%s\n", buffer);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnInitExprF64ConstExpr(uint32_t index,
                                                   uint64_t value) {
  char buffer[WABT_MAX_DOUBLE_HEX];
  write_float_hex(buffer, sizeof(buffer), value);
  PrintDetails(" - init f64=%s\n", buffer);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnInitExprGetGlobalExpr(uint32_t index,
                                                    uint32_t global_index) {
  PrintDetails(" - init global=%d\n", global_index);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnInitExprI32ConstExpr(uint32_t index,
                                                   uint32_t value) {
  PrintDetails(" - init i32=%d\n", value);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnInitExprI64ConstExpr(uint32_t index,
                                                   uint64_t value) {
  PrintDetails(" - init i64=%" PRId64 "\n", value);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnFunctionName(uint32_t index, StringSlice name) {
  PrintDetails(" - func[%d] " PRIstringslice "\n", index,
               WABT_PRINTF_STRING_SLICE_ARG(name));
  return Result::Ok;
}

Result BinaryReaderObjdump::OnLocalName(uint32_t func_index,
                                        uint32_t local_index,
                                        StringSlice name) {
  if (name.length) {
    PrintDetails(" - func[%d] local[%d] " PRIstringslice "\n", func_index,
                 local_index, WABT_PRINTF_STRING_SLICE_ARG(name));
  }
  return Result::Ok;
}

Result BinaryReaderObjdump::OnDataSegmentCount(uint32_t count) {
  return OnCount(count);
}

Result BinaryReaderObjdump::BeginDataSegment(uint32_t index,
                                             uint32_t memory_index) {
  PrintDetails(" - memory[%d]", memory_index);
  return Result::Ok;
}

Result BinaryReaderObjdump::OnDataSegmentData(uint32_t index,
                                              const void* src_data,
                                              uint32_t size) {
  if (ShouldPrintDetails()) {
    write_memory_dump(out_stream, src_data, size, 0, PrintChars::Yes, "  - ",
                      nullptr);
  }
  return Result::Ok;
}

}  // namespace

Result read_binary_objdump(const uint8_t* data,
                           size_t size,
                           ObjdumpOptions* options) {
  ReadBinaryOptions read_options = WABT_READ_BINARY_OPTIONS_DEFAULT;
  read_options.read_debug_names = true;
  read_options.log_stream = options->log_stream;

  if (options->mode == ObjdumpMode::Prepass) {
    BinaryReaderObjdumpPrepass reader(data, size, options);
    return read_binary(data, size, &reader, &read_options);
  } else {
    BinaryReaderObjdump reader(data, size, options);
    return read_binary(data, size, &reader, &read_options);
  }
}

}  // namespace wabt
