/* Test with:

while true; do rm -rf build/common/wabt* src/wabt* && make build/common/wabt.make && ./common/bin/wasm2s ./libc.wasm > libc.wasm.s && ./wasm32-virtual-wasm32/bin/wasm32-virtual-wasm32-gcc -nostdlib -shared -o libc.wasm.s.o libc.wasm.s && ./bin/wasmify-wasm32 libc.wasm.s.o > libc.wasm.s.o.wasm && ./common/bin/wasmdump -d libc.wasm > libc.wasm.wast && ./common/bin/wasmdump -d libc.wasm.s.o.wasm > libc.wasm.s.o.wasm.wast && (diff -u libc.wasm.wast libc.wasm.s.o.wasm.wast | head -1000) && sleep 1m; done

 */

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

#include "binary-reader.h"

#include <float.h>
#include <assert.h>
#include <inttypes.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "binary.h"
#include "config.h"
#include "stream.h"
#include "vector.h"

#if HAVE_ALLOCA
#include <alloca.h>
#endif

namespace wabt {

typedef uint32_t Uint32;
WABT_DEFINE_VECTOR(type, Type)
WABT_DEFINE_VECTOR(uint32, Uint32);
WABT_DEFINE_VECTOR(string_slice, StringSlice);
WABT_DEFINE_VECTOR(ssvec, StringSliceVector);

struct Context {
  const uint8_t* data;
  size_t data_size;
  size_t offset;
  size_t read_end; /* Either the section end or data_size. */
  BinaryReaderContext user_ctx;
  BinaryReader* reader;
  jmp_buf error_jmp_buf;
  TypeVector param_types;
  Uint32Vector target_depths;
  const ReadBinaryOptions* options;
  BinarySection last_known_section;
  uint32_t num_signatures;
  uint32_t num_imports;
  uint32_t num_func_imports;
  uint32_t num_table_imports;
  uint32_t num_memory_imports;
  uint32_t num_global_imports;
  uint32_t num_function_signatures;
  uint32_t num_tables;
  uint32_t num_memories;
  uint32_t num_globals;
  uint32_t num_exports;
  uint32_t num_function_bodies;
};

struct LoggingContext {
  Stream* stream;
  BinaryReader* reader;
  int indent;
};

static void s_on_error(BinaryReaderContext* ctx, const char* message)
{
  fprintf(stderr, "%s\n", message);
  abort();
}

struct QuotedStringSlice : StringSlice {
};

struct TypeChar {
  const Type t;
  TypeChar(const Type t)
    : t(t) {}
  operator Type()
  {
    return t;
  }
};

struct Signature {
  uint32_t num_args;
  const Type* args;
  uint32_t num_results;
  const Type* results;

  Signature(uint32_t num_args, const Type* args,
            uint32_t num_results, const Type* results)
    : num_args(num_args), args(args), num_results(num_results), results(results)
    {}
};

struct OOLComment {
  size_t offset;
  virtual void print(FILE* f) = 0;
};

struct OOLC {
  OOLComment* comment;
  OOLC(OOLComment* comment)
    : comment(comment) {}
};

struct OOLLocalComment : OOLComment {
  uint32_t function_index;
  uint32_t local_index;

  OOLLocalComment(uint32_t function_index, uint32_t local_index)
    : function_index(function_index), local_index(local_index)
    {}

  virtual void print(FILE* f) override;
};

StringSliceVector gFunctionNames;
StringSliceVector gGlobalNames;
StringSliceVector gTableNames;
StringSliceVector gMemoryNames;
StringSliceVector gSignatureNames;
StringSliceVectorVector gBlockNames;
StringSliceVectorVector gLocalNames;

void OOLLocalComment::print(FILE* f)
{
  if (gLocalNames.size > function_index) {
    StringSliceVector* v = &gLocalNames.data[function_index];
    if (v->size > local_index) {
      fprintf(f, "# " PRIstringslice "\n", WABT_PRINTF_STRING_SLICE_ARG(v->data[local_index]));
      return;
    }
  }

  fprintf(f, "# local[%u]\n", local_index);
}

struct OOLFunctionComment : OOLComment {
  uint32_t function_index;

  OOLFunctionComment(uint32_t function_index)
    : function_index(function_index)
    {}

  virtual void print(FILE* f) override;
};

void OOLFunctionComment::print(FILE* f)
{
  if (gFunctionNames.size > function_index)
    fprintf(f, "# " PRIstringslice "\n", WABT_PRINTF_STRING_SLICE_ARG(gFunctionNames.data[function_index]));
  else
    fprintf(f, "# func[%u]\n", function_index);
}

struct OOLGlobalComment : OOLComment {
  uint32_t global_index;

  OOLGlobalComment(uint32_t global_index)
    : global_index(global_index)
    {}

  virtual void print(FILE* f) override;
};

void OOLGlobalComment::print(FILE* f)
{
  if (gGlobalNames.size > global_index)
    fprintf(f, "# " PRIstringslice "\n", WABT_PRINTF_STRING_SLICE_ARG(gGlobalNames.data[global_index]));
  else
    fprintf(f, "# global[%u]\n", global_index);
}

struct OOLTableComment : OOLComment {
  uint32_t table_index;

  OOLTableComment(uint32_t table_index)
    : table_index(table_index)
    {}

  virtual void print(FILE* f) override;
};

void OOLTableComment::print(FILE* f)
{
  if (gTableNames.size > table_index)
    fprintf(f, "# " PRIstringslice "\n", WABT_PRINTF_STRING_SLICE_ARG(gTableNames.data[table_index]));
  else
    fprintf(f, "# table[%u]\n", table_index);
}

struct OOLSignatureComment : OOLComment {
  uint32_t sig_index;

  OOLSignatureComment(uint32_t sig_index)
    : sig_index(sig_index)
    {}

  virtual void print(FILE* f) override;
};

void OOLSignatureComment::print(FILE* f)
{
  if (gSignatureNames.size > sig_index)
    fprintf(f, "# " PRIstringslice "\n", WABT_PRINTF_STRING_SLICE_ARG(gSignatureNames.data[sig_index]));
  else
    fprintf(f, "# sig[%u]\n", sig_index);
}

struct OOLMemoryComment : OOLComment {
  uint32_t memory_index;

  OOLMemoryComment(uint32_t memory_index)
    : memory_index(memory_index)
    {}

  virtual void print(FILE* f) override;
};

struct OOLAddressComment : OOLComment {
  uint32_t address;

  OOLAddressComment(uint32_t address)
    : address(address)
    {}

  virtual void print(FILE* f) override;
};

struct OOLBlockComment : OOLComment {
  uint32_t depth;

  OOLBlockComment(uint32_t depth)
    : depth(depth)
    {}

  virtual void print(FILE* f) override;
};

WABT_DEFINE_VECTOR(oolc, OOLC);

struct SContext {
public:
  template<typename A, typename... As>
  void
  print(A arg, As... args) {
    print(arg);
    print(args...);
  }

  void print() {}

  void print(StringSlice slice);
  void print(QuotedStringSlice slice);
  void print(Signature sig);
  void print(Opcode opcode);
  void print(float f);
  void print(double d);
  void print(int32_t i32);
  void print(int64_t i64);
  void print(unsigned int);
  void print(unsigned long);
  void print(const Limits*);
  void print(const TypeChar);
  void print(const Type);
  void print(const char*);
  void print(OOLComment*);
  void print(OOLFunctionComment*);
  void print(OOLLocalComment*);
  void print(OOLBlockComment*);
  void print(OOLAddressComment*);
  void print(OOLGlobalComment*);
  void print(OOLTableComment*);
  void print(OOLMemoryComment*);
  void print(OOLSignatureComment*);

  template<typename... As>
  void
  printf(As... args) {
    fprintf(f, args...);
  }

  void printf32(const char* format, int, float);
  void printf64(const char* format, int, double);
  void printi32(const char* format, int);
  void printi64(const char* format, long long);
  void prints(const char* format, int, const char*);
  FILE *f;
  OOLCVector comments;
  uint32_t function_index;
  uint32_t depth;
};

void SContext::print(Opcode opcode)
{
  const char* s = get_opcode_name(opcode);

  if (!s)
    abort();

  while (*s) {
    printf("%c", (*s == '/') ? '_' : *s);
    s++;
  }
}

void SContext::print(Signature sig)
{
  print("F");
  for (uint32_t i = 0; i < sig.num_args; i++)
    print(TypeChar(sig.args[i]));
  for (uint32_t i = 0; i < sig.num_results; i++)
    print(TypeChar(sig.results[i]));
  print("E");
}

void SContext::print(StringSlice slice)
{
  printf(PRIstringslice, WABT_PRINTF_STRING_SLICE_ARG(slice));
}

void SContext::print(QuotedStringSlice slice)
{
  printf("\"" PRIstringslice "\"", WABT_PRINTF_STRING_SLICE_ARG(slice));
}

void SContext::print(int32_t x)
{
  fprintf(f, "%d", x);
}

void SContext::print(int64_t x)
{
  fprintf(f, "%lld", static_cast<long long>(x));
}

void SContext::print(float x)
{
  fprintf(f, "%.*g", DECIMAL_DIG, x);
}

void SContext::print(double x)
{
  fprintf(f, "%.*g", DECIMAL_DIG, x);
}

void SContext::print(const Limits* limits)
{
  uint32_t flags = 0;
  if (limits->has_max)
    flags |= WABT_BINARY_LIMITS_HAS_MAX_FLAG;

  print("\t", "rleb128_32 ", flags, "\n");
  print("\t", "rleb128_32 ", limits->initial, "\n");
  if (limits->has_max) {
    print("\t", "rleb128_32 ", limits->max, "\n");
  }
}

void SContext::print(Type t)
{
  switch (t) {
  case Type::I32:
    print("\t", ".byte ", 0x7f, " # i32", "\n"); break;
  case Type::I64:
    print("\t", ".byte ", 0x7e, " # i64", "\n"); break;
  case Type::F32:
    print("\t", ".byte ", 0x7d, " # f32", "\n"); break;
  case Type::F64:
    print("\t", ".byte ", 0x7c, " # f64", "\n"); break;
  case Type::Anyfunc:
    print("\t", ".byte ", 0x70, " # anyfunc", "\n"); break;
  default:
    abort();
  }
}

void SContext::print(TypeChar t)
{
  switch (t) {
  case Type::I32:
    print("i"); break;
  case Type::I64:
    print("l"); break;
  case Type::F32:
    print("f"); break;
  case Type::F64:
    print("d"); break;
  default:
    abort();
  }
}

void SContext::print(unsigned int i)
{
  printf("%u", i);
}

void SContext::print(unsigned long i)
{
  printf("%u", i);
}

void SContext::print(const char* s)
{
  printf("%s", s);
}

void SContext::print(OOLComment* comment)
{
  comment->offset = ftell(f);
  OOLC oolc = OOLC(comment);
  append_oolc_value(&comments, &oolc);
}

void SContext::print(OOLFunctionComment* comment)
{
  comment->offset = ftell(f);
  OOLC oolc = OOLC(comment);
  append_oolc_value(&comments, &oolc);
}

void SContext::print(OOLBlockComment* comment)
{
  comment->offset = ftell(f);
  OOLC oolc = OOLC(comment);
  append_oolc_value(&comments, &oolc);
}

void SContext::print(OOLLocalComment* comment)
{
  comment->offset = ftell(f);
  OOLC oolc = OOLC(comment);
  append_oolc_value(&comments, &oolc);
}

void SContext::print(OOLGlobalComment* comment)
{
  comment->offset = ftell(f);
  OOLC oolc = OOLC(comment);
  append_oolc_value(&comments, &oolc);
}

void SContext::print(OOLMemoryComment* comment)
{
  comment->offset = ftell(f);
  OOLC oolc = OOLC(comment);
  append_oolc_value(&comments, &oolc);
}

void SContext::print(OOLTableComment* comment)
{
  comment->offset = ftell(f);
  OOLC oolc = OOLC(comment);
  append_oolc_value(&comments, &oolc);
}

void SContext::print(OOLSignatureComment* comment)
{
  comment->offset = ftell(f);
  OOLC oolc = OOLC(comment);
  append_oolc_value(&comments, &oolc);
}

static Result s_begin_custom_section(BinaryReaderContext* ctx,
                                     uint32_t size,
                                     StringSlice section_name)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->print("\t", "section ");
  sctx->print(section_name, "\n");

  return Result::Ok;
}

static Result s_begin_module(uint32_t value, void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "# module (", value, ")", "\n");
  sctx->print("\t", ".include \"wasm32-macros.s\"", "\n");
  sctx->print("\t", ".include \"wasm32-header-macros.s\"", "\n");

  return Result::Ok;
}

static Result s_begin_signature_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->print("\t", "section_id type 1", "\n");

  return Result::Ok;
}

static Result s_on_signature(uint32_t index,
                             uint32_t param_count,
                             Type* param_types,
                             uint32_t result_count,
                             Type* result_types,
                             void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);


  sctx->print("\t", ".pushsection .wasm.chars.type", "\n");
  sctx->print("__s_type_", index, ":", "\n");
  sctx->print("\t", ".byte 0", "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  sctx->print("\t", ".pushsection .wasm.payload.type", "\n");
  sctx->print("\t", "signature ");
  sctx->print(Signature(param_count, param_types, result_count, result_types));
  sctx->print("\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  {
    char* buf = new char[3 + param_count + result_count];
    char* p = buf;
    *p++ = 'F';
    for (uint32_t i = 0; i < param_count; i++)
      switch(param_types[i]) {
      case Type::I32:
        *p++ = 'i'; break;
      case Type::F32:
        *p++ = 'l'; break;
      case Type::I64:
        *p++ = 'f'; break;
      case Type::F64:
        *p++ = 'd'; break;
      default:
        *p++ = '?'; break;
      }
    if (result_count)
      for (uint32_t i = 0; i < result_count; i++)
        switch(result_types[i]) {
        case Type::I32:
          *p++ = 'i'; break;
        case Type::F32:
          *p++ = 'l'; break;
        case Type::I64:
          *p++ = 'f'; break;
        case Type::F64:
          *p++ = 'd'; break;
        default:
          *p++ = '?'; break;
        }
    else
      *p++ = 'v';
    *p++ = 'E';
    *p++ = 0;

    StringSlice slice = string_slice_from_cstr(buf);
    append_string_slice_value(&gSignatureNames, &slice);
  }

  return Result::Ok;
}

static Result s_begin_import_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->print("\t", "section_id import 2", "\n");

  return Result::Ok;
}

static bool in_hidden_global_hack = false;

static Result s_on_import(uint32_t index,
                          StringSlice module_name,
                          StringSlice field_name,
                          void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  if (string_slice_eq_cstr(&module_name, "sys") &&
      (string_slice_eq_cstr(&field_name, "got") ||
       string_slice_eq_cstr(&field_name, "gpo") ||
       string_slice_eq_cstr(&field_name, "plt") ||
       string_slice_eq_cstr(&field_name, "table") ||
       string_slice_eq_cstr(&field_name, "memory"))) {
    sctx->print("\t", ".if 0", "\n");
    in_hidden_global_hack = true;
  } else {
    in_hidden_global_hack = false;
  }

  sctx->print("\t", ".pushsection .wasm.chars.import", "\n");
  sctx->print("__s_import_", index, ":", "\n");
  sctx->print("\t", ".byte 0", "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  sctx->print("\t", ".pushsection .wasm.payload.import", "\n");
  sctx->print("\t", "lstring ");
  sctx->print(module_name);
  sctx->print("\n");
  sctx->print("\t", "lstring ");
  sctx->print(field_name);
  sctx->print("\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("", "\n");

  return Result::Ok;
}

static Result s_on_import_func(uint32_t index,
                               uint32_t function_index,
                               uint32_t sig_index,
                               StringSlice module_name,
                               StringSlice field_name,
                               void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", ".pushsection .wasm.chars.function_index.import", "\n");
  sctx->print("__s_func_", function_index, ":", "\n");
  sctx->print("\t", ".byte 0", "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  sctx->print("\t", ".pushsection .wasm.payload.import", "\n");
  sctx->print("\t", ".byte 0 # function", "\n");
  sctx->print("\t", "rleb128_32 __s_type_", sig_index, "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  if (in_hidden_global_hack) {
    sctx->print("\t", ".endif", "\n");
  }

  return Result::Ok;
}

static Result s_on_import_table(uint32_t index,
                                uint32_t table_index,
                                Type elem_type,
                                const Limits* elem_limits,
                                StringSlice module_name,
                                StringSlice field_name,
                                void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", ".pushsection .wasm.chars.table_index.import", "\n");
  sctx->print("__s_table_", table_index, ":", "\n");
  sctx->print("\t", ".byte 0", "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  sctx->print("\t", ".pushsection .wasm.payload.import", "\n");
  sctx->print("\t", ".byte 1 # table", "\n");
  sctx->print(elem_type);
  sctx->print(elem_limits);
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  if (in_hidden_global_hack) {
    sctx->print("\t", ".endif", "\n");
  }

  return Result::Ok;
}

static Result s_on_import_memory(uint32_t index,
                                 uint32_t memory_index,
                                 const Limits* page_limits,
                                 StringSlice module_name,
                                 StringSlice field_name,
                                 void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", ".pushsection .wasm.chars.memory_index.import", "\n");
  sctx->print("__s_memory_", memory_index, ":", "\n");
  sctx->print("\t", ".byte 0", "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  sctx->print("\t", ".pushsection .wasm.payload.import", "\n");
  sctx->print("\t", ".byte 2 # memory", "\n");
  sctx->print(page_limits);
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  if (in_hidden_global_hack) {
    sctx->print("\t", ".endif", "\n");
  }

  return Result::Ok;
}

static Result s_on_import_global(uint32_t index,
                                 uint32_t global_index,
                                 Type type,
                                 bool mutable_,
                                 StringSlice module_name,
                                 StringSlice field_name,
                                 void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", ".pushsection .wasm.chars.global_index.import", "\n");
  sctx->print("__s_global_", global_index, ":", "\n");
  sctx->print("\t", ".byte 0", "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  sctx->print("\t", ".pushsection .wasm.payload.import", "\n");
  sctx->print("\t", ".byte 3 # global", "\n");
  sctx->print(type);
  sctx->print("\t", ".byte ", (mutable_ ? 1 : 0), " # mutable", "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  if (in_hidden_global_hack) {
    sctx->print("\t", ".endif", "\n");
  }

  return Result::Ok;
}


static Result s_end_import_section(BinaryReaderContext* ctx) {
  return Result::Ok;
}

static Result s_on_table(uint32_t index,
                         Type elem_type,
                         const Limits* elem_limits,
                         void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", ".pushsection .wasm.chars.table_index", "\n");
  sctx->print("__s_table_", index, ":", "\n");
  sctx->print("\t", ".byte 0", "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  sctx->print("\t", ".pushsection .wasm.payload.table", "\n");
  sctx->print(elem_type);
  sctx->print(elem_limits);
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  return Result::Ok;
}

static Result s_on_memory(uint32_t index,
                          const Limits* page_limits,
                          void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", ".pushsection .wasm.chars.memory_index", "\n");
  sctx->print("__s_memory_", index, ":", "\n");
  sctx->print("\t", ".byte 0", "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  sctx->print("\t", ".pushsection .wasm.payload.import", "\n");
  sctx->print(page_limits);
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  return Result::Ok;
}

static Result s_on_export(uint32_t index,
                          ExternalKind kind,
                          uint32_t item_index,
                          StringSlice name,
                          void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", ".pushsection .wasm.chars.export", "\n");
  sctx->print("__s_export_", item_index, ":", "\n");
  sctx->print("\t", ".byte 0", "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  sctx->print("\t", ".pushsection .wasm.payload.export", "\n");
  sctx->print("\t", "lstring ");
  sctx->print(name);
  sctx->print("", "\n");
  sctx->print("\t", ".byte ", int(kind), "\n");
  sctx->print("\t", "rleb128_32 ", item_index, "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  return Result::Ok;
}


static Result s_on_local_name(uint32_t function_index,
                              uint32_t local_index,
                              StringSlice name,
                              void* user_data)
{
  while (gLocalNames.size <= function_index) {
    StringSliceVector* ssvec = new StringSliceVector();
    WABT_ZERO_MEMORY(*ssvec);
    append_ssvec_value(&gLocalNames, ssvec);
  }
  StringSliceVector* ssvec = &gLocalNames.data[function_index];
  while (ssvec->size < local_index) {
    StringSlice slice = empty_string_slice();
    append_string_slice_value(ssvec, &slice);
  }
  append_string_slice_value(ssvec, &name);

  return Result::Ok;
}

static Result s_on_function_name(uint32_t function_index,
                                 StringSlice name,
                                 void* user_data)
{
  while (gFunctionNames.size < function_index) {
    StringSlice slice = empty_string_slice();
    append_string_slice_value(&gFunctionNames, &slice);
  }
  append_string_slice_value(&gFunctionNames, &name);

  return Result::Ok;
}

static Result s_on_local_decl_count(uint32_t count,
                                    void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", ".pushsection .wasm.payload.code", "\n");
  sctx->print("\t", "rleb128_32 ", count, "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("", "\n");

  return Result::Ok;
}

static Result s_on_local_decl(uint32_t decl_index,
                              uint32_t count,
                              Type type,
                              void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", ".pushsection .wasm.payload.code", "\n");
  sctx->print("\t", "rleb128_32 ", count, "\n");
  sctx->print(type);
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  return Result::Ok;
}

static Result s_on_block_expr(uint32_t num_types,
                             Type* sig_types,
                             void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "block[]", "\n"); // XXX types

  return Result::Ok;
}

static Result s_on_loop_expr(uint32_t num_types,
                             Type* sig_types,
                             void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "loop[]", "\n"); // XXX types

  return Result::Ok;
}

static Result s_on_binary_expr(Opcode opcode,
                               void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "", opcode, "", "\n");

  return Result::Ok;
}

static Result s_begin_function_signatures_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->print("\t", "section_id function 3", "\n");
  sctx->print("\t", ".section .wasm.payload.function", "\n");

  return Result::Ok;
}

static Result s_begin_table_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->print("\t", "section_id table 4", "\n");

  return Result::Ok;
}

static Result s_begin_memory_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->print("\t", "section_id memory 5", "\n");

  return Result::Ok;
}

static Result s_begin_global_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->print("\t", "section_id global 6", "\n");
  sctx->print("\t", ".section .wasm.payload.global", "\n");

  return Result::Ok;
}

static Result s_begin_export_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->print("\t", "section_id export 7", "\n");

  return Result::Ok;
}

static Result s_begin_start_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->print("\t", "section_id start 8", "\n");

  return Result::Ok;
}

static Result s_begin_elem_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->print("\t", "section_id element 9", "\n");

  return Result::Ok;
}

static Result s_begin_function_bodies_section(BinaryReaderContext* ctx, uint32_t size) {
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->print("\t", "section_id code 10", "\n");
  sctx->print("\t", ".section .wasm.payload.code", "\n");

  return Result::Ok;
}

static Result s_begin_data_section(BinaryReaderContext* ctx, uint32_t size) {
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->print("\t", "section_id data 11", "\n");

  return Result::Ok;
}

static Result s_begin_function_body(BinaryReaderContext* ctx,
                                    uint32_t function_index) {
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->print("\t", ".pushsection .wasm.chars.code", "\n");
  sctx->print("__s_body_", function_index, ":", "\n");
  sctx->print(new OOLFunctionComment(function_index));
  sctx->print("\t", ".byte 0", "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\t", "rleb128_32 __s_endbody_", function_index, " - ");
  sctx->print("__s_startbody_", function_index, "\n");
  sctx->print("__s_startbody_", function_index, ":", "\n");

  sctx->function_index = function_index;

  return Result::Ok;
}

static Result s_end_function_body(uint32_t function_index,
                                  void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "end", "\n");
  sctx->print("__s_endbody_", function_index, ":", "\n");

  return Result::Ok;
}

static Result s_begin_elem_segment(uint32_t index,
                                   uint32_t table_index,
                                   void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", ".pushsection .wasm.chars.element", "\n");
  sctx->print("__s_elemsegment_", index, ":", "\n");
  sctx->print("\t", ".byte 0", "\n");
  sctx->print("\t", ".popsection", "\n");

  sctx->print("\t", ".pushsection .wasm.payload.element", "\n");
  sctx->print("\t", ".pushsection .wasm.payload.element.dummy", "\n");
  sctx->print("\t", "rleb128_32 ", table_index, "\n");

  return Result::Ok;
}

static Result s_end_elem_segment_init_expr(uint32_t index,
                                           void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "end", "\n");
  sctx->print("\t", ".popsection", "\n");

  return Result::Ok;
}

static Result s_on_elem_segment_count(uint32_t count,
                                       void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", ".pushsection .wasm.payload.element", "\n");
  sctx->print("\t", ".pushsection .wasm.payload.element.dummy", "\n");
  sctx->print("\t", "rleb128_32 ", count, "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\t", ".popsection", "\n");

  return Result::Ok;
}

static Result s_on_elem_segment_function_index_count(BinaryReaderContext* ctx,
                                                     uint32_t index,
                                                     uint32_t count)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->print("\t", ".pushsection .wasm.payload.element.dummy", "\n");
  sctx->print("\t", "rleb128_32 ", count,  "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\t", ".pushsection .wasm.chars.element", "\n");
  sctx->print("\t", ".rept ", count, "-1", "\n");
  sctx->print("\t", ".byte 0", "\n");
  sctx->print("\t", ".endr", "\n");
  sctx->print("\t", ".popsection", "\n");

  return Result::Ok;
}

static Result s_on_elem_segment_function_index(uint32_t index,
                                            uint32_t function_index,
                                            void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "rleb128_32 ", function_index, "", "\n");
  sctx->print(new OOLFunctionComment(function_index));

  return Result::Ok;
}

static Result s_on_br_expr(uint32_t depth, void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "br ", depth, "\n");
  return Result::Ok;
}

static Result s_on_br_if_expr(uint32_t depth, void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "br_if ", depth, "\n");
  return Result::Ok;
}

static Result s_on_br_table_expr(BinaryReaderContext* context,
                                 uint32_t num_targets,
                                 uint32_t* target_depths,
                                 uint32_t default_target_depth) {
  SContext* sctx = static_cast<SContext*>(context->user_data);

  sctx->print("\t", "br_table");

  sctx->print(" ", num_targets);
  for (uint32_t i = 0; i < num_targets; i++)
    sctx->print(" ", target_depths[i]);
  sctx->print(" ", default_target_depth, "\n");
  return Result::Ok;
}

static Result s_on_if_expr(uint32_t num_types,
                           Type* sig_types,
                           void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "if[]", "\n");
  return Result::Ok;
}

static Result s_on_load_expr(Opcode opcode,
                             uint32_t alignment_log2,
                             uint32_t offset,
                             void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", opcode, " a=", alignment_log2, " ", offset, "\n");

  return Result::Ok;
}

static Result s_on_store_expr(Opcode opcode,
                             uint32_t alignment_log2,
                             uint32_t offset,
                             void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", opcode, " a=", alignment_log2, " ", offset, "\n");

  return Result::Ok;
}

static Result s_on_call_expr(uint32_t target,
                             void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "call ", target, "\n");

  return Result::Ok;
}

static Result s_on_drop_expr(void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "drop", "\n");

  return Result::Ok;
}

static Result s_on_else_expr(void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "else", "\n");

  return Result::Ok;
}

static Result s_on_end_expr(void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "end", "\n");

  return Result::Ok;
}

static Result s_on_nop_expr(void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "nop", "\n");

  return Result::Ok;
}

static Result s_on_return_expr(void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "return", "\n");

  return Result::Ok;
}

static Result s_on_select_expr(void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "select", "\n");

  return Result::Ok;
}

static Result s_on_current_memory_expr(void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "current_memory", "\n");

  return Result::Ok;
}

static Result s_on_grow_memory_expr(void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "grow_memory", "\n");

  return Result::Ok;
}

static Result s_on_call_indirect_expr(uint32_t sig_index,
                                      void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "call_indirect ", sig_index, " 0", "\n");
  sctx->print(new OOLTableComment(0));
  sctx->print(new OOLSignatureComment(sig_index));

  return Result::Ok;
}

static Result s_on_get_global_expr(uint32_t global_index,
                                   void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "get_global ", global_index, "\n");
  sctx->print(new OOLGlobalComment(global_index));

  return Result::Ok;
}

static Result s_on_set_global_expr(uint32_t global_index,
                                   void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "set_global ", global_index, "\n");
  sctx->print(new OOLGlobalComment(global_index));

  return Result::Ok;
}

static Result s_on_get_local_expr(uint32_t local_index,
                                   void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "get_local ", local_index, "\n");
  sctx->print(new OOLLocalComment(sctx->function_index, local_index));

  return Result::Ok;
}

static Result s_on_set_local_expr(uint32_t local_index,
                                   void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "set_local ", local_index, "\n");
  sctx->print(new OOLLocalComment(sctx->function_index, local_index));

  return Result::Ok;
}

static Result s_on_tee_local_expr(uint32_t local_index,
                                   void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "tee_local ", local_index, "\n");
  sctx->print(new OOLLocalComment(sctx->function_index, local_index));

  return Result::Ok;
}

static Result s_begin_global(uint32_t index,
                             Type type,
                             bool mutable_,
                             void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  sctx->print("\t", ".pushsection .wasm.chars.global_index.global", "\n");
  sctx->print("__s_global_", index, ":", "\n");
  sctx->print("\t", ".byte 0", "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  sctx->print("\t", ".pushsection .wasm.chars.global", "\n");
  sctx->print("\t", ".byte 0", "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  sctx->print("\t", ".pushsection .wasm.payload.global", "\n");
  sctx->print(type);
  sctx->print("\t", ".byte ", (mutable_ ? 1 : 0), "\n");

  return Result::Ok;
}

static Result s_on_f32_const_expr(uint32_t value_bits, void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  float value;
  memcpy(&value, &value_bits, sizeof(value));
  sctx->print("\t", "f32.const ", value, "\n");

  return Result::Ok;
}

static Result s_on_f64_const_expr(uint64_t value_bits, void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  double value;
  memcpy(&value, &value_bits, sizeof(value));
  sctx->print("\t", "f64.const ", value, "\n");

  return Result::Ok;
}

static Result s_on_i32_const_expr(uint32_t value, void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  sctx->print("\t", "i32.const ", int32_t(value), "\n");

  return Result::Ok;
}

static Result s_on_i64_const_expr(uint64_t value, void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  sctx->print("\t", "i64.const ", int64_t(value), "\n");

  return Result::Ok;
}

static Result s_on_init_expr_get_global_expr(uint32_t index,
                                             uint32_t global_index,
                                             void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  sctx->print("\t", "get_global ", global_index, "\n");

  return Result::Ok;
}

static Result s_on_init_expr_f32_const_expr(uint32_t index,
                                            uint32_t value_bits,
                                            void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  float value;
  memcpy(&value, &value_bits, sizeof(value));
  sctx->print("\t", ".float ", value, "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  return Result::Ok;
}

static Result s_on_init_expr_f64_const_expr(uint32_t index,
                                            uint64_t value_bits,
                                            void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  double value;
  memcpy(&value, &value_bits, sizeof(value));
  sctx->print("\t", ".double ", value, "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  return Result::Ok;
}

static Result s_on_init_expr_i32_const_expr(uint32_t index,
                                            uint32_t value,
                                            void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  sctx->print("\t", "i32.const ", int32_t(value), "\n");
  sctx->print("\t", "end", "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  return Result::Ok;
}

static Result s_on_init_expr_i64_const_expr(uint32_t index,
                                            uint64_t value,
                                            void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  sctx->print("\t", "i64.const ", int64_t(value), "\n");
  sctx->print("\t", ".popsection", "\n");
  sctx->print("\n");

  return Result::Ok;
}

static Result s_on_data_segment_data(uint32_t index, const void* data,
                                     uint32_t size, void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  for (uint32_t i = 0; i < size; i++) {
    sctx->print("\t");
    sctx->printf(".byte 0x%02x", (static_cast<const uint8_t*>(data))[i]);
    sctx->print("\n");
  }

  return Result::Ok;
}

static Result s_on_function_signatures_count(uint32_t count,
                                             void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  sctx->print("\t", ".section .wasm.chars.function", "\n");
  sctx->print("\t", ".rept ", count, "\n");
  sctx->print("\t", ".byte 0", "\n");
  sctx->print("\t", ".endr", "\n");
  sctx->print("\t", ".section .wasm.payload.function", "\n");

  return Result::Ok;
}

static Result s_on_function_signature(uint32_t index,
                                      uint32_t sig_index,
                                      void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->print("\t", "rleb128_32 ", sig_index, "\n");

  return Result::Ok;
}

void read_sections(Context* ctx);

Result s_binary(const void* data,
                size_t size,
                BinaryReader* reader,
                uint32_t num_function_passes,
                const ReadBinaryOptions* options)
{
  SContext sctx;
  WABT_ZERO_MEMORY(sctx);
  sctx.f = stdout;
  BinaryReader s_reader;
  WABT_ZERO_MEMORY(s_reader);

  s_reader.user_data = &sctx;

  s_reader.on_error = s_on_error;
  s_reader.begin_module = s_begin_module;
  s_reader.begin_custom_section = s_begin_custom_section;
  s_reader.begin_signature_section = s_begin_signature_section;
  s_reader.on_signature = s_on_signature;
  s_reader.on_import = s_on_import;
  s_reader.on_import_func = s_on_import_func;
  s_reader.on_import_table = s_on_import_table;
  s_reader.on_import_memory = s_on_import_memory;
  s_reader.on_import_global = s_on_import_global;
  s_reader.begin_import_section = s_begin_import_section;
  s_reader.begin_function_signatures_section = s_begin_function_signatures_section;
  s_reader.on_function_signatures_count = s_on_function_signatures_count;
  s_reader.on_function_signature = s_on_function_signature;
  s_reader.end_import_section = s_end_import_section;
#if 0
  s_reader.on_signature_count = s_on_signature_count;
  s_reader.end_signature_section = s_end_signature_section;

  s_reader.on_import_count = s_on_import_count;

n;

  s_reader.end_table_section = s_end_table_section;

  s_reader.on_memory_count = s_on_memory_count;
#endif
  s_reader.begin_table_section = s_begin_table_section;
  s_reader.begin_memory_section = s_begin_memory_section;
  s_reader.on_table = s_on_table;
  s_reader.on_memory = s_on_memory;
  s_reader.on_local_decl = s_on_local_decl;
  s_reader.begin_start_section = s_begin_start_section;
  s_reader.on_export = s_on_export;
  s_reader.begin_function_bodies_section = s_begin_function_bodies_section;
  s_reader.begin_global_section = s_begin_global_section;
  s_reader.begin_elem_section = s_begin_elem_section;
  s_reader.begin_export_section = s_begin_export_section;
  s_reader.on_block_expr = s_on_block_expr;
  s_reader.on_binary_expr = s_on_binary_expr;
  s_reader.begin_global = s_begin_global;
  s_reader.on_br_expr = s_on_br_expr;
  s_reader.on_br_if_expr = s_on_br_if_expr;
#if 0
  s_reader.begin_global_init_expr = s_begin_global_init_expr;

  s_reader.on_global_count = s_on_global_count;
  s_reader.end_global_init_expr = s_end_global_init_expr;
  s_reader.end_global = s_end_global;
  s_reader.end_global_section = s_end_global_section;

  s_reader.on_export_count = s_on_export_count;
  s_reader.end_export_section = s_end_export_section;

  s_reader.on_start_function = s_on_start_function;
  s_reader.end_start_section = s_end_start_section;
  s_reader.on_function_bodies_count = s_on_function_bodies_count;
  s_reader.begin_function_body_pass = s_begin_function_body_pass;
#endif
  s_reader.begin_function_body = s_begin_function_body;
  s_reader.on_local_decl_count = s_on_local_decl_count;
  s_reader.on_br_table_expr = s_on_br_table_expr;
  s_reader.on_f32_const_expr = s_on_f32_const_expr;
  s_reader.on_f64_const_expr = s_on_f64_const_expr;
  s_reader.on_i32_const_expr = s_on_i32_const_expr;
  s_reader.on_i64_const_expr = s_on_i64_const_expr;
  s_reader.on_if_expr = s_on_if_expr;
  s_reader.on_compare_expr = s_on_binary_expr;
  s_reader.on_convert_expr = s_on_binary_expr;
  s_reader.on_unary_expr = s_on_binary_expr;
  s_reader.on_load_expr = s_on_load_expr;
  s_reader.on_loop_expr = s_on_loop_expr;
  s_reader.on_call_expr = s_on_call_expr;
  s_reader.on_call_indirect_expr = s_on_call_indirect_expr;
  s_reader.on_drop_expr = s_on_drop_expr;
  s_reader.on_else_expr = s_on_else_expr;
  s_reader.on_end_expr = s_on_end_expr;
  s_reader.on_nop_expr = s_on_nop_expr;
  s_reader.on_current_memory_expr = s_on_current_memory_expr;
  s_reader.on_return_expr = s_on_return_expr;
  s_reader.on_select_expr = s_on_select_expr;
  s_reader.on_get_global_expr = s_on_get_global_expr;
  s_reader.on_get_local_expr = s_on_get_local_expr;
  s_reader.on_set_global_expr = s_on_set_global_expr;
  s_reader.on_set_local_expr = s_on_set_local_expr;
  s_reader.on_tee_local_expr = s_on_tee_local_expr;
  s_reader.on_store_expr = s_on_store_expr;
  s_reader.on_grow_memory_expr = s_on_grow_memory_expr;
  s_reader.begin_elem_segment = s_begin_elem_segment;
  s_reader.on_elem_segment_count = s_on_elem_segment_count;
  s_reader.end_elem_segment_init_expr = s_end_elem_segment_init_expr;
  s_reader.on_elem_segment_function_index = s_on_elem_segment_function_index;
  s_reader.on_elem_segment_function_index_count = s_on_elem_segment_function_index_count;
  s_reader.end_function_body = s_end_function_body;
#if 0
  s_reader.end_function_body_pass = s_end_function_body_pass;

  s_reader.end_elem_segment = s_end_elem_segment;
  s_reader.end_elem_section = s_end_elem_section;

  s_reader.on_data_segment_count = s_on_data_segment_count;
  s_reader.begin_data_segment = s_begin_data_segment;
  s_reader.begin_data_segment_init_expr = s_begin_data_segment_init_expr;
  s_reader.end_data_segment_init_expr = s_end_data_segment_init_expr;
  s_reader.end_data_segment = s_end_data_segment;
  s_reader.end_data_section = s_end_data_section;
#endif
  s_reader.on_function_name = s_on_function_name;
  s_reader.on_local_name = s_on_local_name;
  s_reader.on_data_segment_data = s_on_data_segment_data;
  s_reader.on_init_expr_get_global_expr = s_on_init_expr_get_global_expr;
  s_reader.on_init_expr_f32_const_expr = s_on_init_expr_f32_const_expr;
  s_reader.on_init_expr_f64_const_expr = s_on_init_expr_f64_const_expr;
  s_reader.on_init_expr_i32_const_expr = s_on_init_expr_i32_const_expr;
  s_reader.on_init_expr_i64_const_expr = s_on_init_expr_i64_const_expr;
  s_reader.begin_data_section = s_begin_data_section;

  read_binary(data, size, &s_reader, 1, options);

  fprintf(sctx.f, "###########\n");
  for (uint32_t i = 0; i < sctx.comments.size; i++) {
    OOLComment* c = sctx.comments.data[i].comment;
    fprintf(sctx.f, "# %ld: ", long(c->offset));
    c->print(sctx.f);
  }

  return Result::Ok;
}

}  // namespace wabt
