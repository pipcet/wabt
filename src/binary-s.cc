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

#define INDENT_SIZE 2

#define INITIAL_PARAM_TYPES_CAPACITY 128
#define INITIAL_BR_TABLE_TARGET_CAPACITY 1000

namespace wabt {

typedef uint32_t Uint32;
WABT_DEFINE_VECTOR(type, Type)
WABT_DEFINE_VECTOR(uint32, Uint32);

#define CALLBACK_CTX(member, ...)                                       \
  RAISE_ERROR_UNLESS(                                                   \
      WABT_SUCCEEDED(                                                   \
          ctx->reader->member                                           \
              ? ctx->reader->member(get_user_context(ctx), __VA_ARGS__) \
              : Result::Ok),                                            \
      #member " callback failed")

#define CALLBACK_CTX0(member)                                         \
  RAISE_ERROR_UNLESS(                                                 \
      WABT_SUCCEEDED(ctx->reader->member                              \
                         ? ctx->reader->member(get_user_context(ctx)) \
                         : Result::Ok),                               \
      #member " callback failed")

#define CALLBACK_SECTION(member, section_size) \
  CALLBACK_CTX(member, section_size)

#define CALLBACK0(member)                                              \
  RAISE_ERROR_UNLESS(                                                  \
      WABT_SUCCEEDED(ctx->reader->member                               \
                         ? ctx->reader->member(ctx->reader->user_data) \
                         : Result::Ok),                                \
      #member " callback failed")

#define CALLBACK(member, ...)                                            \
  RAISE_ERROR_UNLESS(                                                    \
      WABT_SUCCEEDED(                                                    \
          ctx->reader->member                                            \
              ? ctx->reader->member(__VA_ARGS__, ctx->reader->user_data) \
              : Result::Ok),                                             \
      #member " callback failed")

#define FORWARD0(member)                                                   \
  return ctx->reader->member ? ctx->reader->member(ctx->reader->user_data) \
                             : Result::Ok

#define FORWARD_CTX0(member)                  \
  if (!ctx->reader->member)                   \
    return Result::Ok;                        \
  BinaryReaderContext new_ctx = *context;     \
  new_ctx.user_data = ctx->reader->user_data; \
  return ctx->reader->member(&new_ctx);

#define FORWARD_CTX(member, ...)              \
  if (!ctx->reader->member)                   \
    return Result::Ok;                        \
  BinaryReaderContext new_ctx = *context;     \
  new_ctx.user_data = ctx->reader->user_data; \
  return ctx->reader->member(&new_ctx, __VA_ARGS__);

#define FORWARD(member, ...)                                            \
  return ctx->reader->member                                            \
             ? ctx->reader->member(__VA_ARGS__, ctx->reader->user_data) \
             : Result::Ok

#define RAISE_ERROR(...) raise_error(ctx, __VA_ARGS__)

#define RAISE_ERROR_UNLESS(cond, ...) \
  if (!(cond))                        \
    RAISE_ERROR(__VA_ARGS__);

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

struct SContext {
public:
  void print_sslice(StringSlice slice);
  void print_sslice_quoted(StringSlice slice);
  void print_signature(uint32_t, const Type*, uint32_t, const Type*);
  void printf(const char* format);
  void printc(const char* format, int8_t);
  void printu(const char* format, uint32_t);
  void printf32(const char* format, int, float);
  void printf64(const char* format, int, double);
  void printi32(const char* format, int);
  void printi64(const char* format, long long);
  void prints(const char* format, int, const char*);
  void printo(Opcode opcode);
  void println();
  void print_type(Type);
  void print_type_char(Type);
  void print_limits(const Limits*);
  void print_uleb128(const char*);
  void print_uleb128(uint32_t);
  FILE *f;
};

void SContext::printo(Opcode opcode)
{
  const char* s = get_opcode_name(opcode);

  if (!s)
    abort();

  printf("\t");
  while (*s) {
    printc("%c", (*s == '/') ? '_' : *s);
    s++;
  }
}

void SContext::print_signature(uint32_t plen, const Type* p, uint32_t rlen,
                               const Type* r)
{
  printf("F");
  for (uint32_t i = 0; i < plen; i++)
    print_type_char(p[i]);
  for (uint32_t i = 0; i < rlen; i++)
    print_type_char(r[i]);
  printf("E");
}

void SContext::print_sslice(StringSlice slice)
{
  prints(PRIstringslice, WABT_PRINTF_STRING_SLICE_ARG(slice));
}

void SContext::print_sslice_quoted(StringSlice slice)
{
  prints("\"" PRIstringslice "\"", WABT_PRINTF_STRING_SLICE_ARG(slice));
}

void SContext::printf(const char* format)
{
  fprintf(f, "%s", format);
}

void SContext::println()
{
  fprintf(f, "\n");
}

void SContext::prints(const char* format, int count, const char* x)
{
  fprintf(f, format, count, x);
}

void SContext::printc(const char* format, int8_t x)
{
  fprintf(f, format, x);
}

void SContext::printu(const char* format, uint32_t x)
{
  fprintf(f, format, x);
}

void SContext::printi32(const char* format, int x)
{
  fprintf(f, format, x);
}

void SContext::printi64(const char* format, long long x)
{
  fprintf(f, format, x);
}

void SContext::printf32(const char* format, int prec, float x)
{
  fprintf(f, format, prec, x);
}

void SContext::printf64(const char* format, int prec, double x)
{
  fprintf(f, format, prec, x);
}

void SContext::print_uleb128(const char* x)
{
  fprintf(f, "rleb128_32 %s", x);
}

void SContext::print_uleb128(uint32_t x)
{
  fprintf(f, "rleb128_32 %u", x);
}

void SContext::print_limits(const Limits* limits)
{
  uint32_t flags = 0;
  if (limits->has_max)
    flags |= WABT_BINARY_LIMITS_HAS_MAX_FLAG;

  printf("\t"); print_uleb128(flags); println();
  printf("\t"); print_uleb128(limits->initial); println();
  if (limits->has_max) {
    printf("\t"); print_uleb128(limits->max); println();
  }
}

void SContext::print_type(Type t)
{
  switch (t) {
  case Type::I32:
    printu("\t.byte %u # i32\n", 0x7f); break;
  case Type::I64:
    printu("\t.byte %u # i64\n", 0x7e); break;
  case Type::F32:
    printu("\t.byte %u # f32\n", 0x7d); break;
  case Type::F64:
    printu("\t.byte %u # f64\n", 0x7c); break;
  case Type::Anyfunc:
    printu("\t.byte %u # anyfunc\n", 0x70); break;
  default:
    abort();
  }
}

void SContext::print_type_char(Type t)
{
  switch (t) {
  case Type::I32:
    printu("i", int(Type::I32)); break;
  case Type::I64:
    printu("l", int(Type::I64)); break;
  case Type::F32:
    printu("f", int(Type::F32)); break;
  case Type::F64:
    printu("d", int(Type::F64)); break;
  default:
    abort();
  }
}

static Result s_begin_custom_section(BinaryReaderContext* ctx,
                                     uint32_t size,
                                     StringSlice section_name)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->printf("\tsection ");
  sctx->print_sslice(section_name);
  sctx->println();

  return Result::Ok;
}

static Result s_begin_module(uint32_t value, void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printu("\t# module (%u)\n", value);
  sctx->printf("\t.include \"wasm32-macros.s\"\n");
  sctx->printf("\t.include \"wasm32-header-macros.s\"\n");

  return Result::Ok;
}

static Result s_begin_signature_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->printf("\tsection_id type 1\n");

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


  sctx->printf("\t.pushsection .wasm.chars.type\n");
  sctx->printu("__s_type_%u:\n", index);
  sctx->printf("\t.byte 0\n");
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  sctx->printf("\t.pushsection .wasm.payload.type\n");
  sctx->printf("\tsignature ");
  sctx->print_signature(param_count, param_types, result_count, result_types);
  sctx->printf("\n");
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  return Result::Ok;
}

static Result s_begin_import_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->printf("\tsection_id import 2\n");

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
    sctx->printf("\t.if 0\n");
    in_hidden_global_hack = true;
  } else {
    in_hidden_global_hack = false;
  }

  sctx->printf("\t.pushsection .wasm.chars.import\n");
  sctx->printu("__s_import_%u:\n", index);
  sctx->printf("\t.byte 0\n");
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  sctx->printf("\t.pushsection .wasm.payload.import\n");
  sctx->printf("\tlstring ");
  sctx->print_sslice(module_name);
  sctx->printf("\n");
  sctx->printf("\tlstring ");
  sctx->print_sslice(field_name);
  sctx->printf("\n");
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  return Result::Ok;
}

static Result s_on_import_func(uint32_t index,
                               uint32_t function_index,
                               uint32_t sig_index,
                               void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\t.pushsection .wasm.chars.function_index.import\n");
  sctx->printu("__s_func_%u:\n", function_index);
  sctx->printf("\t.byte 0\n");
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  sctx->printf("\t.pushsection .wasm.payload.import\n");
  sctx->printu("\t.byte %u # function\n", 0);
  sctx->printu("\trleb128_32 __s_type_%u\n", sig_index);
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  if (in_hidden_global_hack) {
    sctx->printf("\t.endif\n");
  }

  return Result::Ok;
}

static Result s_on_import_table(uint32_t index,
                                uint32_t table_index,
                                Type elem_type,
                                const Limits* elem_limits,
                                void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\t.pushsection .wasm.chars.table_index.import\n");
  sctx->printu("__s_table_%u:\n", table_index);
  sctx->printf("\t.byte 0\n");
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  sctx->printf("\t.pushsection .wasm.payload.import\n");
  sctx->printu("\t.byte %u # table\n", 1);
  sctx->print_type(elem_type);
  sctx->print_limits(elem_limits);
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  if (in_hidden_global_hack) {
    sctx->printf("\t.endif\n");
  }

  return Result::Ok;
}

static Result s_on_import_memory(uint32_t index,
                                 uint32_t memory_index,
                                 const Limits* page_limits,
                                 void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\t.pushsection .wasm.chars.memory_index.import\n");
  sctx->printu("__s_memory_%u:\n", memory_index);
  sctx->printf("\t.byte 0\n");
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  sctx->printf("\t.pushsection .wasm.payload.import\n");
  sctx->printu("\t.byte %u # memory\n", 2);
  sctx->print_limits(page_limits);
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  if (in_hidden_global_hack) {
    sctx->printf("\t.endif\n");
  }

  return Result::Ok;
}

static Result s_on_import_global(uint32_t index,
                                 uint32_t global_index,
                                 Type type,
                                 bool mutable_,
                                 void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\t.pushsection .wasm.chars.global_index.import\n");
  sctx->printu("__s_global_%u:\n", global_index);
  sctx->printf("\t.byte 0\n");
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  sctx->printf("\t.pushsection .wasm.payload.import\n");
  sctx->printu("\t.byte %u # global\n", 3);
  sctx->print_type(type);
  sctx->printu("\t.byte %u # mutable\n", mutable_ ? 1 : 0);
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  if (in_hidden_global_hack) {
    sctx->printf("\t.endif\n");
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

  sctx->printf("\t.pushsection .wasm.chars.table_index\n");
  sctx->printu("__s_table_%u:\n", index);
  sctx->printf("\t.byte 0\n");
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  sctx->printf("\t.pushsection .wasm.payload.table\n");
  sctx->print_type(elem_type);
  sctx->print_limits(elem_limits);
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  return Result::Ok;
}

static Result s_on_memory(uint32_t index,
                          const Limits* page_limits,
                          void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\t.pushsection .wasm.chars.memory_index\n");
  sctx->printu("__s_memory_%u:\n", index);
  sctx->printf("\t.byte 0\n");
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  sctx->printf("\t.pushsection .wasm.payload.import\n");
  sctx->print_limits(page_limits);
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  return Result::Ok;
}

static Result s_on_export(uint32_t index,
                          ExternalKind kind,
                          uint32_t item_index,
                          StringSlice name,
                          void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\t.pushsection .wasm.chars.export\n");
  sctx->printu("__s_export_%u:\n", item_index);
  sctx->printf("\t.byte 0\n");
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  sctx->printf("\t.pushsection .wasm.payload.export\n");
  sctx->printf("\tlstring ");
  sctx->print_sslice(name);
  sctx->printf("\n");
  sctx->printu("\t.byte %u\n", int(kind));
  sctx->printu("\trleb128_32 %u\n", item_index);
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  return Result::Ok;
}

static Result s_on_local_decl_count(uint32_t count,
                                    void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\t.pushsection .wasm.payload.code\n");
  sctx->printu("\trleb128_32 %u\n", count);
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  return Result::Ok;
}

static Result s_on_local_decl(uint32_t decl_index,
                              uint32_t count,
                              Type type,
                              void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\t.pushsection .wasm.payload.code\n");
  sctx->printu("\trleb128_32 %u\n", count);
  sctx->print_type(type);
  sctx->printf("\t.popsection\n");
  sctx->printf("\n");

  return Result::Ok;
}

static Result s_on_block_expr(uint32_t num_types,
                             Type* sig_types,
                             void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\tblock[]\n"); // XXX types

  return Result::Ok;
}

static Result s_on_loop_expr(uint32_t num_types,
                             Type* sig_types,
                             void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\tloop[]\n"); // XXX types

  return Result::Ok;
}

static Result s_on_binary_expr(Opcode opcode,
                               void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printo(opcode);
  sctx->println();

  return Result::Ok;
}

static Result s_begin_function_signatures_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->printf("\tsection_id function 3\n");
  sctx->printf("\t.section .wasm.payload.function\n");

  return Result::Ok;
}

static Result s_begin_table_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->printf("\tsection_id table 4\n");

  return Result::Ok;
}

static Result s_begin_memory_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->printf("\tsection_id memory 5\n");

  return Result::Ok;
}

static Result s_begin_global_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->printf("\tsection_id global 6\n");
  sctx->printf("\t.section .wasm.payload.global\n");

  return Result::Ok;
}

static Result s_begin_export_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->printf("\tsection_id export 7\n");

  return Result::Ok;
}

static Result s_begin_start_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->printf("\tsection_id start 8\n");

  return Result::Ok;
}

static Result s_begin_elem_section(BinaryReaderContext* ctx, uint32_t size)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->printf("\tsection_id element 9\n");

  return Result::Ok;
}

static Result s_begin_function_bodies_section(BinaryReaderContext* ctx, uint32_t size) {
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->printf("\tsection_id code 10\n");
  sctx->printf("\t.section .wasm.payload.code\n");

  return Result::Ok;
}

static Result s_begin_data_section(BinaryReaderContext* ctx, uint32_t size) {
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->printf("\tsection_id data 11\n");

  return Result::Ok;
}

static Result s_begin_function_body(BinaryReaderContext* ctx,
                                    uint32_t function_index) {
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->printf("\t.pushsection .wasm.chars.code\n");
  sctx->printu("__s_body_%u:\n", function_index);
  sctx->printf("\t.byte 0\n");
  sctx->printf("\t.popsection\n");
  sctx->printu("\trleb128_32 __s_endbody_%u - ", function_index);
  sctx->printu("__s_startbody_%u\n", function_index);
  sctx->printu("__s_startbody_%u:\n", function_index);

  return Result::Ok;
}

static Result s_end_function_body(uint32_t function_index,
                                  void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\tend\n");
  sctx->printu("__s_endbody_%u:\n", function_index);

  return Result::Ok;
}

static Result s_begin_elem_segment(uint32_t index,
                                   uint32_t table_index,
                                   void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\t.pushsection .wasm.chars.element\n");
  sctx->printu("__s_elemsegment_%u:\n", index);
  sctx->printf("\t.byte 0\n");
  sctx->printf("\t.popsection\n");

  sctx->printf("\t.pushsection .wasm.payload.element\n");
  sctx->printf("\t.pushsection .wasm.payload.element.dummy\n");
  sctx->printu("\trleb128_32 %u\n", table_index);

  return Result::Ok;
}

static Result s_end_elem_segment_init_expr(uint32_t index,
                                           void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\tend\n");
  sctx->printf("\t.popsection\n");

  return Result::Ok;
}

static Result s_on_elem_segment_count(uint32_t count,
                                       void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printu("\t.pushsection .wasm.payload.element\n", count);
  sctx->printu("\t.pushsection .wasm.payload.element.dummy\n", count);
  sctx->printu("\trleb128_32 %u\n", count);
  sctx->printu("\t.popsection\n", count);
  sctx->printu("\t.popsection\n", count);

  return Result::Ok;
}

static Result s_on_elem_segment_function_index_count(BinaryReaderContext* ctx,
                                                     uint32_t index,
                                                     uint32_t count)
{
  SContext* sctx = static_cast<SContext*>(ctx->user_data);

  sctx->printu("\t.pushsection .wasm.payload.element.dummy\n", count);
  sctx->printu("\trleb128_32 %u\n", count);
  sctx->printu("\t.popsection\n", count);
  sctx->printu("\t.pushsection .wasm.chars.element\n", count);
  sctx->printu("\t.rept %u-1\n", count);
  sctx->printf("\t.byte 0\n");
  sctx->printf("\t.endr\n");
  sctx->printu("\t.popsection\n", count);

  return Result::Ok;
}

static Result s_on_elem_segment_function_index(uint32_t index,
                                            uint32_t function_index,
                                            void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\t"); sctx->print_uleb128(function_index); sctx->println();

  return Result::Ok;
}

#define LOGF_NOINDENT(...) writef(ctx->stream, __VA_ARGS__)

#define LOGF(...)               \
  do {                          \
    write_indent(ctx);          \
    LOGF_NOINDENT(__VA_ARGS__); \
  } while (0)

#define LOGGING_BEGIN(name)                                                 \
  static Result logging_begin_##name(BinaryReaderContext* context,          \
                                     uint32_t size) {                       \
    LoggingContext* ctx = static_cast<LoggingContext*>(context->user_data); \
    LOGF("begin_" #name "\n");                                              \
    indent(ctx);                                                            \
    FORWARD_CTX(begin_##name, size);                                        \
  }

#define LOGGING_END(name)                                                   \
  static Result logging_end_##name(BinaryReaderContext* context) {          \
    LoggingContext* ctx = static_cast<LoggingContext*>(context->user_data); \
    dedent(ctx);                                                            \
    LOGF("end_" #name "\n");                                                \
    FORWARD_CTX0(end_##name);                                               \
  }

#define LOGGING_UINT32(name)                                       \
  static Result logging_##name(uint32_t value, void* user_data) {  \
    LoggingContext* ctx = static_cast<LoggingContext*>(user_data); \
    LOGF(#name "(%u)\n", value);                                   \
    FORWARD(name, value);                                          \
  }

#define LOGGING_UINT32_CTX(name)                                               \
  static Result logging_##name(BinaryReaderContext* context, uint32_t value) { \
    LoggingContext* ctx = static_cast<LoggingContext*>(context->user_data);    \
    LOGF(#name "(%u)\n", value);                                               \
    FORWARD_CTX(name, value);                                                  \
  }

#define LOGGING_UINT32_DESC(name, desc)                            \
  static Result logging_##name(uint32_t value, void* user_data) {  \
    LoggingContext* ctx = static_cast<LoggingContext*>(user_data); \
    LOGF(#name "(" desc ": %u)\n", value);                         \
    FORWARD(name, value);                                          \
  }

#define LOGGING_UINT32_UINT32(name, desc0, desc1)                   \
  static Result logging_##name(uint32_t value0, uint32_t value1,    \
                               void* user_data) {                   \
    LoggingContext* ctx = static_cast<LoggingContext*>(user_data);  \
    LOGF(#name "(" desc0 ": %u, " desc1 ": %u)\n", value0, value1); \
    FORWARD(name, value0, value1);                                  \
  }

#define LOGGING_UINT32_UINT32_CTX(name, desc0, desc1)                         \
  static Result logging_##name(BinaryReaderContext* context, uint32_t value0, \
                               uint32_t value1) {                             \
    LoggingContext* ctx = static_cast<LoggingContext*>(context->user_data);   \
    LOGF(#name "(" desc0 ": %u, " desc1 ": %u)\n", value0, value1);           \
    FORWARD_CTX(name, value0, value1);                                        \
  }

#define LOGGING0(name)                                             \
  static Result logging_##name(void* user_data) {                  \
    LoggingContext* ctx = static_cast<LoggingContext*>(user_data); \
    LOGF(#name "\n");                                              \
    FORWARD0(name);                                                \
  }

static Result s_on_br_expr(uint32_t depth, void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printu("\tbr %u\n", depth);
  return Result::Ok;
}

static Result s_on_br_if_expr(uint32_t depth, void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printu("\tbr_if %u\n", depth);
  return Result::Ok;
}

static Result s_on_br_table_expr(BinaryReaderContext* context,
                                 uint32_t num_targets,
                                 uint32_t* target_depths,
                                 uint32_t default_target_depth) {
  SContext* sctx = static_cast<SContext*>(context->user_data);

  sctx->printf("\tbr_table");

  sctx->printu(" %u", num_targets);
  for (uint32_t i = 0; i < num_targets; i++)
    sctx->printu(" %u", target_depths[i]);
  sctx->printu(" %u", default_target_depth);
  sctx->println();
  return Result::Ok;
}

static Result s_on_if_expr(uint32_t num_types,
                           Type* sig_types,
                           void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\tif[]\n");
  return Result::Ok;
}

static Result s_on_load_expr(Opcode opcode,
                             uint32_t alignment_log2,
                             uint32_t offset,
                             void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printo(opcode);
  sctx->printu(" a=%u", alignment_log2);
  sctx->printu(" %u", offset);
  sctx->println();

  return Result::Ok;
}

static Result s_on_store_expr(Opcode opcode,
                             uint32_t alignment_log2,
                             uint32_t offset,
                             void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printo(opcode);
  sctx->printu(" a=%u", alignment_log2);
  sctx->printu(" %u", offset);
  sctx->println();

  return Result::Ok;
}

static Result s_on_call_expr(uint32_t target,
                             void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printu("\tcall %u", target);
  sctx->println();

  return Result::Ok;
}

static Result s_on_drop_expr(void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\tdrop\n");

  return Result::Ok;
}

static Result s_on_else_expr(void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\telse\n");

  return Result::Ok;
}

static Result s_on_end_expr(void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\tend\n");

  return Result::Ok;
}

static Result s_on_nop_expr(void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\tnop\n");

  return Result::Ok;
}

static Result s_on_return_expr(void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\treturn\n");

  return Result::Ok;
}

static Result s_on_select_expr(void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\tselect\n");

  return Result::Ok;
}

static Result s_on_current_memory_expr(void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\tcurrent_memory\n");

  return Result::Ok;
}

static Result s_on_grow_memory_expr(void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printf("\tgrow_memory\n");

  return Result::Ok;
}

static Result s_on_call_indirect_expr(uint32_t sig_index,
                                      void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printu("\tcall_indirect %u 0", sig_index);
  sctx->println();

  return Result::Ok;
}

static Result s_on_get_global_expr(uint32_t global_index,
                                   void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printu("\tget_global %u", global_index);
  sctx->println();

  return Result::Ok;
}

static Result s_on_set_global_expr(uint32_t global_index,
                                   void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printu("\tset_global %u", global_index);
  sctx->println();

  return Result::Ok;
}

static Result s_on_get_local_expr(uint32_t local_index,
                                   void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printu("\tget_local %u", local_index);
  sctx->println();

  return Result::Ok;
}

static Result s_on_set_local_expr(uint32_t local_index,
                                   void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printu("\tset_local %u", local_index);
  sctx->println();

  return Result::Ok;
}

static Result s_on_tee_local_expr(uint32_t local_index,
                                   void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printu("\ttee_local %u", local_index);
  sctx->println();

  return Result::Ok;
}

static Result s_begin_global(uint32_t index,
                             Type type,
                             bool mutable_,
                             void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  sctx->printf("\t.pushsection .wasm.chars.global_index.global\n");
  sctx->printu("__s_global_%u:\n", index);
  sctx->printf("\t.byte 0\n");
  sctx->printf("\t.popsection\n");
  sctx->println();

  sctx->printf("\t.pushsection .wasm.chars.global\n");
  sctx->printf("\t.byte 0\n");
  sctx->printf("\t.popsection\n");
  sctx->println();

  sctx->printf("\t.pushsection .wasm.payload.global\n");
  sctx->print_type(type);
  sctx->printu("\t.byte %u\n", mutable_ ? 1 : 0);

  return Result::Ok;
}

static Result s_on_f32_const_expr(uint32_t value_bits, void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  float value;
  memcpy(&value, &value_bits, sizeof(value));
  sctx->printf32("\tf32.const %.*g\n", DECIMAL_DIG, value);

  return Result::Ok;
}

static Result s_on_f64_const_expr(uint64_t value_bits, void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  double value;
  memcpy(&value, &value_bits, sizeof(value));
  sctx->printf64("\tf64.const %.*g\n", DECIMAL_DIG, value);

  return Result::Ok;
}

static Result s_on_i32_const_expr(uint32_t value, void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  sctx->printi32("\ti32.const %d\n", value);

  return Result::Ok;
}

static Result s_on_i64_const_expr(uint64_t value, void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  sctx->printi64("\ti64.const %lld\n", value);

  return Result::Ok;
}

static Result s_on_init_expr_get_global_expr(uint32_t index,
                                             uint32_t global_index,
                                             void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  sctx->printu("\tget_global %u\n", global_index);

  return Result::Ok;
}

static Result s_on_init_expr_f32_const_expr(uint32_t index,
                                            uint32_t value_bits,
                                            void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  float value;
  memcpy(&value, &value_bits, sizeof(value));
  sctx->printf32("\t.float %.*g\n", DECIMAL_DIG, value);
  sctx->printf("\t.popsection\n");
  sctx->println();

  return Result::Ok;
}

static Result s_on_init_expr_f64_const_expr(uint32_t index,
                                            uint64_t value_bits,
                                            void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  double value;
  memcpy(&value, &value_bits, sizeof(value));
  sctx->printf64("\t.double %.*g\n", DECIMAL_DIG, value);
  sctx->printf("\t.popsection\n");
  sctx->println();

  return Result::Ok;
}

static Result s_on_init_expr_i32_const_expr(uint32_t index,
                                            uint32_t value,
                                            void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  sctx->printi32("\ti32.const %d\n", value);
  sctx->printf("\tend\n");
  sctx->printf("\t.popsection\n");
  sctx->println();

  return Result::Ok;
}

static Result s_on_init_expr_i64_const_expr(uint32_t index,
                                            uint64_t value,
                                            void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  sctx->printi64("\t.di %lld\n", value);
  sctx->printf("\t.popsection\n");
  sctx->println();

  return Result::Ok;
}

static Result s_on_data_segment_data(uint32_t index, const void* data,
                                     uint32_t size, void* user_data)
{
  SContext* sctx = static_cast<SContext*>(user_data);

  for (uint32_t i = 0; i < size; i++)
    sctx->printu("\t.byte 0x%02x\n", (static_cast<const uint8_t*>(data))[i]);

  return Result::Ok;
}

static Result s_on_function_signatures_count(uint32_t count,
                                             void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  sctx->printf("\t.section .wasm.chars.function\n");
  sctx->printu("\t.rept %u\n", count);
  sctx->printf("\t.byte 0\n");
  sctx->printf("\t.endr\n");
  sctx->printf("\t.section .wasm.payload.function\n");

  return Result::Ok;
}

static Result s_on_function_signature(uint32_t index,
                                      uint32_t sig_index,
                                      void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);

  sctx->printu("\trleb128_32 %u\n", sig_index);

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

  s_reader.begin_names_section = s_begin_names_section;
  s_reader.on_function_names_count = s_on_function_names_count;
  s_reader.on_function_name = s_on_function_name;
  s_reader.on_local_names_count = s_on_local_names_count;
  s_reader.on_local_name = s_on_local_name;
  s_reader.end_names_section = s_end_names_section;

  s_reader.begin_reloc_section = s_begin_reloc_section;
  s_reader.on_reloc_count = s_on_reloc_count;
  s_reader.end_reloc_section = s_end_reloc_section;

#endif
  s_reader.on_data_segment_data = s_on_data_segment_data;
  s_reader.on_init_expr_get_global_expr = s_on_init_expr_get_global_expr;
  s_reader.on_init_expr_f32_const_expr = s_on_init_expr_f32_const_expr;
  s_reader.on_init_expr_f64_const_expr = s_on_init_expr_f64_const_expr;
  s_reader.on_init_expr_i32_const_expr = s_on_init_expr_i32_const_expr;
  s_reader.on_init_expr_i64_const_expr = s_on_init_expr_i64_const_expr;
  s_reader.begin_data_section = s_begin_data_section;

  read_binary(data, size, &s_reader, 1, options);
  return Result::Ok;
}

}  // namespace wabt
