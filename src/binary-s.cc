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

static BinaryReaderContext* get_user_context(Context* ctx) {
  ctx->user_ctx.user_data = ctx->reader->user_data;
  ctx->user_ctx.data = ctx->data;
  ctx->user_ctx.size = ctx->data_size;
  ctx->user_ctx.offset = ctx->offset;
  return &ctx->user_ctx;
}

static void WABT_PRINTF_FORMAT(2, 3)
    raise_error(Context* ctx, const char* format, ...) {
  WABT_SNPRINTF_ALLOCA(buffer, length, format);
  if (ctx->reader->on_error) {
    ctx->reader->on_error(get_user_context(ctx), buffer);
  } else {
    /* Not great to just print, but we don't want to eat the error either. */
    fprintf(stderr, "*ERROR*: %s\n", buffer);
  }
  longjmp(ctx->error_jmp_buf, 1);
}

#define IN_SIZE(type)                                       \
  if (ctx->offset + sizeof(type) > ctx->read_end) {         \
    RAISE_ERROR("unable to read " #type ": %s", desc);      \
  }                                                         \
  memcpy(out_value, ctx->data + ctx->offset, sizeof(type)); \
  ctx->offset += sizeof(type)

static void in_u8(Context* ctx, uint8_t* out_value, const char* desc) {
  IN_SIZE(uint8_t);
}

static void in_u32(Context* ctx, uint32_t* out_value, const char* desc) {
  IN_SIZE(uint32_t);
}

static void in_f32(Context* ctx, uint32_t* out_value, const char* desc) {
  IN_SIZE(float);
}

static void in_f64(Context* ctx, uint64_t* out_value, const char* desc) {
  IN_SIZE(double);
}

#undef IN_SIZE

#define BYTE_AT(type, i, shift) ((static_cast<type>(p[i]) & 0x7f) << (shift))

#define LEB128_1(type) (BYTE_AT(type, 0, 0))
#define LEB128_2(type) (BYTE_AT(type, 1, 7) | LEB128_1(type))
#define LEB128_3(type) (BYTE_AT(type, 2, 14) | LEB128_2(type))
#define LEB128_4(type) (BYTE_AT(type, 3, 21) | LEB128_3(type))
#define LEB128_5(type) (BYTE_AT(type, 4, 28) | LEB128_4(type))
#define LEB128_6(type) (BYTE_AT(type, 5, 35) | LEB128_5(type))
#define LEB128_7(type) (BYTE_AT(type, 6, 42) | LEB128_6(type))
#define LEB128_8(type) (BYTE_AT(type, 7, 49) | LEB128_7(type))
#define LEB128_9(type) (BYTE_AT(type, 8, 56) | LEB128_8(type))
#define LEB128_10(type) (BYTE_AT(type, 9, 63) | LEB128_9(type))

#define SHIFT_AMOUNT(type, sign_bit) (sizeof(type) * 8 - 1 - (sign_bit))
#define SIGN_EXTEND(type, value, sign_bit)                       \
  (static_cast<type>((value) << SHIFT_AMOUNT(type, sign_bit)) >> \
   SHIFT_AMOUNT(type, sign_bit))

static void in_u32_leb128(Context* ctx, uint32_t* out_value, const char* desc) {
  const uint8_t* p = ctx->data + ctx->offset;
  const uint8_t* end = ctx->data + ctx->read_end;
  size_t bytes_read = read_u32_leb128(p, end, out_value);
  if (!bytes_read)
    RAISE_ERROR("unable to read u32 leb128: %s", desc);
  ctx->offset += bytes_read;
}

static void in_i32_leb128(Context* ctx, uint32_t* out_value, const char* desc) {
  const uint8_t* p = ctx->data + ctx->offset;
  const uint8_t* end = ctx->data + ctx->read_end;
  size_t bytes_read = read_i32_leb128(p, end, out_value);
  if (!bytes_read)
    RAISE_ERROR("unable to read i32 leb128: %s", desc);
  ctx->offset += bytes_read;
}

static void in_i64_leb128(Context* ctx, uint64_t* out_value, const char* desc) {
  const uint8_t* p = ctx->data + ctx->offset;
  const uint8_t* end = ctx->data + ctx->read_end;

  if (p < end && (p[0] & 0x80) == 0) {
    uint64_t result = LEB128_1(uint64_t);
    *out_value = SIGN_EXTEND(int64_t, result, 6);
    ctx->offset += 1;
  } else if (p + 1 < end && (p[1] & 0x80) == 0) {
    uint64_t result = LEB128_2(uint64_t);
    *out_value = SIGN_EXTEND(int64_t, result, 13);
    ctx->offset += 2;
  } else if (p + 2 < end && (p[2] & 0x80) == 0) {
    uint64_t result = LEB128_3(uint64_t);
    *out_value = SIGN_EXTEND(int64_t, result, 20);
    ctx->offset += 3;
  } else if (p + 3 < end && (p[3] & 0x80) == 0) {
    uint64_t result = LEB128_4(uint64_t);
    *out_value = SIGN_EXTEND(int64_t, result, 27);
    ctx->offset += 4;
  } else if (p + 4 < end && (p[4] & 0x80) == 0) {
    uint64_t result = LEB128_5(uint64_t);
    *out_value = SIGN_EXTEND(int64_t, result, 34);
    ctx->offset += 5;
  } else if (p + 5 < end && (p[5] & 0x80) == 0) {
    uint64_t result = LEB128_6(uint64_t);
    *out_value = SIGN_EXTEND(int64_t, result, 41);
    ctx->offset += 6;
  } else if (p + 6 < end && (p[6] & 0x80) == 0) {
    uint64_t result = LEB128_7(uint64_t);
    *out_value = SIGN_EXTEND(int64_t, result, 48);
    ctx->offset += 7;
  } else if (p + 7 < end && (p[7] & 0x80) == 0) {
    uint64_t result = LEB128_8(uint64_t);
    *out_value = SIGN_EXTEND(int64_t, result, 55);
    ctx->offset += 8;
  } else if (p + 8 < end && (p[8] & 0x80) == 0) {
    uint64_t result = LEB128_9(uint64_t);
    *out_value = SIGN_EXTEND(int64_t, result, 62);
    ctx->offset += 9;
  } else if (p + 9 < end && (p[9] & 0x80) == 0) {
    /* the top bits should be a sign-extension of the sign bit */
    bool sign_bit_set = (p[9] & 0x1);
    int top_bits = p[9] & 0xfe;
    if ((sign_bit_set && top_bits != 0x7e) ||
        (!sign_bit_set && top_bits != 0)) {
      RAISE_ERROR("invalid i64 leb128: %s", desc);
    }
    uint64_t result = LEB128_10(uint64_t);
    *out_value = result;
    ctx->offset += 10;
  } else {
    /* past the end */
    RAISE_ERROR("unable to read i64 leb128: %s", desc);
  }
}

#undef BYTE_AT
#undef LEB128_1
#undef LEB128_2
#undef LEB128_3
#undef LEB128_4
#undef LEB128_5
#undef LEB128_6
#undef LEB128_7
#undef LEB128_8
#undef LEB128_9
#undef LEB128_10
#undef SHIFT_AMOUNT
#undef SIGN_EXTEND

static void in_type(Context* ctx, Type* out_value, const char* desc) {
  uint32_t type = 0;
  in_i32_leb128(ctx, &type, desc);
  /* Must be in the vs7 range: [-128, 127). */
  if (static_cast<int32_t>(type) < -128 || static_cast<int32_t>(type) > 127)
    RAISE_ERROR("invalid type: %d", type);
  *out_value = static_cast<Type>(type);
}

static void in_str(Context* ctx, StringSlice* out_str, const char* desc) {
  uint32_t str_len = 0;
  in_u32_leb128(ctx, &str_len, "string length");

  if (ctx->offset + str_len > ctx->read_end)
    RAISE_ERROR("unable to read string: %s", desc);

  out_str->start = reinterpret_cast<const char*>(ctx->data) + ctx->offset;
  out_str->length = str_len;
  ctx->offset += str_len;
}

static void in_bytes(Context* ctx,
                     const void** out_data,
                     uint32_t* out_data_size,
                     const char* desc) {
  uint32_t data_size = 0;
  in_u32_leb128(ctx, &data_size, "data size");

  if (ctx->offset + data_size > ctx->read_end)
    RAISE_ERROR("unable to read data: %s", desc);

  *out_data = static_cast<const uint8_t*>(ctx->data) + ctx->offset;
  *out_data_size = data_size;
  ctx->offset += data_size;
}

static bool is_valid_external_kind(uint8_t kind) {
  return kind < kExternalKindCount;
}

static bool is_concrete_type(Type type) {
  switch (type) {
    case Type::I32:
    case Type::I64:
    case Type::F32:
    case Type::F64:
      return true;

    default:
      return false;
  }
}

static bool is_inline_sig_type(Type type) {
  return is_concrete_type(type) || type == Type::Void;
}

static uint32_t num_total_funcs(Context* ctx) {
  return ctx->num_func_imports + ctx->num_function_signatures;
}

static uint32_t num_total_tables(Context* ctx) {
  return ctx->num_table_imports + ctx->num_tables;
}

static uint32_t num_total_memories(Context* ctx) {
  return ctx->num_memory_imports + ctx->num_memories;
}

static uint32_t num_total_globals(Context* ctx) {
  return ctx->num_global_imports + ctx->num_globals;
}

static void destroy_context(Context* ctx) {
  destroy_type_vector(&ctx->param_types);
  destroy_uint32_vector(&ctx->target_depths);
}

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
  void printf32(const char* format, float);
  void printf64(const char* format, double);
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

void SContext::printf32(const char* format, float x)
{
  fprintf(f, format, x);
}

void SContext::printf64(const char* format, double x)
{
  fprintf(f, format, x);
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
  sctx->printf32("\tf32.const %f\n", value);

  return Result::Ok;
}

static Result s_on_f64_const_expr(uint64_t value_bits, void* user_data) {
  SContext* sctx = static_cast<SContext*>(user_data);
  double value;
  memcpy(&value, &value_bits, sizeof(value));
  sctx->printf64("\tf64.const %f\n", value);

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
  sctx->printf32("\t.float %f\n", value);
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
  sctx->printf64("\t.double %f\n", value);
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

static void read_init_expr(Context* ctx, uint32_t index) {
  uint8_t opcode;
  in_u8(ctx, &opcode, "opcode");
  switch (static_cast<Opcode>(opcode)) {
    case Opcode::I32Const: {
      uint32_t value = 0;
      in_i32_leb128(ctx, &value, "init_expr i32.const value");
      CALLBACK(on_init_expr_i32_const_expr, index, value);
      break;
    }

    case Opcode::I64Const: {
      uint64_t value = 0;
      in_i64_leb128(ctx, &value, "init_expr i64.const value");
      CALLBACK(on_init_expr_i64_const_expr, index, value);
      break;
    }

    case Opcode::F32Const: {
      uint32_t value_bits = 0;
      in_f32(ctx, &value_bits, "init_expr f32.const value");
      CALLBACK(on_init_expr_f32_const_expr, index, value_bits);
      break;
    }

    case Opcode::F64Const: {
      uint64_t value_bits = 0;
      in_f64(ctx, &value_bits, "init_expr f64.const value");
      CALLBACK(on_init_expr_f64_const_expr, index, value_bits);
      break;
    }

    case Opcode::GetGlobal: {
      uint32_t global_index;
      in_u32_leb128(ctx, &global_index, "init_expr get_global index");
      CALLBACK(on_init_expr_get_global_expr, index, global_index);
      break;
    }

    case Opcode::End:
      return;

    default:
      RAISE_ERROR("unexpected opcode in initializer expression: %d (0x%x)",
                  opcode, opcode);
      break;
  }

  in_u8(ctx, &opcode, "opcode");
  RAISE_ERROR_UNLESS(static_cast<Opcode>(opcode) == Opcode::End,
                     "expected END opcode after initializer expression");
}

static void read_table(Context* ctx,
                       Type* out_elem_type,
                       Limits* out_elem_limits) {
  in_type(ctx, out_elem_type, "table elem type");
  RAISE_ERROR_UNLESS(*out_elem_type == Type::Anyfunc,
                     "table elem type must by anyfunc");

  uint32_t flags;
  uint32_t initial;
  uint32_t max = 0;
  in_u32_leb128(ctx, &flags, "table flags");
  in_u32_leb128(ctx, &initial, "table initial elem count");
  bool has_max = flags & WABT_BINARY_LIMITS_HAS_MAX_FLAG;
  if (has_max) {
    in_u32_leb128(ctx, &max, "table max elem count");
    RAISE_ERROR_UNLESS(initial <= max,
                       "table initial elem count must be <= max elem count");
  }

  out_elem_limits->has_max = has_max;
  out_elem_limits->initial = initial;
  out_elem_limits->max = max;
}

static void read_memory(Context* ctx, Limits* out_page_limits) {
  uint32_t flags;
  uint32_t initial;
  uint32_t max = 0;
  in_u32_leb128(ctx, &flags, "memory flags");
  in_u32_leb128(ctx, &initial, "memory initial page count");
  bool has_max = flags & WABT_BINARY_LIMITS_HAS_MAX_FLAG;
  RAISE_ERROR_UNLESS(initial <= WABT_MAX_PAGES, "invalid memory initial size");
  if (has_max) {
    in_u32_leb128(ctx, &max, "memory max page count");
    RAISE_ERROR_UNLESS(max <= WABT_MAX_PAGES, "invalid memory max size");
    RAISE_ERROR_UNLESS(initial <= max,
                       "memory initial size must be <= max size");
  }

  out_page_limits->has_max = has_max;
  out_page_limits->initial = initial;
  out_page_limits->max = max;
}

static void read_global_header(Context* ctx,
                               Type* out_type,
                               bool* out_mutable) {
  Type global_type;
  uint8_t mutable_;
  in_type(ctx, &global_type, "global type");
  RAISE_ERROR_UNLESS(is_concrete_type(global_type),
                     "expected valid global type");

  in_u8(ctx, &mutable_, "global mutability");
  RAISE_ERROR_UNLESS(mutable_ <= 1, "global mutability must be 0 or 1");

  *out_type = global_type;
  *out_mutable = mutable_;
}

static void read_function_body(Context* ctx, uint32_t end_offset) {
  bool seen_end_opcode = false;
  while (ctx->offset < end_offset) {
    uint8_t opcode_u8;
    in_u8(ctx, &opcode_u8, "opcode");
    Opcode opcode = static_cast<Opcode>(opcode_u8);
    CALLBACK_CTX(on_opcode, opcode);
    switch (opcode) {
      case Opcode::Unreachable:
        CALLBACK0(on_unreachable_expr);
        CALLBACK_CTX0(on_opcode_bare);
        break;

      case Opcode::Block: {
        Type sig_type;
        in_type(ctx, &sig_type, "block signature type");
        RAISE_ERROR_UNLESS(is_inline_sig_type(sig_type),
                           "expected valid block signature type");
        uint32_t num_types = sig_type == Type::Void ? 0 : 1;
        CALLBACK(on_block_expr, num_types, &sig_type);
        CALLBACK_CTX(on_opcode_block_sig, num_types, &sig_type);
        break;
      }

      case Opcode::Loop: {
        Type sig_type;
        in_type(ctx, &sig_type, "loop signature type");
        RAISE_ERROR_UNLESS(is_inline_sig_type(sig_type),
                           "expected valid block signature type");
        uint32_t num_types = sig_type == Type::Void ? 0 : 1;
        CALLBACK(on_loop_expr, num_types, &sig_type);
        CALLBACK_CTX(on_opcode_block_sig, num_types, &sig_type);
        break;
      }

      case Opcode::If: {
        Type sig_type;
        in_type(ctx, &sig_type, "if signature type");
        RAISE_ERROR_UNLESS(is_inline_sig_type(sig_type),
                           "expected valid block signature type");
        uint32_t num_types = sig_type == Type::Void ? 0 : 1;
        CALLBACK(on_if_expr, num_types, &sig_type);
        CALLBACK_CTX(on_opcode_block_sig, num_types, &sig_type);
        break;
      }

      case Opcode::Else:
        CALLBACK0(on_else_expr);
        CALLBACK_CTX0(on_opcode_bare);
        break;

      case Opcode::Select:
        CALLBACK0(on_select_expr);
        CALLBACK_CTX0(on_opcode_bare);
        break;

      case Opcode::Br: {
        uint32_t depth;
        in_u32_leb128(ctx, &depth, "br depth");
        CALLBACK(on_br_expr, depth);
        CALLBACK_CTX(on_opcode_uint32, depth);
        break;
      }

      case Opcode::BrIf: {
        uint32_t depth;
        in_u32_leb128(ctx, &depth, "br_if depth");
        CALLBACK(on_br_if_expr, depth);
        CALLBACK_CTX(on_opcode_uint32, depth);
        break;
      }

      case Opcode::BrTable: {
        uint32_t num_targets;
        in_u32_leb128(ctx, &num_targets, "br_table target count");
        if (num_targets > ctx->target_depths.capacity) {
          reserve_uint32s(&ctx->target_depths, num_targets);
          ctx->target_depths.size = num_targets;
        }

        uint32_t i;
        for (i = 0; i < num_targets; ++i) {
          uint32_t target_depth;
          in_u32_leb128(ctx, &target_depth, "br_table target depth");
          ctx->target_depths.data[i] = target_depth;
        }

        uint32_t default_target_depth;
        in_u32_leb128(ctx, &default_target_depth,
                      "br_table default target depth");

        CALLBACK_CTX(on_br_table_expr, num_targets, ctx->target_depths.data,
                     default_target_depth);
        break;
      }

      case Opcode::Return:
        CALLBACK0(on_return_expr);
        CALLBACK_CTX0(on_opcode_bare);
        break;

      case Opcode::Nop:
        CALLBACK0(on_nop_expr);
        CALLBACK_CTX0(on_opcode_bare);
        break;

      case Opcode::Drop:
        CALLBACK0(on_drop_expr);
        CALLBACK_CTX0(on_opcode_bare);
        break;

      case Opcode::End:
        if (ctx->offset == end_offset)
          seen_end_opcode = true;
        else
          CALLBACK0(on_end_expr);
        break;

      case Opcode::I32Const: {
        uint32_t value = 0;
        in_i32_leb128(ctx, &value, "i32.const value");
        CALLBACK(on_i32_const_expr, value);
        CALLBACK_CTX(on_opcode_uint32, value);
        break;
      }

      case Opcode::I64Const: {
        uint64_t value = 0;
        in_i64_leb128(ctx, &value, "i64.const value");
        CALLBACK(on_i64_const_expr, value);
        CALLBACK_CTX(on_opcode_uint64, value);
        break;
      }

      case Opcode::F32Const: {
        uint32_t value_bits = 0;
        in_f32(ctx, &value_bits, "f32.const value");
        CALLBACK(on_f32_const_expr, value_bits);
        CALLBACK_CTX(on_opcode_f32, value_bits);
        break;
      }

      case Opcode::F64Const: {
        uint64_t value_bits = 0;
        in_f64(ctx, &value_bits, "f64.const value");
        CALLBACK(on_f64_const_expr, value_bits);
        CALLBACK_CTX(on_opcode_f64, value_bits);
        break;
      }

      case Opcode::GetGlobal: {
        uint32_t global_index;
        in_u32_leb128(ctx, &global_index, "get_global global index");
        CALLBACK(on_get_global_expr, global_index);
        CALLBACK_CTX(on_opcode_uint32, global_index);
        break;
      }

      case Opcode::GetLocal: {
        uint32_t local_index;
        in_u32_leb128(ctx, &local_index, "get_local local index");
        CALLBACK(on_get_local_expr, local_index);
        CALLBACK_CTX(on_opcode_uint32, local_index);
        break;
      }

      case Opcode::SetGlobal: {
        uint32_t global_index;
        in_u32_leb128(ctx, &global_index, "set_global global index");
        CALLBACK(on_set_global_expr, global_index);
        CALLBACK_CTX(on_opcode_uint32, global_index);
        break;
      }

      case Opcode::SetLocal: {
        uint32_t local_index;
        in_u32_leb128(ctx, &local_index, "set_local local index");
        CALLBACK(on_set_local_expr, local_index);
        CALLBACK_CTX(on_opcode_uint32, local_index);
        break;
      }

      case Opcode::Call: {
        uint32_t func_index;
        in_u32_leb128(ctx, &func_index, "call function index");
        RAISE_ERROR_UNLESS(func_index < num_total_funcs(ctx),
                           "invalid call function index");
        CALLBACK(on_call_expr, func_index);
        CALLBACK_CTX(on_opcode_uint32, func_index);
        break;
      }

      case Opcode::CallIndirect: {
        uint32_t sig_index;
        in_u32_leb128(ctx, &sig_index, "call_indirect signature index");
        RAISE_ERROR_UNLESS(sig_index < ctx->num_signatures,
                           "invalid call_indirect signature index");
        uint32_t reserved;
        in_u32_leb128(ctx, &reserved, "call_indirect reserved");
        RAISE_ERROR_UNLESS(reserved == 0,
                           "call_indirect reserved value must be 0");
        CALLBACK(on_call_indirect_expr, sig_index);
        CALLBACK_CTX(on_opcode_uint32_uint32, sig_index, reserved);
        break;
      }

      case Opcode::TeeLocal: {
        uint32_t local_index;
        in_u32_leb128(ctx, &local_index, "tee_local local index");
        CALLBACK(on_tee_local_expr, local_index);
        CALLBACK_CTX(on_opcode_uint32, local_index);
        break;
      }

      case Opcode::I32Load8S:
      case Opcode::I32Load8U:
      case Opcode::I32Load16S:
      case Opcode::I32Load16U:
      case Opcode::I64Load8S:
      case Opcode::I64Load8U:
      case Opcode::I64Load16S:
      case Opcode::I64Load16U:
      case Opcode::I64Load32S:
      case Opcode::I64Load32U:
      case Opcode::I32Load:
      case Opcode::I64Load:
      case Opcode::F32Load:
      case Opcode::F64Load: {
        uint32_t alignment_log2;
        in_u32_leb128(ctx, &alignment_log2, "load alignment");
        uint32_t offset;
        in_u32_leb128(ctx, &offset, "load offset");

        CALLBACK(on_load_expr, opcode, alignment_log2, offset);
        CALLBACK_CTX(on_opcode_uint32_uint32, alignment_log2, offset);
        break;
      }

      case Opcode::I32Store8:
      case Opcode::I32Store16:
      case Opcode::I64Store8:
      case Opcode::I64Store16:
      case Opcode::I64Store32:
      case Opcode::I32Store:
      case Opcode::I64Store:
      case Opcode::F32Store:
      case Opcode::F64Store: {
        uint32_t alignment_log2;
        in_u32_leb128(ctx, &alignment_log2, "store alignment");
        uint32_t offset;
        in_u32_leb128(ctx, &offset, "store offset");

        CALLBACK(on_store_expr, opcode, alignment_log2, offset);
        CALLBACK_CTX(on_opcode_uint32_uint32, alignment_log2, offset);
        break;
      }

      case Opcode::CurrentMemory: {
        uint32_t reserved;
        in_u32_leb128(ctx, &reserved, "current_memory reserved");
        RAISE_ERROR_UNLESS(reserved == 0,
                           "current_memory reserved value must be 0");
        CALLBACK0(on_current_memory_expr);
        CALLBACK_CTX(on_opcode_uint32, reserved);
        break;
      }

      case Opcode::GrowMemory: {
        uint32_t reserved;
        in_u32_leb128(ctx, &reserved, "grow_memory reserved");
        RAISE_ERROR_UNLESS(reserved == 0,
                           "grow_memory reserved value must be 0");
        CALLBACK0(on_grow_memory_expr);
        CALLBACK_CTX(on_opcode_uint32, reserved);
        break;
      }

      case Opcode::I32Add:
      case Opcode::I32Sub:
      case Opcode::I32Mul:
      case Opcode::I32DivS:
      case Opcode::I32DivU:
      case Opcode::I32RemS:
      case Opcode::I32RemU:
      case Opcode::I32And:
      case Opcode::I32Or:
      case Opcode::I32Xor:
      case Opcode::I32Shl:
      case Opcode::I32ShrU:
      case Opcode::I32ShrS:
      case Opcode::I32Rotr:
      case Opcode::I32Rotl:
      case Opcode::I64Add:
      case Opcode::I64Sub:
      case Opcode::I64Mul:
      case Opcode::I64DivS:
      case Opcode::I64DivU:
      case Opcode::I64RemS:
      case Opcode::I64RemU:
      case Opcode::I64And:
      case Opcode::I64Or:
      case Opcode::I64Xor:
      case Opcode::I64Shl:
      case Opcode::I64ShrU:
      case Opcode::I64ShrS:
      case Opcode::I64Rotr:
      case Opcode::I64Rotl:
      case Opcode::F32Add:
      case Opcode::F32Sub:
      case Opcode::F32Mul:
      case Opcode::F32Div:
      case Opcode::F32Min:
      case Opcode::F32Max:
      case Opcode::F32Copysign:
      case Opcode::F64Add:
      case Opcode::F64Sub:
      case Opcode::F64Mul:
      case Opcode::F64Div:
      case Opcode::F64Min:
      case Opcode::F64Max:
      case Opcode::F64Copysign:
        CALLBACK(on_binary_expr, opcode);
        CALLBACK_CTX0(on_opcode_bare);
        break;

      case Opcode::I32Eq:
      case Opcode::I32Ne:
      case Opcode::I32LtS:
      case Opcode::I32LeS:
      case Opcode::I32LtU:
      case Opcode::I32LeU:
      case Opcode::I32GtS:
      case Opcode::I32GeS:
      case Opcode::I32GtU:
      case Opcode::I32GeU:
      case Opcode::I64Eq:
      case Opcode::I64Ne:
      case Opcode::I64LtS:
      case Opcode::I64LeS:
      case Opcode::I64LtU:
      case Opcode::I64LeU:
      case Opcode::I64GtS:
      case Opcode::I64GeS:
      case Opcode::I64GtU:
      case Opcode::I64GeU:
      case Opcode::F32Eq:
      case Opcode::F32Ne:
      case Opcode::F32Lt:
      case Opcode::F32Le:
      case Opcode::F32Gt:
      case Opcode::F32Ge:
      case Opcode::F64Eq:
      case Opcode::F64Ne:
      case Opcode::F64Lt:
      case Opcode::F64Le:
      case Opcode::F64Gt:
      case Opcode::F64Ge:
        CALLBACK(on_compare_expr, opcode);
        CALLBACK_CTX0(on_opcode_bare);
        break;

      case Opcode::I32Clz:
      case Opcode::I32Ctz:
      case Opcode::I32Popcnt:
      case Opcode::I64Clz:
      case Opcode::I64Ctz:
      case Opcode::I64Popcnt:
      case Opcode::F32Abs:
      case Opcode::F32Neg:
      case Opcode::F32Ceil:
      case Opcode::F32Floor:
      case Opcode::F32Trunc:
      case Opcode::F32Nearest:
      case Opcode::F32Sqrt:
      case Opcode::F64Abs:
      case Opcode::F64Neg:
      case Opcode::F64Ceil:
      case Opcode::F64Floor:
      case Opcode::F64Trunc:
      case Opcode::F64Nearest:
      case Opcode::F64Sqrt:
        CALLBACK(on_unary_expr, opcode);
        CALLBACK_CTX0(on_opcode_bare);
        break;

      case Opcode::I32TruncSF32:
      case Opcode::I32TruncSF64:
      case Opcode::I32TruncUF32:
      case Opcode::I32TruncUF64:
      case Opcode::I32WrapI64:
      case Opcode::I64TruncSF32:
      case Opcode::I64TruncSF64:
      case Opcode::I64TruncUF32:
      case Opcode::I64TruncUF64:
      case Opcode::I64ExtendSI32:
      case Opcode::I64ExtendUI32:
      case Opcode::F32ConvertSI32:
      case Opcode::F32ConvertUI32:
      case Opcode::F32ConvertSI64:
      case Opcode::F32ConvertUI64:
      case Opcode::F32DemoteF64:
      case Opcode::F32ReinterpretI32:
      case Opcode::F64ConvertSI32:
      case Opcode::F64ConvertUI32:
      case Opcode::F64ConvertSI64:
      case Opcode::F64ConvertUI64:
      case Opcode::F64PromoteF32:
      case Opcode::F64ReinterpretI64:
      case Opcode::I32ReinterpretF32:
      case Opcode::I64ReinterpretF64:
      case Opcode::I32Eqz:
      case Opcode::I64Eqz:
        CALLBACK(on_convert_expr, opcode);
        CALLBACK_CTX0(on_opcode_bare);
        break;

      default:
        RAISE_ERROR("unexpected opcode: %d (0x%x)", static_cast<int>(opcode),
                    static_cast<unsigned>(opcode));
    }
  }
  RAISE_ERROR_UNLESS(ctx->offset == end_offset,
                     "function body longer than given size");
  RAISE_ERROR_UNLESS(seen_end_opcode, "function body must end with END opcode");
}

static void read_custom_section(Context* ctx, uint32_t section_size) {
  StringSlice section_name;
  in_str(ctx, &section_name, "section name");
  CALLBACK_CTX(begin_custom_section, section_size, section_name);

  bool name_section_ok = ctx->last_known_section >= BinarySection::Import;
  if (ctx->options->read_debug_names && name_section_ok &&
      strncmp(section_name.start, WABT_BINARY_SECTION_NAME,
              section_name.length) == 0) {
    CALLBACK_SECTION(begin_names_section, section_size);
    uint32_t i, num_functions;
    in_u32_leb128(ctx, &num_functions, "function name count");
    CALLBACK(on_function_names_count, num_functions);
    for (i = 0; i < num_functions; ++i) {
      StringSlice function_name;
      in_str(ctx, &function_name, "function name");
      CALLBACK(on_function_name, i, function_name);

      uint32_t num_locals;
      in_u32_leb128(ctx, &num_locals, "local name count");
      CALLBACK(on_local_names_count, i, num_locals);
      uint32_t j;
      for (j = 0; j < num_locals; ++j) {
        StringSlice local_name;
        in_str(ctx, &local_name, "local name");
        CALLBACK(on_local_name, i, j, local_name);
      }
    }
    CALLBACK_CTX0(end_names_section);
  } else if (strncmp(section_name.start, WABT_BINARY_SECTION_RELOC,
                     strlen(WABT_BINARY_SECTION_RELOC)) == 0) {
    CALLBACK_SECTION(begin_reloc_section, section_size);
    uint32_t i, num_relocs, section;
    in_u32_leb128(ctx, &section, "section");
    WABT_ZERO_MEMORY(section_name);
    if (static_cast<BinarySection>(section) == BinarySection::Custom)
      in_str(ctx, &section_name, "section name");
    in_u32_leb128(ctx, &num_relocs, "relocation count");
    CALLBACK(on_reloc_count, num_relocs, static_cast<BinarySection>(section),
             section_name);
    for (i = 0; i < num_relocs; ++i) {
      uint32_t reloc_type, offset;
      in_u32_leb128(ctx, &reloc_type, "relocation type");
      in_u32_leb128(ctx, &offset, "offset");
      CALLBACK(on_reloc, static_cast<RelocType>(reloc_type), offset);
    }
    CALLBACK_CTX0(end_reloc_section);
  } else {
    /* This is an unknown custom section, skip it. */
    ctx->offset = ctx->read_end;
  }
  CALLBACK_CTX0(end_custom_section);
}

static void read_type_section(Context* ctx, uint32_t section_size) {
  CALLBACK_SECTION(begin_signature_section, section_size);
  uint32_t i;
  in_u32_leb128(ctx, &ctx->num_signatures, "type count");
  CALLBACK(on_signature_count, ctx->num_signatures);

  for (i = 0; i < ctx->num_signatures; ++i) {
    Type form;
    in_type(ctx, &form, "type form");
    RAISE_ERROR_UNLESS(form == Type::Func, "unexpected type form");

    uint32_t num_params;
    in_u32_leb128(ctx, &num_params, "function param count");

    if (num_params > ctx->param_types.capacity)
      reserve_types(&ctx->param_types, num_params);

    uint32_t j;
    for (j = 0; j < num_params; ++j) {
      Type param_type;
      in_type(ctx, &param_type, "function param type");
      RAISE_ERROR_UNLESS(is_concrete_type(param_type),
                         "expected valid param type");
      ctx->param_types.data[j] = param_type;
    }

    uint32_t num_results;
    in_u32_leb128(ctx, &num_results, "function result count");
    RAISE_ERROR_UNLESS(num_results <= 1, "result count must be 0 or 1");

    Type result_type = Type::Void;
    if (num_results) {
      in_type(ctx, &result_type, "function result type");
      RAISE_ERROR_UNLESS(is_concrete_type(result_type),
                         "expected valid result type");
    }

    CALLBACK(on_signature, i, num_params, ctx->param_types.data, num_results,
             &result_type);
  }
  CALLBACK_CTX0(end_signature_section);
}

static void read_import_section(Context* ctx, uint32_t section_size) {
  CALLBACK_SECTION(begin_import_section, section_size);
  uint32_t i;
  in_u32_leb128(ctx, &ctx->num_imports, "import count");
  CALLBACK(on_import_count, ctx->num_imports);
  for (i = 0; i < ctx->num_imports; ++i) {
    StringSlice module_name;
    in_str(ctx, &module_name, "import module name");
    StringSlice field_name;
    in_str(ctx, &field_name, "import field name");
    CALLBACK(on_import, i, module_name, field_name);

    uint32_t kind;
    in_u32_leb128(ctx, &kind, "import kind");
    switch (static_cast<ExternalKind>(kind)) {
      case ExternalKind::Func: {
        uint32_t sig_index;
        in_u32_leb128(ctx, &sig_index, "import signature index");
        RAISE_ERROR_UNLESS(sig_index < ctx->num_signatures,
                           "invalid import signature index");
        CALLBACK(on_import_func, i, ctx->num_func_imports, sig_index);
        ctx->num_func_imports++;
        break;
      }

      case ExternalKind::Table: {
        Type elem_type;
        Limits elem_limits;
        read_table(ctx, &elem_type, &elem_limits);
        CALLBACK(on_import_table, i, ctx->num_table_imports, elem_type,
                 &elem_limits);
        ctx->num_table_imports++;
        break;
      }

      case ExternalKind::Memory: {
        Limits page_limits;
        read_memory(ctx, &page_limits);
        CALLBACK(on_import_memory, i, ctx->num_memory_imports, &page_limits);
        ctx->num_memory_imports++;
        break;
      }

      case ExternalKind::Global: {
        Type type;
        bool mutable_;
        read_global_header(ctx, &type, &mutable_);
        CALLBACK(on_import_global, i, ctx->num_global_imports, type, mutable_);
        ctx->num_global_imports++;
        break;
      }

      default:
        RAISE_ERROR("invalid import kind: %d", kind);
    }
  }
  CALLBACK_CTX0(end_import_section);
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

static void read_function_section(Context* ctx, uint32_t section_size) {
  CALLBACK_SECTION(begin_function_signatures_section, section_size);
  uint32_t i;
  in_u32_leb128(ctx, &ctx->num_function_signatures, "function signature count");
  CALLBACK(on_function_signatures_count, ctx->num_function_signatures);
  for (i = 0; i < ctx->num_function_signatures; ++i) {
    uint32_t func_index = ctx->num_func_imports + i;
    uint32_t sig_index;
    in_u32_leb128(ctx, &sig_index, "function signature index");
    RAISE_ERROR_UNLESS(sig_index < ctx->num_signatures,
                       "invalid function signature index: %d", sig_index);
    CALLBACK(on_function_signature, func_index, sig_index);
  }
  CALLBACK_CTX0(end_function_signatures_section);
}

static void read_table_section(Context* ctx, uint32_t section_size) {
  CALLBACK_SECTION(begin_table_section, section_size);
  uint32_t i;
  in_u32_leb128(ctx, &ctx->num_tables, "table count");
  RAISE_ERROR_UNLESS(ctx->num_tables <= 1, "table count (%d) must be 0 or 1",
                     ctx->num_tables);
  CALLBACK(on_table_count, ctx->num_tables);
  for (i = 0; i < ctx->num_tables; ++i) {
    uint32_t table_index = ctx->num_table_imports + i;
    Type elem_type;
    Limits elem_limits;
    read_table(ctx, &elem_type, &elem_limits);
    CALLBACK(on_table, table_index, elem_type, &elem_limits);
  }
  CALLBACK_CTX0(end_table_section);
}

static void read_memory_section(Context* ctx, uint32_t section_size) {
  CALLBACK_SECTION(begin_memory_section, section_size);
  uint32_t i;
  in_u32_leb128(ctx, &ctx->num_memories, "memory count");
  RAISE_ERROR_UNLESS(ctx->num_memories <= 1, "memory count must be 0 or 1");
  CALLBACK(on_memory_count, ctx->num_memories);
  for (i = 0; i < ctx->num_memories; ++i) {
    uint32_t memory_index = ctx->num_memory_imports + i;
    Limits page_limits;
    read_memory(ctx, &page_limits);
    CALLBACK(on_memory, memory_index, &page_limits);
  }
  CALLBACK_CTX0(end_memory_section);
}

static void read_global_section(Context* ctx, uint32_t section_size) {
  CALLBACK_SECTION(begin_global_section, section_size);
  uint32_t i;
  in_u32_leb128(ctx, &ctx->num_globals, "global count");
  CALLBACK(on_global_count, ctx->num_globals);
  for (i = 0; i < ctx->num_globals; ++i) {
    uint32_t global_index = ctx->num_global_imports + i;
    Type global_type;
    bool mutable_;
    read_global_header(ctx, &global_type, &mutable_);
    CALLBACK(begin_global, global_index, global_type, mutable_);
    CALLBACK(begin_global_init_expr, global_index);
    read_init_expr(ctx, global_index);
    CALLBACK(end_global_init_expr, global_index);
    CALLBACK(end_global, global_index);
  }
  CALLBACK_CTX0(end_global_section);
}

static void read_export_section(Context* ctx, uint32_t section_size) {
  CALLBACK_SECTION(begin_export_section, section_size);
  uint32_t i;
  in_u32_leb128(ctx, &ctx->num_exports, "export count");
  CALLBACK(on_export_count, ctx->num_exports);
  for (i = 0; i < ctx->num_exports; ++i) {
    StringSlice name;
    in_str(ctx, &name, "export item name");

    uint8_t external_kind;
    in_u8(ctx, &external_kind, "export external kind");
    RAISE_ERROR_UNLESS(is_valid_external_kind(external_kind),
                       "invalid export external kind");

    uint32_t item_index;
    in_u32_leb128(ctx, &item_index, "export item index");
    switch (static_cast<ExternalKind>(external_kind)) {
      case ExternalKind::Func:
        RAISE_ERROR_UNLESS(item_index < num_total_funcs(ctx),
                           "invalid export func index: %d", item_index);
        break;
      case ExternalKind::Table:
        RAISE_ERROR_UNLESS(item_index < num_total_tables(ctx),
                           "invalid export table index");
        break;
      case ExternalKind::Memory:
        RAISE_ERROR_UNLESS(item_index < num_total_memories(ctx),
                           "invalid export memory index");
        break;
      case ExternalKind::Global:
        RAISE_ERROR_UNLESS(item_index < num_total_globals(ctx),
                           "invalid export global index");
        break;
    }

    CALLBACK(on_export, i, static_cast<ExternalKind>(external_kind), item_index,
             name);
  }
  CALLBACK_CTX0(end_export_section);
}

static void read_start_section(Context* ctx, uint32_t section_size) {
  CALLBACK_SECTION(begin_start_section, section_size);
  uint32_t func_index;
  in_u32_leb128(ctx, &func_index, "start function index");
  RAISE_ERROR_UNLESS(func_index < num_total_funcs(ctx),
                     "invalid start function index");
  CALLBACK(on_start_function, func_index);
  CALLBACK_CTX0(end_start_section);
}

static void read_elem_section(Context* ctx, uint32_t section_size) {
  CALLBACK_SECTION(begin_elem_section, section_size);
  uint32_t i, num_elem_segments;
  in_u32_leb128(ctx, &num_elem_segments, "elem segment count");
  CALLBACK(on_elem_segment_count, num_elem_segments);
  RAISE_ERROR_UNLESS(num_elem_segments == 0 || num_total_tables(ctx) > 0,
                     "elem section without table section");
  for (i = 0; i < num_elem_segments; ++i) {
    uint32_t table_index;
    in_u32_leb128(ctx, &table_index, "elem segment table index");
    CALLBACK(begin_elem_segment, i, table_index);
    CALLBACK(begin_elem_segment_init_expr, i);
    read_init_expr(ctx, i);
    CALLBACK(end_elem_segment_init_expr, i);

    uint32_t j, num_function_indexes;
    in_u32_leb128(ctx, &num_function_indexes,
                  "elem segment function index count");
    CALLBACK_CTX(on_elem_segment_function_index_count, i, num_function_indexes);
    for (j = 0; j < num_function_indexes; ++j) {
      uint32_t func_index;
      in_u32_leb128(ctx, &func_index, "elem segment function index");
      CALLBACK(on_elem_segment_function_index, i, func_index);
    }
    CALLBACK(end_elem_segment, i);
  }
  CALLBACK_CTX0(end_elem_section);
}

static void read_code_section(Context* ctx, uint32_t section_size) {
  CALLBACK_SECTION(begin_function_bodies_section, section_size);
  uint32_t i;
  in_u32_leb128(ctx, &ctx->num_function_bodies, "function body count");
  RAISE_ERROR_UNLESS(ctx->num_function_signatures == ctx->num_function_bodies,
                     "function signature count != function body count");
  CALLBACK(on_function_bodies_count, ctx->num_function_bodies);
  for (i = 0; i < ctx->num_function_bodies; ++i) {
    uint32_t func_index = ctx->num_func_imports + i;
    uint32_t func_offset = ctx->offset;
    ctx->offset = func_offset;
    CALLBACK_CTX(begin_function_body, func_index);
    uint32_t body_size;
    in_u32_leb128(ctx, &body_size, "function body size");
    uint32_t body_start_offset = ctx->offset;
    uint32_t end_offset = body_start_offset + body_size;

    uint32_t num_local_decls;
    in_u32_leb128(ctx, &num_local_decls, "local declaration count");
    CALLBACK(on_local_decl_count, num_local_decls);
    uint32_t k;
    for (k = 0; k < num_local_decls; ++k) {
      uint32_t num_local_types;
      in_u32_leb128(ctx, &num_local_types, "local type count");
      Type local_type;
      in_type(ctx, &local_type, "local type");
      RAISE_ERROR_UNLESS(is_concrete_type(local_type),
                         "expected valid local type");
      CALLBACK(on_local_decl, k, num_local_types, local_type);
    }

    read_function_body(ctx, end_offset);

    CALLBACK(end_function_body, func_index);
  }
  CALLBACK_CTX0(end_function_bodies_section);
}

static void read_data_section(Context* ctx, uint32_t section_size) {
  CALLBACK_SECTION(begin_data_section, section_size);
  uint32_t i, num_data_segments;
  in_u32_leb128(ctx, &num_data_segments, "data segment count");
  CALLBACK(on_data_segment_count, num_data_segments);
  RAISE_ERROR_UNLESS(num_data_segments == 0 || num_total_memories(ctx) > 0,
                     "data section without memory section");
  for (i = 0; i < num_data_segments; ++i) {
    uint32_t memory_index;
    in_u32_leb128(ctx, &memory_index, "data segment memory index");
    CALLBACK(begin_data_segment, i, memory_index);
    CALLBACK(begin_data_segment_init_expr, i);
    read_init_expr(ctx, i);
    CALLBACK(end_data_segment_init_expr, i);

    uint32_t data_size;
    const void* data;
    in_bytes(ctx, &data, &data_size, "data segment data");
    CALLBACK(on_data_segment_data, i, data, data_size);
    CALLBACK(end_data_segment, i);
  }
  CALLBACK_CTX0(end_data_section);
}

static void read_sections(Context* ctx) {
  while (ctx->offset < ctx->data_size) {
    uint32_t section_code;
    uint32_t section_size;
    /* Temporarily reset read_end to the full data size so the next section
     * can be read. */
    ctx->read_end = ctx->data_size;
    in_u32_leb128(ctx, &section_code, "section code");
    in_u32_leb128(ctx, &section_size, "section size");
    ctx->read_end = ctx->offset + section_size;
    if (section_code >= kBinarySectionCount) {
      RAISE_ERROR("invalid section code: %u; max is %u", section_code,
                  kBinarySectionCount - 1);
    }

    BinarySection section = static_cast<BinarySection>(section_code);

    if (ctx->read_end > ctx->data_size)
      RAISE_ERROR("invalid section size: extends past end");

    if (ctx->last_known_section != BinarySection::Invalid &&
        section != BinarySection::Custom &&
        section <= ctx->last_known_section) {
      RAISE_ERROR("section %s out of order", get_section_name(section));
    }

    CALLBACK_CTX(begin_section, section, section_size);

#define V(Name, name, code)                   \
  case BinarySection::Name:                   \
    read_##name##_section(ctx, section_size); \
    break;

    switch (section) {
      WABT_FOREACH_BINARY_SECTION(V)

      default:
        assert(0);
        break;
    }

#undef V

    if (ctx->offset != ctx->read_end) {
      RAISE_ERROR("unfinished section (expected end: 0x%" PRIzx ")",
                  ctx->read_end);
    }

    if (section != BinarySection::Custom)
      ctx->last_known_section = section;
  }
}

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

  Context context;
  WABT_ZERO_MEMORY(context);
  /* all the macros assume a Context* named ctx */
  Context* ctx = &context;
  ctx->data = static_cast<const uint8_t*>(data);
  ctx->data_size = ctx->read_end = size;
  ctx->reader = &s_reader;
  ctx->options = options;
  ctx->last_known_section = BinarySection::Invalid;

  if (setjmp(ctx->error_jmp_buf) == 1) {
    destroy_context(ctx);
    return Result::Error;
  }

  reserve_types(&ctx->param_types, INITIAL_PARAM_TYPES_CAPACITY);
  reserve_uint32s(&ctx->target_depths, INITIAL_BR_TABLE_TARGET_CAPACITY);

  uint32_t magic;
  in_u32(ctx, &magic, "magic");
  RAISE_ERROR_UNLESS(magic == WABT_BINARY_MAGIC, "bad magic value");
  uint32_t version;
  in_u32(ctx, &version, "version");
  RAISE_ERROR_UNLESS(version == WABT_BINARY_VERSION,
                     "bad wasm file version: %#x (expected %#x)", version,
                     WABT_BINARY_VERSION);

  CALLBACK(begin_module, version);
  read_sections(ctx);
  CALLBACK0(end_module);
  destroy_context(ctx);
  return Result::Ok;
}

}  // namespace wabt
