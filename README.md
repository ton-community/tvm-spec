# TVM Instructions Specification

There is ~365 instructions in TVM, so it's quite painful to implement tools such as disassembler, decompiler, etc.
This repo's goal is to provide machine-readable (JSON) description of TVM instructions: bytecode format, value flow,
control flow and implementation information.

| Codepage | Specification                                     |
|----------|---------------------------------------------------|
| 0        | [cp0.json](./cp0.json) (**current**)              |
| -        | [cp0_legacy.json](./cp0_legacy.json) (**legacy**) |

## Files Overview

| File/Folder                                                  | Purpose                                                                                   |
|--------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| [`.github/workflows/`](.github/workflows)                    | CI for JSON/schema validation, matcher output checks                                      |
| [`matcher/`](matcher)                                        | Python scripts that extract `exec_*` C++ functions and match them to mnemonics            |
| [`cp0.json`](cp0.json)                                       | Current maintained spec (~365 instructions)                                               |
| [`cp0_legacy.json`](cp0_legacy.json)                         | Older file with 800+ instructions — still useful for comparison                           |
| [`match-report.json`](match-report.json)                     | Output from matcher scripts with C++ line/function mapping                                |
| [`schema.json`](schema.json)                                 | JSON schema definition for runtime validation                                             |
| [`schema.ts`](schema.ts)                                     | TypeScript schema for editor tooling, autocomplete, and static typing                     |
| [`update-cp0.py`](update-cp0.py)                             | Script for regenerating `cp0.json`                                                        |
| [`common-instructions.txt`](common-instructions.txt)         | List of the ~365 core instructions                                                        |
| [`matcher/matcher-all.py`](matcher/matcher-all.py)           | Runner for executing all matcher modules (stack, arith, etc.)                             |
| [`ton-blockchain.revision.txt`](ton-blockchain.revision.txt) | revision of [ton-blockchain/ton](https://github.com/ton-blockchain/ton) used for TVM sync |

## Features

| JSON key       | Status        | Description                                                                                                                                                                                                                                                                                  |
|----------------|---------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| doc            | ✅ Implemented | Provides human-readable information about instructions. Can be useful to provide integrated docs to user, for example, in disassembler.                                                                                                                                                      |
| bytecode       | ✅ Implemented | Describes instruction encoding. It contains information to build assemblers and disassemblers.                                                                                                                                                                                               |
| value_flow     | ✅ Implemented | Describes how instruction changes current stack. This part of specification allows to analyze how instructions interact with each other, so it becomes possible to implement high-level tools such as decompilers.                                                                           |
| control_flow   | ✅ Implemented | Describes code flow (operations with cc register). It helps to reconstruct a control flow graph. This part mainly contains semantics of cont_* category instructions. For example, both JMPX and CALLX transfers execution to continuation on stack, but only CALLX returns and JMPX is not. |
| aliases        | ✅ Implemented | Specifies instruction aliases. Can be used to provide to user information about special cases (for example, SWAP is a special case of XCHG_0i with i = 1).                                                                                                                                   |
| implementation | ✅ Implemented | Maps mnemonics to C++ source: function name, line number, and file path from the TON codebase. Helps trace and verify runtime behavior.                                                                                                                                                      |

## Usage

Convenient way is to add submodule to your tool. This will greatly simplify debugging and upgrading process.

```bash
git submodule add https://github.com/ton-community/tvm-spec
```

However, nothing can stop you from just copying `cp0.json` (and `schema.json` if necessary).

## Projects based on tvm-spec

1. [tvm-spec-example](https://github.com/hacker-volodya/tvm-spec-example), tiny TVM disassembler
2. [tvm-research](https://github.com/hacker-volodya/tvm-research), collection of tool prototypes with the power of
   tvm-spec
3. [ton-opcode](https://github.com/tact-lang/ton-opcode), full-fledged TVM disassembler

## Instruction Specification Example

```json
{
  "mnemonic": "XCHG_0I",
  "since_version": 0,
  "doc": {
    "category": "stack_basic",
    "description": "Interchanges `s0` with `s[i]`, `1 <= i <= 15`.",
    "gas": "18",
    "fift": "s[i] XCHG0",
    "fift_examples": [],
    "opcode": "0i",
    "stack": ""
  },
  "bytecode": {
    "tlb": "#0 i:(## 4) {1 <= i}",
    "prefix": "0",
    "operands_range_check": { "length": 4, "from": 1, "to": 15 },
    "operands": [
      {
        "name": "i",
        "type": "uint",
        "size": 4,
        "min_value": 1,
        "max_value": 15,
        "display_hints": [
          { "type": "stack" }
        ]
      }
    ]
  },
  "value_flow": {
    "inputs": { "registers": [] },
    "outputs": { "registers": [] }
  },
  "control_flow": { "branches": [], "nobranch": true },
  "implementation": [
    {
      "file": "stackops.cpp",
      "path": "https://raw.githubusercontent.com/ton-blockchain/ton/cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/stackops.cpp",
      "line": 43,
      "function_name": "exec_xchg0"
    }
  ]
}

```

### Documentation

| Key                                 | Description                                                                                                                                                                                                                                                       |
|-------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| mnemonic                            | How instruction is named in [original TVM implementation](https://github.com/ton-blockchain/ton/blob/master/crypto/vm). Not necessarily unique (currently only DEBUG is not unique). Required.                                                                    |
| since_version                       | Global version (ConfigParam 8) which enables this instruction. Version 9999 means that instruction has no global version and currently unavailable in mainnet.                                                                                                    |
| doc                                 | Free-form human-friendly information which should be used for documentation purposes only. Required.                                                                                                                                                              |
| doc.category                        | Category of instruction (examples: cont_loops, stack_basic, dict_get). Required.                                                                                                                                                                                  |
| doc.description                     | Free-form markdown description of instruction. Required.                                                                                                                                                                                                          |
| doc.gas                             | Free-form description of gas amount used by instruction. Required.                                                                                                                                                                                                |
| doc.fift                            | Free-form fift usage description. Required.                                                                                                                                                                                                                       |
| doc.fift_examples                   | Array of usage examples in Fift. Each array element is object with `fift` and `description` keys. Required.                                                                                                                                                       |
| doc.opcode                          | Free-form bytecode format description. Required.                                                                                                                                                                                                                  |
| doc.stack                           | Free-form description of stack inputs and outputs. Usually the form is `[inputs] - [outputs]` where `[inputs]` are consumed stack values and `outputs` are produced stack values (top of stack is the last value). Required.                                      |
| bytecode                            | Information related to bytecode format of an instruction. Assuming that each instruction has format `prefix \|\| operand_1 \|\| operand_2 \|\| ...` (also some operands may be refs, not bitstring part). Required.                                               |
| bytecode.tlb                        | TL-b bytecode format description. Required.                                                                                                                                                                                                                       |
| bytecode.prefix                     | Prefix to determine next instruction to parse. It is a hex bitstring as in TL-b (suffixed with `_` if bit length is not divisible by 4, trailing `'1' + '0' * x` must be removed). Required.                                                                      |
| bytecode.operands_range_check       | In TVM, it is possible for instructions to have overlapping prefixes, so to determine actual instruction it is required to read next `length` bits after prefix as uint `i` and check `from <= i <= to`. Optional, there is no operands check in case of absence. |
| bytecode.operands                   | Describes how to parse operands. Order of objects in this array represents the actual order of operands in instruction. Required.                                                                                                                                 |
| bytecode.operands[i].name           | Operand variable name. Allowed chars are `a-zA-Z0-9_`, must not begin with digit or underscore and must not end with underscore. Required.                                                                                                                        |
| bytecode.operands[i].type           | Type of operand. Must be one of `int`, `uint`, `ref`, `pushint_long`, `subslice`. Types are described below. Required.                                                                                                                                            |
| bytecode.operands[i].*              | Additional options for types, specified below.                                                                                                                                                                                                                    |
| value_flow                          | Information related to usage of stack and registers by instruction. Required.                                                                                                                                                                                     |
| value_flow.inputs                   | Incoming values constraints. Required.                                                                                                                                                                                                                            |
| value_flow.inputs.registers         | Defines how registers is used by instruction. Instruction must not operate on registers other than defined here. Required.                                                                                                                                        |
| value_flow.inputs.registers[i]      | Register which is access by instruction.                                                                                                                                                                                                                          |
| value_flow.inputs.registers[i].type | Type of register: "constant", "variable", "special". Required.                                                                                                                                                                                                    |
| value_flow.inputs.registers[i].*    | Properties for registers of each type are described below.                                                                                                                                                                                                        |
| value_flow.inputs.stack             | Defines how current stack is used by instruction. Instruction must not operate on stack entries other than defined here. Optional, input stack is unconstrained if absent.                                                                                        |
| value_flow.inputs.stack[i]          | Stack entry or group of stack entries.                                                                                                                                                                                                                            |
| value_flow.inputs.stack[i].type     | Type of stack entry. Can be one of "simple", "const", "conditional", "array". Required.                                                                                                                                                                           |
| value_flow.inputs.stack[i].*        | Properties for stack entries of each type are described below.                                                                                                                                                                                                    |
| value_flow.outputs                  | Outgoing values constraints. Required. Identical to value_flow.inputs.                                                                                                                                                                                            |
| control_flow                        | Information related to current cc modification by instruction. Required.                                                                                                                                                                                          |
| control_flow.branches               | Array of possible branches of an instruction. Specifies all possible values of cc after instruction execution. Required. Each branch described by a `Continuation` object described below.                                                                        |
| control_flow.nobranch               | Can this instruction not perform any of specified branches in certain cases (do not modify cc)? Required. If instruction has no control flow, nobranch is true and branches are empty.                                                                            |
| implementation                      | Array of source mappings that define where this instruction is implemented in the TON C++ codebase. Includes `file`, `path`, `line`, and `function_name`. Optional but recommended.                                                                               |

### Operand Types Specification and Examples

`display_hints` property is available for `uint`, `int`, `ref` and `subslice` operand types. For `ref` and `subslice`
there is `continuation` and `dictionary` hint types, and for `uint` there is `add`, `stack`, `register`, `pushint4`,
`optional_nargs` and `plduz` hints.

| display_hints[i].type | Description                                                                                                                                               |
|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| continuation          | Slice from this operand (type = ref, subslice) is a continuation.                                                                                         |
| dictionary            | Slice from this operand (type = ref, subslice) is a dictionary with key size defined in `size_var` property of a hint.                                    |
| add                   | Some constant must be added in order to correctly display this operand (type = uint). `[cc+1] LDU` <=> `{ "type": "add", "value": 1 }`.                   |
| stack                 | This operand (type = uint) is a stack entry reference (`s0` for example).                                                                                 |
| register              | This operand (type = uint) is a register reference (`c0` for example).                                                                                    |
| pushint4              | To display this operand (type = uint), 16 must be substracted, but only if operand value > 10. For example, 0xF displayed as -1, 0xA is 10 and 0xB is -5. |
| optional_nargs        | 0xF is displayed as -1, other values left untouched (type = uint).                                                                                        |
| plduz                 | This operand (type = uint) is displayed as `32*(c+1)`. If value is not divisible by 32 during assembly, error should be raised.                           |

#### uint

```json
{
  "name": "i",
  "type": "uint",
  "size": 4,
  "min_value": 0,
  "max_value": 15,
  "display_hints": [{ "type": "stack" }, { "type": "add", "value": 1 }]
}
```

Type of unsigned `size`-bit integer with valid values in range `min_value`...`max_value`. Arguments `size`, `min_value`,
`max_value` of type `number` and `display_hints` of type `array` are required.

#### int

```json
{
  "name": "i",
  "type": "int",
  "size": 4,
  "min_value": -8,
  "max_value": 7,
  "display_hints": []
}
```

Type of signed `size`-bit integer with valid values in range `min_value`...`max_value`. Arguments `size`, `min_value`,
`max_value` of type `number` and `display_hints` of type `array` are required.

#### ref

```json
{
  "name": "c",
  "type": "ref",
  "display_hints": [{ "type": "continuation" }]
}
```

Type of a single reference. Unlike `subslice` with `refs_add = 1`, should dereference instead of returning empty cell
with a single reference.

#### pushint_long

```json
{
  "name": "x",
  "type": "pushint_long"
}
```

Special type which currently is used only in `PUSHINT_LONG` instruction. Consists of 5-bit uint `size` and integer of
bit size `8 * size + 19`.

#### subslice

```json
{
  "name": "slice",
  "type": "subslice",
  "bits_length_var_size": 5,
  "refs_length_var_size": 2,
  "bits_padding": 1,
  "refs_add": 1,
  "completion_tag": true,
  "max_bits": 248,
  "min_bits": 0,
  "max_refs": 4,
  "min_refs": 1,
  "display_hints": []
}
```

_TLB notation: `r:(## 2) xx:(## 5) c:((r + 1) * ^Cell) ssss:((8 * xx + 1) * Bit)`_

Loads `r` uint of size `refs_length_var_size` (if present), `x` uint of size `bits_length_var_size`. Then loads subslice
of bit length `x * 8 + bits_padding` and ref count `r + refs_add`. If `completion_tag` argument with value `true` is
passed, remove completion tag from bitstring (trailing `'1' + '0' * x`).

| Argument             | Description                                                                              |
|----------------------|------------------------------------------------------------------------------------------|
| bits_length_var_size | Size of bit length operand. Required.                                                    |
| bits_padding         | Constant integer value to add to length of bitstring to load. Required.                  |
| refs_length_var_size | Size of ref count operand. Optional, assuming no refs if absent.                         |
| refs_add             | Constant integer value to add to ref count. Optional, assuming 0 if absent.              |
| completion_tag       | Boolean flag, tells to remove trailing `'1' + '0' * x` from bitstring if true. Required. |
| max_bits             | Hint for maximum bits available to store for this operand. Required.                     |
| min_bits             | Hint for minimum bits available to store for this operand. Required.                     |
| max_refs             | Hint for maximum refs available to store for this operand. Required.                     |
| min_refs             | Hint for minimum refs available to store for this operand. Required.                     |
| display_hints        | Set of hints for converters between Asm.fif and bytecode representations. Required.      |

### Stack Entry Specification and Examples

#### Simple

```json
{
  "type": "simple",
  "name": "c",
  "value_types": ["Continuation"]
}
```

Specifies a single stack entry, attaches `name` to it and optionally constraints its type by `value_types`. Possible
types are `Integer`, `Cell`, `Builder`, `Slice`, `Tuple`, `Continuation`, `Null`. For example, dict is actually
`"value_types": ["Slice", "Null"]` as it can be either Slice or Null. Absence of `value_types` means that this stack
entry may be of any type.

#### Const

```json
{
  "type": "const",
  "value": 32,
  "value_type": "Integer"
}
```

Specifies a constant value on stack. `value_type` is either `Integer` or `Null`, with `number` type value for `Integer`
and `null` value for `Null`.

#### Conditional

```json
[
  {
    "type": "conditional",
    "name": "status",
    "match": [
      {
        "value": 0,
        "stack": []
      },
      {
        "value": -1,
        "stack": [
          {
            "type": "simple",
            "name": "c",
            "value_types": ["Cell"]
          }
        ]
      }
    ]
  },
  {
    "type": "simple",
    "name": "status",
    "value_types": ["Integer"]
  }
]
```

_Stack notation: `0 or c -1`_

```json
[
  {
    "type": "conditional",
    "name": "x",
    "match": [
      {"value": 0, "stack": []}
    ],
    "else": [
      {
        "type": "const",
        "value": null,
        "value_type": "Null"
      }
    ]
  },
  {
    "type": "simple",
    "name": "x",
    "value_types": ["Integer"]
  }
]
```

_Stack notation: `x or null x`_

Depending on `value` of variable specified in `name`, put values specified in corresponding arm of `match`. If `else`arm
is not present, then input for this conditional may be only of specified values.

#### Array

```json
{
  "type": "array",
  "name": "key_message_pairs",
  "length_var": "n",
  "array_entry": [
    {
      "type": "simple",
      "name": "pk",
      "value_types": ["Slice"]
    },
    {
      "type": "simple",
      "name": "msg",
      "value_types": ["Slice"]
    }
  ]
}
```

_Stack notation: `pk_1 msg_1 ... pk_n msg_n`_

Specifies a bunch of stack entries with length from variable `length_var`, usually noted as `x_1 ... x_n`. Each part of
array, such as `x_i` or `x_i y_i` is described in `array_entry`. Used in tuple, continuation arguments and crypto
operations.

#### Notes

1. Each variable name is unique across `operands`, `value_flow`, and `control_flow` sections of each instruction.
   Assumed that variables are immutable, so if variable `x` is defined both in inputs and outputs, it goes to output
   without any modification.
2. Value flow describes only `cc` stack usage before the actual jump or call. Subsequent continuations may have a
   separate stack, so this will be defined in control flow section of this spec.

### Register Specification and Examples

#### constant

```json
{
  "type": "constant",
  "index": 0
}
```

Represents `c{index}` register.

#### variable

```json
{
  "type": "variable",
  "var_name": "i"
}
```

Represents `c{{var_name}}` register. Its number is taken from variable `var_name`, defined in stack inputs or operands.

#### special

```json
{
  "type": "special",
  "name": "gas"
}
```

```json
{
  "type": "special",
  "name": "cstate"
}
```

Represents gas registers (used by app_gas instructions) and cstate (used by COMMIT instruction).

### Continuations Specification and Examples

Each object represents a continuation, which can be constructed in several ways:

* from a variable (operand or stack)
* from cc register
* from c0-c3 registers
* by "extraordinary continuation" constructors (as in [tvm.pdf](https://docs.ton.org/tvm.pdf), p.50: "4.1.5.
  Extraordinary continuations.")

Savelist can be defined using `save` property. Keys are `c0`, `c1`, `c2`, `c3` and values are continuation objects (in
fact, continuation is a recursive type, representing a tree of continuations). Please note that savelist defined here
will not override already saved continuation registers (that's the standard behaviour of TVM when saving registers).

#### variable

```json
{
  "type": "variable",
  "var_name": "c",
  "save": {
    "c0": {
      "type": "cc",
      "save": {
        "c0": { "type": "register", "index": 0 }
      }
    }
  }
}
```

Specifies a variable-backed continuation. Variable may be not referenced previously (in `operands` or `value_flow`
section), assuming that it is defined somewhere in the actual implementation of the instruction. Example of such
instruction is `DICTIGETJMP`: internally it does dictionary lookup for continuation retrieval, so `x` in control flow is
expected to be defined in the implementation of `DICTIGETJMP`.

#### cc

```json
{
  "type": "cc",
  "save": {
    "c0": { "type": "register", "index": 0 }
  }
}
```

Specifies a continuation, which is constructed from cc code and `save` registers. In C++ implementation this operation
is implemented
in [VmState::extract_cc](https://github.com/ton-blockchain/ton/blob/17c3477f7191fe6e5db22b71631b5c7472046c2f/crypto/vm/vm.cpp#L356).

#### register

```json
{
  "type": "register",
  "index": 3,
  "save": {
    "c0": {
      "type": "cc",
      "save": {
        "c0": { "type": "register", "index": 0 }
      }
    }
  }
}
```

Specifies continuation from register with `index` (`"index": 3` => take continuation from `c3`).

#### special

```json
{
  "type": "special",
  "name": "repeat",
  "args": {
    "count": "n",
    "body": {
      "type": "variable",
      "var_name": "c"
    },
    "after": {
      "type": "cc",
      "save": {
        "c0": { "type": "register", "index": 0 }
      }
    }
  }
}
```

Specifies extraordinary continuation. `save` property does not apply here.

| name    | args                                   | description                                                                                                                                      |
|---------|----------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| repeat  | string count; continuation body, after | Count is the name of a count variable. Jumps to `body` with `c0 = repeat(count - 1, body, after)`, jumps to `after` if `count <= 0`.             |
| until   | continuation body, after               | Pops boolean from stack, jumps to `after` if it is `true`, otherwise jumps to `body` with `c0 = until(body, after)`.                             |
| while   | continuation cond, body, after         | Pops boolean from stack, jumps to `after` if it is `false`, otherwise jumps to `body` with `c0 = cond` and `cond.c0 = while(cond, body, after)`. |
| again   | continuation body                      | Jumps to body with `c0 = again(body)`.                                                                                                           |
| pushint | continuation next; integer value       | Push `value` on stack, jump to `next`.                                                                                                           |

## Alias Specification

### Example

```json
{
  "mnemonic": "ROT2",
  "alias_of": "BLKSWAP",
  "doc_fift": "ROT2\n2ROT",
  "doc_stack": "a b c d e f - c d e f a b",
  "description": "Rotates the three topmost pairs of stack entries.",
  "operands": {
    "i": 1,
    "j": 3
  }
}
```

| Key         | Description                                                                                                                                                                                                                                                 |
|-------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| mnemonic    | Alias name. Required.                                                                                                                                                                                                                                       |
| alias_of    | Mnemonic of aliased instruction. Required.                                                                                                                                                                                                                  |
| doc_fift    | Free-form fift usage description. Optional.                                                                                                                                                                                                                 |
| doc_stack   | Free-form description of stack inputs and outputs. Usually the form is `[inputs] - [outputs]` where `[inputs]` are consumed stack values and `outputs` are produced stack values (top of stack is the last value).                                          |
| description | Free-form markdown description of alias. Optional.                                                                                                                                                                                                          |
| operands    | Values of original instruction operands which are fixed in this alias. Currently it can be integer or slice without references which is represented by string of '0' and '1's. Type should be inferred from original instruction operand loaders. Required. |

### Implementation Specification and Examples

The `implementation` field maps a TVM instruction to one or more C++ functions in
the [TON Virtual Machine source code](https://github.com/ton-blockchain/ton). This makes it possible to trace how an
instruction is actually executed during runtime.

Each object inside the `implementation` array includes:

| Key             | Description                                                                                              |
|-----------------|----------------------------------------------------------------------------------------------------------|
| `file`          | Name of the source file in the TON codebase where the instruction is implemented (e.g., `stackops.cpp`). |
| `path`          | Full raw GitHub URL pointing to the exact commit and file location. Used for linking to source directly. |
| `line`          | Line number in the file where the C++ function begins.                                                   |
| `function_name` | Name of the C++ function that executes the instruction logic (e.g., `exec_xchg0`).                       |

This is primarily used for:

- Debugging and validating opcode behavior
- Tooling (e.g., linking disassembler output back to implementation)
- Verifying matcher output from scripts like `matcher-all.py`

#### Example

```json
"implementation": [
  {
    "file": "stackops.cpp",
    "path": "https://raw.githubusercontent.com/ton-blockchain/ton/cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/stackops.cpp",
    "line": 43,
    "function_name": "exec_xchg0"
  }
]
```

If multiple function variants implement the same mnemonic (e.g., based on operand ranges), multiple entries can be
listed in the array.

#### Notes

* Line numbers are based on static commits and may go out of sync if the underlying code changes. To update them, re-run
  the matchers.
* These links are generated by matcher scripts under the `matcher/` directory and written to `match-report.json`.
