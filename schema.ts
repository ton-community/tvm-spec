export type var_name = string;

export interface alias {
  mnemonic: string;
  alias_of: string;
  operands: { [key: string]: number | string };
  doc_fift?: string;
  doc_stack?: string;
  description?: string;
}

export type register_flow =
  | { type: 'constant'; index: number }
  | { type: 'variable'; var_name: var_name }
  | { type: 'special'; name: 'gas' | 'cstate' };


export interface stack_entry_simple {
  type: 'simple';
  name: var_name;
  value_types?: Array<
    | 'Integer'
    | 'Cell'
    | 'Builder'
    | 'Slice'
    | 'Tuple'
    | 'Continuation'
    | 'Null'
  >;
}

export interface stack_entry_const {
  type: 'const';
  value_type: 'Integer' | 'Null';
  value: number | null;
}

export interface stack_match_arm {
  value: number;
  stack: stack;
}

export interface stack_entry_conditional {
  type: 'conditional';
  name: var_name;
  match: stack_match_arm[];
  else?: stack;
}

export interface stack_entry_array {
  type: 'array';
  name: var_name;
  length_var: var_name;
  array_entry: stack;
}

export type stack_entry =
  | stack_entry_simple
  | stack_entry_const
  | stack_entry_conditional
  | stack_entry_array;

export type stack = stack_entry[];

export interface values {
  stack?: stack;
  registers: register_flow[];
}

export type display_hint =
  | { type: 'continuation' }
  | { type: 'dictionary'; size_var: var_name }
  | { type: 'add'; value: number }
  | { type: 'stack' }
  | { type: 'register' }
  | { type: 'pushint4' }
  | { type: 'optional_nargs' }
  | { type: 'plduz' };

export type display_hints = display_hint[];

export interface operand_uint {
  name: var_name;
  type: 'uint';
  display_hints: display_hints;
  size: number;
  max_value: number;
  min_value: number;
}
export interface operand_int {
  name: var_name;
  type: 'int';
  display_hints: display_hints;
  size: number;
  max_value: number;
  min_value: number;
}
export interface operand_pushint_long {
  name: var_name;
  type: 'pushint_long';
}
export interface operand_ref {
  name: var_name;
  type: 'ref';
  display_hints: display_hints;
}
export interface operand_subslice {
  name: var_name;
  type: 'subslice';
  display_hints: display_hints;
  bits_length_var_size: number;
  bits_padding: number;
  refs_length_var_size?: number;
  refs_add?: number;
  completion_tag: boolean;
  max_bits: number;
  min_bits: number;
  max_refs: number;
  min_refs: number;
}
export type operand =
  | operand_uint
  | operand_int
  | operand_pushint_long
  | operand_ref
  | operand_subslice;

export interface save_list {
  c0?: continuation;
  c1?: continuation;
  c2?: continuation;
  c3?: continuation;
}

export interface continuation_cc {
  type: 'cc';
  save: save_list;
}
export interface continuation_variable {
  type: 'variable';
  var_name: var_name;
  save: save_list;
}
export interface continuation_register {
  type: 'register';
  index: number;
  save?: save_list;
}
export interface continuation_special_until {
  type: 'special';
  name: 'until';
  args: { body: continuation; after: continuation };
}
export interface continuation_special_while {
  type: 'special';
  name: 'while';
  args: {
    cond: continuation;
    body: continuation;
    after: continuation;
  };
}
export interface continuation_special_again {
  type: 'special';
  name: 'again';
  args: { body: continuation };
}
export interface continuation_special_repeat {
  type: 'special';
  name: 'repeat';
  args: {
    count: var_name;
    body: continuation;
    after: continuation;
  };
}
export interface continuation_special_pushint {
  type: 'special';
  name: 'pushint';
  args: { value: number; next: continuation };
}

export interface continuation_fallback {
  [key: string]: any;
}

export type continuation =
  | continuation_cc
  | continuation_variable
  | continuation_register
  | continuation_special_until
  | continuation_special_while
  | continuation_special_again
  | continuation_special_repeat
  | continuation_special_pushint
  | continuation_fallback;


export interface code_location {
  path: string;
  line: number;
  function_name?: string;
  commit?: string;
}

export interface instruction {
  mnemonic: string;
  since_version: number;
  doc: {
    opcode?: string;
    stack: string;
    category: string;
    description: string;
    gas: string;
    fift: string;
    fift_examples: Array<{ fift: string; description: string }>;
  };
  bytecode: {
    tlb: string;
    prefix: string;
    operands_range_check?: { length: number; from: number; to: number };
    operands: operand[];
  };
  value_flow: {
    inputs: values;
    outputs: values;
  };
  control_flow: {
    branches: continuation[];
    nobranch: boolean;
  };
    /**
   * Implementation details: where this instruction is implemented in the code.
   * @items code_location
   */
  implementation: code_location[];
}

export interface root_schema {
  $schema?: string;
  instructions: instruction[];
  aliases: alias[];
}