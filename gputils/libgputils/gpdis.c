/* Disassemble memory
   Copyright (C) 2001, 2002, 2003, 2004, 2005
   Craig Franklin

    Copyright (C) 2014-2016 Molnar Karoly

This file is part of gputils.

gputils is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

gputils is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with gputils; see the file COPYING.  If not, write to
the Free Software Foundation, 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#include "stdhdr.h"
#include "libgputils.h"

#define IS_VALID_BANK(State, Mask) \
        (((State)->bank_valid & (Mask)) == (Mask))

#define IS_UNBANKED16(Addr) \
        (((Addr) <= 0x0f) || (((Addr) >= 0x18) && ((Addr) <= 0x1f)))

#define BANK12_ADDR(State, Mask) \
        (((State)->bank & (Mask)) << PIC12_BANK_SHIFT)

#define BANK14_ADDR(State, Mask) \
        (((State)->bank & (Mask)) << PIC14_BANK_SHIFT)

#define BANK16_ADDR(State, Mask) \
        (((State)->bank & (Mask)) << PIC16_BANK_SHIFT)

    /*....................................................*/

#define PRINT_ARG0() \
        length += snprintf(&Buffer[length], Buffer_length - length, "%s", instruction->name)

#define PRINT_ARG1_N(W1, Arg1) \
        length += snprintf(&Buffer[length], Buffer_length - length, "%-*s0x%0*x", TABULATOR_SIZE, instruction->name, W1, Arg1)

#define PRINT_ARG1_S(Arg1, Offs1) \
	if ((Offs1) > 0) { \
          length += snprintf(&Buffer[length], Buffer_length - length, "%-*s(%s + %i)", TABULATOR_SIZE, instruction->name, Arg1, Offs1); \
	} \
	else { \
          length += snprintf(&Buffer[length], Buffer_length - length, "%-*s%s", TABULATOR_SIZE, instruction->name, Arg1); \
	}

#define PRINT_ARG2_N_N(W1, Arg1, W2, Arg2) \
        length += snprintf(&Buffer[length], Buffer_length - length, "%-*s0x%0*x, 0x%0*x", TABULATOR_SIZE, instruction->name, W1, Arg1, W2, Arg2)

#define PRINT_ARG2_N_S(W1, Arg1, Arg2, Offs2) \
	if ((Offs2) > 0) { \
          length += snprintf(&Buffer[length], Buffer_length - length, "%-*s0x%0*x, (%s + %i)", TABULATOR_SIZE, instruction->name, W1, Arg1, Arg2, Offs2); \
	} \
	else { \
          length += snprintf(&Buffer[length], Buffer_length - length, "%-*s0x%0*x, %s", TABULATOR_SIZE, instruction->name, W1, Arg1, Arg2); \
	}

#define PRINT_ARG2_S_N(Arg1, Offs1, W2, Arg2) \
	if ((Offs1) > 0) { \
          length += snprintf(&Buffer[length], Buffer_length - length, "%-*s(%s + %i), 0x%0*x", TABULATOR_SIZE, instruction->name, Arg1, Offs1, W2, Arg2); \
	} \
	else { \
          length += snprintf(&Buffer[length], Buffer_length - length, "%-*s%s, 0x%0*x", TABULATOR_SIZE, instruction->name, Arg1, W2, Arg2); \
	}

#define PRINT_ARG2_S_S(Arg1, Offs1, Arg2, Offs2) \
	if ((Offs1) > 0) { \
	  if ((Offs2) > 0) { \
            length += snprintf(&Buffer[length], Buffer_length - length, "%-*s(%s + %i), (%s + %i)", TABULATOR_SIZE, instruction->name, Arg1, Offs1, Arg2, Offs2); \
	  } \
	  else { \
            length += snprintf(&Buffer[length], Buffer_length - length, "%-*s(%s + %i), %s", TABULATOR_SIZE, instruction->name, Arg1, Offs1, Arg2); \
	  } \
	} \
	else { \
	  if ((Offs2) > 0) { \
            length += snprintf(&Buffer[length], Buffer_length - length, "%-*s%s, (%s + %i)", TABULATOR_SIZE, instruction->name, Arg1, Arg2, Offs2); \
          } \
	else { \
            length += snprintf(&Buffer[length], Buffer_length - length, "%-*s%s, %s", TABULATOR_SIZE, instruction->name, Arg1, Arg2); \
	  } \
	}

#define PRINT_ARG3_N_N_N(W1, Arg1, W2, Arg2, W3, Arg3) \
        length += snprintf(&Buffer[length], Buffer_length - length, "%-*s0x%0*x, 0x%0*x, 0x%0*x", TABULATOR_SIZE, instruction->name, W1, Arg1, W2, Arg2, W3, Arg3)

#define PRINT_ARG3_N_N_S(W1, Arg1, W2, Arg2, Arg3) \
        length += snprintf(&Buffer[length], Buffer_length - length, "%-*s0x%0*x, 0x%0*x, %s", TABULATOR_SIZE, instruction->name, W1, Arg1, W2, Arg2, Arg3)

#define PRINT_ARG3_N_S_S(W1, Arg1, Arg2, Arg3) \
        length += snprintf(&Buffer[length], Buffer_length - length, "%-*s0x%0*x, %s, %s", TABULATOR_SIZE, instruction->name, W1, Arg1, Arg2, Arg3)

#define PRINT_ARG3_S_N_S(Arg1, Offs1, W2, Arg2, Arg3) \
	if ((Offs1) > 0) { \
          length += snprintf(&Buffer[length], Buffer_length - length, "%-*s(%s + %i), 0x%0*x, %s", TABULATOR_SIZE, instruction->name, Arg1, Offs1, W2, Arg2, Arg3); \
	} \
	else { \
          length += snprintf(&Buffer[length], Buffer_length - length, "%-*s%s, 0x%0*x, %s", TABULATOR_SIZE, instruction->name, Arg1, W2, Arg2, Arg3); \
	}

#define PRINT_ARG3_S_S_S(Arg1, Offs1, Arg2, Arg3) \
	if ((Offs1) > 0) { \
          length += snprintf(&Buffer[length], Buffer_length - length, "%-*s(%s + %i), %s, %s", TABULATOR_SIZE, instruction->name, Arg1, Offs1, Arg2, Arg3); \
	} \
	else { \
          length += snprintf(&Buffer[length], Buffer_length - length, "%-*s%s, %s, %s", TABULATOR_SIZE, instruction->name, Arg1, Arg2, Arg3); \
	}

#define PRINT_MOVINDF_S_N_S(Arg1, Arg2, Arg3) \
        length += snprintf(&Buffer[length], Buffer_length - length, "%-*s%s%#x%s", TABULATOR_SIZE, instruction->name, Arg1, Arg2, Arg3)

#define PRINT_MOVINDF_S_S_S(Arg1, Arg2, Arg3) \
        length += snprintf(&Buffer[length], Buffer_length - length, "%-*s%s%s%s", TABULATOR_SIZE, instruction->name, Arg1, Arg2, Arg3)

    /*....................................................*/

#define FLAG_FW(Flag)   ((Flag) ? "F" : "W")
#define FLAG_BA(Flag)   ((Flag) ? "B" : "A")

    /*....................................................*/

gp_boolean gp_decode_mnemonics = false;
gp_boolean gp_decode_extended = false;

/*------------------------------------------------------------------------------------------------*/

GPUTILS_GCC_DIAG_TOP(switch)

unsigned int
gp_disassemble_mark_false_addresses(MemBlock_t *M, unsigned int Byte_address, pic_processor_t Processor)
{
  proc_class_t  class;
  uint16_t      opcode;
  const insn_t *instruction;
  unsigned int  num_words;

  class = Processor->class;

  if (class->find_insn == NULL) {
    return 0;
  }

  num_words = 1;

  if (class->i_memory_get(M, Byte_address, &opcode, NULL, NULL) != W_USED_ALL) {
    return num_words;
  }

  instruction = class->find_insn(class, opcode);

  if (instruction == NULL)  {
    return num_words;
  }

GPUTILS_GCC_DIAG_OFF(switch)

  switch (instruction->class) {
    case INSN_CLASS_LIT20:
      /* PIC16E goto */
    case INSN_CLASS_CALL20:
      /* PIC16E call */
    case INSN_CLASS_FLIT12:
      /* PIC16E lfsr */
    case INSN_CLASS_FF:
      /* PIC16E movff */
    case INSN_CLASS_SF:
      /* PIC16E movsf */
      if ((class->i_memory_get(M, Byte_address + 2, &opcode, NULL, NULL) == W_USED_ALL) &&
          ((opcode & PIC16E_BMSK_SEC_INSN_WORD) == PIC16E_BMSK_SEC_INSN_WORD)) {
        gp_mem_b_set_type(M, Byte_address + 2, W_SECOND_WORD);
        num_words = 2;
      }
      break;

    case INSN_CLASS_SS:
      /* PIC16E movss */
      if ((class->i_memory_get(M, Byte_address + 2, &opcode, NULL, NULL) == W_USED_ALL) &&
          ((opcode & 0xff80) == PIC16E_BMSK_SEC_INSN_WORD)) {
        gp_mem_b_set_type(M, Byte_address + 2, W_SECOND_WORD);
        num_words = 2;
      }
      break;
    } /* switch (instruction->class) */

GPUTILS_GCC_DIAG_ON(switch)

  return num_words;
}

/*------------------------------------------------------------------------------------------------*/

unsigned int
gp_disassemble_find_labels(MemBlock_t *M, unsigned int Byte_address, pic_processor_t Processor,
                           gpdasm_fstate_t *Fstate)
{
  proc_class_t      class;
  unsigned int      page_mask;
  unsigned int      prog_max_org;
  unsigned int      value;
  unsigned int      src_page;
  int               dst_org;
  uint16_t          opcode;
  const insn_t     *instruction;
  enum common_insn  icode;
  unsigned int      num_words;
  uint16_t          file1;
  uint16_t          file2;
  unsigned int      tmp;
  unsigned int      dest_byte_addr;
  unsigned int      type;
  int               wreg;
  int               pclath;
  int               pclath_valid;

  class = Processor->class;

  if (class->find_insn == NULL) {
    return 0;
  }

  num_words = 1;

  if (class->i_memory_get(M, Byte_address, &opcode, NULL, NULL) != W_USED_ALL) {
    return num_words;
  }

  instruction = class->find_insn(class, opcode);

  if (instruction == NULL)  {
    return num_words;
  }

  icode = instruction->icode;

  wreg         = Fstate->wreg;
  pclath       = Fstate->pclath;
  pclath_valid = Fstate->pclath_valid;
  page_mask    = (class->page_size > 0) ? ~(class->page_size - 1) : 0;
  prog_max_org = (Processor->prog_mem_size > 0) ? (Processor->prog_mem_size - 1) : 0;
  src_page     = gp_processor_insn_from_byte_c(class, Byte_address) & page_mask;

GPUTILS_GCC_DIAG_OFF(switch)

  switch (instruction->class) {
    case INSN_CLASS_LIT7:
      /* PIC14E movlp */
      pclath = opcode & PIC14E_BMSK_PAGE512;
      pclath_valid = 0xff;
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT8C12:
      /* PIC12x call, SX call */
      value   = opcode & PIC12_BMSK_CALL;
      dst_org = value;

      if ((prog_max_org > 0) && (prog_max_org <= PIC12_BMSK_CALL)) {
        /* The PCLATH is not required. */
        goto _class_lit8c12;
      }
      else if ((pclath_valid & (PIC12_PAGE_BITS >> 8)) == (PIC12_PAGE_BITS >> 8)) {
        /* The value of the PCLATH is known. */
        dst_org |= (pclath << 8) & PIC12_PAGE_BITS;

_class_lit8c12:

        if ((prog_max_org > 0) && (dst_org <= prog_max_org)) {
          dest_byte_addr = gp_processor_byte_from_insn_c(class, dst_org);
          gp_mem_b_set_addr_type(M, Byte_address, W_ADDR_T_BRANCH_SRC, dest_byte_addr);
          gp_mem_b_set_addr_type(M, dest_byte_addr, W_ADDR_T_FUNC, 0);
          wreg = -1;

          if ((dst_org & page_mask) != src_page) {
            pclath_valid = 0;
          }
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT8C16:
      /* PIC16 lcall */
      value   = opcode & 0x00ff;
      dst_org = value;

      if ((pclath_valid & 0xff) == 0xff) {
        /* The value of the PCLATH is known. */
        dst_org |= (pclath & 0xff) << 8;

        if ((prog_max_org > 0) && (dst_org <= prog_max_org)) {
          dest_byte_addr = gp_processor_byte_from_insn_c(class, dst_org);
          gp_mem_b_set_addr_type(M, Byte_address, W_ADDR_T_BRANCH_SRC, dest_byte_addr);
          gp_mem_b_set_addr_type(M, dest_byte_addr, W_ADDR_T_FUNC, 0);
          wreg = -1;

          if ((dst_org & page_mask) != src_page) {
            pclath_valid = 0;
          }
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT8:
      /* PIC1xx (addlw, andlw, iorlw, movlw, retlw, sublw, xorlw),
         PIC16  movlb,
         PIC16x mullw,
         PIC16E pushl */
      if ((class == PROC_CLASS_PIC14) || (class == PROC_CLASS_PIC14E) ||
          (class == PROC_CLASS_PIC14EX) || (class == PROC_CLASS_PIC16)) {
        tmp = opcode & 0x00ff;

        if (icode == ICODE_MOVLW) {
          wreg = tmp;
        }
        else if (wreg >= 0) {
          if (icode == ICODE_ADDLW) {
            wreg = (wreg + tmp) & 0xff;
          }
          else if (icode == ICODE_ANDLW) {
            wreg = (wreg & tmp) & 0xff;
          }
          else if (icode == ICODE_IORLW) {
            wreg = (wreg | tmp) & 0xff;
          }
          else if (icode == ICODE_SUBLW) {
            wreg = (tmp - wreg) & 0xff;
          }
          else if (icode == ICODE_XORLW) {
            wreg = (wreg ^ tmp) & 0xff;
          }
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT9:
      /* PIC12 goto, SX goto */
      value   = opcode & PIC12_BMSK_GOTO;
      dst_org = value;

      if ((prog_max_org > 0) && (prog_max_org <= PIC12_BMSK_GOTO)) {
        /* The PCLATH is not required. */
        goto _class_lit9;
      }
      else if ((pclath_valid & (PIC12_PAGE_BITS >> 8)) == (PIC12_PAGE_BITS >> 8)) {
        /* The value of the PCLATH is known. */
        dst_org |= (pclath << 8) & PIC12_PAGE_BITS;

_class_lit9:

        if ((prog_max_org > 0) && (dst_org <= prog_max_org)) {
          dest_byte_addr = gp_processor_byte_from_insn_c(class, dst_org);
          gp_mem_b_set_addr_type(M, Byte_address, W_ADDR_T_BRANCH_SRC, dest_byte_addr);
          gp_mem_b_set_addr_type(M, dest_byte_addr, W_ADDR_T_FUNC, 0);
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT11:
      /* PIC14x (call, goto) */
      value   = opcode & PIC14_BMSK_BRANCH;
      dst_org = value;
      tmp     = ((class == PROC_CLASS_PIC14E) || (class == PROC_CLASS_PIC14EX)) ? PIC14E_PAGE_BITS : PIC14_PAGE_BITS;

      if ((prog_max_org > 0) && (prog_max_org <= PIC14_BMSK_BRANCH)) {
        /* The PCLATH is not required. */
        goto _class_lit11;
      }
      else if ((pclath_valid & (tmp >> 8)) == (tmp >> 8)) {
        /* The value of the PCLATH is known. */
        dst_org |= (pclath << 8) & tmp;

_class_lit11:

        if ((prog_max_org > 0) && (dst_org <= prog_max_org)) {
          dest_byte_addr = gp_processor_byte_from_insn_c(class, dst_org);
          type = (icode == ICODE_CALL) ? W_ADDR_T_FUNC : W_ADDR_T_LABEL;
          gp_mem_b_set_addr_type(M, Byte_address, W_ADDR_T_BRANCH_SRC, dest_byte_addr);
          gp_mem_b_set_addr_type(M, dest_byte_addr, type, 0);

          if (icode == ICODE_CALL) {
            wreg = -1;

            if ((dst_org & page_mask) != src_page) {
              pclath_valid = 0;
            }
          }
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_RBRA8:
      /* PIC16E (bc, bn, bnc, bnn, bnov, bnz, bov, bz) */
      value = opcode & PIC16E_BMSK_RBRA8;
      /* twos complement number */
      if (value & 0x80) {
        value = -((value ^ PIC16E_BMSK_RBRA8) + 1);
      }

      dest_byte_addr = Byte_address + value * 2 + 2;

      if ((gp_mem_b_get_type(M, dest_byte_addr) & W_SECOND_WORD) == 0) {
        dst_org = gp_processor_insn_from_byte_c(class, dest_byte_addr);

        if ((prog_max_org > 0) && (dst_org >= 0) && (dst_org <= prog_max_org)) {
          gp_mem_b_set_addr_type(M, Byte_address, W_ADDR_T_BRANCH_SRC, dest_byte_addr);
          gp_mem_b_set_addr_type(M, dest_byte_addr, W_ADDR_T_LABEL, 0);
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_RBRA9:
      /* PIC14E bra */
      value = opcode & PIC14E_BMSK_RBRA9;
      /* twos complement number */
      if (value & 0x100) {
        value = -((value ^ PIC14E_BMSK_RBRA9) + 1);
      }

      dest_byte_addr = Byte_address + value * 2 + 2;
      dst_org = gp_processor_insn_from_byte_c(class, dest_byte_addr);

      if ((prog_max_org > 0) && (dst_org >= 0) && (dst_org <= prog_max_org)) {
        gp_mem_b_set_addr_type(M, Byte_address, W_ADDR_T_BRANCH_SRC, dest_byte_addr);
        gp_mem_b_set_addr_type(M, dest_byte_addr, W_ADDR_T_LABEL, 0);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_RBRA11:
      /* PIC16E (bra, rcall) */
      value = opcode & PIC16E_BMSK_RBRA11;
      /* twos complement number */
      if (value & 0x400) {
        value = -((value ^ PIC16E_BMSK_RBRA11) + 1);
      }

      dest_byte_addr = Byte_address + value * 2 + 2;

      if ((gp_mem_b_get_type(M, dest_byte_addr) & W_SECOND_WORD) == 0) {
        dst_org = gp_processor_insn_from_byte_c(class, dest_byte_addr);

        if ((prog_max_org > 0) && (dst_org >= 0) && (dst_org <= prog_max_org)) {
          type = (icode == ICODE_RCALL) ? W_ADDR_T_FUNC : W_ADDR_T_LABEL;
          gp_mem_b_set_addr_type(M, Byte_address, W_ADDR_T_BRANCH_SRC, dest_byte_addr);
          gp_mem_b_set_addr_type(M, dest_byte_addr, type, 0);
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT20:
      /* PIC16E goto */
    case INSN_CLASS_CALL20:
      /* PIC16E call */
      {
        uint16_t dest;

        if ((class->i_memory_get(M, Byte_address + 2, &dest, NULL, NULL) == W_USED_ALL) &&
            ((dest & PIC16E_BMSK_SEC_INSN_WORD) == PIC16E_BMSK_SEC_INSN_WORD)) {
          dest  = (dest & PIC16E_BMSK_BRANCH_HIGHER) << 8;
          dest |= opcode & PIC16E_BMSK_BRANCH_LOWER;
          dest_byte_addr = dest * 2;

          if ((gp_mem_b_get_type(M, dest_byte_addr) & W_SECOND_WORD) == 0) {
            dst_org = gp_processor_byte_from_insn_c(class, dest_byte_addr);

            if ((prog_max_org > 0) && (dst_org >= 0) && (dst_org <= prog_max_org)) {
              type = (icode == ICODE_CALL) ? W_ADDR_T_FUNC : W_ADDR_T_LABEL;
              gp_mem_b_set_addr_type(M, Byte_address, W_ADDR_T_BRANCH_SRC, dest_byte_addr);
              gp_mem_b_set_addr_type(M, dest_byte_addr, type, 0);
            }

            num_words = 2;
          }
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_FP:
      /* PIC16 movfp */
      file1 = opcode & PIC16_BMSK_FILE;
      file2 = (opcode >> 8) & 0x1f;

      if ((file1 == PIC16_REG_WREG) && (file2 == PIC16_REG_PCLATH)) {
        pclath = wreg;
        pclath_valid = (wreg >= 0) ? 0xff : 0;
      }
      else if (file2 == PIC16_REG_WREG) {
        /* The destination the WREG. */
        wreg = -1;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_PF:
      /* PIC16 movpf */
      file1 = (opcode >> 8) & 0x1f;
      file2 = opcode & PIC16_BMSK_FILE;

      if ((file1 == PIC16_REG_WREG) && (file2 == PIC16_REG_PCLATH)) {
        pclath = wreg;
        pclath_valid = (wreg >= 0) ? 0xff : 0;
      }
      else if (file2 == PIC16_REG_WREG) {
        /* The destination the WREG. */
        wreg = -1;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPWF5:
      /* {PIC12x, SX} (addwf, andwf, comf, decf, decfsz, incf, incfsz,
                       iorwf, movf, rlf, rrf, subwf, swapf, xorwf) */
      /* Destination flag: 0 = W, 1 = F */
      tmp = (opcode >> 5) & 1;

      if (tmp == 0) {
        /* The destination the WREG. */
        wreg = -1;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_B5:
      /* {PIC12x, SX} (bcf, bsf, btfsc, btfss) */
      file1 = opcode & PIC12_BMSK_FILE;
      /* The bits of register. */
      tmp   = (opcode >> 5) & 7;

      if ((file1 == PIC12_REG_STATUS) && ((tmp == 5) || (tmp == 6))) {
        tmp = 1 << (tmp - 4);

        if (icode == ICODE_BCF) {
          pclath &= ~tmp;
          pclath_valid |= tmp;
        }
        else if (icode == ICODE_BSF) {
          pclath |= tmp;
          pclath_valid |= tmp;
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPF7:
      /* PIC14x (clrf, movwf, tris) */
      file1 = opcode & PIC14_BMSK_FILE;

      if (icode == ICODE_CLRF) {
        if (file1 == PIC14_REG_PCLATH) {
          pclath = 0;
          pclath_valid = 0xff;
        }
        else if (((class == PROC_CLASS_PIC14E) || (class == PROC_CLASS_PIC14EX)) &&
                 (file1 == PIC14E_REG_WREG)) {
          wreg = 0;
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPWF7:
      /* PIC14x (addwf, andwf, comf, decf, decfsz, incf, incfsz, iorwf, movf,
                 rlf, rrf, subwf, swapf, xorwf)
         PIC14E (addwfc, asrf, lslf, lsrf, subwfb) */
      /* Destination flag: 0 = W, 1 = F */
      tmp = (opcode >> 7) & 1;

      if (tmp == 0) {
        wreg = -1;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_B7:
      /* PIC14x (bcf, bsf, btfsc, btfss) */
      file1 = opcode & PIC14_BMSK_FILE;
      /* The bits of register. */
      tmp   = (opcode >> 7) & 7;

      if (class == PROC_CLASS_PIC14) {
        if ((file1 == PIC14_REG_PCLATH) && ((tmp == 3) || (tmp == 4))) {
          tmp = 1 << tmp;

          if (icode == ICODE_BCF) {
            pclath &= ~tmp;
            pclath_valid |= tmp;
          }
          else if (icode == ICODE_BSF) {
            pclath |= tmp;
            pclath_valid |= tmp;
          }
        }
      }
      else {
        /* PROC_CLASS_PIC14E or PROC_CLASS_PIC14EX */
        if ((file1 == PIC14_REG_PCLATH) && (tmp >= 3) && (tmp <= 6)) {
          tmp = 1 << tmp;

          if (icode == ICODE_BCF) {
            pclath &= ~tmp;
            pclath_valid |= tmp;
          }
          else if (icode == ICODE_BSF) {
            pclath |= tmp;
            pclath_valid |= tmp;
          }
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPF8:
      /* PIC16 (cpfseq, cpfsgt, cpfslt, movwf, mulwf, tstfsz) */
      file1 = opcode & PIC16_BMSK_FILE;

      if ((file1 == PIC16_REG_PCLATH) && (icode == ICODE_MOVWF)) {
        pclath = wreg;
        pclath_valid = (wreg >= 0) ? 0xff : 0;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPWF8:
      /* PIC16 (addwf, addwfc, andwf, clrf, comf, daw, decf, decfsz, dcfsnz, incf,
                incfsz, infsnz, iorwf, rlcf, rlncf, rrcf, rrncf, setf, subwf, subwfb,
                swapf, xorwf) */
      file1 = opcode & PIC16_BMSK_FILE;
      /* Destination flag: 0 = W, 1 = F */
      tmp   = (opcode >> 8) & 1;

      if (icode == ICODE_SETF) {
        if ((tmp == 0) || (file1 == PIC16_REG_WREG)) {
          wreg = 0xff;
        }
      }
      else if (icode == ICODE_CLRF) {
        if ((tmp == 0) || (file1 == PIC16_REG_WREG)) {
          wreg = 0;
        }
      }
      else if (tmp == 0) {
        /* The destination the WREG. */
        wreg = -1;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_IMPLICIT:
      /* PIC12x  (clrw, clrwdt, nop, option, return, sleep)
         PIC12E  return
         PIC12I  (retfie, return)
         SX      (iread, movmw, movwm, reti, retiw, retp, return)
         PIC14x  (clrw, clrwdt, halt, nop, option, retfie, return, sleep)
         PIC14E  (brw, callw, reset)
         PIC16   (clrwdt, nop, retfie, return, sleep)
         PIC16E  (clrwdt, daw, halt, nop, pop, push, reset, sleep, trap, tret)
         PIX16EX callw */
      if (icode == ICODE_CLRW) {
        wreg = 0;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_FLIT12:
      /* PIC16E lfsr */
    case INSN_CLASS_FF:
      /* PIC16E movff */
    case INSN_CLASS_SF:
      /* PIC16E movsf */
      if ((class->i_memory_get(M, Byte_address + 2, &file1, NULL, NULL) == W_USED_ALL) &&
          ((file1 & PIC16E_BMSK_SEC_INSN_WORD) == PIC16E_BMSK_SEC_INSN_WORD)) {
        num_words = 2;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_SS:
      /* PIC16E movss */
      if ((class->i_memory_get(M, Byte_address + 2, &file1, NULL, NULL) == W_USED_ALL) &&
          ((file1 & 0xff80) == PIC16E_BMSK_SEC_INSN_WORD)) {
        num_words = 2;
      }
      break;
    } /* switch (instruction->class) */

GPUTILS_GCC_DIAG_ON(switch)

  Fstate->wreg         = wreg;
  Fstate->pclath       = pclath;
  Fstate->pclath_valid = pclath_valid;
  return num_words;
}

/*------------------------------------------------------------------------------------------------*/

static void
_pic12_reg_eval(MemBlock_t *M, unsigned int Byte_address, gpdasm_fstate_t *Fstate, pic_processor_t Processor,
                unsigned int File, int Bit_number, void (*User_data_finder)(MemArg_t *))
{
  proc_class_t         class;
  MemArgList_t         args;
  const gp_register_t *reg1;
  unsigned int         bmask;

  class = Processor->class;

  args.first.arg   = NULL;
  args.first.val   = File;
  args.first.offs  = 0;
  args.second.arg  = NULL;
  args.second.val  = Bit_number;
  args.second.offs = 0;
  reg1             = NULL;

  if (class == PROC_CLASS_SX) {
    args.first.arg = gp_processor_find_sfr_name(class, args.first.val);
    Fstate->need_sfr_equ = true;
  }
  else {
    args.first.arg = gp_processor_find_sfr_name(class, args.first.val);
    reg1 = gp_register_find_reg(Fstate->proc_regs, args.first.val);

    if (args.first.arg != NULL) {
      if (reg1 == NULL) {
        gp_debug("%s.%s() -- The \"%s\" core SFR not exist in the register database!", __FILE__, __func__, args.first.arg);
        Fstate->need_sfr_equ = true;
      }
      else if (strcmp(args.first.arg, reg1->name) != 0) {
        gp_debug("%s.%s() -- These SFRs there is the same address: \"%s\", \"%s\"", __FILE__, __func__, args.first.arg, reg1->name);
        Fstate->need_sfr_equ = true;
      }
    }
    else {
      bmask = Processor->num_banks - 1;

      if (IS_VALID_BANK(Fstate, bmask)) {
        args.first.val += BANK12_ADDR(Fstate, bmask);
        reg1 = gp_register_find_reg(Fstate->proc_regs, args.first.val);
      }
    }

    if (reg1 != NULL) {
      args.first.arg = reg1->name;

      if (Bit_number >= 0) {
        args.second.arg = gp_register_find_bit_name(reg1, Bit_number);
      }
    }
  }

  if (User_data_finder != NULL) {
    (*User_data_finder)(&args.first);
  }

  gp_mem_b_set_args(M, Byte_address, W_ARG_T_BOTH, &args);
}

/*------------------------------------------------------------------------------------------------*/

static void
_pic14_reg_eval(MemBlock_t *M, unsigned int Byte_address, gpdasm_fstate_t *Fstate, pic_processor_t Processor,
                unsigned int File, int Bit_number, void (*User_data_finder)(MemArg_t *))
{
  proc_class_t         class;
  MemArgList_t         args;
  const gp_register_t *reg1;
  unsigned int         bmask;

  class = Processor->class;

  args.first.arg   = gp_processor_find_sfr_name(class, File);
  args.first.val   = File;
  args.first.offs  = 0;
  args.second.arg  = NULL;
  args.second.val  = Bit_number;
  args.second.offs = 0;
  reg1             = gp_register_find_reg(Fstate->proc_regs, File);

  if (args.first.arg != NULL) {
    if (reg1 == NULL) {
      gp_debug("%s.%s() -- The \"%s\" core SFR not exist in the register database!", __FILE__, __func__, args.first.arg);
      Fstate->need_sfr_equ = true;
    }
    else if (strcmp(args.first.arg, reg1->name) != 0) {
      gp_debug("%s.%s() -- These SFRs there is the same address: \"%s\", \"%s\"", __FILE__, __func__, args.first.arg, reg1->name);
      Fstate->need_sfr_equ = true;
    }
  }
  else {
    bmask = Processor->num_banks - 1;

    if (IS_VALID_BANK(Fstate, bmask)) {
      args.first.val += BANK14_ADDR(Fstate, bmask);
      reg1 = gp_register_find_reg(Fstate->proc_regs, args.first.val);
    }
  }

  if (reg1 != NULL) {
    args.first.arg = reg1->name;

    if (Bit_number >= 0) {
      args.second.arg = gp_register_find_bit_name(reg1, Bit_number);
    }
  }

  if (User_data_finder != NULL) {
    (*User_data_finder)(&args.first);
  }

  gp_mem_b_set_args(M, Byte_address, W_ARG_T_BOTH, &args);
}

/*------------------------------------------------------------------------------------------------*/

static void
_pic16_reg_eval(MemBlock_t *M, unsigned int Byte_address, gpdasm_fstate_t *Fstate, pic_processor_t Processor,
                unsigned int File, int Bit_number, void (*User_data_finder)(MemArg_t *))
{
  proc_class_t         class;
  MemArgList_t         args;
  const gp_register_t *reg1;

  class = Processor->class;

  args.first.arg   = NULL;
  args.first.val   = File;
  args.first.offs  = 0;
  args.second.arg  = NULL;
  args.second.val  = Bit_number;
  args.second.offs = 0;
  reg1             = NULL;

  if (IS_UNBANKED16(args.first.val)) {
    reg1 = gp_register_find_reg(Fstate->proc_regs, args.first.val);

    if (reg1 == NULL) {
      args.first.arg = gp_processor_find_sfr_name(class, args.first.val);

      if (args.first.arg != NULL) {
        Fstate->need_sfr_equ = true;
      }
    }
  }
  else if (IS_VALID_BANK(Fstate, PIC16_BMSK_BANK)) {
    args.first.val += BANK16_ADDR(Fstate, PIC16_BMSK_BANK);
    reg1 = gp_register_find_reg(Fstate->proc_regs, args.first.val);
  }

  if (reg1 != NULL) {
    args.first.arg = reg1->name;

    if (Bit_number >= 0) {
      args.second.arg = gp_register_find_bit_name(reg1, Bit_number);
    }
  }

  if (User_data_finder != NULL) {
    (*User_data_finder)(&args.first);
  }

  gp_mem_b_set_args(M, Byte_address, W_ARG_T_BOTH, &args);
}

/*------------------------------------------------------------------------------------------------*/

static int
_pic16e_reg_eval(MemBlock_t *M, unsigned int Byte_address, gpdasm_fstate_t *Fstate, pic_processor_t Processor,
                 unsigned int File, int Bit_number, gp_boolean Ram_acc, void (*User_data_finder)(MemArg_t *))
{
  proc_class_t         class;
  MemArgList_t         args;
  const gp_register_t *reg1;
  int                  reg_addr;

  class = Processor->class;

  args.first.arg   = NULL;
  args.first.val   = File;
  args.first.offs  = 0;
  args.second.arg  = NULL;
  args.second.val  = Bit_number;
  args.second.offs = 0;
  reg1             = NULL;

  if ((!Ram_acc) && (Fstate->bsr_boundary > 0) && (args.first.val >= Fstate->bsr_boundary)) {
    /* This register in the Access Bank can be found. */
    args.first.val += 0xF00;
    reg1 = gp_register_find_reg(Fstate->proc_regs, args.first.val);

    if (reg1 == NULL) {
      args.first.arg = gp_processor_find_sfr_name(class, args.first.val);

      if (args.first.arg != NULL) {
        Fstate->need_sfr_equ = true;
      }
    }

    reg_addr = args.first.val;
  }
  else if (IS_VALID_BANK(Fstate, PIC16E_BMSK_BANK)) {
        /* This register in the GPR Bank can be found. */
    args.first.val += BANK16_ADDR(Fstate, PIC16E_BMSK_BANK);
    reg1 = gp_register_find_reg(Fstate->proc_regs, args.first.val);
    reg_addr = args.first.val;
  }
  else {
    args.first.arg = NULL;
    reg_addr = -1;
  }

  if (reg1 != NULL) {
    args.first.arg = reg1->name;

    if (Bit_number >= 0) {
      args.second.arg = gp_register_find_bit_name(reg1, Bit_number);
    }
  }

  if (User_data_finder != NULL) {
    (*User_data_finder)(&args.first);
  }

  gp_mem_b_set_args(M, Byte_address, W_ARG_T_BOTH, &args);
  return reg_addr;
}

/*------------------------------------------------------------------------------------------------*/

        /* This function partially handle the registers of SX family. */

unsigned int
gp_disassemble_find_registers(MemBlock_t *M, unsigned int Byte_address, pic_processor_t Processor,
                              gpdasm_fstate_t *Fstate, void (*User_data_finder)(MemArg_t *))
{
  proc_class_t      class;
  uint16_t          opcode;
  const insn_t     *instruction;
  enum common_insn  icode;
  unsigned int      num_words;
  uint16_t          file1;
  uint16_t          file2;
  unsigned int      tmp;
  gp_boolean        ram_acc;
  int               addr;
  MemArgList_t      args;

  class = Processor->class;

  if (class->find_insn == NULL) {
    return 0;
  }

  num_words = 1;

  if (class->i_memory_get(M, Byte_address, &opcode, NULL, NULL) != W_USED_ALL) {
    return num_words;
  }

  instruction = class->find_insn(class, opcode);

  if (instruction == NULL)  {
    return num_words;
  }

  icode = instruction->icode;

  if ((Byte_address > 0) && (gp_mem_b_get_addr_type(M, Byte_address, NULL, NULL) & W_ADDR_T_MASK)) {
    /* This address is destination of a branch. */
    Fstate->wreg = -1;
    Fstate->bank_valid = 0;
  }

GPUTILS_GCC_DIAG_OFF(switch)

  switch (instruction->class) {
    case INSN_CLASS_LIT3:
      /* PIC12E, PIC12I movlb */
      Fstate->bank = opcode & PIC12E_BMSK_BANK;
      Fstate->bank_valid = PIC12E_BMSK_BANK;
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT4L:
      /* PIC16E movlb */
      Fstate->bank = opcode & PIC16E_BMSK_MOVLB;
      Fstate->bank_valid = PIC16E_BMSK_MOVLB;
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT4H:
      /* PIC16 movlr */
      Fstate->bank &= ~PIC16_BMSK_MOVLR;
      Fstate->bank |= opcode & PIC16_BMSK_MOVLR;
      Fstate->bank_valid |= PIC16_BMSK_MOVLR;
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT5:
      /* PIC14E movlb */
      Fstate->bank = opcode & PIC14E_BMSK_BANK;
      Fstate->bank_valid = PIC14E_BMSK_BANK;
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LITBSR_6:
      /* PIC14EX movlb */
      Fstate->bank = opcode & PIC14EX_BMSK_BANK;
      Fstate->bank_valid = PIC14EX_BMSK_BANK;
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT8:
      /* PIC1xx (addlw, andlw, iorlw, movlw, retlw, sublw, xorlw),
         PIC16  movlb,
         PIC16x mullw,
         PIC16E pushl */
      tmp = opcode & 0xff;

      if ((class == PROC_CLASS_PIC16) && (icode == ICODE_MOVLB)) {
        Fstate->bank &= ~PIC16_BMSK_MOVLB;
        Fstate->bank |= tmp & PIC16_BMSK_MOVLB;
        Fstate->bank_valid |= PIC16_BMSK_MOVLB;
      }
      else if (Fstate->wreg >= 0) {
        switch (icode) {
        case ICODE_ADDLW: Fstate->wreg = (Fstate->wreg + tmp) & 0xff; break;
        case ICODE_ANDLW: Fstate->wreg = (Fstate->wreg & tmp) & 0xff; break;
        case ICODE_IORLW: Fstate->wreg = (Fstate->wreg | tmp) & 0xff; break;
        case ICODE_SUBLW: Fstate->wreg = (tmp - Fstate->wreg) & 0xff; break;
        case ICODE_XORLW: Fstate->wreg = (Fstate->wreg ^ tmp) & 0xff; break;
        }
      }
      else if (icode == ICODE_MOVLW) {
        Fstate->wreg = tmp;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT8C12:
      /* PIC12x call, SX call */
    case INSN_CLASS_LIT8C16:
      /* PIC16 lcall */
    case INSN_CLASS_LIT9:
      /* PIC12 goto, SX goto */
    case INSN_CLASS_LIT11:
      /* PIC14x (call, goto) */
    case INSN_CLASS_LIT13:
      /* PIC16 (call, goto) */
    case INSN_CLASS_RBRA8:
      /* PIC16E (bc, bn, bnc, bnn, bnov, bnz, bov, bz) */
    case INSN_CLASS_RBRA9:
      /* PIC14E bra */
    case INSN_CLASS_RBRA11:
      /* PIC16E (bra, rcall) */

      if ((icode == ICODE_CALL) || (icode == ICODE_RCALL)) {
        Fstate->wreg = -1;
        Fstate->bank_valid = 0;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT20:
      /* PIC16E goto */
    case INSN_CLASS_FLIT12:
      /* PIC16E lfsr */
      if ((class->i_memory_get(M, Byte_address + 2, &file1, NULL, NULL) == W_USED_ALL) &&
          ((file1 & PIC16E_BMSK_SEC_INSN_WORD) == PIC16E_BMSK_SEC_INSN_WORD)) {
        num_words = 2;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_SS:
      /* PIC16E movss */
      if ((class->i_memory_get(M, Byte_address + 2, &file1, NULL, NULL) == W_USED_ALL) &&
          ((file1 & 0xff80) == PIC16E_BMSK_SEC_INSN_WORD)) {
        num_words = 2;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_CALL20:
      /* PIC16E call */
      if ((class->i_memory_get(M, Byte_address + 2, &file1, NULL, NULL) == W_USED_ALL) &&
          ((file1 & PIC16E_BMSK_SEC_INSN_WORD) == PIC16E_BMSK_SEC_INSN_WORD)) {
        num_words = 2;
      }

      Fstate->wreg = -1;
      Fstate->bank_valid = 0;
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_FF:
      /* PIC16E movff */
      if ((class->i_memory_get(M, Byte_address + 2, &file2, NULL, NULL) == W_USED_ALL) &&
          ((file2 & PIC16E_BMSK_SEC_INSN_WORD) == PIC16E_BMSK_SEC_INSN_WORD)) {
        args.first.val   = opcode & 0x0fff;
        args.first.offs  = 0;
        args.second.val  = file2 & 0x0fff;
        args.second.offs = 0;
        args.first.arg   = gp_register_find_reg_name(Fstate->proc_regs, args.first.val);
        args.second.arg  = gp_register_find_reg_name(Fstate->proc_regs, args.second.val);

        if (args.first.arg == NULL) {
          args.first.arg = gp_processor_find_sfr_name(class, args.first.val);

          if (args.first.arg != NULL) {
            Fstate->need_sfr_equ = true;
          }
        }

        if (User_data_finder != NULL) {
          (*User_data_finder)(&args.first);
        }

        if (args.second.arg == NULL) {
          args.second.arg = gp_processor_find_sfr_name(class, args.second.val);

          if (args.second.arg != NULL) {
            Fstate->need_sfr_equ = true;
          }
        }

        if (User_data_finder != NULL) {
          (*User_data_finder)(&args.second);
        }

        gp_mem_b_set_args(M, Byte_address, W_ARG_T_BOTH, &args);
        num_words = 2;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_FP:
      /* PIC16 movfp */
      args.first.val  = opcode & PIC16_BMSK_FILE;
      args.second.val = (opcode >> 8) & 0x1f;

      if (IS_UNBANKED16(args.first.val)) {
        /* This a unbanked address. */
        args.first.arg = gp_register_find_reg_name(Fstate->proc_regs, args.first.val);

        if (args.first.arg == NULL) {
          args.first.arg = gp_processor_find_sfr_name(class, args.first.val);

          if (args.first.arg != NULL) {
            Fstate->need_sfr_equ = true;
          }
        }
      }
      else if (IS_VALID_BANK(Fstate, PIC16_BMSK_BANK)) {
        args.first.val += BANK16_ADDR(Fstate, PIC16_BMSK_BANK);
        args.first.arg = gp_register_find_reg_name(Fstate->proc_regs, args.first.val);

        if (User_data_finder != NULL) {
          (*User_data_finder)(&args.first);
        }
      }
      else {
        args.first.arg = NULL;
      }

      if (IS_UNBANKED16(args.second.val)) {
        /* This a unbanked address. */
        args.second.arg = gp_register_find_reg_name(Fstate->proc_regs, args.second.val);

        if (args.second.arg == NULL) {
          args.second.arg = gp_processor_find_sfr_name(class, args.second.val);

          if (args.second.arg != NULL) {
            Fstate->need_sfr_equ = true;
          }
        }
      }
      else if (IS_VALID_BANK(Fstate, PIC16_BMSK_BANK)) {
        args.second.val += BANK16_ADDR(Fstate, PIC16_BMSK_BANK);
        args.second.arg = gp_register_find_reg_name(Fstate->proc_regs, args.second.val);

        if (User_data_finder != NULL) {
          (*User_data_finder)(&args.second);
        }
      }
      else {
        args.second.arg = NULL;
      }

      goto _insn_class_pf;
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_PF:
      /* PIC16 movpf */
      args.first.val  = (opcode >> 8) & 0x1f;
      args.second.val = opcode & PIC16_BMSK_FILE;

      if (IS_UNBANKED16(args.first.val)) {
        /* This a unbanked address. */
        args.first.arg = gp_register_find_reg_name(Fstate->proc_regs, args.first.val);

        if (args.first.arg == NULL) {
          args.first.arg = gp_processor_find_sfr_name(class, args.first.val);

          if (args.first.arg != NULL) {
            Fstate->need_sfr_equ = true;
          }
        }
      }
      else if (IS_VALID_BANK(Fstate, PIC16_BMSK_BANK)) {
        args.first.val += BANK16_ADDR(Fstate, PIC16_BMSK_BANK);
        args.first.arg = gp_register_find_reg_name(Fstate->proc_regs, args.first.val);

        if (User_data_finder != NULL) {
          (*User_data_finder)(&args.first);
        }
      }
      else {
        args.first.arg = NULL;
      }

      if (IS_UNBANKED16(args.second.val)) {
        /* This a unbanked address. */
        args.second.arg = gp_register_find_reg_name(Fstate->proc_regs, args.second.val);

        if (args.second.arg == NULL) {
          args.second.arg = gp_processor_find_sfr_name(class, args.second.val);

          if (args.second.arg != NULL) {
            Fstate->need_sfr_equ = true;
          }
        }
      }
      else if (IS_VALID_BANK(Fstate, PIC16_BMSK_BANK)) {
        args.second.val += BANK16_ADDR(Fstate, PIC16_BMSK_BANK);
        args.second.arg = gp_register_find_reg_name(Fstate->proc_regs, args.second.val);

        if (User_data_finder != NULL) {
          (*User_data_finder)(&args.second);
        }
      }
      else {
        args.second.arg = NULL;
      }

_insn_class_pf:

      gp_mem_b_set_args(M, Byte_address, W_ARG_T_BOTH, &args);

      if (args.second.val == PIC16_REG_WREG) {
        /* The destination the WREG. */
        Fstate->wreg = -1;
      }
      else if ((args.first.val == PIC16_REG_WREG) && (args.second.val == PIC16_REG_BSR)) {
        if (Fstate->wreg < 0) {
          Fstate->bank_valid = 0;
        }
        else {
          Fstate->bank = Fstate->wreg;
          Fstate->bank_valid = 0xff;
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_SF:
      /* PIC16E movsf */
      if ((class->i_memory_get(M, Byte_address + 2, &file2, NULL, NULL) == W_USED_ALL) &&
          ((file2 & PIC16E_BMSK_SEC_INSN_WORD) == PIC16E_BMSK_SEC_INSN_WORD)) {
        args.second.val = file2 & 0x0fff;
        args.second.arg = gp_register_find_reg_name(Fstate->proc_regs, args.second.val);

        if (args.second.arg == NULL) {
          args.second.arg = gp_processor_find_sfr_name(class, args.second.val);

          if (args.second.arg != NULL) {
            Fstate->need_sfr_equ = true;
          }
        }

        if (User_data_finder != NULL) {
          (*User_data_finder)(&args.second);
        }

        if (args.second.arg != NULL) {
          gp_mem_b_set_args(M, Byte_address, W_ARG_T_SECOND, &args);
        }

        num_words = 2;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPF5:
      /* {PIC12x, SX} (clrf, movwf), SX tris */
      file1 = opcode & PIC12_BMSK_FILE;
      _pic12_reg_eval(M, Byte_address, Fstate, Processor, file1, -1, User_data_finder);

      if ((class == PROC_CLASS_PIC12) && (file1 == PIC12_REG_FSR)) {
        if (icode == ICODE_CLRF) {
          Fstate->bank = 0;
          Fstate->bank_valid = 0xff;
        }
        else if (icode == ICODE_MOVWF) {
          if (Fstate->wreg < 0) {
            Fstate->bank_valid = 0;
          }
          else {
            Fstate->bank = Fstate->wreg;
            Fstate->bank_valid = 0xff;
          }
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPWF5:
      /* {PIC12x, SX} (addwf, andwf, comf, decf, decfsz, incf, incfsz,
                       iorwf, movf, rlf, rrf, subwf, swapf, xorwf) */
      file1 = opcode & PIC12_BMSK_FILE;
      /* Destination flag: 0 = W, 1 = F */
      tmp   = (opcode >> 5) & 1;
      _pic12_reg_eval(M, Byte_address, Fstate, Processor, file1, -1, User_data_finder);

      if (tmp == 0) {
        /* The destination the WREG. */
        Fstate->wreg = -1;
      }
      else if ((class == PROC_CLASS_PIC12) && (file1 == PIC12_REG_FSR)) {
        Fstate->bank_valid = 0;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_B5:
      /* {PIC12x, SX} (bcf, bsf, btfsc, btfss) */
      file1 = opcode & PIC12_BMSK_FILE;
      /* The bits of register. */
      tmp   = (opcode >> 5) & 7;
      _pic12_reg_eval(M, Byte_address, Fstate, Processor, file1, tmp, User_data_finder);

      if ((file1 == PIC12_REG_FSR) && ((tmp >= 5) && (tmp <= 7))) {
        tmp = 1 << (tmp - 5);

        if (icode == ICODE_BCF) {
          Fstate->bank &= ~tmp;
          Fstate->bank_valid |= tmp;
        }
        else if (icode == ICODE_BSF) {
          Fstate->bank |= tmp;
          Fstate->bank_valid |= tmp;
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_B8:
      /* PIC16 (bcf, bsf, btfsc, btfss, btg) */
      file1 = opcode & PIC16_BMSK_FILE;
      /* The bits of register. */
      tmp   = (opcode >> 8) & 7;
      _pic16_reg_eval(M, Byte_address, Fstate, Processor, file1, tmp, User_data_finder);

      tmp = 1 << tmp;

      if (file1 == PIC16_REG_BSR) {
        if (icode == ICODE_BCF) {
          Fstate->bank &= ~tmp;
          Fstate->bank_valid |= tmp;
        }
        else if (icode == ICODE_BSF) {
          Fstate->bank |= tmp;
          Fstate->bank_valid |= tmp;
        }
        else if (icode == ICODE_BTG) {
          Fstate->bank ^= tmp;
          Fstate->bank_valid |= tmp;
        }
      }
      else if ((file1 == PIC16_REG_WREG) && (Fstate->wreg >= 0)) {
        if (icode == ICODE_BCF) {
          Fstate->wreg &= ~tmp;
        }
        else if (icode == ICODE_BSF) {
          Fstate->wreg |= tmp;
        }
        else if (icode == ICODE_BTG) {
          Fstate->wreg ^= tmp;
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPF7:
      /* PIC14x (clrf, movwf, tris) */
      file1 = opcode & PIC14_BMSK_FILE;

      if ((icode == ICODE_CLRF) || (icode == ICODE_MOVWF)) {
        _pic14_reg_eval(M, Byte_address, Fstate, Processor, file1, -1, User_data_finder);
      }

      if (class == PROC_CLASS_PIC14) {
        if (file1 == PIC14_REG_STATUS) {
          if (icode == ICODE_CLRF) {
            Fstate->bank = 0;
            Fstate->bank_valid = PIC14_BMSK_BANK;
          }
          else if (icode == ICODE_MOVWF) {
            Fstate->bank_valid = 0;
          }
        }
      }
      else {
        if (file1 == PIC14E_REG_BSR) {
          if (icode == ICODE_CLRF) {
            Fstate->bank = 0;
            Fstate->bank_valid = PIC14E_BMSK_BANK;
          }
          else if (icode == ICODE_MOVWF) {
            Fstate->bank_valid = 0;
          }
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPF8:
      /* PIC16 (cpfseq, cpfsgt, cpfslt, movwf, mulwf, tstfsz) */
      file1 = opcode & PIC16_BMSK_FILE;
      _pic16_reg_eval(M, Byte_address, Fstate, Processor, file1, -1, User_data_finder);

      if ((icode == ICODE_MOVWF) && (file1 == PIC16_REG_BSR)) {
        if (Fstate->wreg >= 0) {
          Fstate->bank = Fstate->wreg;
          Fstate->bank_valid = 0xff;
        }
        else {
          Fstate->bank_valid = 0;
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPWF7:
      /* PIC14x (addwf, andwf, comf, decf, decfsz, incf, incfsz, iorwf, movf,
                 rlf, rrf, subwf, swapf, xorwf)
         PIC14E (addwfc, asrf, lslf, lsrf, subwfb) */
      file1 = opcode & PIC14_BMSK_FILE;
      /* Destination flag: 0 = W, 1 = F */
      tmp   = (opcode >> 7) & 1;
      _pic14_reg_eval(M, Byte_address, Fstate, Processor, file1, -1, User_data_finder);

      if (tmp == 0) {
        /* The destination the WREG. */
        Fstate->wreg = -1;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPWF8:
      /* PIC16 (addwf, addwfc, andwf, clrf, comf, daw, decf, decfsz, dcfsnz, incf,
                incfsz, infsnz, iorwf, rlcf, rlncf, rrcf, rrncf, setf, subwf, subwfb,
                swapf, xorwf) */
      file1 = opcode & PIC16_BMSK_FILE;
      /* Destination flag: 0 = W, 1 = F */
      tmp   = (opcode >> 8) & 1;
      _pic16_reg_eval(M, Byte_address, Fstate, Processor, file1, -1, User_data_finder);

      if ((tmp == 0) || (file1 == PIC16_REG_WREG)) {
        /* The destination the WREG. */
        Fstate->wreg = -1;
      }
      else if (file1 == PIC16_REG_BSR) {
        Fstate->bank_valid = 0;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_B7:
      /* PIC14x (bcf, bsf, btfsc, btfss) */
      file1 = opcode & PIC14_BMSK_FILE;
      /* The bits of register. */
      tmp   = (opcode >> 7) & 7;
      _pic14_reg_eval(M, Byte_address, Fstate, Processor, file1, tmp, User_data_finder);

      if ((class == PROC_CLASS_PIC14E) || (class == PROC_CLASS_PIC14EX)) {
        tmp = 1 << tmp;

        if (file1 == PIC14E_REG_BSR) {
          if (icode == ICODE_BCF) {
            Fstate->bank &= ~tmp;
            Fstate->bank_valid |= tmp;
          }
          else if (icode == ICODE_BSF) {
            Fstate->bank |= tmp;
            Fstate->bank_valid |= tmp;
          }
        }
        else if ((file1 == PIC14E_REG_WREG) && (Fstate->wreg >= 0)) {
          if (icode == ICODE_BCF) {
            Fstate->wreg &= ~tmp;
          }
          else if (icode == ICODE_BSF) {
            Fstate->wreg |= tmp;
          }
        }
      }
      else {
        if ((file1 == PIC14_REG_STATUS) && ((tmp == PIC14_BIT_STATUS_RP0) ||
                                            (tmp == PIC14_BIT_STATUS_RP1))) {
          tmp = 1 << (tmp - PIC14_BIT_STATUS_RP0);

          if (icode == ICODE_BCF) {
            Fstate->bank &= ~tmp;
            Fstate->bank_valid |= tmp;
          }
          else if (icode == ICODE_BSF) {
            Fstate->bank |= tmp;
            Fstate->bank_valid |= tmp;
          }
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPFA8:
      /* PIC16E (clrf, cpfseq, cpfsgt, cpfslt, movwf, mulwf, negf, setf, tstfsz) */
      file1   = opcode & PIC16_BMSK_FILE;
      /* RAM access flag: 0 = Access Bank, 1 = GPR Bank */
      ram_acc = (opcode & 0x100) ? true : false;
      addr    = _pic16e_reg_eval(M, Byte_address, Fstate, Processor, file1, -1, ram_acc, User_data_finder);

      if (addr == PIC16E_REG_BSR) {
        /* The address of register is known. */
        if (icode == ICODE_CLRF) {
          Fstate->bank = 0;
          Fstate->bank_valid = PIC16_BMSK_BANK;
        }
        else if (icode == ICODE_SETF) {
          Fstate->bank = 0xff;
          Fstate->bank_valid = PIC16_BMSK_BANK;
        }
        else if ((icode == ICODE_MOVWF) || (icode == ICODE_NEGF)) {
          Fstate->bank_valid = 0;
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_BA8:
      /* PIC16E (bcf, bsf, btfsc, btfss, btg) */
      file1   = opcode & PIC16_BMSK_FILE;
      /* The bits of register. */
      tmp     = (opcode >> 9) & 7;
      /* RAM access flag: 0 = Access Bank, 1 = GPR Bank */
      ram_acc = (opcode & 0x100) ? true : false;
      addr    = _pic16e_reg_eval(M, Byte_address, Fstate, Processor, file1, tmp, ram_acc, User_data_finder);

      if ((addr == PIC16E_REG_BSR) && IS_VALID_BANK(Fstate, PIC16_BMSK_BANK)) {
        /* The address of register is known and known the value of. */
        tmp = 1 << tmp;

        if (icode == ICODE_BCF) {
          Fstate->bank &= ~tmp;
        }
        else if (icode == ICODE_BSF) {
          Fstate->bank |= tmp;
        }
        else if (icode == ICODE_BTG) {
          Fstate->bank ^= tmp;
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPWFA8:
      /* PIC16E (addwf, addwfc, andwf, comf, decf, decfsz, dcfsnz, incf, incfsz,
                 infsnz, iorwf, movf, rlcf, rlncf, rrcf, rrncf, subfwb, subwf,
                 subwfb, swapf, xorwf) */
      file1   = opcode & PIC16_BMSK_FILE;
      /* Destination flag: 0 = W, 1 = F */
      tmp     = (opcode >> 9) & 1;
      /* RAM access flag: 0 = Access Bank, 1 = GPR Bank */
      ram_acc = (opcode & 0x100) ? true : false;
      addr    = _pic16e_reg_eval(M, Byte_address, Fstate, Processor, file1, -1, ram_acc, User_data_finder);

      if ((addr == PIC16E_REG_BSR) && (tmp != 0)) {
        Fstate->bank_valid = 0;
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_TBL2:
      /* PIC16 (tlrd, tlwt) */
      file1 = opcode & PIC16_BMSK_FILE;
      _pic16_reg_eval(M, Byte_address, Fstate, Processor, file1, -1, User_data_finder);

      if (icode == ICODE_TLRD) {
        if (file1 == PIC16_REG_WREG) {
          Fstate->wreg = -1;
        }
        else if (file1 == PIC16_REG_BSR) {
          Fstate->bank_valid = 0;
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_TBL3:
      /* PIC16 (tablrd, tablwt) */
      file1 = opcode & PIC16_BMSK_FILE;
      _pic16_reg_eval(M, Byte_address, Fstate, Processor, file1, -1, User_data_finder);

      if (icode == ICODE_TABLRD) {
        if (file1 == PIC16_REG_WREG) {
          Fstate->wreg = -1;
        }
        else if (file1 == PIC16_REG_BSR) {
          Fstate->bank_valid = 0;
        }
      }
      break;
    } /* switch (instruction->class) */

GPUTILS_GCC_DIAG_ON(switch)

  return num_words;
}

/*------------------------------------------------------------------------------------------------*/

static unsigned int
print_word(char *Buffer, size_t Buffer_length, size_t Current_length, uint16_t Opcode,
           unsigned int Behavior) {
  int    l;
  size_t length;
  char   bytes[2];

  l = snprintf(&Buffer[Current_length], Buffer_length - Current_length, "%-*s0x%04x",
               TABULATOR_SIZE, "dw", (unsigned int)Opcode);

  if (l <= 0) {
    return 0;
  }

  length = Current_length + l;
  bytes[0] = (uint8_t)(Opcode & 0xFF);
  bytes[1] = (uint8_t)((Opcode >> 8) & 0xFF);

  if (Behavior & GPDIS_SHOW_BYTES) {
    if (isprint(Opcode)) {
      gp_exclamation(Buffer, Buffer_length, length, "; '%c'", bytes[0]);
    }
    else if (isprint((unsigned char)bytes[0]) && isprint((unsigned char)bytes[1])) {
      gp_exclamation(Buffer, Buffer_length, length, "; '%c%c'", bytes[0], bytes[1]);
    }
  }

  return 1;
}

/*------------------------------------------------------------------------------------------------*/

static void
_show_word(char *Buffer, size_t Buffer_length, size_t Current_length, const uint8_t *bytes)
{
  unsigned int v;

  v  = (isprint(bytes[0])) ? 1 : 0;
  v |= (isprint(bytes[1])) ? 2 : 0;

  switch (v) {
    case 1: {
      gp_exclamation(Buffer, Buffer_length, Current_length, "; '%c'", bytes[0]);
      break;
    }

    case 2: {
      gp_exclamation(Buffer, Buffer_length, Current_length, ";  '%c'", bytes[1]);
      break;
    }

    case 3: {
      gp_exclamation(Buffer, Buffer_length, Current_length, "; '%c%c'", bytes[0], bytes[1]);
      break;
    }
  }
}

/*------------------------------------------------------------------------------------------------*/

void
gp_disassemble_show_data(MemBlock_t *M, unsigned int Byte_address, proc_class_t Class,
                         unsigned int Behavior, char *Buffer, size_t Buffer_length, size_t Current_length)
{
  const insn_t     *instruction;
  enum common_insn  icode;
  uint16_t          opcode;
  uint8_t           bytes[2];
  int               l;
  size_t            length;

  length = Current_length;

  if (Class->find_insn == NULL) {
    snprintf(&Buffer[length], Buffer_length - length, "unsupported processor class");
    return;
  }

  if (Class->i_memory_get(M, Byte_address, &opcode, NULL, NULL) == W_USED_ALL) {
    bytes[0] = (uint8_t)(opcode & 0xFF);
    bytes[1] = (uint8_t)((opcode >> 8) & 0xFF);

    if ((Class == PROC_CLASS_PIC16) || (Class == PROC_CLASS_PIC16E)) {
      l = snprintf(&Buffer[Current_length], Buffer_length - Current_length, "%-*s0x%02x, 0x%02x",
                   TABULATOR_SIZE, "db", bytes[0], bytes[1]);

      if (l <= 0) {
        return;
      }

      length = Current_length + l;

      if (Behavior & GPDIS_SHOW_BYTES) {
        _show_word(Buffer, Buffer_length, length, bytes);
      }
    }
    else {
      instruction = Class->find_insn(Class, opcode);
      icode = (instruction != NULL) ? instruction->icode : -1;

      if (icode == ICODE_RETLW) {
        l = snprintf(&Buffer[Current_length], Buffer_length - Current_length, "%-*s0x%02x",
                     TABULATOR_SIZE, "dt", bytes[0]);

        if (l <= 0) {
          return;
        }

        length = Current_length + l;

        if (Behavior & GPDIS_SHOW_BYTES) {
          if (isprint(bytes[0])) {
            gp_exclamation(Buffer, Buffer_length, length, "; '%c'", bytes[0]);
          }
        }
      }
      else {
        l = snprintf(&Buffer[Current_length], Buffer_length - Current_length, "%-*s0x%04x",
                     TABULATOR_SIZE, "dw", (unsigned int)opcode);

        if (l <= 0) {
          return;
        }

        length = Current_length + l;

        if (Behavior & GPDIS_SHOW_BYTES) {
          _show_word(Buffer, Buffer_length, length, bytes);
        }
      }
    }
  } /* if (class->i_memory_get(M, Byte_address, &opcode, NULL, NULL) == W_USED_ALL) */
}

/*------------------------------------------------------------------------------------------------*/

unsigned int
gp_disassemble(MemBlock_t *M, unsigned int Byte_address, proc_class_t Class, unsigned int Bsr_boundary,
               unsigned int Prog_mem_size, unsigned int Behavior, char *Buffer, size_t Buffer_length,
               size_t Current_length)
{
  int               value;
  uint16_t          opcode = 0;
  const insn_t     *instruction = NULL;
  enum common_insn  icode;
  unsigned int      prog_max_org;
  unsigned int      type;
  const char       *dest_name;
  int               org;
  unsigned int      num_words = 1;
  uint16_t          file1;
  uint16_t          file2;
  unsigned int      tmp;
  unsigned int      ram_acc;
  MemArgList_t      args;
  int               addr_digits;
  size_t            length;
  unsigned int      dest_byte_addr;
  const char       *instr;
  const char       *neg;
  const char       *reg;

  length = Current_length;

  if (Class->find_insn == NULL) {
    snprintf(&Buffer[length], Buffer_length - length, "unsupported processor Class");
    return 0;
  }

  prog_max_org = (Prog_mem_size > 0) ? (Prog_mem_size - 1) : 0;

  addr_digits     = Class->addr_digits;
  type            = 0;
  dest_name       = NULL;
  args.first.arg  = NULL;
  args.second.arg = NULL;

  if (Class->i_memory_get(M, Byte_address, &opcode, NULL, NULL) == W_USED_ALL) {
    org  = gp_processor_insn_from_byte_c(Class, Byte_address);
    type = gp_mem_b_get_addr_type(M, Byte_address, NULL, &dest_byte_addr);

    if (Behavior & GPDIS_SHOW_NAMES) {
      if (type & W_ADDR_T_BRANCH_SRC) {
        gp_mem_b_get_addr_type(M, dest_byte_addr, &dest_name, NULL);
      }

      gp_mem_b_get_args(M, Byte_address, &args);
    }
  }

  /* Special case for pic14 enhanced moviw k[FSRn] & movwi k[FSRn]. */
  if ((Class == PROC_CLASS_PIC14E) || (Class == PROC_CLASS_PIC14EX)) {
    instr = NULL;
    tmp   = opcode & PIC14E_MASK_MOVIW_IDX;

    if (tmp == PIC14E_INSN_MOVIW_IDX) {
      instr = "moviw";
    }
    else if (tmp == PIC14E_INSN_MOVWI_IDX) {
      instr = "movwi";
    }

    if (instr != NULL) {
      /* twos complement number */
      value = opcode & 0x003f;
      tmp   = (opcode >> 6) & 1;

      if (value & 0x20) {
        value = (value ^ 0x3f) + 1;
        neg = "-";
      }
      else {
        neg = "";
      }

      if (Behavior & GPDIS_SHOW_NAMES) {
        reg = (Behavior & GPDIS_SHOW_FSRN) ? "FSR" : "INDF";
        snprintf(&Buffer[length], Buffer_length - length, "%-*s%s.%d[%s%i]", TABULATOR_SIZE, instr, neg, value, reg, tmp);
      }
      else {
        if (Behavior & GPDIS_SHOW_FSRN) {
          tmp |= 2;
        }

        switch (tmp) {
          case 0: tmp = PIC14E_REG_INDF0; break;
          case 1: tmp = PIC14E_REG_INDF1; break;
          case 2: tmp = PIC14E_REG_FSR0;  break;
          case 3: tmp = PIC14E_REG_FSR1;  break;
        }

        snprintf(&Buffer[length], Buffer_length - length, "%-*s%s.%d[%u]", TABULATOR_SIZE, instr, neg, value, tmp);
      }

      return num_words;
    }
  }

  instruction = Class->find_insn(Class, opcode);

  if (instruction == NULL)  {
    return print_word(Buffer, Buffer_length, Current_length, opcode, Behavior);
  }

  icode = instruction->icode;

GPUTILS_GCC_DIAG_OFF(switch)

  switch (instruction->class) {
    case INSN_CLASS_LIT3_BANK:
      /* SX bank */
      PRINT_ARG1_N(1, (opcode & SX_BMSK_BANK) << 5);
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT3_PAGE:
      /* SX page */
      PRINT_ARG1_N(1, (opcode & SX_BMSK_PAGE) << 9);
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT1:
      /* PIC16E (retfie, return) */
      PRINT_ARG1_N(1, opcode & 0x0001);
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT3:
      /* PIC12E, PIC12I movlb */
      PRINT_ARG1_N(1, opcode & PIC12E_BMSK_BANK);
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT4:
      /* SX mode */
      PRINT_ARG1_N(1, opcode & SX_BMSK_MODE);
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT4L:
      /* PIC16E movlb */
      PRINT_ARG1_N(1, opcode & PIC16E_BMSK_MOVLB);
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT4H:
      /* PIC16 movlr */
      PRINT_ARG1_N(1, (opcode & PIC16_BMSK_MOVLR) >> 4);
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT5:
      /* PIC14E movlb */
      PRINT_ARG1_N(2, opcode & PIC14E_BMSK_BANK);
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LITBSR_6:
      /* PIC14EX movlb */
      PRINT_ARG1_N(2, opcode & PIC14EX_BMSK_BANK);
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT6:
      /* PIC16E (addulnk, subulnk) */
      PRINT_ARG1_N(2, opcode & PIC16EX_BMSK_xxxULNK);
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT7:
      /* PIC14E movlp */
      PRINT_ARG1_N(2, opcode & PIC14E_BMSK_PAGE512);
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT8:
      /* PIC1xx (addlw, andlw, iorlw, movlw, retlw, sublw, xorlw),
         PIC16  movlb,
         PIC16x mullw,
         PIC16E pushl */
      if ((Class == PROC_CLASS_PIC16) && (icode == ICODE_MOVLB)) {
        PRINT_ARG1_N(1, opcode & PIC16_BMSK_MOVLB);
      }
      else {
        PRINT_ARG1_N(2, opcode & 0x00ff);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT8C12:
      /* PIC12x call, SX call */
    case INSN_CLASS_LIT8C16:
      /* PIC16 lcall */
      org = opcode & 0x00ff;

      if (Behavior & GPDIS_SHOW_ALL_BRANCH) {
        PRINT_ARG1_N(addr_digits, org);
      }
      else if ((prog_max_org > 0) && (org <= prog_max_org)) {
        /* The target address exist. */
        if (dest_name != NULL) {
          PRINT_ARG1_S(dest_name, 0);
        }
        else {
          PRINT_ARG1_N(addr_digits, org);
        }
      }
      else {
        /* The target address not exist. */
        return print_word(Buffer, Buffer_length, Current_length, opcode, Behavior);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT9:
      /* PIC12 goto, SX goto */
      org = opcode & PIC12_BMSK_GOTO;

      if (Behavior & GPDIS_SHOW_ALL_BRANCH) {
        PRINT_ARG1_N(addr_digits, org);
      }
      else if ((prog_max_org > 0) && (org <= prog_max_org)) {
        /* The target address exist. */
        if (dest_name != NULL) {
          PRINT_ARG1_S(dest_name, 0);
        }
        else {
          PRINT_ARG1_N(addr_digits, org);
        }
      }
      else {
        /* The target address not exist. */
        return print_word(Buffer, Buffer_length, Current_length, opcode, Behavior);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT11:
      /* PIC14x (call, goto) */
      org = opcode & PIC14_BMSK_BRANCH;

      if (Behavior & GPDIS_SHOW_ALL_BRANCH) {
        PRINT_ARG1_N(addr_digits, org);
      }
      else if ((prog_max_org > 0) && (org <= prog_max_org)) {
        /* The target address exist. */
        if (dest_name != NULL) {
          PRINT_ARG1_S(dest_name, 0);
        }
        else {
          PRINT_ARG1_N(addr_digits, org);
        }
      }
      else {
        /* The target address not exist. */
        return print_word(Buffer, Buffer_length, Current_length, opcode, Behavior);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT13:
      /* PIC16 (call, goto) */
      org = opcode & PIC16_BMSK_BRANCH;

      if (Behavior & GPDIS_SHOW_ALL_BRANCH) {
        PRINT_ARG1_N(addr_digits, org);
      }
      else if ((prog_max_org > 0) && (org <= prog_max_org)) {
        /* The target address exist. */
        PRINT_ARG1_N(addr_digits, org);
      }
      else {
        /* The target address not exist. */
        return print_word(Buffer, Buffer_length, Current_length, opcode, Behavior);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LITFSR_14:
      /* PIC14E addfsr */
      {
        value = opcode & 0x003f;
        tmp   = (opcode & 0x0040) >> 6;

        if (value & 0x20) {
          value = (value ^ 0x3f) + 1;
          neg = "-";
        }
        else {
          neg = "";
        }

        if (Behavior & GPDIS_SHOW_NAMES) {
          snprintf(&Buffer[length], Buffer_length - length, "%-*sFSR%i, %s.%d", TABULATOR_SIZE, instruction->name,
                   tmp, neg, value);
        }
        else {
          snprintf(&Buffer[length], Buffer_length - length, "%-*s%u, %s.%d", TABULATOR_SIZE, instruction->name,
                   (tmp) ? PIC14E_REG_FSR1 : PIC14E_REG_FSR0, neg, value);
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LITFSR_16:
      /* PIC16E (addfsr, subfsr) */
      PRINT_ARG2_N_N(1, ((opcode >> 6) & 0x3), 2, (opcode & 0x003f));
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_RBRA8:
      /* PIC16E (bc, bn, bnc, bnn, bnov, bnz, bov, bz) */
      value = opcode & PIC16E_BMSK_RBRA8;
      /* twos complement number */
      if (value & 0x80) {
        value = -((value ^ PIC16E_BMSK_RBRA8) + 1);
      }

      org = gp_processor_insn_from_byte_c(Class, Byte_address + value * 2 + 2);

      if (Behavior & GPDIS_SHOW_ALL_BRANCH) {
        PRINT_ARG1_N(addr_digits, org);
      }
      else if ((prog_max_org > 0) && (org >= 0) && (org <= prog_max_org)) {
        /* The target address exist. */
        if (dest_name != NULL) {
          PRINT_ARG1_S(dest_name, 0);
        }
        else {
          PRINT_ARG1_N(addr_digits, org);
        }
      }
      else {
        /* The target address not exist. */
        return print_word(Buffer, Buffer_length, Current_length, opcode, Behavior);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_RBRA9:
      /* PIC14E bra */
      value = opcode & PIC14E_BMSK_RBRA9;
      /* twos complement number */
      if (value & 0x100) {
        value = -((value ^ PIC14E_BMSK_RBRA9) + 1);
      }

      org = gp_processor_insn_from_byte_c(Class, Byte_address + value * 2 + 2);

      if (Behavior & GPDIS_SHOW_ALL_BRANCH) {
        PRINT_ARG1_N(addr_digits, org);
      }
      else if ((prog_max_org > 0) && (org >= 0) && (org <= prog_max_org)) {
        /* The target address exist. */
        PRINT_ARG1_N(addr_digits, org);
      }
      else {
        /* The target address not exist. */
        return print_word(Buffer, Buffer_length, Current_length, opcode, Behavior);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_RBRA11:
      /* PIC16E (bra, rcall) */
      value = opcode & PIC16E_BMSK_RBRA11;
      /* twos complement number */
      if (value & 0x400) {
        value = -((value ^ PIC16E_BMSK_RBRA11) + 1);
      }

      org = gp_processor_insn_from_byte_c(Class, Byte_address + value * 2 + 2);

      if (Behavior & GPDIS_SHOW_ALL_BRANCH) {
        PRINT_ARG1_N(addr_digits, org);
      }
      else if ((prog_max_org > 0) && (org >= 0) && (org <= prog_max_org)) {
        /* The target address exist. */
        if (dest_name != NULL) {
          PRINT_ARG1_S(dest_name, 0);

          if (Behavior & GPDIS_SHOW_EXCLAMATION) {
            gp_exclamation(Buffer, Buffer_length, length, "; dest: 0x%0*x", addr_digits, org);
          }
        }
        else {
          PRINT_ARG1_N(addr_digits, org);
        }
      }
      else {
        /* The target address not exist. */
        return print_word(Buffer, Buffer_length, Current_length, opcode, Behavior);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_LIT20:
      /* PIC16E goto */
      {
        uint16_t dest;

        if ((Class->i_memory_get(M, Byte_address + 2, &dest, NULL, NULL) == W_USED_ALL) &&
            ((dest & PIC16E_BMSK_SEC_INSN_WORD) == PIC16E_BMSK_SEC_INSN_WORD)) {
          dest  = (dest & PIC16E_BMSK_BRANCH_HIGHER) << 8;
          dest |= opcode & PIC16E_BMSK_BRANCH_LOWER;

          org = gp_processor_insn_from_byte_c(Class, dest * 2);

          if (Behavior & GPDIS_SHOW_ALL_BRANCH) {
            PRINT_ARG1_N(addr_digits, org);
          }
          else if ((prog_max_org > 0) && (org >= 0) && (org <= prog_max_org)) {
            /* The target address exist. */
            if (dest_name != NULL) {
              PRINT_ARG1_S(dest_name, 0);

              if (Behavior & GPDIS_SHOW_EXCLAMATION) {
                gp_exclamation(Buffer, Buffer_length, length, "; dest: 0x%0*x", addr_digits, org);
              }
            }
            else {
              PRINT_ARG1_N(addr_digits, org);
            }
          }
          else {
            /* The target address not exist. */
            return print_word(Buffer, Buffer_length, Current_length, opcode, Behavior);
          }

          num_words = 2;
        }
        else {
          return print_word(Buffer, Buffer_length, Current_length, opcode, Behavior);
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_CALL20:
      /* PIC16E call */
      {
        uint16_t dest;

        if ((Class->i_memory_get(M, Byte_address + 2, &dest, NULL, NULL) == W_USED_ALL) &&
            ((dest & PIC16E_BMSK_SEC_INSN_WORD) == PIC16E_BMSK_SEC_INSN_WORD)) {
          dest  = (dest & PIC16E_BMSK_BRANCH_HIGHER) << 8;
          dest |= opcode & PIC16E_BMSK_BRANCH_LOWER;
          tmp   = (opcode >> 8) & 1;

          org = gp_processor_insn_from_byte_c(Class, dest * 2);

          if (Behavior & GPDIS_SHOW_ALL_BRANCH) {
            PRINT_ARG2_N_N(addr_digits, org, 1, tmp);
          }
          else if ((prog_max_org > 0) && (org >= 0) && (org <= prog_max_org)) {
            /* The target address exist. */
            if (dest_name != NULL) {
              PRINT_ARG2_S_N(dest_name, 0, 1, tmp);

              if (Behavior & GPDIS_SHOW_EXCLAMATION) {
                gp_exclamation(Buffer, Buffer_length, length, "; dest: 0x%0*x", addr_digits, org);
              }
            }
            else {
              PRINT_ARG2_N_N(addr_digits, org, 1, tmp);
            }
          }
          else {
            /* The target address not exist. */
            return print_word(Buffer, Buffer_length, Current_length, opcode, Behavior);
          }

          num_words = 2;
        }
        else {
          return print_word(Buffer, Buffer_length, Current_length, opcode, Behavior);
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_FLIT12:
      /* PIC16E lfsr */
      {
        uint16_t k;

        if ((Class->i_memory_get(M, Byte_address + 2, &k, NULL, NULL) == W_USED_ALL) &&
            ((k & PIC16E_BMSK_SEC_INSN_WORD) == PIC16E_BMSK_SEC_INSN_WORD)) {
          k = ((opcode & 0x000f) << 8) | (k & 0x00ff);
          file1 = (opcode >> 4) & 3;
          PRINT_ARG2_N_N(1, file1, 3, k);
          num_words = 2;
        }
        else {
          return print_word(Buffer, Buffer_length, Current_length, opcode, Behavior);
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_FF:
      /* PIC16E movff */
      file1 = opcode & 0x0fff;

      if ((Class->i_memory_get(M, Byte_address + 2, &file2, NULL, NULL) == W_USED_ALL) &&
          ((file2 & PIC16E_BMSK_SEC_INSN_WORD) == PIC16E_BMSK_SEC_INSN_WORD)) {
        file2 &= 0xfff;

        tmp  = (args.first.arg  != NULL) ? 2 : 0;
        tmp |= (args.second.arg != NULL) ? 1 : 0;

        switch (tmp) {
        case 3:
          PRINT_ARG2_S_S(args.first.arg, args.first.offs, args.second.arg, args.second.offs);

          if (Behavior & GPDIS_SHOW_EXCLAMATION) {
            gp_exclamation(Buffer, Buffer_length, length, "; reg1: 0x%03x, reg2: 0x%03x", args.first.val, args.second.val);
          }
          break;

        case 2:
          PRINT_ARG2_S_N(args.first.arg, args.first.offs, 3, file2);

          if (Behavior & GPDIS_SHOW_EXCLAMATION) {
            gp_exclamation(Buffer, Buffer_length, length, "; reg1: 0x%03x", args.first.val);
          }
          break;

        case 1:
          PRINT_ARG2_N_S(3, file1, args.second.arg, args.second.offs);

          if (Behavior & GPDIS_SHOW_EXCLAMATION) {
            gp_exclamation(Buffer, Buffer_length, length, "; reg2: 0x%03x", args.second.val);
          }
          break;

        default:
          PRINT_ARG2_N_N(3, file1, 3, file2);
        }

        num_words = 2;
      }
      else {
        return print_word(Buffer, Buffer_length, Current_length, opcode, Behavior);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_FP:
      /* PIC16 movfp */
      file1 = opcode & PIC16_BMSK_FILE;
      file2 = (opcode >> 8) & 0x1f;
      goto _insn_class_pf;
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_PF:
      /* PIC16 movpf */
      file1 = (opcode >> 8) & 0x1f;
      file2 = opcode & PIC16_BMSK_FILE;

_insn_class_pf:

      tmp  = (args.first.arg  != NULL) ? 2 : 0;
      tmp |= (args.second.arg != NULL) ? 1 : 0;

      switch (tmp) {
      case 3:
        PRINT_ARG2_S_S(args.first.arg, 0, args.second.arg, 0);
        break;

      case 2:
        PRINT_ARG2_S_N(args.first.arg, 0, 2, file2);
        break;

      case 1:
        PRINT_ARG2_N_S(2, file1, args.second.arg, 0);
        break;

      default:
        PRINT_ARG2_N_N(2, file1, 2, file2);
      }

      if (Behavior & GPDIS_SHOW_EXCLAMATION) {
        gp_exclamation(Buffer, Buffer_length, length, "; reg1: 0x%03x, reg2: 0x%03x", args.first.val, args.second.val);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_SF:
      /* PIC16E movsf */
      {
        uint16_t offset;

        offset = opcode & 0x007f;

        if ((Class->i_memory_get(M, Byte_address + 2, &file2, NULL, NULL) == W_USED_ALL) &&
            ((file2 & PIC16E_BMSK_SEC_INSN_WORD) == PIC16E_BMSK_SEC_INSN_WORD)) {
          file2 &= 0xfff;

          if (args.second.arg != NULL) {
            PRINT_ARG2_N_S(2, offset, args.second.arg, args.second.offs);

            if (Behavior & GPDIS_SHOW_EXCLAMATION) {
              gp_exclamation(Buffer, Buffer_length, length, "; reg2: 0x%03x", args.second.val);
            }
          }
          else {
            PRINT_ARG2_N_N(2, offset, 3, file2);
          }

          num_words = 2;
        }
        else {
          return print_word(Buffer, Buffer_length, Current_length, opcode, Behavior);
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_SS:
      /* PIC16E movss */
      {
        uint16_t offset2;

        if ((Class->i_memory_get(M, Byte_address + 2, &offset2, NULL, NULL) == W_USED_ALL) &&
            ((offset2 & 0xff80) == PIC16E_BMSK_SEC_INSN_WORD)) {
          PRINT_ARG2_N_N(2, opcode & 0x007f, 2, offset2 & 0x007f);
          num_words = 2;
        }
        else {
          return print_word(Buffer, Buffer_length, Current_length, opcode, Behavior);
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPF3:
      /* PIC12 tris */
      PRINT_ARG1_N(1, opcode & PIC12_BMSK_TRIS);
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPF5:
      /* {PIC12x, SX} (clrf, movwf), SX tris */
      file1 = opcode & PIC12_BMSK_FILE;

      if (args.first.arg != NULL) {
        PRINT_ARG1_S(args.first.arg, args.first.offs);
      }
      else {
        PRINT_ARG1_N(2, file1);
      }

      if (Behavior & GPDIS_SHOW_EXCLAMATION) {
        gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPWF5:
      /* {PIC12x, SX} (addwf, andwf, comf, decf, decfsz, incf, incfsz,
                       iorwf, movf, rlf, rrf, subwf, swapf, xorwf) */
      file1 = opcode & PIC12_BMSK_FILE;
      /* Destination flag: 0 = W, 1 = F */
      tmp   = (opcode >> 5) & 1;

      if (args.first.arg != NULL) {
        PRINT_ARG2_S_S(args.first.arg, args.first.offs, FLAG_FW(tmp), 0);
      }
      else if (Behavior & GPDIS_SHOW_NAMES) {
        PRINT_ARG2_N_S(2, file1, FLAG_FW(tmp), 0);
      }
      else {
        PRINT_ARG2_N_N(2, file1, 1, tmp);
      }

      if (Behavior & GPDIS_SHOW_EXCLAMATION) {
        gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_B5:
      /* {PIC12x, SX} (bcf, bsf, btfsc, btfss) */
      file1 = opcode & PIC12_BMSK_FILE;
      /* The bits of register. */
      tmp   = (opcode >> 5) & 7;

      if (args.first.arg != NULL) {
        if (args.second.arg != NULL) {
          PRINT_ARG2_S_S(args.first.arg, args.first.offs, args.second.arg, 0);

          if (Behavior & GPDIS_SHOW_EXCLAMATION) {
            gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x, bit: %u", args.first.val, args.second.val);
          }
        }
        else {
          PRINT_ARG2_S_N(args.first.arg, args.first.offs, 1, tmp);

          if (Behavior & GPDIS_SHOW_EXCLAMATION) {
            gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
          }
        }
      }
      else {
        PRINT_ARG2_N_N(2, file1, 1, tmp);

        if (Behavior & GPDIS_SHOW_EXCLAMATION) {
          gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_B8:
      /* PIC16 (bcf, bsf, btfsc, btfss, btg) */
      file1 = opcode & PIC16_BMSK_FILE;
      /* The bits of register. */
      tmp   = (opcode >> 8) & 7;

      if (args.first.arg != NULL) {
        if (args.second.arg != NULL) {
          PRINT_ARG2_S_S(args.first.arg, args.first.offs, args.second.arg, 0);

          if (Behavior & GPDIS_SHOW_EXCLAMATION) {
            gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x, bit: %u", args.first.val, args.second.val);
          }
        }
        else {
          PRINT_ARG2_S_N(args.first.arg, args.first.offs, 1, tmp);

          if (Behavior & GPDIS_SHOW_EXCLAMATION) {
            gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
          }
        }
      }
      else {
        PRINT_ARG2_N_N(2, file1, 1, tmp);

        if (Behavior & GPDIS_SHOW_EXCLAMATION) {
          gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPF7:
      /* PIC14x (clrf, movwf, tris) */
      file1 = opcode & PIC14_BMSK_FILE;

      if (args.first.arg != NULL) {
        PRINT_ARG1_S(args.first.arg, args.first.offs);

        if (Behavior & GPDIS_SHOW_EXCLAMATION) {
          gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
        }
      }
      else {
        PRINT_ARG1_N(2, file1);

        if (icode != ICODE_TRIS) {
          if (Behavior & GPDIS_SHOW_EXCLAMATION) {
            gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
          }
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPF8:
      /* PIC16 (cpfseq, cpfsgt, cpfslt, movwf, mulwf, tstfsz) */
      file1 = opcode & PIC16_BMSK_FILE;

      if (args.first.arg != NULL) {
        PRINT_ARG1_S(args.first.arg, args.first.offs);
      }
      else {
        PRINT_ARG1_N(2, file1);
      }

      if (Behavior & GPDIS_SHOW_EXCLAMATION) {
        gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPWF7:
      /* PIC14x (addwf, andwf, comf, decf, decfsz, incf, incfsz, iorwf, movf,
                 rlf, rrf, subwf, swapf, xorwf)
         PIC14E (addwfc, asrf, lslf, lsrf, subwfb) */
      file1 = opcode & PIC14_BMSK_FILE;
      /* Destination flag: 0 = W, 1 = F */
      tmp   = (opcode >> 7) & 1;

      if (args.first.arg != NULL) {
        PRINT_ARG2_S_S(args.first.arg, args.first.offs, FLAG_FW(tmp), 0);
      }
      else if (Behavior & GPDIS_SHOW_NAMES) {
        PRINT_ARG2_N_S(2, file1, FLAG_FW(tmp), 0);
      }
      else {
        PRINT_ARG2_N_N(2, file1, 1, tmp);
      }

      if (Behavior & GPDIS_SHOW_EXCLAMATION) {
        gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPWF8:
      /* PIC16 (addwf, addwfc, andwf, clrf, comf, daw, decf, decfsz, dcfsnz, incf,
                incfsz, infsnz, iorwf, rlcf, rlncf, rrcf, rrncf, setf, subwf, subwfb,
                swapf, xorwf) */
      file1 = opcode & PIC16_BMSK_FILE;
      /* Destination flag: 0 = W, 1 = F */
      tmp   = (opcode >> 8) & 1;

      if (args.first.arg != NULL) {
        PRINT_ARG2_S_S(args.first.arg, args.first.offs, FLAG_FW(tmp), 0);
      }
      else if (Behavior & GPDIS_SHOW_NAMES) {
        PRINT_ARG2_N_S(2, file1, FLAG_FW(tmp), 0);
      }
      else {
        PRINT_ARG2_N_N(2, file1, 1, tmp);
      }

      if (Behavior & GPDIS_SHOW_EXCLAMATION) {
        gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_B7:
      /* PIC14x (bcf, bsf, btfsc, btfss) */
      file1 = opcode & PIC14_BMSK_FILE;
      /* The bits of register. */
      tmp   = (opcode >> 7) & 7;

      if (args.first.arg != NULL) {
        if (args.second.arg != NULL) {
          PRINT_ARG2_S_S(args.first.arg, args.first.offs, args.second.arg, 0);

          if (Behavior & GPDIS_SHOW_EXCLAMATION) {
            gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x, bit: %u", args.first.val, args.second.val);
          }
        }
        else {
          PRINT_ARG2_S_N(args.first.arg, args.first.offs, 1, tmp);

          if (Behavior & GPDIS_SHOW_EXCLAMATION) {
            gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
          }
        }
      }
      else {
        PRINT_ARG2_N_N(2, file1, 1, tmp);

        if (Behavior & GPDIS_SHOW_EXCLAMATION) {
          gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPFA8:
      /* PIC16E (clrf, cpfseq, cpfsgt, cpfslt, movwf, mulwf, negf, setf, tstfsz) */
      file1   = opcode & PIC16_BMSK_FILE;
      /* RAM access flag: 0 = Access Bank, 1 = GPR Bank */
      ram_acc = (opcode >> 8) & 1;

      if (args.first.arg != NULL) {
        PRINT_ARG2_S_S(args.first.arg, args.first.offs, FLAG_BA(ram_acc), 0);
      }
      else if (Behavior & GPDIS_SHOW_NAMES) {
        PRINT_ARG2_N_S(2, file1, FLAG_BA(ram_acc), 0);
      }
      else {
        PRINT_ARG2_N_N(2, file1, 1, ram_acc);
      }

      if (Behavior & GPDIS_SHOW_EXCLAMATION) {
        gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_BA8:
      /* PIC16E (bcf, bsf, btfsc, btfss, btg) */
      file1   = opcode & PIC16_BMSK_FILE;
      /* The bits of register. */
      tmp     = (opcode >> 9) & 7;
      /* RAM access flag: 0 = Access Bank, 1 = GPR Bank */
      ram_acc = (opcode >> 8) & 1;

      if (args.first.arg != NULL) {
        if (args.second.arg != NULL) {
          PRINT_ARG3_S_S_S(args.first.arg, args.first.offs, args.second.arg, FLAG_BA(ram_acc));

          if (Behavior & GPDIS_SHOW_EXCLAMATION) {
            gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x, bit: %u", args.first.val, args.second.val);
          }
        }
        else {
          PRINT_ARG3_S_N_S(args.first.arg, args.first.offs, 1, tmp, FLAG_BA(ram_acc));

          if (Behavior & GPDIS_SHOW_EXCLAMATION) {
            gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
          }
        }
      }
      else if (Behavior & GPDIS_SHOW_NAMES) {
        PRINT_ARG3_N_N_S(2, file1, 1, tmp, FLAG_BA(ram_acc));

        if (Behavior & GPDIS_SHOW_EXCLAMATION) {
          gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
        }
      }
      else {
        PRINT_ARG3_N_N_N(2, file1, 1, tmp, 1, ram_acc);

        if (Behavior & GPDIS_SHOW_EXCLAMATION) {
          gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_OPWFA8:
      /* PIC16E (addwf, addwfc, andwf, comf, decf, decfsz, dcfsnz, incf, incfsz,
                 infsnz, iorwf, movf, rlcf, rlncf, rrcf, rrncf, subfwb, subwf,
                 subwfb, swapf, xorwf) */
      file1   = opcode & PIC16_BMSK_FILE;
      /* Destination flag: 0 = W, 1 = F */
      tmp     = (opcode >> 9) & 1;
      /* RAM access flag: 0 = Access Bank, 1 = GPR Bank */
      ram_acc = (opcode >> 8) & 1;

      if (args.first.arg != NULL) {
        PRINT_ARG3_S_S_S(args.first.arg, args.first.offs, FLAG_FW(tmp), FLAG_BA(ram_acc));
      }
      else if (Behavior & GPDIS_SHOW_NAMES) {
        PRINT_ARG3_N_S_S(2, file1, FLAG_FW(tmp), FLAG_BA(ram_acc));
      }
      else {
        PRINT_ARG3_N_N_N(2, file1, 1, tmp, 1, ram_acc);
      }

      if (Behavior & GPDIS_SHOW_EXCLAMATION) {
        gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_IMPLICIT:
      /* PIC12x  (clrw, clrwdt, nop, option, return, sleep)
         PIC12E  return
         PIC12I  (retfie, return)
         SX      (iread, movmw, movwm, reti, retiw, retp, return)
         PIC14x  (clrw, clrwdt, halt, nop, option, retfie, return, sleep)
         PIC14E  (brw, callw, reset)
         PIC16   (clrwdt, nop, retfie, return, sleep)
         PIC16E  (clrwdt, daw, halt, nop, pop, push, reset, sleep, trap, tret)
         PIX16EX callw */
      PRINT_ARG0();
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_TBL:
      /* PIC16E (tblrd, tblwt) */
      {
        const char *op[] = { "*", "*+", "*-", "+*" };

        snprintf(&Buffer[length], Buffer_length - length, "%s%s", instruction->name, op[opcode & 0x0003]);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_TBL2:
      /* PIC16 (tlrd, tlwt) */
      file1 = opcode & PIC16_BMSK_FILE;
      tmp   = (opcode >> 9) & 1;

      if (args.first.arg != NULL) {
        PRINT_ARG2_N_S(1, tmp, args.first.arg, 0);
      }
      else {
        PRINT_ARG2_N_N(1, tmp, 2, file1);
      }

      if (Behavior & GPDIS_SHOW_EXCLAMATION) {
        gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_TBL3:
      /* PIC16 (tablrd, tablwt) */
      {
        unsigned int inc;

        file1 = opcode & PIC16_BMSK_FILE;
        tmp   = (opcode >> 9) & 1;
        inc   = (opcode >> 8) & 1;

        if (args.first.arg != NULL) {
          PRINT_ARG3_N_N_S(1, tmp, 1, inc, args.first.arg);
        }
        else {
          PRINT_ARG3_N_N_N(1, tmp, 1, inc, 2, file1);
        }

        if (Behavior & GPDIS_SHOW_EXCLAMATION) {
          gp_exclamation(Buffer, Buffer_length, length, "; reg: 0x%03x", args.first.val);
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    case INSN_CLASS_MOVINDF:
      /* PIC14E (moviw, movwi) */
      {
        static const char *op_pre[]  = { "++", "--", "",   ""   };
        static const char *op_post[] = { "",   "",   "++", "--" };

        file1 = (opcode >> 2) & 1;
        tmp   = opcode & 0x0003;

        if (Behavior & GPDIS_SHOW_NAMES) {
          reg = (Behavior & GPDIS_SHOW_FSRN) ? "FSR" : "INDF";

          snprintf(&Buffer[length], Buffer_length - length, "%-*s%s%s%i%s", TABULATOR_SIZE, instruction->name,
                   op_pre[tmp], reg, file1, op_post[tmp]);
        }
        else {
          if (Behavior & GPDIS_SHOW_FSRN) {
            file1 |=  2;
          }

          switch (file1) {
            case 0: file1 = PIC14E_REG_INDF0; break;
            case 1: file1 = PIC14E_REG_INDF1; break;
            case 2: file1 = PIC14E_REG_FSR0;  break;
            case 3: file1 = PIC14E_REG_FSR1;  break;
          }

          PRINT_MOVINDF_S_N_S(op_pre[tmp], file1, op_post[tmp]);
        }
      }
      break;

    /*@@@@@@@@@@@@@@@@@@@@@@@@*/

    default:
      assert(0);
    } /* switch (instruction->Class) */

GPUTILS_GCC_DIAG_ON(switch)

  return num_words;
}

/*------------------------------------------------------------------------------------------------*/

unsigned int
gp_disassemble_byte(MemBlock_t *M, unsigned int Byte_address, char *Buffer, size_t Buffer_length)
{
  uint8_t byte;

  gp_mem_b_assert_get(M, Byte_address, &byte, NULL, NULL);
  snprintf(Buffer, Buffer_length, "%-*s0x%02x", TABULATOR_SIZE, "db", (unsigned int)byte);
  return 1;
}

/*------------------------------------------------------------------------------------------------*/

unsigned int
gp_disassemble_word(MemBlock_t *M, unsigned int Byte_address, proc_class_t Class, char *Buffer,
                    size_t Buffer_length)
{
  uint16_t word;

  Class->i_memory_get(M, Byte_address, &word, NULL, NULL);
  snprintf(Buffer, Buffer_length, "%-*s0x%04x", TABULATOR_SIZE, "dw", (unsigned int)word);
  return 2;
}

/*------------------------------------------------------------------------------------------------*/

unsigned int
gp_disassemble_size(MemBlock_t *M, unsigned int Byte_address, proc_class_t Class, unsigned int Bsr_boundary,
                    unsigned int Prog_mem_size, unsigned int Behavior, char *Buffer, size_t Buffer_length,
                    unsigned int Size)
{
  char dasmbuf[512];
  int  num_words;

  if (Size == 1) {
    return gp_disassemble_byte(M, Byte_address, Buffer, Buffer_length);
  }
  else if (Size == 2) {
    num_words = gp_disassemble(M, Byte_address, Class, Bsr_boundary, Prog_mem_size, Behavior,
                               dasmbuf, sizeof(dasmbuf), 0);

    if (num_words != 1) {
      return gp_disassemble_word(M, Byte_address, Class, Buffer, Buffer_length);
    }
    else {
      strncpy(Buffer, dasmbuf, Buffer_length);
      return (2 * num_words);
    }
  }
  else {
    return (2 * gp_disassemble(M, Byte_address, Class, Bsr_boundary, Prog_mem_size, Behavior,
                               Buffer, Buffer_length, 0));
  }
}
