/* top level functions for gpasm
   Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005
   James Bowman, Craig Franklin

   Copyright (C) 2014-2016 Molnár Károly

   Dump COFF file contents option.
   Copyright (C) 2019 Gonzalo Pérez de Olaguer Córdoba <salo@gpoc.es>

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
#include "gpasm.h"
#include "gpmsg.h"
#include "scan.h"
#include "deps.h"
#include "directive.h"
#include "file.h"
#include "lst.h"
#include "cod.h"
#include "processor.h"
#include "coff.h"
#include "gpcfg.h"

extern int yyparse(void);
extern int yydebug;

struct gpasm_state state;

static gp_boolean cmd_processor = false;
static const char *processor_name = NULL;

#define GET_OPTIONS "D:I:a:cCde:fghijkl::LmMno:p:qr:s::S:tuvw:yP:X"

typedef struct {
  pic_processor_t processor;
  proc_class_t    class0;
  proc_class_t    class1;
  proc_class_t    class2;
} list_params_t;

enum {
  OPT_MPASM_COMPATIBLE = 0x100,
  OPT_STRICT_OPTIONS
#ifdef GPUTILS_DEBUG
  , OPT_DUMP_COFF
#endif
};

static struct option longopts[] =
{
  { "define",                    required_argument, NULL, 'D' },
  { "include",                   required_argument, NULL, 'I' },
  { "hex-format",                required_argument, NULL, 'a' },
  { "object",                    no_argument,       NULL, 'c' },
  { "new-coff",                  no_argument,       NULL, 'C' },
  { "debug",                     no_argument,       NULL, 'd' },
  { "expand",                    required_argument, NULL, 'e' },
  { "full-address",              no_argument,       NULL, 'f' },
  { "debug-info",                no_argument,       NULL, 'g' },
  { "help",                      no_argument,       NULL, 'h' },
  { "ignore-case",               no_argument,       NULL, 'i' },
  { "sdcc-dev16-list",           no_argument,       NULL, 'j' },
  { "error",                     no_argument,       NULL, 'k' },
  { "list-chips",                optional_argument, NULL, 'l' },
  { "force-list",                no_argument,       NULL, 'L' },
  { "dump",                      no_argument,       NULL, 'm' },
  { "deps",                      no_argument,       NULL, 'M' },
  { "dos",                       no_argument,       NULL, 'n' },
  { "output",                    required_argument, NULL, 'o' },
  { "processor",                 required_argument, NULL, 'p' },
  { "quiet",                     no_argument,       NULL, 'q' },
  { "radix",                     required_argument, NULL, 'r' },
  { "list-processor-properties", optional_argument, NULL, 's' },
  { "strict",                    required_argument, NULL, 'S' },
  { "strict-options",            no_argument,       NULL, OPT_STRICT_OPTIONS },
  { "sdcc-dev14-list",           no_argument,       NULL, 't' },
  { "absolute",                  no_argument,       NULL, 'u' },
  { "version",                   no_argument,       NULL, 'v' },
  { "warning",                   required_argument, NULL, 'w' },
  { "extended",                  no_argument,       NULL, 'y' },
  { "mpasm-compatible",          no_argument,       NULL, OPT_MPASM_COMPATIBLE },
  { "preprocess",                required_argument, NULL, 'P' },
  { "macro-dereference",         no_argument,       NULL, 'X' },
#ifdef GPUTILS_DEBUG
  { "dump-coff",                 no_argument,       NULL, OPT_DUMP_COFF },
#endif
  { NULL,                        no_argument,       NULL, '\0' }
};

static list_params_t list_options;

/*------------------------------------------------------------------------------------------------*/

static void
_show_usage(void)
{
  printf("Usage: gpasm [options] file\n");
  printf("Options: [defaults in brackets after descriptions]\n");
  printf("  -a FMT, --hex-format FMT       Select hex file format. [inhx32]\n");
  printf("  -c, --object                   Output relocatable object.\n");
  printf("  -C, --old-coff                 Use old Microchip COFF format.\n");
  printf("  -d, --debug                    Output debug messages.\n");
  printf("  -D SYM=VAL, --define SYM=VAL   Define SYM with value VAL.\n");
#ifdef GPUTILS_DEBUG
  printf("      --dump-coff                Dump COFF file contents.\n");
#endif
  printf("  -e [ON|OFF], --expand [ON|OFF] Macro expansion.\n");
  printf("  -f, --full-address             Show full address in .lst file at the memory map region.\n");
  printf("  -g, --debug-info               Use debug directives for COFF.\n");
  printf("  -h, --help                     Show this usage message.\n");
  printf("  -i, --ignore-case              Case insensitive.\n");
  printf("  -I DIR, --include DIR          Specify include directory.\n");
  printf("  -j, --sdcc-dev16-list          Help to the extension of the pic16devices.txt file\n"
         "                                 in the sdcc project. Using by itself, displays the all\n"
         "                                 '16e' devices. Along with the '-p' option, shows only\n"
         "                                 the specified device.\n");
  printf("  -k, --error                    Enables creation of the error file.\n");
  printf("  -l[12[ce]|14[cef]|16[ce]], --list-chips[=([12[ce]|14[cef]|16[ce]])]\n"
         "                                 Lists the names of the supported processors, based on\n"
         "                                 various aspects. ('f' mean 'x')\n");
  printf("  -L, --force-list               Ignore nolist directives.\n");
  printf("  -m, --dump                     Memory dump.\n");
  printf("      --mpasm-compatible         MPASM(X) compatibility mode.\n");
  printf("  -M, --deps                     Output dependency file.\n");
#ifndef HAVE_DOS_BASED_FILE_SYSTEM
  printf("  -n, --dos                      Use DOS newlines in hex file.\n");
#endif
  printf("  -o FILE, --output FILE         Alternate name of output files. Option effect of:\n"
         "                                 -- If the \"-c\" option included in the command line:\n"
         "                                      FILE.o, FILE.lst, FILE.err\n"
         "                                        (The \"FILE.o\" should specified.)\n");
  printf("                                 -- If the \"-c\" option not included in the command line:\n"
         "                                      FILE.hex, FILE.cod, FILE.lst, FILE.err\n"
         "                                        (The \"FILE.hex\" should specified.)\n");
  printf("  -p PROC, --processor PROC      Select processor.\n");
  printf("  -P FILE, --preprocess FILE     Write preprocessed asm file to FILE.\n");
  printf("  -q, --quiet                    Suppress anything sent to standard output.\n");
  printf("  -r RADIX, --radix RADIX        Select radix. [hex]\n");
  printf("  -s[12[ce]|14[cef]|16[ce]], --list-processor-properties[=([12[ce]|14[cef]|16[ce]])]\n"
         "                                 Lists properties of the processors. Using by itself,\n"
         "                                 displays the all devices or group of the devices. Along\n"
         "                                 with the '-p' option, shows only the specified device.\n"
         "                                   ('f' mean 'x')\n");
  printf("  -S [0|1|2], --strict [0|1|2]   Set the strict level of the recommended instruction-parameters\n"
         "                                 (W or F and A or B) and the \"Undefined Processor\" messages.\n"
         "                                 The \"strict messages\" have higher priority than the warnings.\n"
         "                                 (See: -w [0|1|2]) [0]\n");
  printf("                                     0: Is the default. No strict messages.\n"
         "                                     1: Show warning messages if one of is missing.\n"
         "                                     2: Show error messages if one of is missing.\n");
  printf("  -t, --sdcc-dev14-list          Help to the extension of the pic14devices.txt file\n"
         "                                 in the sdcc project. Using by itself, displays the all\n"
         "                                 '14', '14e' and '14f' devices. Along with the '-p'\n"
         "                                 option, shows only the specified device.\n");
  printf("      --strict-options           If this is set, then an option may not be parameter\n"
         "                                 of an another option. For example: -I -c\n");
  printf("  -u, --absolute                 Use absolute paths. \n");
  printf("  -v, --version                  Show version information and exit.\n");
  printf("  -w [0|1|2], --warning [0|1|2]  Set message level. [0]\n"
         "                                     0: Is the default. It will allow all messages,\n"
         "                                        warnings and errors to be reported.\n"
         "                                     1: Will suppress the messages.\n"
         "                                     2: Will suppress the messages and warnings.\n");
  printf("  -X, --macro-dereference        Use the source from where the macro was invoked for errors.\n");
  printf("  -y, --extended                 Enable 18xx extended mode.\n\n");
#ifdef USE_DEFAULT_PATHS
  if (gp_header_path != NULL) {
    printf("Default header file path %s\n", gp_header_path);
  }
  else {
    printf("Default header file path NOT SET.\n");
  }
  printf("\n");
#endif
  printf("Report bugs to:\n");
  printf("%s\n", PACKAGE_BUGREPORT);
}

/*------------------------------------------------------------------------------------------------*/

static void
_set_global_constants(void)
{
  if (!state.mpasm_compatible) {
    set_global("__GPUTILS_SVN_VERSION",   GPUTILS_SVN_VERSION,   VAL_CONSTANT, false, false);
    set_global("__GPUTILS_VERSION_MAJOR", GPUTILS_VERSION_MAJOR, VAL_CONSTANT, false, false);
    set_global("__GPUTILS_VERSION_MINOR", GPUTILS_VERSION_MINOR, VAL_CONSTANT, false, false);
    set_global("__GPUTILS_VERSION_MICRO", GPUTILS_VERSION_MICRO, VAL_CONSTANT, false, false);
    set_global("__WHILE_LOOP_COUNT_MAX",  WHILE_LOOP_COUNT_MAX,  VAL_CONSTANT, false, false);
  }
}

/*------------------------------------------------------------------------------------------------*/

static void
_setup_second_pass(symbol_table_t *Cmd_defines)
{
  state.pass++;
  state.byte_addr          = 0;
  state.device.id_location = 0;
  state.cblock             = 0;
  state.cblock_defined     = false;
  /* Clean out defines for second pass. */
  state.stDefines          = gp_sym_push_table(Cmd_defines, state.case_insensitive);
  state.stMacros           = gp_sym_push_table(NULL, state.case_insensitive);
  state.stMacroParams      = gp_sym_push_table(NULL, state.case_insensitive);
}

/*------------------------------------------------------------------------------------------------*/

void
init(void)
{
  gp_init();

  memset(&state, 0, sizeof(state));

  /* restore gpasm to its initialized state */
  state.mode            = MODE_ABSOLUTE;

  state.radix           = 16;
  state.hex_format      = INHX32;
  state.preproc.do_emit = true;

  state.maxram          = MAX_RAM - 1;

  state.cod_file        = OUT_NORMAL;
  state.dep_file        = OUT_SUPPRESS;
  state.err_file        = OUT_SUPPRESS;
  state.hex_file        = OUT_NORMAL;
  state.lst_file        = OUT_NORMAL;
  state.obj_file        = OUT_SUPPRESS;

  state.obj.newcoff     = true;         /* use new Microchip COFF format by default */

  state.next_state      = STATE_NOCHANGE;
}

/*------------------------------------------------------------------------------------------------*/

/* This is a sdcc specific helper function. */

static void
_pic14_lister(pic_processor_t Processor)
{
  proc_class_t           class;
  const gp_cfg_device_t *dev;
  const int             *pair;
  int                    tmp;
  int                    bank_mask;

  if ((Processor == NULL) || ((class = Processor->class) == NULL)) {
    fprintf(stderr, "Warning: The processor not selected!\n");
    return;
  }

  if ((class != PROC_CLASS_PIC14) && (class != PROC_CLASS_PIC14E) && (class != PROC_CLASS_PIC14EX)) {
    fprintf(stderr, "Warning: The type of the %s processor is not PIC14, not PIC14E and not PIC14EX!\n",
            Processor->names[2]);
    return;
  }

  dev = gp_cfg_find_pic_multi_name(Processor->names, ARRAY_SIZE(Processor->names));

  if (dev == NULL) {
    fprintf(stderr, "Warning: The %s processor has no entries in the config db.\n", Processor->names[2]);
    return;
  }

  printf("processor %s\n", Processor->names[2]);

  if (Processor->prog_mem_size < 1024) {
    printf("\tprogram\t\t%i\n", Processor->prog_mem_size);
  }
  else {
    printf("\tprogram\t\t%iK\n", Processor->prog_mem_size / 1024);
  }

  printf("\tdata\t\t???\n");

  if ((pair = gp_processor_eeprom_exist(Processor)) != NULL) {
    tmp = pair[1] - pair[0] + 1;
  }
  else {
    tmp = 0;
  }

  printf("\teeprom\t\t%i\n", tmp);
  printf("\tio\t\t???\n");
  bank_mask = (Processor->num_banks - 1) << class->addr_bits_in_bank;

  if ((class == PROC_CLASS_PIC14E) || (class == PROC_CLASS_PIC14EX)) {
    printf("\tenhanced\t1\n"
           "\tmaxram\t\t0x07f\n");
  }
  else {
    tmp = -1;
    tmp <<= class->addr_bits_in_bank;
    tmp ^= -1;
    tmp |= bank_mask;
    printf("\tmaxram\t\t0x%03x\n", tmp);
  }

  if (bank_mask > 0) {
    printf("\tbankmsk\t\t0x%03x\n", bank_mask);
  }

  if ((pair = gp_processor_config_exist(Processor)) != NULL) {
    if (pair[0] < pair[1]) {
      printf("\tconfig\t\t0x%04x 0x%04x\n", pair[0], pair[1]);
    }
    else {
      printf("\tconfig\t\t0x%04x\n", pair[0]);
    }
  }

  if (bank_mask > 0) {
    printf("\tregmap\t\t???\n"
           "\tmemmap\t\t???\n");
  }

  printf("\n");
}

/*------------------------------------------------------------------------------------------------*/

/* This is a sdcc specific helper function. */

static void
_pic16e_lister(pic_processor_t Processor)
{
  proc_class_t           class;
  const gp_cfg_device_t *dev;
  const int             *pair;
  int                    addr0;
  int                    addr1;

  if ((Processor == NULL) || ((class = Processor->class) == NULL)) {
    fprintf(stderr, "Warning: The processor not selected!\n");
    return;
  }

  if (class != PROC_CLASS_PIC16E) {
    fprintf(stderr, "Warning: The type of the %s processor is not PIC16E!\n", Processor->names[2]);
    return;
  }

  dev = gp_cfg_find_pic_multi_name(Processor->names, ARRAY_SIZE(Processor->names));

  if (dev == NULL) {
    fprintf(stderr, "Warning: The %s processor has no entries in the config db.\n", Processor->names[2]);
    return;
  }

  printf("name        %s\n", Processor->names[2]);
  printf("ramsize     ???\n");
  printf("split       0x%02X\n", gp_processor_bsr_boundary(Processor));

  gp_cfg_real_config_boundaries(dev, &addr0, &addr1);

  if ((addr0 > 0) && (addr1 >= addr0)) {
    printf("configrange 0x%06X 0x%06X\n", addr0, addr1);
    gp_cfg_brief_device(dev, "configword  ", class->addr_digits, class->config_digits,
                        (Processor->cpu_flags & CPU_18FJ_FAMILY) ? true : false);
  }

  if (Processor->cpu_flags & CPU_HAVE_EXTINST) {
    printf("XINST       1\n");
  }

  if ((pair = gp_processor_idlocs_exist(Processor)) != NULL) {
    printf("idlocrange  0x%06X 0x%06X\n", pair[0], pair[1]);
  }

  printf("\n");
}

/*------------------------------------------------------------------------------------------------*/

static void
_lister_of_devices(pic_processor_t Processor)
{
  proc_class_t           class;
  const gp_cfg_device_t *dev;
  const int             *pair;
  int                    addr_digits;
  const char            *txt;

  if ((Processor == NULL) || ((class = Processor->class) == NULL)) {
    fprintf(stderr, "Warning: The processor not selected!\n");
    return;
  }

  dev = gp_cfg_find_pic_multi_name(Processor->names, ARRAY_SIZE(Processor->names));

  if (dev == NULL) {
    fprintf(stderr, "Warning: The %s processor has no entries in the config db.\n", Processor->names[2]);
    return;
  }

  addr_digits = class->addr_digits;
  printf("Names          : %s, %s, %s\n", Processor->names[0], Processor->names[1], Processor->names[2]);
  printf("Class          : %s\n", gp_processor_class_to_str(class));
  printf("Bank Size      : %i bytes\n", class->bank_size);

  if (class == PROC_CLASS_PIC16E) {
    printf("Access Split   : 0x%02X\n", gp_processor_bsr_boundary(Processor));
  }
  else {
    printf("Bank Number    : %i\n", Processor->num_banks);
    printf("Bank Mask      : 0x%03X\n", Processor->bank_bits);
  }

  if ((pair = gp_processor_common_ram_exist(Processor)) != NULL) {
    printf("Common RAM     : 0x%02X - 0x%02X\n", pair[0], pair[1]);
  }

  if (Processor->common_ram_max > 0) {
    printf("Max. Common RAM: 0x%02X\n", Processor->common_ram_max);
  }

  if ((pair = gp_processor_linear_ram_exist(Processor)) != NULL) {
    printf("Linear RAM     : 0x%04X - 0x%04X\n", pair[0], pair[1]);
  }

  printf("Max. RAM Addr. : 0x%03X\n", Processor->maxram);

  txt = (Processor->class == PROC_CLASS_PIC16E) ? "bytes" : "words";

  if (class->page_size > 0) {
    printf("Page Size      : %i %s\n", class->page_size, txt);
    printf("Page Number    : %i\n", Processor->num_pages);
  }

  printf("Program Size   : %i %s\n", Processor->prog_mem_size, txt);

  if ((pair = gp_processor_idlocs_exist(Processor)) != NULL) {
    if (pair[0] < pair[1]) {
      printf("Idlocs Range   : 0x%0*X - 0x%0*X\n", addr_digits, pair[0], addr_digits, pair[1]);
    }
    else {
      printf("Idlocs         : 0x%0*X\n", addr_digits, pair[0]);
    }
    if (class != PROC_CLASS_PIC16E) {
      printf("Idlocs OR Mask : 0x%0*X\n", addr_digits, Processor->idlocs_mask);
    }
  }

  if ((pair = gp_processor_config_exist(Processor)) != NULL) {
    if (pair[0] < pair[1]) {
      printf("Config Range   : 0x%0*X - 0x%0*X\n", addr_digits, pair[0], addr_digits, pair[1]);
    }
    else {
      printf("Config         : 0x%0*X\n", addr_digits, pair[0]);
    }

    gp_cfg_full_list_device(dev, "  Config Word  : ", addr_digits, class->config_digits);
  }

  if ((pair = gp_processor_eeprom_exist(Processor)) != NULL) {
    printf("EEPROM Range   : 0x%0*X - 0x%0*X\n", addr_digits, pair[0], addr_digits, pair[1]);
  }

  printf("Max. ROM Addr. : 0x%0*X\n", addr_digits, Processor->maxrom);

  if (Processor->header != NULL) {
    printf("Header File    : %s\n", Processor->header);
  }

  if (Processor->script != NULL) {
    printf("Linker Script  : %s\n", Processor->script);
  }

  printf("\n");
}

/*------------------------------------------------------------------------------------------------*/

static void
_add_path(const char *Path)
{
  if (Path[0] == '\0') {
    /* This is an empty path. */
    return;
  }

  if (state.num_paths < MAX_PATHS) {
    state.paths[state.num_paths++] = GP_Strdup(Path);
  }
  else {
    fprintf(stderr, "Too many -I paths.\n");
    exit(1);
  }
}

/*------------------------------------------------------------------------------------------------*/

void
process_args(int argc, char *argv[])
{
  int         option_index;
  const char *command;
  int         c;
  long        pic_family;
  gp_boolean  usage          = false;
  gp_boolean  sdcc_dev14     = false;
  gp_boolean  sdcc_dev16     = false;
  gp_boolean  properties     = false;
  gp_boolean  strict_options = false;
  int         usage_code = 0;
  char       *pc;

  list_options.processor = NULL;
  list_options.class0    = PROC_CLASS_UNKNOWN;
  list_options.class1    = PROC_CLASS_UNKNOWN;
  list_options.class2    = PROC_CLASS_UNKNOWN;

  /* Scan through the options for the --strict-options flag. */
  while ((c = getopt_long(argc, argv, GET_OPTIONS, longopts, NULL)) != EOF) {
    if (c == OPT_STRICT_OPTIONS) {
      strict_options = true;
      break;
    }
  }

  /* Restores the getopt_long index. */
  optind = 1;

  /* Scan through the options for the -i flag. It must be set before the
     defines are read. */
  while (true) {
    /* This is necessary for the exit_is_excluded_arg() function. */
    option_index = -1;
    command = argv[optind];
    if ((c = getopt_long(argc, argv, GET_OPTIONS, longopts, &option_index)) == EOF) {
      break;
    }

    if (strict_options) {
      gp_exit_if_arg_an_option(longopts, ARRAY_SIZE(longopts), option_index, optarg, c, command);
    }

    if (c == 'i') {
      state.case_insensitive = true;
      break;
    }
  }

  /* reset the getopt_long index for the next call */
  optind = 1;

  /* initalize the defines table for command line arguments */
  state.stDefines = gp_sym_push_table(NULL, state.case_insensitive);

  while ((c = getopt_long(argc, argv, GET_OPTIONS, longopts, NULL)) != EOF) {
    switch (c) {
      case '?':
        usage_code = 1;
      case 'h':
        usage = true;
        break;

      case 'a':
        select_hex_format(optarg);
        state.cmd_line.hex_format = true;
        break;

      case 'c':
        state.mode     = MODE_RELOCATABLE;
        state.cod_file = OUT_SUPPRESS;
        state.hex_file = OUT_SUPPRESS;
        state.lst_file = OUT_NORMAL;
        state.obj_file = OUT_NORMAL;
        break;

      case 'C':
        state.obj.newcoff = false;
        break;

      case 'd':
        gp_debug_disable = false;
        break;

      case 'D': {
        if ((optarg != NULL) && (strlen(optarg) > 0)) {
          symbol_t *sym;
          char     *lhs;
          char     *rhs;

          lhs = GP_Strdup(optarg);
          rhs = strchr(lhs, '=');

          if (rhs != NULL) {
            *rhs = '\0';  /* Terminate the left-hand side */
            rhs++;        /* right-hand side begins after the '=' */
          }

          sym = gp_sym_get_symbol(state.stDefines, lhs);

          if (sym == NULL) {
            sym = gp_sym_add_symbol(state.stDefines, lhs);
          }

          if (rhs != NULL) {
            gp_sym_annotate_symbol(sym, mk_list(mk_string(rhs), NULL));
          }
        }
        break;
      }

      case 'e':
        select_expand(optarg);
        state.cmd_line.macro_expand = true;
        break;

      case 'f':
        state.show_full_addr = true;
        break;

      case 'g':
        state.debug_info = true;
        break;

      case 'I':
        _add_path(optarg);
        break;

      case 'i':
        state.case_insensitive = true;
        break;

      case 'j':
        sdcc_dev16 = true;
        break;

      case 'k':
        state.err_file = OUT_NORMAL;
        break;

      case 'L':
        state.cmd_line.lst_force = true;
        break;

      case 'l': {
        gp_boolean all;

        pic_family = -1;

        if (optarg != NULL) {
          pic_family = strtol(optarg, NULL, 16);
        }

        all = false;

        switch (pic_family) {
          case 0x12:
            list_options.class0 = PROC_CLASS_PIC12;
            list_options.class1 = PROC_CLASS_PIC12E;
            list_options.class2 = PROC_CLASS_PIC12I;
            break;

          case 0x12C:
            list_options.class0 = PROC_CLASS_PIC12;
            break;

          case 0x12E:
            list_options.class0 = PROC_CLASS_PIC12E;
            list_options.class1 = PROC_CLASS_PIC12I;
            break;

          case 0x14:
            list_options.class0 = PROC_CLASS_PIC14;
            list_options.class1 = PROC_CLASS_PIC14E;
            list_options.class2 = PROC_CLASS_PIC14EX;
            break;

          case 0x14C:
            list_options.class0 = PROC_CLASS_PIC14;
            break;

          case 0x14E:
            list_options.class0 = PROC_CLASS_PIC14E;
            break;

          case 0x14F:
            list_options.class0 = PROC_CLASS_PIC14EX;
            break;

          case 0x16:
            list_options.class0 = PROC_CLASS_PIC16;
            list_options.class1 = PROC_CLASS_PIC16E;
            break;

          case 0x16C:
            list_options.class0 = PROC_CLASS_PIC16;
            break;

          case 0x16E:
            list_options.class0 = PROC_CLASS_PIC16E;
            break;

          default:
            all = true;
          }

        gp_dump_processor_list(all, list_options.class0, list_options.class1, list_options.class2);
        exit(0);
        break;
      }

      case 'M':
        state.dep_file = OUT_NORMAL;
        break;

      case 'm':
        state.memory_dump = true;
        break;

      case 'n':
        #ifndef HAVE_DOS_BASED_FILE_SYSTEM
          state.dos_newlines = true;
        #endif
        break;

      case 'o': {
        gp_strncpy(state.obj_file_name, optarg, sizeof(state.obj_file_name));
        gp_strncpy(state.base_file_name, optarg, sizeof(state.base_file_name));
        pc = strrchr(state.base_file_name, '.');

        if (pc != NULL) {
          *pc = '\0';
        }
        break;
      }

      case 'p':
        cmd_processor = true;
        processor_name = optarg;
        break;

      case 'P':
        state.preproc.preproc_file_name = optarg;
        break;

      case 'q':
        state.quiet = true;
        break;

      case 'r':
        select_radix(optarg);
        state.cmd_line.radix = true;
        break;

      case 's': {
        pic_family = -1;

        if (optarg != NULL) {
          pic_family = strtol(optarg, NULL, 16);
        }

        switch (pic_family) {
          case 0x12:
            list_options.class0 = PROC_CLASS_PIC12;
            list_options.class1 = PROC_CLASS_PIC12E;
            list_options.class2 = PROC_CLASS_PIC12I;
            break;

          case 0x12C:
            list_options.class0 = PROC_CLASS_PIC12;
            break;

          case 0x12E:
            list_options.class0 = PROC_CLASS_PIC12E;
            list_options.class1 = PROC_CLASS_PIC12I;
            break;

          case 0x14:
            list_options.class0 = PROC_CLASS_PIC14;
            list_options.class1 = PROC_CLASS_PIC14E;
            list_options.class2 = PROC_CLASS_PIC14EX;
            break;

          case 0x14C:
            list_options.class0 = PROC_CLASS_PIC14;
            break;

          case 0x14E:
            list_options.class0 = PROC_CLASS_PIC14E;
            break;

          case 0x14F:
            list_options.class0 = PROC_CLASS_PIC14EX;
            break;

          case 0x16:
            list_options.class0 = PROC_CLASS_PIC16;
            list_options.class1 = PROC_CLASS_PIC16E;
            break;

          case 0x16C:
            list_options.class0 = PROC_CLASS_PIC16;
            break;

          case 0x16E:
            list_options.class0 = PROC_CLASS_PIC16E;
            break;

          default:
            list_options.class0 = PROC_CLASS_UNKNOWN;
            list_options.class1 = PROC_CLASS_UNKNOWN;
            list_options.class2 = PROC_CLASS_UNKNOWN;
          }

        properties = true;
        break;
      }

      case 'S':
        select_strict_level(atoi(optarg));
        state.cmd_line.strict_level = true;
        break;

      case 't':
        sdcc_dev14 = true;
        break;

      case 'u':
        state.use_absolute_path = true;
        break;

      case 'w':
        select_error_level(atoi(optarg));
        state.cmd_line.error_level = true;
        break;

      case 'X':
        state.macro_dereference = true;
        break;

      case 'y':
        state.extended_pic16e = true;
        break;

      case 'v':
        fprintf(stderr, "%s\n", GPASM_VERSION_STRING);
        exit(0);

      case OPT_MPASM_COMPATIBLE:
        state.mpasm_compatible = true;
        break;

#ifdef GPUTILS_DEBUG
      case OPT_DUMP_COFF:
        gp_dump_coff = true;
        break;
#endif

      case OPT_STRICT_OPTIONS:
        break;
    } /* switch (c) */

    if (usage) {
      break;
    }
  }

  if (properties) {
    list_options.processor = (cmd_processor) ? gp_find_processor(processor_name) : NULL;

    if (list_options.processor != NULL) {
      _lister_of_devices(list_options.processor);
    }
    else {
      gp_processor_invoke_custom_lister(list_options.class0, list_options.class1,
                                        list_options.class2, _lister_of_devices);
    }

    exit(0);
  }
  else if (sdcc_dev14) {
    list_options.processor = (cmd_processor) ? gp_find_processor(processor_name) : NULL;

    if (list_options.processor != NULL) {
      _pic14_lister(list_options.processor);
    }
    else {
      gp_processor_invoke_custom_lister(PROC_CLASS_PIC14, PROC_CLASS_PIC14E, PROC_CLASS_PIC14EX, _pic14_lister);
    }

    exit(0);
  }
  else if (sdcc_dev16) {
    list_options.processor = (cmd_processor) ? gp_find_processor(processor_name) : NULL;

    if (list_options.processor != NULL) {
      _pic16e_lister(list_options.processor);
    }
    else {
      gp_processor_invoke_custom_lister(PROC_CLASS_PIC16E, PROC_CLASS_UNKNOWN, PROC_CLASS_UNKNOWN, _pic16e_lister);
    }

    exit(0);
  }

  if ((optind + 1) == argc) {
    state.src_file_name = argv[optind];
  }
  else {
    usage = true;
  }

  if (usage) {
    _show_usage();
    exit(usage_code);
  }

  /* Add the header path to the include paths list last, so that the user
     specified directories are searched first. */
  if (gp_header_path != NULL) {
    _add_path(gp_header_path);
  }

  if (state.use_absolute_path) {
    state.src_file_name = gp_absolute_path(state.src_file_name);
  }
}

/*------------------------------------------------------------------------------------------------*/

int
assemble(void)
{
  char           *pc;
  symbol_table_t *cmd_defines;

  /* Store the command line defines to restore on second pass. */
  cmd_defines    = state.stDefines;
  state.c_memory = gp_mem_i_create();
  state.i_memory = state.c_memory;

  if (state.base_file_name[0] == '\0') {
    gp_strncpy(state.base_file_name, state.src_file_name, sizeof(state.base_file_name));
    pc = strrchr(state.base_file_name, '.');

    if (pc != NULL) {
      *pc = '\0';
    }
  }

  /* Builtins are always case insensitive. */
  state.stBuiltin     = gp_sym_push_table(NULL, true);
  state.stDirective   = state.stBuiltin;
  state.stTop         = gp_sym_push_table(NULL, state.case_insensitive);
  state.stGlobal      = state.stTop;
  state.stDefines     = gp_sym_push_table(cmd_defines, state.case_insensitive);
  state.stMacros      = gp_sym_push_table(NULL, state.case_insensitive);
  state.stMacroParams = gp_sym_push_table(NULL, state.case_insensitive);
  opcode_init(0);

  /* The tables are built, select the processor if -p was used. */
  if (cmd_processor) {
    select_processor(processor_name);
    state.cmd_line.processor = true;
  }

  _set_global_constants();

  state.pass = 1;
  open_src(state.src_file_name, false);
  yyparse();
  yylex_destroy();

  _setup_second_pass(cmd_defines);
  state.preproc.do_emit = true;
  delete_variable_symbols(state.stTop);
//  delete_processor_variable_symbols(state.stTop);

  if (!state.cmd_line.radix) {
    state.radix = 16;
  }

  state.obj.symbol_num  = 0;
  state.obj.section_num = 0;
  /* finish the MACRO and WHILE definition */
  state.mac_prev        = NULL;
  state.mac_head        = state.while_head = NULL;
  state.while_depth     = 0;

  state.astack = NULL;

  /* Initial section. */
  state.obj.new_sect_flags = (state.mode == MODE_ABSOLUTE) ? STYP_TEXT : 0;

  state.found_config = false;
  state.found_devid  = false;
  state.found_idlocs = false;
  state.found_end    = false;
  coff_init();
  cod_init();
  gpmsg_init();
  deps_init();
  lst_init();
  preproc_init();

  /* reset the processor for 2nd pass */
  state.processor          = NULL;
  state.processor_chosen   = false;
  state.cmd_line.processor = false;

  if (cmd_processor) {
    select_processor(processor_name);
    state.cmd_line.processor = true;
  }

  _set_global_constants();

  open_src(state.src_file_name, false);
  yydebug = (!gp_debug_disable) ? true : false;
  yyparse();

  assert(state.pass == 2);

  if (state.obj.object != NULL) {
    /* Set F_ABSOLUTE COFF flag if absolute mode. */
    if (state.mode == MODE_ABSOLUTE) {
      state.obj.object->flags |= F_ABSOLUTE;
    }

    /* Set F_EXTENDED18 COFF flag if 18xx extended mode enabled. */
    if (state.extended_pic16e) {
      state.obj.object->flags |= F_EXTENDED18;
    }
  }

  gp_sym_pop_table(state.stBuiltin);

  hex_create();

  if (state.memory_dump) {
    gp_mem_i_print(state.i_memory, state.processor);
  }

  /* Maybe produce a symbol table. */
  if (state.lst.symbol_table) {
    lst_throw(); /* Start symbol table on a fresh page. */
    lst_symbol_table();
  }

  /* Maybe produce a memory map. */
  if ((state.mode == MODE_ABSOLUTE) && (state.lst.memory_map)) {
    lst_memory_map(state.i_memory);
  }

  /* Finish off the object, dependency, listing, and symbol files. */
  coff_close_file();
  deps_close();
  lst_close();

  if (state.processor != NULL) {
    cod_close_file();
  }

  file_free();
  gp_bitarray_delete(&state.badrom);
  gpmsg_close();
  return (((state.num.errors > 0) || (gp_num_errors > 0)) ? EXIT_FAILURE : EXIT_SUCCESS);
}
