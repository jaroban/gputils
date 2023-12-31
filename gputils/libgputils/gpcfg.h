
#ifndef g__GPCFG_H__
#define g__GPCFG_H__

/* This file is generated automatically by the cfg-import.pl 2022-01-21 16:02:31 UTC. */

/* gpcfg.h - header file for pic configurations
   Copyright (C) 2006
   Michael Ballbach */

/*  Copyright (C) 2014-2018 Molnar Karoly

This file is part of gputils.

Gputils is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

Gputils is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with gputils; see the file COPYING. If not, write to
the Free Software Foundation, 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA. */

#include "gptypes.h"

/* A directive value. */
typedef struct {
  const char* name;                         /* Name of the value. */
  uint16_t    value;                        /* The value. */
} gp_cfg_option_t;

/* A directive, i.e., FOSC. */
typedef struct {
  const char*             name;             /* Name of the directive. */
  uint16_t                mask;             /* Mask of words in the config address that apply to its value. */
  unsigned int            option_count;     /* Number of possible values. */
  const gp_cfg_option_t** options;          /* Array of addresses of values. */
} gp_cfg_directive_t;

/* One particular configuration address, i.e., 0x300001. */
typedef struct {
  unsigned int              address;        /* The address. */
  uint16_t                  def_value;      /* Its default value. */
  unsigned int              directive_count;/* Count of relevant directives. */
  const gp_cfg_directive_t* directives;     /* Array of directives. */
} gp_cfg_addr_t;

/* A device - that is, a collection of configuration addresses. */
typedef struct {
  const char*          name;                /* Name of the device. */
  unsigned int         address_count;       /* Number of configuration addresses. */
  const gp_cfg_addr_t* addresses;           /* Array of configuration addresses. */
} gp_cfg_device_t;

#define GP_CFG_ADDR_HIT_MAX         16
#define GP_CFG_ADDR_PACK_MAX        16

typedef struct {
  const gp_cfg_directive_t* directive;
  const gp_cfg_option_t*    option;
} gp_cfg_addr_hit_pair_t;

typedef struct {
  unsigned int           max_dir_width;     /* The size of the longest directive name. */
  uint16_t               def_value;         /* Default value of this gp_cfg_addr_t. */
  unsigned int           pair_count;        /* Number of the pairs. */
  gp_cfg_addr_hit_pair_t pairs[GP_CFG_ADDR_HIT_MAX];
} gp_cfg_addr_hit_t;

typedef struct {
  unsigned int      max_dir_width;          /* The size of the longest directive name. */
  unsigned int      hit_count;              /* Number of the hits. */
  gp_cfg_addr_hit_t hits[GP_CFG_ADDR_PACK_MAX];
} gp_cfg_addr_pack_t;

extern const gp_cfg_device_t gp_cfg_devices[];
extern const int             gp_cfg_device_count;

extern const gp_cfg_device_t* gp_cfg_find_pic(const char* Pic);

extern const gp_cfg_device_t* gp_cfg_find_pic_multi_name(const char* const* Pics, unsigned int Count);

extern void gp_cfg_real_config_boundaries(const gp_cfg_device_t* Device, int* Address_low, int* Address_high);

extern const gp_cfg_directive_t* gp_cfg_find_directive(const gp_cfg_device_t* Device, const char* Directive,
                                                       unsigned int* Out_config_addr, uint16_t* Out_def_value);

extern void gp_cfg_brief_device(const gp_cfg_device_t* Device, const char* Head, int Addr_digits,
                                int Word_digits, gp_boolean Pic18J);

extern void gp_cfg_full_list_device(const gp_cfg_device_t* Device, const char* Head, int Addr_digits,
                                    int Word_digits);

extern const gp_cfg_option_t* gp_cfg_find_option(const gp_cfg_directive_t* Directive, const char* Option);

extern const gp_cfg_addr_t* gp_cfg_find_config(const gp_cfg_device_t* Device, unsigned int Address);

extern uint16_t gp_cfg_get_default(const gp_cfg_device_t* Device, unsigned int Address);

extern unsigned int gp_cfg_decode_directive(const gp_cfg_device_t* Device, unsigned int Address, unsigned int Value,
                                            gp_cfg_addr_hit_t* Hit);

#endif /* g__GPCFG_H__ */
