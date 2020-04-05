/*
 *  Copyright (C) 2002-2010  The DOSBox Team
 *  Copyright (C) 2020 Joel Lehtonen
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdint.h>

// This feature should be tested but assuming recent enough gcc
#define GCC_ATTRIBUTE(x) __attribute__ ((x))

typedef         double     Real64;

typedef uint8_t Bit8u;
typedef int8_t Bit8s;

typedef uint16_t Bit16u;
typedef int16_t Bit16s;

typedef uint32_t Bit32u;
typedef int32_t Bit32s;

typedef uint64_t Bit64u;
typedef int64_t Bit64s;

typedef uint_least32_t Bitu;
typedef int_least32_t Bits;
