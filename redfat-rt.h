/*
 *      ____          _ _____     _   
 *     |  _ \ ___  __| |  ___|_ _| |_ 
 * --- | |_) / _ \/ _` | |_ / _` | __| ---------------------->
 *     |  _ <  __/ (_| |  _| (_| | |_ 
 *     |_| \_\___|\__,_|_|  \__,_|\__| BINARY HARDENING SYSTEM
 *
 * Copyright (C) 2022 National University of Singapore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __REDFAT_RT_H
#define __REDFAT_RT_H

/*
 * Allow-list.
 */
#define ALLOW_REDZONE                       0           // Redzone-only
#define ALLOW_LOWFAT                        1           // Redzone+Lowfat
#define ALLOW_NONFAT                        2           // Only seen non-fat
#define ALLOW_UNKNOWN                       3           // Not reached

/*
 * Profiling.
 */
#define REDFAT_PROFILE      0x0ff000
#define TABLE_SIZES         0x100000
#define TABLE_MAGICS        0x180000
#define TABLE_SIZE          ((UINT16_MAX + 1) * sizeof(uint64_t))
#define REDFAT_PAGE_SIZE    4096

#define REDFAT_PROFILE_REDZONE_READ_UNOPTIMIZED_CHECKS      0
#define REDFAT_PROFILE_REDZONE_WRITE_UNOPTIMIZED_CHECKS     1
#define REDFAT_PROFILE_LOWFAT_READ_UNOPTIMIZED_CHECKS       2
#define REDFAT_PROFILE_LOWFAT_WRITE_UNOPTIMIZED_CHECKS      3
#define REDFAT_PROFILE_REDZONE_READ_OPTIMIZED_CHECKS        4
#define REDFAT_PROFILE_REDZONE_WRITE_OPTIMIZED_CHECKS       5
#define REDFAT_PROFILE_LOWFAT_READ_OPTIMIZED_CHECKS         6
#define REDFAT_PROFILE_LOWFAT_WRITE_OPTIMIZED_CHECKS        7
#define REDFAT_PROFILE_REDZONE_READ_NONLEGACY_CHECKS        8
#define REDFAT_PROFILE_REDZONE_WRITE_NONLEGACY_CHECKS       9
#define REDFAT_PROFILE_LOWFAT_READ_NONLEGACY_CHECKS         10
#define REDFAT_PROFILE_LOWFAT_WRITE_NONLEGACY_CHECKS        11
#define REDFAT_PROFILE_VAR(var)                                         \
    (int)(REDFAT_PROFILE + (var) * sizeof(size_t))

/*
 * Flags.
 */
#define REDFAT_FLAG_ALLOWLIST_GEN           0x1
#define REDFAT_FLAG_ALLOWLIST_USE           0x2
#define REDFAT_FLAG_PROFILE                 0x4

/*
 * Redfat data.
 */
struct redfat
{
    uint64_t flags;                 // Flags
    struct
    {
        char allowlist[2048];       // Allowlist filename (if used)
    } filename;
};

#endif
