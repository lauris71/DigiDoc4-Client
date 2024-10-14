#ifndef __CDOC_H__
#define __CDOC_H__

/*
 * libcdoc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

namespace libcdoc {

// Placeholder until we implrmrnt i18n
#define t_(s) s

static constexpr int OK = 0;
static constexpr int NOT_IMPLEMENTED = -100;
static constexpr int NOT_SUPPORTED = -101;
static constexpr int WRONG_ARGUMENTS = -102;
static constexpr int WORKFLOW_ERROR = -103;
static constexpr int IO_ERROR = -104;
static constexpr int DATA_FORMAT_ERROR = -105;
static constexpr int CRYPTO_ERROR = -106;
static constexpr int HASH_MISMATCH = -107;
static constexpr int UNSPECIFIED_ERROR = -108;

}; // namespace libcdoc

#endif // CDOC_H
