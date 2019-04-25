/**
 * @file otp.h
 *
 * @brief One-time-password-related functions.
 *
 * @copyright The contents of this file have been placed into the public domain;
 * see the file COPYING for more details.
 */

#ifndef __CPPTOTP_OTP_H__
#define __CPPTOTP_OTP_H__

#include "bytes.h"
#include "sha1.h"

#include <iostream>
#include <cstdint>

namespace CppTotp
{
    /*
     * The 64-bit-blocksize variant of HMAC-SHA1. 
     */
    Bytes::ByteString hmacSha1_64(const Bytes::ByteString & key, const Bytes::ByteString & msg){
        return hmacSha1(key, msg, 64);
    }

    /*
     * Calculate the HOTP value of the given key, message and digit count.
     */
    uint32_t hotp(const Bytes::ByteString & key, uint64_t counter, size_t digitCount = 6, HmacFunc hmacf = hmacSha1_64)
    {
        Bytes::ByteString msg = Bytes::u64beToByteString(counter);
        Bytes::ByteStringDestructor dmsg(&msg);

        Bytes::ByteString hmac = hmacf(key, msg);
        Bytes::ByteStringDestructor dhmac(&hmac);

        uint32_t digits10 = 1;
        for (size_t i = 0; i < digitCount; ++i)
        {
            digits10 *= 10;
        }

        // fetch the offset (from the last nibble)
        uint8_t offset = hmac[hmac.size()-1] & 0x0F;

        // fetch the four bytes from the offset
        Bytes::ByteString fourWord = hmac.substr(offset, 4);
        Bytes::ByteStringDestructor dfourWord(&fourWord);

        // turn them into a 32-bit integer
        uint32_t ret =
            (fourWord[0] << 24) |
            (fourWord[1] << 16) |
            (fourWord[2] <<  8) |
            (fourWord[3] <<  0)
        ;

        // snip off the MSB (to alleviate signed/unsigned troubles)
        // and calculate modulo digit count
        return (ret & 0x7fffffff) % digits10;
    }

    /*
     * Calculate the TOTP value from the given parameters.
     */
    uint32_t totp(const Bytes::ByteString & key, uint64_t timeNow, uint64_t timeStart, uint64_t timeStep, size_t digitCount = 6, HmacFunc hmacf = hmacSha1_64)
    {
        uint64_t timeValue = (timeNow - timeStart) / timeStep;
        return hotp(key, timeValue, digitCount, hmacf);
    }
}

#endif
