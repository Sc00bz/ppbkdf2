<?php

/*
	PPBKDF2 - A Password KDF called Parallel PBKDF2.

	Written in 2020 Steve "Sc00bz" Thomas (steve at tobtu dot com)

	To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring
	rights to this software to the public domain worldwide. This software is distributed without any warranty.

	You should have received a copy of the CC0 Public Domain Dedication along with this software.
	If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
*/

/**
 * Parallel PBKDF2 (PPBKDF2) - A computationally hard password KDF
 *
 * work = xorBlocks(pbkdf2(pw, salt, iterations:1024, length:384*hashLen*cost))
 * key = pbkdf2(pw, work, iterations:1, length)
 * 
 * Note each block of output is calculated independently of each
 * other. This can use SIMD and threads to compute faster.
 *
 * @param string $algo - Hashing algorithm
 * @param string $password
 * @param string $salt
 * @param string $cost - Cost is equivalent to 384*1024*cost iterations with PBKDF2
 * @param integer $length - Number of bytes to output
 * @param bool $binary - Output raw bytes or hex encoded
 * @return string|false
 */
function ppbkdf2($algo, $password, $salt, $cost, $length = 0, $binary = false)
{
	// Hash length and PHP limits
	// There is no actual limit to cost. When 384*cost is more than 2^32-1,
	// iterations is doubled and cost is halved until 384*cost is less than 2^32.
	$hashLen = strlen(hash_pbkdf2($algo, '', '', 1, 0, true));
	if ($cost <= 0 || $cost > 0x7fffffff / 384 / $hashLen)
	{
		return false;
	}

	// Work
	$len = 384 * $cost * $hashLen;
	$hash = hash_pbkdf2($algo, $password, $salt, 1024, $len, true);
	$work = substr($hash, 0, $hashLen);
	for ($i = $hashLen; $i < $len; $i += $hashLen)
	{
		$work = $work ^ substr($hash, $i, $hashLen);
	}

	// KDF
	$key = hash_pbkdf2($algo, $password, $work, 1, $length, true);
	if (!$binary)
	{
		$key = bin2hex($key);
	}
	return $key;
}
