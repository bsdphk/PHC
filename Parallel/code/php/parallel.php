<pre>
<?php
// Copyright (c) 2014 Steve Thomas <steve AT tobtu DOT com>

function PHS($outlen, $in, $salt, $t_cost, $m_cost)
{
	$sequentialLoops = $t_cost >> 16;
	$parallelLoops   = $t_cost & 0xffff;
	if ($m_cost > 18 || $parallelLoops > 30 || $sequentialLoops > 31 || $outlen > 64)
	{
		return false;
	}
	// $sequentialLoops = 1, 2, 3, 4, 6, 8, 12, 16, ...
	if ($sequentialLoops == 0)
	{
		$sequentialLoops = 1;
	}
	else
	{
		$sequentialLoops = (3 - ($sequentialLoops & 1)) << (($sequentialLoops - 1) >> 1);
	}
	// $parallelLoops = 2, 3, 4, 6, 8, 12, 16, ...
	if ($parallelLoops == 0)
	{
		$parallelLoops = 1;
	}
	else
	{
		$parallelLoops = (3 - ($parallelLoops & 1)) << (($parallelLoops - 1) >> 1);
	}
	$parallelLoops = 3 * 5 * 128 * $parallelLoops;

	// key = SHA512(SHA512(salt) || in)
	$key = mhash(MHASH_SHA512, mhash(MHASH_SHA512, $salt) . $in);

	// Work
	for ($i = 0; $i < $sequentialLoops; $i++)
	{
		// Clear work
		$work = str_repeat("\0", 64);

		for ($j = 0; $j < $parallelLoops; $j++)
		{
			// work ^= SHA512(WRITE_BIG_ENDIAN_64(i) || WRITE_BIG_ENDIAN_64(j) || key)
			$work ^= mhash(MHASH_SHA512, pack('N4', 0, $i, 0, $j) . $key);
		}

		// Finish
		// key = truncate(SHA512(SHA512(work || key)), outlen) || zeros(64 - outlen)
		$key = substr(mhash(MHASH_SHA512, mhash(MHASH_SHA512, $work . $key)), 0, $outlen) . str_repeat("\0", 64 - $outlen);
	}

	return substr($key, 0, $outlen);
}

function testVector($p, $s, $t, $m, $ol)
{
	echo "outlen:       $ol\n";
	echo "password hex: " . bin2hex($p) . "\n";
	echo "salt hex:     " . bin2hex($s) . "\n";
	printf("t_cost:       0x%05x\n", $t);
	echo "m_cost:       0\n";
	echo "hash:         " . bin2hex(PHS($ol, $p, $s, $t, $m)) . "\n\n";
}

testVector('password', 'salt', 0x00000, 0, 64);
testVector('password', 'salt', 0x00000, 0, 32);
testVector('passwordpassword', 'salt', 0x00001, 0, 64);
testVector('password', 'saltsalt', 0x00001, 0, 64);
testVector('password', 'salt', 0x00001, 0, 64);
testVector('password', 'salt', 0x00002, 0, 64);
testVector('password', 'salt', 0x00003, 0, 64);
testVector('password', 'salt', 0x00004, 0, 64);
testVector('password', 'salt', 0x10001, 0, 64);
testVector('password', 'salt', 0x20002, 0, 64);
testVector('password', 'salt', 0x30003, 0, 64);
testVector('password', 'salt', 0x40004, 0, 64);

testVector("\xff\0", "\x80", 0x00000, 0, 64);
testVector("\xff\0", "\x80", 0x10001, 0, 64);
testVector("\xff\0", "\x80", 0x20002, 0, 64);
testVector("\xff\0", "\x80", 0x30003, 0, 64);

for ($i = 0; $i < 32; $i++)
{
	$p = '';
	for ($j = 0; $j < $i; $j++)
	{
		$p .= chr($j);
	}
	testVector($p, strrev($p), 0x00002, 0, 64);
}
