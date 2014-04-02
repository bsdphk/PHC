<pre>
<?php
// Copyright (c) 2014 Steve Thomas <steve AT tobtu DOT com>

// I believe this is the minimum version requirements
// PHP 4 >= 4.0.2, PHP 5

/*
*** Core2 Quad Q9300 2.5 GHz ***

battcrypt in PHP vs compiled bcrypt
battcrypt t: 1, m: 3:     8.07 ms +103.329% (-0.752% blowfish blocks)
bcrypt  5:                3.97 ms
battcrypt t: 8, m: 0:     6.93 ms  +74.620% (+2.255% blowfish blocks)

battcrypt t: 1, m: 4:    11.71 ms  +95.957% (-1.234% blowfish blocks)
bcrypt  6:                5.97 ms
battcrypt t:10, m: 0:    12.95 ms +116.762% (+0.285% blowfish blocks)

battcrypt t: 1, m: 5:    22.96 ms  +91.570% (-1.480% blowfish blocks)
bcrypt  7:               11.98 ms
battcrypt t:10, m: 1:    25.10 ms +109.461% (+0.048% blowfish blocks)

battcrypt t: 1, m: 6:    45.10 ms  +93.900% (-1.603% blowfish blocks)
bcrypt  8:               23.26 ms
battcrypt t: 8, m: 3:    49.27 ms +111.828% (+1.460% blowfish blocks)

battcrypt t: 1, m: 7:    89.15 ms  +90.630% (-1.665% blowfish blocks)
bcrypt  9:               46.76 ms
battcrypt t: 8, m: 4:    98.82 ms +111.323% (+1.402% blowfish blocks)

battcrypt t: 1, m: 8:   177.64 ms  +90.879% (-1.696% blowfish blocks)
bcrypt 10:               93.07 ms
battcrypt t: 8, m: 5:   194.91 ms +109.427% (+1.373% blowfish blocks)

battcrypt t: 1, m: 9:   354.46 ms  +91.638% (-1.712% blowfish blocks)
bcrypt 11:              184.96 ms
battcrypt t: 8, m: 6:   390.11 ms +110.908% (+1.358% blowfish blocks)

battcrypt t: 1, m:10:   707.22 ms  +91.141% (-1.720% blowfish blocks)
bcrypt 12:              370.00 ms
battcrypt t: 8, m: 7:   784.15 ms +111.933% (+1.351% blowfish blocks)

battcrypt t: 1, m:11:  1418.67 ms  +91.802% (-1.724% blowfish blocks)
bcrypt 13:              739.65 ms
battcrypt t: 8, m: 8:  1566.08 ms +111.732% (+1.347% blowfish blocks)

battcrypt t: 1, m:12:  2837.70 ms  +91.746% (-1.726% blowfish blocks)
bcrypt 14:             1479.93 ms
battcrypt t: 8, m: 9:  3158.38 ms +113.414% (+1.345% blowfish blocks)

battcrypt t: 1, m:13:  5670.57 ms  +91.668% (-1.726% blowfish blocks)
bcrypt 15:             2958.54 ms
battcrypt t: 8, m:10:  6318.70 ms +113.575% (+1.344% blowfish blocks)

Total time: 29.87 seconds
*/

function PHS($outlen, $in, $salt, $t_cost, $m_cost)
{
	$upgradeLoops = $t_cost >> 16;
	$loops        = $t_cost & 0xffff;
	if ($m_cost > 18 || $loops > 30 || $upgradeLoops > 31 || $outlen > 64)
	{
		return false;
	}
	// $upgradeLoops = 1, 2, 3, 4, 6, 8, 12, 16, ...
	if ($upgradeLoops == 0)
	{
		$upgradeLoops = 1;
	}
	else
	{
		$upgradeLoops = (3 - ($upgradeLoops & 1)) << (($upgradeLoops - 1) >> 1);
	}
	// $loops = 2, 3, 4, 6, 8, 12, 16, ...
	$loops = (($loops & 1) + 2) << ($loops >> 1);
	$memSize      = 4 << $m_cost;
	$memMask      = $memSize - 1;
	$mem = array();
	$key = mhash(MHASH_SHA512, mhash(MHASH_SHA512, $salt) . $in);
	for ($u = 0; $u < $upgradeLoops; $u++)
	{
		$blowfish = mcrypt_module_open(MCRYPT_BLOWFISH, '', MCRYPT_MODE_CBC, '');
		if ($blowfish === false)
		{
			return false;
		}
		if (mcrypt_generic_init($blowfish, substr($key, 0, 56), "\0\0\0\0\0\0\0\0") !== 0)
		{
			mcrypt_generic_deinit($blowfish);
			return false;
		}

		// data = SHA512(BIG_ENDIAN_64( 0) || key) ||
		//        SHA512(BIG_ENDIAN_64( 1) || key) ||
		//        ...
		//        SHA512(BIG_ENDIAN_64(31) || key)
		$data = '';
		$key3 = $key2 = "\0\0\0\0\0\0\0\0" . $key;
		for ($i = 0; $i < 32; $i += 2)
		{
			$key2[7] = chr($i);
			$key3[7] = chr($i + 1);
			$data .= mhash(MHASH_SHA512, $key2) . mhash(MHASH_SHA512, $key3);
		}

		// Init
		for ($i = 0; $i < $memSize; $i++)
		{
			$mem[$i] = $data = mcrypt_generic($blowfish, $data);
		}
		$data = mcrypt_generic($blowfish, $data);

		// Work
		for ($i = 0; $i < $loops; $i++)
		{
			for ($j = 0; $j < $memSize; $j++)
			{
				// r = last32Bits_bigEndian(data) % memSize
				// mem[j] = blowfish_cbc_encrypt(data ^ $mem[$j] ^ mem[r])
				// data = data ^ mem[j]
				$r = unpack('N', substr($data, -4));
				$data ^= $mem[$j] = mcrypt_generic($blowfish, $mem[$j] ^ $data ^ $mem[$r[1] & $memMask]);
			}
		}

		// Finish
		// key = truncate(SHA512(SHA512(data || key)), outlen) || zeros(64 - outlen)
		$key = substr(mhash(MHASH_SHA512, mhash(MHASH_SHA512, $data . $key)), 0, $outlen) . str_repeat("\0", 64 - $outlen);
	}

	// Clean up
	mcrypt_generic_deinit($blowfish);

	return substr($key, 0, $outlen);
}

function benchmark($battcrypt_t1, $battcrypt_m1, $bcrypt_c, $battcrypt_t2, $battcrypt_m2)
{
	// bcrypt
	if ($bcrypt_c < 10)
	{
		$settings = '$2a$0' . $bcrypt_c . '$......................';
	}
	else
	{
		$settings = '$2a$' . $bcrypt_c . '$......................';
	}
	$s = microtime(true);
	$hash = crypt('password', $settings);
	$e = microtime(true);
	$bcryptTime = $e - $s;
	$bcryptError = substr($hash, 0, 4) != '$2a$';
	$bcryptBlocks = (4 * (1024 + 18) * ((2 << $bcrypt_c) + 1) + 64 * 24) / 8;

	// battcrypt
	if ($battcrypt_t1 !== false && $battcrypt_m1 !== false)
	{
		$s = microtime(true);
		$hash = PHS(64, 'password', 'salt', $battcrypt_t1, $battcrypt_m1);
		$e = microtime(true);
		if ($hash !== false)
		{
			$time = $e - $s;
			$upgradeLoops = $battcrypt_t1 >> 16;
			$loops        = $battcrypt_t1 & 0xffff;
			$memSize      = 2 << $battcrypt_m1;
			// $upgradeLoops = 1, 2, 3, 4, 6, 8, 12, 16, ...
			if ($upgradeLoops == 0)
			{
				$upgradeLoops = 1;
			}
			else
			{
				$upgradeLoops = (3 - ($upgradeLoops & 1)) << (($upgradeLoops - 1) >> 1);
			}
			// $loops = 2, 3, 4, 6, 8, 12, 16, ...
			$loops = (($loops & 1) + 2) << ($loops >> 1);
			$battcryptBlocks = $upgradeLoops * (4 * 1024 * ($loops * $memSize + $memSize + 1) + 4 * (1024 + 18)) / 8;
			printf("battcrypt t:% 2u, m:% 2u: % 8.2f ms %+ 8.3f%% (%+ 6.3f%% blowfish blocks)\n",
				$battcrypt_t1,
				$battcrypt_m1,
				1000 * $time,
				100 * ($time - $bcryptTime) / $bcryptTime,
				100 * ($battcryptBlocks - $bcryptBlocks) / $bcryptBlocks);
		}
		else
		{
			printf("battcrypt t:% 2u, m:% 2u: error\n", $battcrypt_t1, $battcrypt_m1);
		}
	}

	if (!$bcryptError)
	{
		printf("bcrypt % 2u:            % 8.2f ms\n", $bcrypt_c, 1000 * $bcryptTime);
	}
	else
	{
		printf("bcrypt % 2u:            error\n", $bcrypt_c);
	}

	// battcrypt
	if ($battcrypt_t2 !== false && $battcrypt_m2 !== false)
	{
		$s = microtime(true);
		$hash = PHS(64, 'password', 'salt', $battcrypt_t2, $battcrypt_m2);
		$e = microtime(true);
		if ($hash !== false)
		{
			$time = $e - $s;
			$upgradeLoops = $battcrypt_t2 >> 16;
			$loops        = $battcrypt_t2 & 0xffff;
			$memSize      = 2 << $battcrypt_m2;
			// $upgradeLoops = 1, 2, 3, 4, 6, 8, 12, 16, ...
			if ($upgradeLoops == 0)
			{
				$upgradeLoops = 1;
			}
			else
			{
				$upgradeLoops = (3 - ($upgradeLoops & 1)) << (($upgradeLoops - 1) >> 1);
			}
			// $loops = 2, 3, 4, 6, 8, 12, 16, ...
			$loops = (($loops & 1) + 2) << ($loops >> 1);
			$battcryptBlocks = $upgradeLoops * (4 * 1024 * ($loops * $memSize + $memSize + 1) + 4 * (1024 + 18)) / 8;
			printf("battcrypt t:% 2u, m:% 2u: % 8.2f ms %+ 8.3f%% (%+ 6.3f%% blowfish blocks)\n",
				$battcrypt_t2,
				$battcrypt_m2,
				1000 * $time,
				100 * ($time - $bcryptTime) / $bcryptTime,
				100 * ($battcryptBlocks - $bcryptBlocks) / $bcryptBlocks);
		}
		else
		{
			printf("battcrypt t:% 2u, m:% 2u: error\n", $battcrypt_t2, $battcrypt_m2);
		}
	}
	echo "\n";
}

// The first call is sometimes slow depending on if it's cached or not?
crypt('password', '$2a$05$......................');
PHS(64, 'password', 'salt', 3, 3);

echo "battcrypt in PHP vs compiled bcrypt\n";

$s = microtime(true);
benchmark(1, 3, 5, 8, 0);
benchmark(1, 4, 6,10, 0);
benchmark(1, 5, 7,10, 1); // or benchmark(12, 0, 7,10, 1);
benchmark(1, 6, 8, 8, 3); // or benchmark(10, 2, 8, 8, 3);
benchmark(1, 7, 9, 8, 4); // or benchmark(10, 3, 9, 8, 4);
benchmark(1, 8,10, 8, 5); // or benchmark(10, 4,10, 8, 5);
benchmark(1, 9,11, 8, 6); // or benchmark(10, 5,11, 8, 6);
benchmark(1,10,12, 8, 7); // or benchmark(10, 6,12, 8, 7);
benchmark(1,11,13, 8, 8); // or benchmark(10, 7,13, 8, 8);
benchmark(1,12,14, 8, 9); // or benchmark(10, 8,14, 8, 9);
benchmark(1,13,15, 8,10); // or benchmark(10, 9,15, 8,10);
$e = microtime(true);
printf("Total time: % 0.2f seconds\n", $e - $s);
