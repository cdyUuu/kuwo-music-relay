<?php
/**
 * Kuwo Music Relay Decrypt Server (Single File)
 *
 * Receives an encrypted music URL and ekey, decrypts the audio in real-time,
 * and streams it to media players. Supports HTTP Range requests (seeking).
 *
 * Usage:
 *   http://your-server/decrypt.php?url=<encrypted_url>&ekey=<encryption_key>
 *
 * Third-party player plugins (e.g. LX Music) can construct this URL
 * and pass it directly to the player for playback.
 *
 * Requirements:
 *   - PHP 7.4+ (64-bit)
 *   - cURL extension
 *
 * Supported formats:
 *   - .mflac / .mflac0  →  FLAC audio (audio/flac)
 *   - .mgg   / .mggl    →  OGG Vorbis audio (audio/ogg)
 *   - .mmp3              →  MP3 audio (audio/mpeg)
 *
 * Algorithm source: https://github.com/006lp/nonebot-plugin-kuwo (Rust implementation)
 * Licensed under the MIT License.
 */

// ============================================================
// Configuration (edit these values to customize behavior)
// ============================================================
define('RELAY_CACHE_DIR', sys_get_temp_dir() . '/mflac_relay');
define('RELAY_LOG_FILE', __DIR__ . '/access.log');
define('RELAY_ENABLE_LOG', true);
define('RELAY_CACHE_TIME', 3600);          // Cache TTL in seconds (default: 1 hour)
define('RELAY_DOWNLOAD_TIMEOUT', 300);     // Download timeout in seconds (default: 5 min)
define('RELAY_CONNECT_TIMEOUT', 15);       // Connection timeout in seconds
define('RELAY_MAX_CACHE_SIZE', 536870912); // Max total cache size in bytes (default: 512MB)
define('RELAY_MAX_CACHE_FILES', 50);       // Max number of cached files
define('RELAY_MAX_LOG_SIZE', 10485760);    // Max log file size in bytes (default: 10MB)
define('RELAY_MEMORY_LIMIT', '256M');       // PHP memory limit for this script
define('RELAY_VERSION', '1.0.0');           // Server version
// ============================================================

// --- Environment checks ---

if (PHP_INT_SIZE !== 8) {
    http_response_code(500);
    die('This script requires 64-bit PHP.');
}

if (!extension_loaded('curl')) {
    http_response_code(500);
    die('This script requires the cURL extension.');
}

// Disable output buffering for real-time streaming
while (ob_get_level() > 0) {
    ob_end_clean();
}
ini_set('output_buffering', 'off');
ini_set('zlib.output_compression', '0');

// ============================================================
// KuwoDes - DES encrypt/decrypt implementation (for ekey decryption)
// ============================================================
class KuwoDes
{
    private const KUWO_SECRET_KEY = 'ylzsxkwm';

    // DES permutation tables
    private const ARRAY_E = [
        31, 0, 1, 2, 3, 4, -1, -1, 3, 4, 5, 6, 7, 8, -1, -1,
        7, 8, 9, 10, 11, 12, -1, -1, 11, 12, 13, 14, 15, 16, -1, -1,
        15, 16, 17, 18, 19, 20, -1, -1, 19, 20, 21, 22, 23, 24, -1, -1,
        23, 24, 25, 26, 27, 28, -1, -1, 27, 28, 29, 30, 31, 30, -1, -1,
    ];

    private const ARRAY_IP = [
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    ];

    private const ARRAY_IP_1 = [
        39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24,
    ];

    private const ARRAY_LS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
    private const ARRAY_LS_MASK = [0, 0x100001, 0x300003];

    private const ARRAY_P = [
        15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
        1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24,
    ];

    private const ARRAY_PC_1 = [
        56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1,
        58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38,
        30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36,
        28, 20, 12, 4, 27, 19, 11, 3,
    ];

    private const ARRAY_PC_2 = [
        13, 16, 10, 23, 0, 4, -1, -1, 2, 27, 14, 5, 20, 9, -1, -1,
        22, 18, 11, 3, 25, 7, -1, -1, 15, 6, 26, 19, 12, 1, -1, -1,
        40, 51, 30, 36, 46, 54, -1, -1, 29, 39, 50, 44, 32, 47, -1, -1,
        43, 48, 38, 55, 33, 52, -1, -1, 45, 41, 49, 35, 28, 31, -1, -1,
    ];

    private const MATRIX_NS_BOX = [
        [14, 4, 3, 15, 2, 13, 5, 3, 13, 14, 6, 9, 11, 2, 0, 5,
         4, 1, 10, 12, 15, 6, 9, 10, 1, 8, 12, 7, 8, 11, 7, 0,
         0, 15, 10, 5, 14, 4, 9, 10, 7, 8, 12, 3, 13, 1, 3, 6,
         15, 12, 6, 11, 2, 9, 5, 0, 4, 2, 11, 14, 1, 7, 8, 13],
        [15, 0, 9, 5, 6, 10, 12, 9, 8, 7, 2, 12, 3, 13, 5, 2,
         1, 14, 7, 8, 11, 4, 0, 3, 14, 11, 13, 6, 4, 1, 10, 15,
         3, 13, 12, 11, 15, 3, 6, 0, 4, 10, 1, 7, 8, 4, 11, 14,
         13, 8, 0, 6, 2, 15, 9, 5, 7, 1, 10, 12, 14, 2, 5, 9],
        [10, 13, 1, 11, 6, 8, 11, 5, 9, 4, 12, 2, 15, 3, 2, 14,
         0, 6, 13, 1, 3, 15, 4, 10, 14, 9, 7, 12, 5, 0, 8, 7,
         13, 1, 2, 4, 3, 6, 12, 11, 0, 13, 5, 14, 6, 8, 15, 2,
         7, 10, 8, 15, 4, 9, 11, 5, 9, 0, 14, 3, 10, 7, 1, 12],
        [7, 10, 1, 15, 0, 12, 11, 5, 14, 9, 8, 3, 9, 7, 4, 8,
         13, 6, 2, 1, 6, 11, 12, 2, 3, 0, 5, 14, 10, 13, 15, 4,
         13, 3, 4, 9, 6, 10, 1, 12, 11, 0, 2, 5, 0, 13, 14, 2,
         8, 15, 7, 4, 15, 1, 10, 7, 5, 6, 12, 11, 3, 8, 9, 14],
        [2, 4, 8, 15, 7, 10, 13, 6, 4, 1, 3, 12, 11, 7, 14, 0,
         12, 2, 5, 9, 10, 13, 0, 3, 1, 11, 15, 5, 6, 8, 9, 14,
         14, 11, 5, 6, 4, 1, 3, 10, 2, 12, 15, 0, 13, 2, 8, 5,
         11, 8, 0, 15, 7, 14, 9, 4, 12, 7, 10, 9, 1, 13, 6, 3],
        [12, 9, 0, 7, 9, 2, 14, 1, 10, 15, 3, 4, 6, 12, 5, 11,
         1, 14, 13, 0, 2, 8, 7, 13, 15, 5, 4, 10, 8, 3, 11, 6,
         10, 4, 6, 11, 7, 9, 0, 6, 4, 2, 13, 1, 9, 15, 3, 8,
         15, 3, 1, 14, 12, 5, 11, 0, 2, 12, 14, 7, 5, 10, 8, 13],
        [4, 1, 3, 10, 15, 12, 5, 0, 2, 11, 9, 6, 8, 7, 6, 9,
         11, 4, 12, 15, 0, 3, 10, 5, 14, 13, 7, 8, 13, 14, 1, 2,
         13, 6, 14, 9, 4, 1, 2, 14, 11, 13, 5, 0, 1, 10, 8, 3,
         0, 11, 3, 5, 9, 4, 15, 2, 7, 8, 12, 15, 10, 7, 6, 12],
        [13, 7, 10, 0, 6, 9, 5, 15, 8, 4, 3, 10, 11, 14, 12, 5,
         2, 11, 9, 6, 15, 12, 0, 3, 4, 1, 14, 13, 1, 2, 7, 8,
         1, 2, 12, 15, 10, 4, 0, 3, 13, 14, 6, 9, 7, 8, 9, 6,
         15, 1, 5, 12, 3, 10, 14, 5, 8, 7, 11, 0, 4, 13, 2, 11],
    ];

    /**
     * Bit transform: extract and rearrange bits from the input value
     * according to the given array of bit indices.
     */
    private static function bitTransform(array $arr, int $n, int $value): int
    {
        $transformed = 0;
        for ($index = 0; $index < $n; $index++) {
            $bitIndex = $arr[$index];
            if ($bitIndex >= 0 && ($value & (1 << $bitIndex)) !== 0) {
                $transformed |= (1 << $index);
            }
        }
        return $transformed;
    }

    /**
     * DES single-block encrypt/decrypt
     */
    private static function des64(array $longs, int $value): int
    {
        $output = self::bitTransform(self::ARRAY_IP, 64, $value);
        $source0 = $output & 0xFFFFFFFF;
        $source1 = ($output >> 32) & 0xFFFFFFFF;

        foreach ($longs as $roundKey) {
            $right = self::bitTransform(self::ARRAY_E, 64, $source1) ^ $roundKey;

            $partial = [];
            for ($i = 0; $i < 8; $i++) {
                $partial[$i] = ($right >> ($i * 8)) & 0xFF;
            }

            $sOut = 0;
            for ($boxIndex = 7; $boxIndex >= 0; $boxIndex--) {
                $sOut = ($sOut << 4) & 0xFFFFFFFF;
                $sOut |= self::MATRIX_NS_BOX[$boxIndex][$partial[$boxIndex]];
            }

            $right = self::bitTransform(self::ARRAY_P, 32, $sOut);
            $left = $source0;
            $source0 = $source1;
            $source1 = $left ^ $right;
        }

        // Swap source0 and source1
        $temp = $source0;
        $source0 = $source1;
        $source1 = $temp;

        $merged = ($source1 << 32) | ($source0 & 0xFFFFFFFF);
        return self::bitTransform(self::ARRAY_IP_1, 64, $merged);
    }

    /**
     * Generate subkeys
     */
    private static function subKeys(int $value, int $mode): array
    {
        $keySchedule = [];
        $transformed = self::bitTransform(self::ARRAY_PC_1, 56, $value);

        for ($index = 0; $index < 16; $index++) {
            $shift = self::ARRAY_LS[$index];
            $mask = self::ARRAY_LS_MASK[$shift];
            $notMask = ~$mask;
            $transformed = (($transformed & $mask) << (28 - $shift)) | (($transformed & $notMask) >> $shift);
            $keySchedule[$index] = self::bitTransform(self::ARRAY_PC_2, 64, $transformed);
        }

        if ($mode === 1) {
            $keySchedule = array_reverse($keySchedule);
        }
        return $keySchedule;
    }

    /**
     * Kuwo DES encrypt/decrypt
     * @param string $message Input data
     * @param int $mode 0=encrypt, 1=decrypt
     * @param string $key 8-byte key
     */
    public static function crypto(string $message, int $mode, string $key): string
    {
        $input = $message;

        if ($mode === 0) {
            $padding = (8 - strlen($input) % 8) % 8;
            if ($padding > 0) {
                $input .= str_repeat("\0", $padding);
            }
        } else {
            if (strlen($input) % 8 !== 0) {
                throw new RuntimeException('In decrypt mode, data length must be a multiple of 8');
            }
        }

        // Pack the 8-byte key into a 64-bit integer (little-endian)
        $keyBlock = unpack('P', $key)[1];
        $schedule = self::subKeys($keyBlock, $mode);

        $result = '';
        $chunks = str_split($input, 8);
        foreach ($chunks as $chunk) {
            $block = unpack('P', $chunk)[1];
            $encrypted = self::des64($schedule, $block);
            for ($i = 0; $i < 8; $i++) {
                $result .= chr(($encrypted >> ($i * 8)) & 0xFF);
            }
        }

        return $result;
    }

    /**
     * Kuwo Base64 decrypt: Base64 decode -> DES decrypt -> remove trailing null bytes
     */
    public static function base64Decrypt(string $value): string
    {
        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            throw new RuntimeException('Invalid Base64 input');
        }
        $result = self::crypto($decoded, 1, self::KUWO_SECRET_KEY);
        return rtrim($result, "\0");
    }
}

// ============================================================
// QmcTea - TC-TEA (Tencent TEA) decryption implementation
// ============================================================
class QmcTea
{
    private const DELTA = 0x9E3779B9;

    /**
     * TEA single-block decrypt (8 bytes)
     */
    private static function teaDecryptBlock(string $block, string $key): string
    {
        $v0 = unpack('N', substr($block, 0, 4))[1];
        $v1 = unpack('N', substr($block, 4, 4))[1];
        $k0 = unpack('N', substr($key, 0, 4))[1];
        $k1 = unpack('N', substr($key, 4, 4))[1];
        $k2 = unpack('N', substr($key, 8, 4))[1];
        $k3 = unpack('N', substr($key, 12, 4))[1];

        $sum = (self::DELTA * 16) & 0xFFFFFFFF;

        for ($i = 0; $i < 16; $i++) {
            // v1 = v1 - ((v0<<4)+k2 ^ v0+sum ^ (v0>>5)+k3)
            $t1 = (($v0 << 4) + $k2) & 0xFFFFFFFF;
            $t2 = ($v0 + $sum) & 0xFFFFFFFF;
            $t3 = (($v0 >> 5) + $k3) & 0xFFFFFFFF;
            $v1 = ($v1 - ($t1 ^ $t2 ^ $t3)) & 0xFFFFFFFF;

            // v0 = v0 - ((v1<<4)+k0 ^ v1+sum ^ (v1>>5)+k1)
            $t1 = (($v1 << 4) + $k0) & 0xFFFFFFFF;
            $t2 = ($v1 + $sum) & 0xFFFFFFFF;
            $t3 = (($v1 >> 5) + $k1) & 0xFFFFFFFF;
            $v0 = ($v0 - ($t1 ^ $t2 ^ $t3)) & 0xFFFFFFFF;

            $sum = ($sum - self::DELTA) & 0xFFFFFFFF;
        }

        return pack('N', $v0) . pack('N', $v1);
    }

    /**
     * XOR two 8-byte strings using native string XOR (C-level speed)
     */
    private static function xor8Bytes(string $left, string $right): string
    {
        return $left ^ $right;
    }

    /**
     * Decrypt the next block (internal helper method)
     */
    private static function decryptNextBlock(
        string &$decryptedBlock,
        string &$ivPrev,
        string &$ivCur,
        int &$inputPos,
        int &$destIdx,
        string $inputBuffer,
        string $key
    ): void {
        $ivPrev = $ivCur;
        $ivCur = substr($inputBuffer, $inputPos, 8);
        $xored = self::xor8Bytes($decryptedBlock, $ivCur);
        $decryptedBlock = self::teaDecryptBlock($xored, $key);
        $inputPos += 8;
        $destIdx = 0;
    }

    /**
     * TC-TEA decrypt (CBC mode variant)
     */
    public static function decryptTencentTea(string $inputBuffer, string $key): string
    {
        $saltLen = 2;
        $zeroLen = 7;
        $inputLen = strlen($inputBuffer);

        if ($inputLen % 8 !== 0) {
            throw new RuntimeException('Input data length is not a multiple of 8');
        }
        if ($inputLen < 16) {
            throw new RuntimeException('Input data length is too small');
        }

        $decryptedBlock = self::teaDecryptBlock(substr($inputBuffer, 0, 8), $key);
        $padLen = ord($decryptedBlock[0]) & 0x7;
        $outputLen = $inputLen - 1 - $padLen - $saltLen - $zeroLen;

        if ($outputLen < 0) {
            throw new RuntimeException('Invalid padding length');
        }

        $output = str_repeat("\0", $outputLen);

        $ivPrev = str_repeat("\0", 8);
        $ivCur = substr($inputBuffer, 0, 8);
        $inputPos = 8;
        $destIdx = 1 + $padLen;

        // Skip salt
        $saltIndex = 1;
        while ($saltIndex <= $saltLen) {
            if ($destIdx < 8) {
                $destIdx++;
                $saltIndex++;
            } else {
                self::decryptNextBlock($decryptedBlock, $ivPrev, $ivCur, $inputPos, $destIdx, $inputBuffer, $key);
            }
        }

        // Decrypt output data
        $outputPos = 0;
        while ($outputPos < $outputLen) {
            if ($destIdx < 8) {
                $output[$outputPos] = chr(ord($decryptedBlock[$destIdx]) ^ ord($ivPrev[$destIdx]));
                $destIdx++;
                $outputPos++;
            } else {
                self::decryptNextBlock($decryptedBlock, $ivPrev, $ivCur, $inputPos, $destIdx, $inputBuffer, $key);
            }
        }

        // Verify trailing zero bytes
        $zeroIndex = 1;
        while ($zeroIndex <= $zeroLen) {
            if ($destIdx < 8) {
                if (ord($decryptedBlock[$destIdx]) !== ord($ivPrev[$destIdx])) {
                    throw new RuntimeException('Zero byte validation failed');
                }
                $destIdx++;
                $zeroIndex++;
            } else {
                self::decryptNextBlock($decryptedBlock, $ivPrev, $ivCur, $inputPos, $destIdx, $inputBuffer, $key);
            }
        }

        return $output;
    }
}

// ============================================================
// QmcKeyDerivation - QMC key derivation
// ============================================================
class QmcKeyDerivation
{
    private const QMC_RAW_KEY_LENGTHS = [704, 364];
    private const QMC_V2_KEY_PREFIX = 'QQMusic EncV2,Key:';
    private const QMC_V2_DERIVE_KEY_1 = "\x33\x38\x36\x5A\x4A\x59\x21\x40\x23\x2A\x24\x25\x5E\x26\x29\x28";
    private const QMC_V2_DERIVE_KEY_2 = "\x2A\x2A\x23\x21\x28\x23\x24\x25\x26\x5E\x61\x31\x63\x5A\x2C\x54";

    /**
     * Extract the QMC raw key from ekey
     */
    public static function extractRawKeyFromEkey(string $ekey): string
    {
        $decrypted = KuwoDes::base64Decrypt($ekey);
        $trimmed = rtrim($decrypted, "\0");

        foreach (self::QMC_RAW_KEY_LENGTHS as $keyLength) {
            if (strlen($trimmed) < $keyLength) {
                continue;
            }
            $candidate = substr($trimmed, strlen($trimmed) - $keyLength);
            if (base64_decode($candidate, true) !== false) {
                return $candidate;
            }
        }

        throw new RuntimeException('Failed to extract QMC raw key from Kuwo ekey');
    }

    /**
     * Generate a simple key (based on the tan function)
     */
    private static function simpleMakeKey(int $salt, int $length): string
    {
        $key = '';
        for ($index = 0; $index < $length; $index++) {
            $val = (int)(abs(tan($salt + $index * 0.1) * 100.0)) & 0xFF;
            $key .= chr($val);
        }
        return $key;
    }

    /**
     * V1 key derivation
     */
    private static function deriveKeyV1(string $rawKeyDecoded): string
    {
        if (strlen($rawKeyDecoded) < 16) {
            throw new RuntimeException('Key length is too short');
        }

        $simpleKey = self::simpleMakeKey(106, 8);
        $teaKey = str_repeat("\0", 16);
        for ($index = 0; $index < 8; $index++) {
            $teaKey[$index * 2] = $simpleKey[$index];
            $teaKey[$index * 2 + 1] = $rawKeyDecoded[$index];
        }

        $decrypted = QmcTea::decryptTencentTea(substr($rawKeyDecoded, 8), $teaKey);
        return substr($rawKeyDecoded, 0, 8) . $decrypted;
    }

    /**
     * V2 key derivation
     */
    private static function deriveKeyV2(string $rawKey): string
    {
        $buffer = QmcTea::decryptTencentTea($rawKey, self::QMC_V2_DERIVE_KEY_1);
        $buffer = QmcTea::decryptTencentTea($buffer, self::QMC_V2_DERIVE_KEY_2);
        $decoded = base64_decode($buffer, true);
        if ($decoded === false) {
            throw new RuntimeException('V2 key contains invalid Base64');
        }
        return $decoded;
    }

    /**
     * Derive the QMC key
     */
    public static function deriveQmcKey(string $rawKey): string
    {
        $decoded = base64_decode($rawKey, true);
        if ($decoded === false) {
            throw new RuntimeException('Raw key contains invalid Base64');
        }

        // Check if it is V2 format
        $prefixLen = strlen(self::QMC_V2_KEY_PREFIX);
        if (strlen($decoded) >= $prefixLen && substr($decoded, 0, $prefixLen) === self::QMC_V2_KEY_PREFIX) {
            $decoded = self::deriveKeyV2(substr($decoded, $prefixLen));
        }

        return self::deriveKeyV1($decoded);
    }

    /**
     * Create a cipher from ekey
     */
    public static function createCipherFromEkey(string $ekey): QmcCipherInterface
    {
        $rawKey = self::extractRawKeyFromEkey($ekey);
        $key = self::deriveQmcKey($rawKey);
        return QmcCipherFactory::create($key);
    }
}

// ============================================================
// QMC cipher interface
// ============================================================
interface QmcCipherInterface
{
    /**
     * Decrypt data
     * @param string $data Encrypted data
     * @param int $offset Offset of the data within the file
     * @return string Decrypted data
     */
    public function decrypt(string $data, int $offset): string;
}

// ============================================================
// MapCipher - Map cipher (key <= 300 bytes)
// ============================================================
class MapCipher implements QmcCipherInterface
{
    private array $key;
    private int $size;

    public function __construct(string $key)
    {
        $keyLen = strlen($key);
        if ($keyLen === 0) {
            throw new RuntimeException('Map cipher key cannot be empty');
        }
        $this->key = array_values(unpack('C*', $key));
        $this->size = $keyLen;
    }

    /**
     * Bit rotation
     */
    private static function rotate(int $value, int $bits): int
    {
        $rotate = ($bits + 4) % 8;
        return (($value << $rotate) | ($value >> $rotate)) & 0xFF;
    }

    /**
     * Get the mask for the given offset
     */
    private function getMask(int $offset): int
    {
        $normalizedOffset = $offset > 0x7FFF ? ($offset % 0x7FFF) : $offset;
        $index = (($normalizedOffset * $normalizedOffset) + 71214) % $this->size;
        return self::rotate($this->key[$index], $index & 0x7);
    }

    public function decrypt(string $data, int $offset): string
    {
        $len = strlen($data);
        if ($len === 0) {
            return $data;
        }
        // Build a keystream string, then batch XOR using PHP's native ^ operator (C-level speed)
        $keystream = str_repeat("\0", $len);
        for ($i = 0; $i < $len; $i++) {
            $keystream[$i] = chr($this->getMask($offset + $i));
        }
        return $data ^ $keystream;
    }
}

// ============================================================
// Rc4Cipher - RC4 cipher (key > 300 bytes)
// ============================================================
class Rc4Cipher implements QmcCipherInterface
{
    private const RC4_FIRST_SEGMENT_SIZE = 128;
    private const RC4_SEGMENT_SIZE = 5120;

    private array $key;
    private int $size;
    private array $boxState;
    private int $hash;
    private ?string $firstSegmentKeystream = null;
    private array $segmentSkipCache = [];

    public function __construct(string $key)
    {
        $keyLen = strlen($key);
        if ($keyLen === 0) {
            throw new RuntimeException('RC4 cipher key cannot be empty');
        }

        $this->key = array_values(unpack('C*', $key));
        $this->size = $keyLen;

        // Initialize box state
        $this->boxState = [];
        for ($i = 0; $i < $keyLen; $i++) {
            $this->boxState[$i] = $i & 0xFF;
        }

        // KSA (Key-Scheduling Algorithm)
        $j = 0;
        for ($i = 0; $i < $keyLen; $i++) {
            $j = ($j + $this->boxState[$i] + $this->key[$i]) % $keyLen;
            $temp = $this->boxState[$i];
            $this->boxState[$i] = $this->boxState[$j];
            $this->boxState[$j] = $temp;
        }

        $this->hash = self::getHashBase($this->key);
    }

    /**
     * Compute hash base
     */
    private static function getHashBase(array $key): int
    {
        $result = 1;
        $len = count($key);
        for ($i = 0; $i < $len; $i++) {
            $value = $key[$i];
            if ($value === 0) {
                continue;
            }
            $nextHash = ($result * $value) & 0xFFFFFFFF;
            if ($nextHash === 0 || $nextHash <= $result) {
                break;
            }
            $result = $nextHash;
        }
        return $result;
    }

    /**
     * Get segment skip value (cached)
     */
    private function getSegmentSkip(int $segmentId): int
    {
        if (isset($this->segmentSkipCache[$segmentId])) {
            return $this->segmentSkipCache[$segmentId];
        }
        $seed = $this->key[$segmentId % $this->size];
        if ($seed === 0) {
            $result = 0;
        } else {
            $index = (int)(($this->hash / (($segmentId + 1) * $seed)) * 100.0);
            $result = $index % $this->size;
        }
        $this->segmentSkipCache[$segmentId] = $result;
        return $result;
    }

    /**
     * Decrypt the first segment (first 128 bytes) - uses precomputed keystream + string XOR
     */
    private function decryptFirstSegment(string &$data, int $fileOffset, int $dataOffset, int $length): void
    {
        // Precompute the full keystream for the first segment (only needs to be computed once, 128 bytes)
        if ($this->firstSegmentKeystream === null) {
            $ks = str_repeat("\0", self::RC4_FIRST_SEGMENT_SIZE);
            for ($i = 0; $i < self::RC4_FIRST_SEGMENT_SIZE; $i++) {
                $skip = $this->getSegmentSkip($i);
                $ks[$i] = chr($this->key[$skip]);
            }
            $this->firstSegmentKeystream = $ks;
        }

        // Take the corresponding offset from the precomputed keystream and batch-decrypt using string XOR
        $keystream = substr($this->firstSegmentKeystream, $fileOffset, $length);
        $decrypted = substr($data, $dataOffset, $length) ^ $keystream;
        $data = substr_replace($data, $decrypted, $dataOffset, $length);
    }

    /**
     * Decrypt subsequent segments - build a keystream string + batch XOR
     */
    private function decryptSegmentRange(string &$data, int $fileOffset, int $dataOffset, int $length): void
    {
        // Clone the box state
        $boxState = $this->boxState;
        $j = 0;
        $k = 0;
        $size = $this->size;
        $segmentId = intdiv($fileOffset, self::RC4_SEGMENT_SIZE);
        $skipLength = ($fileOffset % self::RC4_SEGMENT_SIZE) + $this->getSegmentSkip($segmentId);

        // Build the keystream string (RC4 stream only writes to keystream, no byte-by-byte XOR of data)
        $keystream = str_repeat("\0", $length);
        $totalLen = $skipLength + $length;

        for ($index = 0; $index < $totalLen; $index++) {
            $j = ($j + 1) % $size;
            $k = ($boxState[$j] + $k) % $size;

            // Swap
            $temp = $boxState[$j];
            $boxState[$j] = $boxState[$k];
            $boxState[$k] = $temp;

            if ($index >= $skipLength) {
                $xorIndex = ($boxState[$j] + $boxState[$k]) % $size;
                $keystream[$index - $skipLength] = chr($boxState[$xorIndex]);
            }
        }

        // Batch XOR using PHP's native ^ operator (C-level speed)
        $decrypted = substr($data, $dataOffset, $length) ^ $keystream;
        $data = substr_replace($data, $decrypted, $dataOffset, $length);
    }

    public function decrypt(string $data, int $offset): string
    {
        $len = strlen($data);
        if ($len === 0) {
            return $data;
        }

        $result = $data;
        $toProcess = $len;
        $processed = 0;

        // First segment: first 128 bytes
        if ($offset < self::RC4_FIRST_SEGMENT_SIZE) {
            $blockSize = min($toProcess, self::RC4_FIRST_SEGMENT_SIZE - $offset);
            $this->decryptFirstSegment($result, $offset, $processed, $blockSize);
            $offset += $blockSize;
            $toProcess -= $blockSize;
            $processed += $blockSize;
            if ($toProcess === 0) {
                return $result;
            }
        }

        // Unaligned segment
        if ($offset % self::RC4_SEGMENT_SIZE !== 0) {
            $blockSize = min($toProcess, self::RC4_SEGMENT_SIZE - ($offset % self::RC4_SEGMENT_SIZE));
            $this->decryptSegmentRange($result, $offset, $processed, $blockSize);
            $offset += $blockSize;
            $toProcess -= $blockSize;
            $processed += $blockSize;
            if ($toProcess === 0) {
                return $result;
            }
        }

        // Full segments
        while ($toProcess > self::RC4_SEGMENT_SIZE) {
            $this->decryptSegmentRange($result, $offset, $processed, self::RC4_SEGMENT_SIZE);
            $offset += self::RC4_SEGMENT_SIZE;
            $toProcess -= self::RC4_SEGMENT_SIZE;
            $processed += self::RC4_SEGMENT_SIZE;
        }

        // Remaining part
        if ($toProcess > 0) {
            $this->decryptSegmentRange($result, $offset, $processed, $toProcess);
        }

        return $result;
    }
}

// ============================================================
// QmcCipherFactory - cipher factory
// ============================================================
class QmcCipherFactory
{
    public static function create(string $key): QmcCipherInterface
    {
        $len = strlen($key);
        if ($len > 300) {
            return new Rc4Cipher($key);
        }
        if ($len > 0) {
            return new MapCipher($key);
        }
        throw new RuntimeException('QMC key cannot be empty');
    }
}

// ============================================================
// MflacRelayServer - MFLAC relay decrypt server (download cache mode)
// ============================================================
class MflacRelayServer
{
    private string $tempDir;
    private string $logFile;
    private bool $enableLog;
    private int $cacheTime;
    private int $downloadTimeout;
    private int $connectTimeout;
    private int $maxCacheSize;
    private int $maxCacheFiles;
    private int $maxLogSize;
    private string $audioFormat = 'flac';
    private string $contentType = 'audio/flac';
    private string $cacheExt = '.flac';

    public function __construct()
    {
        $this->tempDir = RELAY_CACHE_DIR;
        if (!is_dir($this->tempDir)) {
            @mkdir($this->tempDir, 0755, true);
        }
        $this->logFile = RELAY_LOG_FILE;
        $this->enableLog = RELAY_ENABLE_LOG;
        $this->cacheTime = RELAY_CACHE_TIME;
        $this->downloadTimeout = RELAY_DOWNLOAD_TIMEOUT;
        $this->connectTimeout = RELAY_CONNECT_TIMEOUT;
        $this->maxCacheSize = RELAY_MAX_CACHE_SIZE;
        $this->maxCacheFiles = RELAY_MAX_CACHE_FILES;
        $this->maxLogSize = RELAY_MAX_LOG_SIZE;
    }

    /**
     * Write log entry (single-line JSON)
     */
    private function log(string $level, string $message, array $extra = []): void
    {
        if (!$this->enableLog) return;

        $entry = array_merge([
            'time'    => date('Y-m-d H:i:s'),
            'level'   => $level,
            'ip'      => $_SERVER['REMOTE_ADDR'] ?? '-',
            'method'  => $_SERVER['REQUEST_METHOD'] ?? '-',
            'uri'     => $_SERVER['REQUEST_URI'] ?? '-',
            'message' => $message,
        ], $extra);

        $line = json_encode($entry, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";

        // Log rotation: rebuild when exceeding max size
        if (file_exists($this->logFile) && filesize($this->logFile) > $this->maxLogSize) {
            $old = $this->logFile . '.old';
            @rename($this->logFile, $old);
        }

        @file_put_contents($this->logFile, $line, FILE_APPEND | LOCK_EX);
    }

    /**
     * Handle request
     */
    public function handle(): void
    {
        @set_time_limit(0);
        @ini_set('memory_limit', RELAY_MEMORY_LIMIT);
        // Disable output buffering for real-time streaming
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }
        @ini_set('output_buffering', '0');
        @ini_set('zlib.output_compression', '0');
        // Handle client disconnection ourselves
        @ignore_user_abort(true);

        // CORS headers for browser-based players
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, HEAD, OPTIONS');
        header('Access-Control-Allow-Headers: Range, Content-Type');
        header('Access-Control-Expose-Headers: Content-Length, Content-Range, Accept-Ranges, X-Duration, X-Sample-Rate, X-Channels, X-Bits-Per-Sample');
        header('X-Powered-By: KuwoRelay/' . RELAY_VERSION);

        // Handle CORS preflight
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        if ($method === 'OPTIONS') {
            http_response_code(204);
            return;
        }

        $url = $_GET['url'] ?? null;
        $ekey = $_GET['ekey'] ?? null;

        if (!$url || !$ekey) {
            $this->showHelpPage();
            return;
        }

        // Security: validate URL scheme (only allow http/https)
        $urlScheme = parse_url($url, PHP_URL_SCHEME);
        if (!in_array(strtolower($urlScheme ?? ''), ['http', 'https'], true)) {
            http_response_code(400);
            header('Content-Type: text/plain; charset=utf-8');
            echo 'Invalid URL scheme. Only http and https are allowed.';
            return;
        }

        // Security: SSRF protection — block internal/reserved IP ranges
        $urlHost = parse_url($url, PHP_URL_HOST);
        if ($urlHost && !$this->isSafeRemoteHost($urlHost)) {
            http_response_code(403);
            header('Content-Type: text/plain; charset=utf-8');
            echo 'Access denied: target host resolves to a private or reserved address.';
            return;
        }

        // Security: validate ekey (base64-encoded, typically 100-2000 chars)
        $ekeyLen = strlen($ekey);
        if ($ekeyLen < 50 || $ekeyLen > 4096) {
            http_response_code(400);
            header('Content-Type: text/plain; charset=utf-8');
            echo 'Invalid ekey length.';
            return;
        }

        $startTime = microtime(true);
        $rangeHeader = $_SERVER['HTTP_RANGE'] ?? '';
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $ekeyPrefix = substr($ekey, 0, 16);
        $this->log('INFO', 'Request started', [
            'method'     => $method,
            'ekey_prefix' => $ekeyPrefix,
            'range'       => $rangeHeader ?: null,
            'ua'          => $_SERVER['HTTP_USER_AGENT'] ?? null,
        ]);

        try {
            // Detect audio format (.mflac→flac, .mgg→ogg, .mmp3→mp3)
            $this->detectAudioFormat($url);

            // Generate cache key: extract a stable identifier from the URL (trackmedia filename)
            // Kuwo's signed URLs change every time, but the trackmedia/{id}.mflac part is fixed
            $urlPath = parse_url($url, PHP_URL_PATH) ?: '';
            $stableId = basename($urlPath); // e.g. Q0M0003Tljhm2QZ3lq...mflac
            if (empty($stableId)) {
                $stableId = md5($url); // fallback
            }
            $cacheKey = hash('sha256', $stableId . '|' . $ekey);
            $cacheFile = $this->tempDir . '/' . $cacheKey . $this->cacheExt;
            $doneFile = $this->tempDir . '/' . $cacheKey . '.done';

            // HEAD request: return file size and metadata, without downloading the body
            if ($method === 'HEAD') {
                if ($this->isCacheValid($cacheFile, $doneFile)) {
                    clearstatcache(true, $cacheFile);
                    $fileSize = filesize($cacheFile);
                    http_response_code(200);
                    header('Content-Type: ' . $this->contentType);
                    header('Content-Length: ' . $fileSize);
                    header('Accept-Ranges: bytes');
                    // FLAC metadata headers are only sent for FLAC format
                    if ($this->audioFormat === 'flac') {
                        $flacInfo = $this->getFlacInfoFromCache($cacheFile);
                        $this->sendFlacHeaders($flacInfo);
                        $this->log('INFO', 'HEAD cache hit', [
                            'size' => $fileSize,
                            'duration' => $flacInfo['duration'] ?? null,
                        ]);
                    } else {
                        $this->log('INFO', 'HEAD cache hit', [
                            'size' => $fileSize,
                            'format' => $this->audioFormat,
                        ]);
                    }
                } else {
                    // Cache does not exist, probe file size from CDN
                    $remoteSize = $this->getRemoteFileSize($url);
                    if ($remoteSize > 0) {
                        @file_put_contents($cacheFile . '.size', (string)$remoteSize);
                    }
                    $this->log('INFO', 'HEAD request (no cache)', [
                        'remote_size' => $remoteSize,
                        'format' => $this->audioFormat,
                    ]);
                    http_response_code(200);
                    header('Content-Type: ' . $this->contentType);
                    header('Accept-Ranges: bytes');
                    if ($remoteSize > 0) {
                        header('Content-Length: ' . $remoteSize);
                    }
                }
                $this->log('INFO', 'Request completed', [
                    'source' => 'head',
                    'ms'     => round((microtime(true) - $startTime) * 1000, 1),
                ]);
                return;
            }

            // Check if cache is valid (done file exists = complete cache)
            if ($this->isCacheValid($cacheFile, $doneFile)) {
                $this->log('INFO', 'Cache hit', ['file' => basename($cacheFile)]);
                $this->serveFile($cacheFile);
                $this->log('INFO', 'Request completed', [
                    'source' => 'cache',
                    'ms'     => round((microtime(true) - $startTime) * 1000, 1),
                ]);
                return;
            }

            // Range request + incomplete cache: forward the Range to CDN, only download the requested byte range
            // No lock needed, no cache write — fast response for player seeking
            $rangeStart = null;
            $rangeEnd = null;
            if ($rangeHeader && preg_match('/bytes=(\d+)-(\d*)/', $rangeHeader, $matches)) {
                $rangeStart = (int)$matches[1];
                $rangeEnd = ($matches[2] !== '') ? (int)$matches[2] : null;
            }
            if ($rangeStart !== null) {
                $this->log('INFO', 'Range request (cache incomplete), forwarding to CDN', ['range' => $rangeHeader]);
                $this->streamRangeFromCDN($url, $ekey, $rangeStart, $rangeEnd, $cacheFile);
                $this->log('INFO', 'Request completed', [
                    'source' => 'range_cdn',
                    'ms'     => round((microtime(true) - $startTime) * 1000, 1),
                ]);
                return;
            }

            // Concurrency lock: prevent the same track from being downloaded multiple times
            $lockFile = $this->tempDir . '/' . $cacheKey . '.lock';
            $lockFp = @fopen($lockFile, 'w');
            if ($lockFp && flock($lockFp, LOCK_EX | LOCK_NB)) {
                // Lock acquired, double-check cache
                clearstatcache(true, $cacheFile);
                clearstatcache(true, $doneFile);
                if ($this->isCacheValid($cacheFile, $doneFile)) {
                    $this->log('INFO', 'Cache hit (double-check inside lock)');
                    flock($lockFp, LOCK_UN);
                    fclose($lockFp);
                    @unlink($lockFile);
                    $this->serveFile($cacheFile);
                    $this->log('INFO', 'Request completed', [
                        'source' => 'cache',
                        'ms'     => round((microtime(true) - $startTime) * 1000, 1),
                    ]);
                    return;
                }

                // Streaming download decrypt: download, decrypt, and output to the player simultaneously + write to cache
                // Check if partial cache exists for resume from partial cache
                $resumeOffset = 0;
                if (file_exists($cacheFile) && !file_exists($doneFile)) {
                    clearstatcache(true, $cacheFile);
                    $partialSize = filesize($cacheFile);
                    if ($partialSize > 0) {
                        $resumeOffset = $partialSize;
                        $this->log('INFO', 'Partial cache found, resuming', ['resume_offset' => $resumeOffset]);
                    }
                }
                if ($resumeOffset === 0) {
                    $this->log('INFO', 'Cache miss, starting streaming download and decryption');
                }
                $dlStart = microtime(true);
                $this->streamDownloadAndDecrypt($url, $ekey, $cacheFile, $doneFile, $resumeOffset);
                $dlTime = round((microtime(true) - $dlStart) * 1000, 1);
                clearstatcache(true, $cacheFile);
                $fileSize = filesize($cacheFile) ?: 0;
                $this->log('INFO', 'Streaming completed', [
                    'ms'   => $dlTime,
                    'size' => $fileSize,
                    'mb'   => round($fileSize / 1048576, 2),
                ]);

                // Release lock
                flock($lockFp, LOCK_UN);
                fclose($lockFp);
                @unlink($lockFile);

                $this->log('INFO', 'Request completed', [
                    'source' => 'stream',
                    'ms'     => round((microtime(true) - $startTime) * 1000, 1),
                ]);
                $this->cleanupCache();

            } else {
                // Lock not acquired, wait for another process to finish downloading then serve from cache
                if ($lockFp) fclose($lockFp);
                $this->log('INFO', 'Another process is downloading, waiting for cache to be ready...');
                $waitStart = microtime(true);
                $maxWait = 300;
                $pollInterval = 500000; // 0.5 seconds

                while ((microtime(true) - $waitStart) < $maxWait) {
                    usleep($pollInterval);
                    clearstatcache(true, $cacheFile);
                    clearstatcache(true, $doneFile);
                    if ($this->isCacheValid($cacheFile, $doneFile)) {
                        $waitMs = round((microtime(true) - $waitStart) * 1000, 1);
                        $this->log('INFO', 'Wait finished, cache ready', ['wait_ms' => $waitMs]);
                        $this->serveFile($cacheFile);
                        $this->log('INFO', 'Request completed', [
                            'source' => 'wait',
                            'ms'     => round((microtime(true) - $startTime) * 1000, 1),
                        ]);
                        return;
                    }
                    // Lock gone but cache invalid, means the previous process failed, retry ourselves
                    if (!file_exists($lockFile)) {
                        $lockFp = @fopen($lockFile, 'w');
                        if ($lockFp && flock($lockFp, LOCK_EX | LOCK_NB)) {
                            $this->log('WARN', 'Previous process failed, retrying download ourselves');
                            $retryResume = 0;
                            if (file_exists($cacheFile) && !file_exists($doneFile)) {
                                clearstatcache(true, $cacheFile);
                                $retryResume = filesize($cacheFile) ?: 0;
                                if ($retryResume > 0) {
                                    $this->log('INFO', 'Resume from partial cache (retry)', ['resume_offset' => $retryResume]);
                                }
                            }
                            $this->streamDownloadAndDecrypt($url, $ekey, $cacheFile, $doneFile, $retryResume);
                            $dlTime = round((microtime(true) - $waitStart) * 1000, 1);
                            clearstatcache(true, $cacheFile);
                            $fileSize = filesize($cacheFile) ?: 0;
                            $this->log('INFO', 'Streaming completed', ['ms' => $dlTime, 'size' => $fileSize, 'mb' => round($fileSize / 1048576, 2)]);
                            flock($lockFp, LOCK_UN);
                            fclose($lockFp);
                            @unlink($lockFile);
                            $this->log('INFO', 'Request completed', [
                                'source' => 'stream_retry',
                                'ms'     => round((microtime(true) - $startTime) * 1000, 1),
                            ]);
                            $this->cleanupCache();
                            return;
                        }
                    }
                }
                throw new RuntimeException('Timed out waiting for another process to finish downloading');
            }

        } catch (Throwable $e) {
            $this->log('ERROR', $e->getMessage(), [
                'ms'        => round((microtime(true) - $startTime) * 1000, 1),
                'exception' => get_class($e),
            ]);
            if (!headers_sent()) {
                http_response_code(500);
                header('Content-Type: text/plain; charset=utf-8');
            }
            echo 'Error: ' . $e->getMessage() . "\n";
            if ($e->getPrevious()) {
                echo 'Cause: ' . $e->getPrevious()->getMessage() . "\n";
            }
        }
    }

    /**
     * Detect audio format from URL
     * .mflac/.mflac0 → flac, .mgg → ogg, .mmp3 → mp3
     */
    private function detectAudioFormat(string $url): void
    {
        $urlPath = parse_url($url, PHP_URL_PATH) ?: '';
        $ext = strtolower(pathinfo($urlPath, PATHINFO_EXTENSION));

        switch ($ext) {
            case 'mflac':
            case 'mflac0':
                $this->audioFormat = 'flac';
                $this->contentType = 'audio/flac';
                $this->cacheExt = '.flac';
                break;
            case 'mgg':
            case 'mggl':
                $this->audioFormat = 'ogg';
                $this->contentType = 'audio/ogg';
                $this->cacheExt = '.ogg';
                break;
            case 'mmp3':
                $this->audioFormat = 'mp3';
                $this->contentType = 'audio/mpeg';
                $this->cacheExt = '.mp3';
                break;
            default:
                $this->audioFormat = 'flac';
                $this->contentType = 'audio/flac';
                $this->cacheExt = '.flac';
                break;
        }
    }

    /**
     * Check if a host is safe to connect to (SSRF protection).
     * Blocks private, reserved, loopback, and link-local IP ranges.
     */
    private function isSafeRemoteHost(string $host): bool
    {
        // Allow hostnames (non-IP) — only block if DNS resolves to private IP
        $ip = filter_var($host, FILTER_VALIDATE_IP);
        if ($ip === false) {
            // Hostname: resolve and check
            $resolved = @gethostbynamel($host);
            if (empty($resolved)) {
                return true; // Can't resolve, allow (will fail at connection)
            }
            foreach ($resolved as $addr) {
                if (!$this->isPublicIp($addr)) {
                    return false;
                }
            }
            return true;
        }
        return $this->isPublicIp($ip);
    }

    /**
     * Check if an IP address is public (not private/reserved/loopback/link-local)
     */
    private function isPublicIp(string $ip): bool
    {
        // IPv4 checks
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
        }
        // IPv6: block loopback (::1) and link-local (fe80::/10)
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            if ($ip === '::1') return false;
            if (strpos($ip, 'fe80') === 0 || strpos($ip, 'FE80') === 0) return false;
            if (strpos($ip, 'fc') === 0 || strpos($ip, 'FC') === 0) return false;
            if (strpos($ip, 'fd') === 0 || strpos($ip, 'FD') === 0) return false;
            return true;
        }
        return false;
    }

    /**
     * Check cache validity
     */
    private function isCacheValid(string $cacheFile, string $doneFile): bool
    {
        clearstatcache(true, $cacheFile);
        clearstatcache(true, $doneFile);
        if (!file_exists($cacheFile) || !file_exists($doneFile)) {
            return false;
        }
        if ((time() - filemtime($doneFile)) > $this->cacheTime) {
            return false;
        }
        $size = filesize($cacheFile);
        if ($size === false || $size === 0) {
            return false;
        }
        return true;
    }

    /**
     * Parse metadata (STREAMINFO) from decrypted FLAC data
     * Returns: duration(seconds), sample_rate, channels, bps, total_samples
     */
    private function parseFlacInfo(string $data): ?array
    {
        // FLAC files start with "fLaC"
        if (strlen($data) < 42 || substr($data, 0, 4) !== 'fLaC') {
            return null;
        }

        // The first metadata block should be STREAMINFO (type 0)
        $blockType = ord($data[4]);
        if (($blockType & 0x7f) !== 0) {
            return null; // First block is not STREAMINFO
        }

        // STREAMINFO block length (should be 34)
        // $blockLength = (ord($data[5]) << 16) | (ord($data[6]) << 8) | ord($data[7]);

        // Parse the 8-byte packed field (file offset 18-25)
        $hi = (ord($data[18]) << 24) | (ord($data[19]) << 16) | (ord($data[20]) << 8) | ord($data[21]);
        $lo = (ord($data[22]) << 24) | (ord($data[23]) << 16) | (ord($data[24]) << 8) | ord($data[25]);

        $sampleRate = ($hi >> 12) & 0xFFFFF;
        $channels = (($hi >> 9) & 0x7) + 1;
        $bps = (($hi >> 4) & 0x1F) + 1;
        $totalSamples = (($hi & 0xF) << 32) | $lo;
        $duration = $sampleRate > 0 ? $totalSamples / $sampleRate : 0;

        return [
            'duration'      => round($duration, 3),
            'sample_rate'   => $sampleRate,
            'channels'      => $channels,
            'bps'           => $bps,
            'total_samples' => $totalSamples,
        ];
    }

    /**
     * Read FLAC metadata from cache file
     */
    private function getFlacInfoFromCache(string $cacheFile): ?array
    {
        $fp = @fopen($cacheFile, 'rb');
        if (!$fp) return null;
        $header = fread($fp, 256); // First 256 bytes are enough to parse STREAMINFO
        fclose($fp);
        return $this->parseFlacInfo($header);
    }

    /**
     * Send FLAC metadata response headers
     */
    private function sendFlacHeaders(?array $flacInfo): void
    {
        if (!$flacInfo) return;
        if ($flacInfo['duration'] > 0) {
            header('X-Duration: ' . $flacInfo['duration']);
            header('Content-Duration: ' . $flacInfo['duration']);
        }
        if (!empty($flacInfo['sample_rate'])) {
            header('X-Sample-Rate: ' . $flacInfo['sample_rate']);
        }
        if (!empty($flacInfo['channels'])) {
            header('X-Channels: ' . $flacInfo['channels']);
        }
        if (!empty($flacInfo['bps'])) {
            header('X-Bits-Per-Sample: ' . $flacInfo['bps']);
        }
    }

    /**
     * Get file size from remote URL (HEAD or Range probe)
     */
    private function getRemoteFileSize(string $url): int
    {
        // Try HEAD request first
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_NOBODY => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_HTTPHEADER => [
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            ],
        ]);
        curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $contentLength = curl_getinfo($ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD);
        curl_close($ch);

        if (($httpCode === 200 || $httpCode === 206) && $contentLength > 0) {
            return (int)$contentLength;
        }

        // HEAD failed, try Range bytes=0-0
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RANGE => '0-0',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_HEADER => true,
            CURLOPT_NOBODY => false,
            CURLOPT_HTTPHEADER => [
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            ],
        ]);
        $response = curl_exec($ch);
        curl_close($ch);

        // Parse Content-Range: bytes 0-0/12345
        if (preg_match('/Content-Range:\s*bytes\s+\d+-\d+\/(\d+)/i', $response, $m)) {
            return (int)$m[1];
        }

        return 0;
    }

    /**
     * Streaming download decrypt: download, decrypt, and output to the player simultaneously + write cache file
     * First request uses small chunks for fast playback start, then larger chunks for throughput
     * Parse FLAC metadata before outputting the first chunk, send Content-Length and Duration headers
     */
    private function streamDownloadAndDecrypt(string $url, string $ekey, string $cacheFile, string $doneFile, int $resumeOffset = 0): void
    {
        $isResume = ($resumeOffset > 0);

        // Clean up old files (preserved when resuming)
        if (!$isResume) {
            if (file_exists($cacheFile)) @unlink($cacheFile);
            if (file_exists($doneFile)) @unlink($doneFile);
        }

        // Create cipher
        $cipher = QmcKeyDerivation::createCipherFromEkey($ekey);

        // Open cache file for simultaneous writing (append when resuming)
        $cacheFp = fopen($cacheFile, $isResume ? 'ab' : 'wb');
        if (!$cacheFp) {
            throw new RuntimeException('Failed to create cache file: ' . $cacheFile);
        }

        // Disable Apache compression
        if (function_exists('apache_setenv')) {
            @apache_setenv('no-gzip', '1');
        }

        // Streaming state
        $offset = $resumeOffset;        // Decrypt offset (start from cached position when resuming)
        $buffer = '';                   // Encrypted data buffer
        $firstChunkSize = 65536;        // First chunk 64KB — fast playback start
        $normalChunkSize = 262144;      // Subsequent 256KB — high throughput
        $totalDownloaded = 0;
        $totalDecrypted = 0;
        $headersSent = false;           // Whether HTTP headers have been sent
        $remoteFileSize = 0;            // File size obtained from CDN response headers
        $lastFlushTime = microtime(true); // Last flush time
        $clientDisconnected = false;     // Whether client has disconnected

        // Resume: load total size from .size file
        if ($isResume) {
            $sizeFile = $cacheFile . '.size';
            if (file_exists($sizeFile)) {
                $remoteFileSize = (int)file_get_contents($sizeFile);
            }
        }

        // cURL header callback: capture total file size (prefer Content-Range, then Content-Length)
        $headerCallback = function ($ch, $header) use (&$remoteFileSize, $cacheFile) {
            // Content-Range: bytes X-Y/Z → Z is the total size (always correct in Range responses)
            if (preg_match('/Content-Range:\s*bytes\s+\d+-\d+\/(\d+)/i', $header, $m)) {
                $remoteFileSize = (int)$m[1];
                @file_put_contents($cacheFile . '.size', (string)$remoteFileSize);
                return strlen($header);
            }
            // Content-Length (in non-Range responses = total size)
            if ($remoteFileSize === 0 && preg_match('/Content-Length:\s*(\d+)/i', $header, $m)) {
                $remoteFileSize = (int)$m[1];
                @file_put_contents($cacheFile . '.size', (string)$remoteFileSize);
            }
            return strlen($header);
        };

        // Force flush output to client
        $forceFlush = function () use (&$lastFlushTime) {
            // Flush all levels of output buffering
            while (ob_get_level() > 0) {
                @ob_end_flush();
            }
            @flush();
            $lastFlushTime = microtime(true);
        };

        // Check if client is still connected
        $checkConnection = function () use (&$clientDisconnected) {
            if (connection_status() !== CONNECTION_NORMAL) {
                $clientDisconnected = true;
                return false;
            }
            return true;
        };

        // Resume: send HTTP headers first + output cached data, then continue downloading the rest
        if ($isResume) {
            // Send HTTP headers (using total size from .size file)
            http_response_code(200);
            header('Content-Type: ' . $this->contentType);
            header('Accept-Ranges: bytes');
            header('Cache-Control: public, max-age=3600');
            header('X-Accel-Buffering: no');
            if ($remoteFileSize > 0) {
                header('Content-Length: ' . $remoteFileSize);
            }
            // FLAC metadata headers are only sent for FLAC format
            if ($this->audioFormat === 'flac') {
                $flacInfo = $this->getFlacInfoFromCache($cacheFile);
                $this->sendFlacHeaders($flacInfo);
            }
            $headersSent = true;

            $this->log('INFO', 'Resume: sending headers + outputting cached data', [
                'resume_offset' => $resumeOffset,
                'total_size'    => $remoteFileSize,
            ]);

            // Output cached data
            $readFp = fopen($cacheFile, 'rb');
            if ($readFp) {
                $readChunkSize = 1048576; // 1MB
                $remaining = $resumeOffset;
                while ($remaining > 0 && !feof($readFp)) {
                    $read = min($readChunkSize, $remaining);
                    $data = fread($readFp, $read);
                    if ($data === false) break;
                    if (!$checkConnection()) {
                        fclose($readFp);
                        fflush($cacheFp);
                        fclose($cacheFp);
                        $this->log('WARN', 'Client disconnected while outputting cached data during resume', [
                            'output_bytes' => $resumeOffset - $remaining,
                        ]);
                        return;
                    }
                    echo $data;
                    $forceFlush();
                    $remaining -= strlen($data);
                }
                fclose($readFp);
            }

            $this->log('INFO', 'Cached data output, continuing to download remaining part', ['cached_bytes' => $resumeOffset]);
        }

        // Decrypt and output a chunk
        $processChunk = function (string $chunk) use (
            $cipher, $cacheFp, &$offset, &$totalDecrypted,
            &$headersSent, &$remoteFileSize, &$clientDisconnected,
            $forceFlush, $checkConnection
        ) {
            $decrypted = $cipher->decrypt($chunk, $offset);
            $offset += strlen($chunk);

            // First chunk: parse metadata first, send full HTTP headers, then output
            if (!$headersSent) {
                http_response_code(200);
                header('Content-Type: ' . $this->contentType);
                header('Accept-Ranges: bytes');
                header('Cache-Control: public, max-age=3600');
                header('X-Accel-Buffering: no');

                // RC4/Map is stream encryption, ciphertext size = plaintext size
                if ($remoteFileSize > 0) {
                    header('Content-Length: ' . $remoteFileSize);
                }

                // FLAC metadata headers are only parsed and sent for FLAC format
                $logMeta = [];
                if ($this->audioFormat === 'flac') {
                    $flacInfo = $this->parseFlacInfo($decrypted);
                    $this->sendFlacHeaders($flacInfo);
                    $logMeta = [
                        'duration'    => $flacInfo['duration'] ?? null,
                        'sample_rate' => $flacInfo['sample_rate'] ?? null,
                        'channels'    => $flacInfo['channels'] ?? null,
                        'bps'         => $flacInfo['bps'] ?? null,
                    ];
                }

                $headersSent = true;

                $this->log('INFO', 'Streaming headers sent', array_merge([
                    'content_length' => $remoteFileSize,
                    'format'         => $this->audioFormat,
                ], $logMeta));
            }

            // Check if client is still connected
            if (!$checkConnection()) {
                return;
            }

            // Output to player
            echo $decrypted;
            $forceFlush();

            // Write to cache file
            fwrite($cacheFp, $decrypted);
            $totalDecrypted += strlen($decrypted);
        };

        // cURL write callback
        $self = $this;
        $writeCallback = function ($ch, $data) use (
            &$buffer, &$totalDownloaded, &$processChunk,
            &$clientDisconnected, $firstChunkSize, $normalChunkSize,
            $checkConnection, $self
        ) {
            // Client disconnected, stop processing (returning 0 will abort cURL)
            if ($clientDisconnected) {
                return 0;
            }

            $len = strlen($data);
            $totalDownloaded += $len;
            $buffer .= $data;

            // First chunk uses small threshold for fast playback start, then larger threshold for throughput
            $threshold = ($totalDownloaded <= $firstChunkSize * 2) ? $firstChunkSize : $normalChunkSize;

            // Decrypt and output when buffer reaches threshold
            while (strlen($buffer) >= $threshold && !$clientDisconnected) {
                $chunk = substr($buffer, 0, $threshold);
                $buffer = substr($buffer, $threshold);
                $processChunk($chunk);
                // After first chunk output, switch to normal chunk size
                $threshold = $normalChunkSize;
            }

            // Periodically check connection status
            if (!$checkConnection()) {
                return 0;
            }

            return $len;
        };

        $ch = curl_init($url);
        $curlOptions = [
            CURLOPT_WRITEFUNCTION => $writeCallback,
            CURLOPT_HEADERFUNCTION => $headerCallback,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => $this->downloadTimeout,
            CURLOPT_CONNECTTIMEOUT => $this->connectTimeout,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_TCP_NODELAY => true,
            CURLOPT_BUFFERSIZE => 524288,
            // Low-speed detection: abort if download speed is below 1KB/s for 30 consecutive seconds
            CURLOPT_LOW_SPEED_LIMIT => 1024,
            CURLOPT_LOW_SPEED_TIME => 30,
            CURLOPT_HTTPHEADER => [
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept: */*',
                'Connection: keep-alive',
            ],
        ];
        // Resume: start downloading from the cached position
        if ($isResume) {
            $curlOptions[CURLOPT_RANGE] = "{$resumeOffset}-";
        }
        curl_setopt_array($ch, $curlOptions);

        $success = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $dlSize = curl_getinfo($ch, CURLINFO_SIZE_DOWNLOAD);
        $error = curl_error($ch);
        curl_close($ch);

        // If headers haven't been sent yet (file too small, less than first chunk size), send them here
        if (!$headersSent && strlen($buffer) > 0) {
            $processChunk($buffer);
            $buffer = '';
        } elseif (strlen($buffer) > 0 && !$clientDisconnected) {
            // Output remaining data in buffer
            $decrypted = $cipher->decrypt($buffer, $offset);
            if ($checkConnection()) {
                echo $decrypted;
                $forceFlush();
            }
            fwrite($cacheFp, $decrypted);
            $totalDecrypted += strlen($decrypted);
            $buffer = '';
        }

        fflush($cacheFp);
        fclose($cacheFp);

        // Client disconnected: keep partial cache, don't report error (next request can resume from partial cache)
        if ($clientDisconnected) {
            $outputBytes = $resumeOffset + $totalDecrypted;
            $this->log('WARN', 'Client disconnected, keeping partial cache', [
                'dl_bytes'      => $totalDownloaded,
                'dec_bytes'     => $totalDecrypted,
                'output_bytes'  => $outputBytes,
                'output_mb'     => round($outputBytes / 1048576, 2),
                'cache_size'    => $outputBytes,
                'expected_size' => $remoteFileSize,
                'expected_mb'   => round($remoteFileSize / 1048576, 2),
                'complete_pct'  => $remoteFileSize > 0 ? round($outputBytes / $remoteFileSize * 100, 1) : 0,
            ]);
            // Save total size (for subsequent Range requests)
            if ($remoteFileSize > 0) {
                @file_put_contents($cacheFile . '.size', (string)$remoteFileSize);
            }
            return; // Don't write doneFile, keep partial cache
        }

        $outputBytes = $resumeOffset + $totalDecrypted;
        $this->log('INFO', 'Download completed', [
            'http_code'     => $httpCode,
            'dl_bytes'      => (int)$dlSize,
            'dl_mb'         => round($dlSize / 1048576, 2),
            'dec_bytes'     => $totalDecrypted,
            'dec_mb'        => round($totalDecrypted / 1048576, 2),
            'output_bytes'  => $outputBytes,
            'output_mb'     => round($outputBytes / 1048576, 2),
            'expected_size' => $remoteFileSize,
            'expected_mb'   => round($remoteFileSize / 1048576, 2),
            'complete_pct'  => $remoteFileSize > 0 ? round($outputBytes / $remoteFileSize * 100, 1) : 0,
        ]);

        // Save total size
        if ($remoteFileSize > 0) {
            @file_put_contents($cacheFile . '.size', (string)$remoteFileSize);
        }

        if (!$success || ($httpCode !== 200 && $httpCode !== 206) || $totalDownloaded === 0) {
            // Data already sent to player: don't delete cache, just log the error
            if ($headersSent) {
                $this->log('ERROR', "Download interrupted (partial data already sent) HTTP {$httpCode}: {$error}");
                if (!$isResume) {
                    @unlink($cacheFile);
                }
                return;
            }
            // No data sent yet: safe to delete and report error
            if (!$isResume) {
                @unlink($cacheFile);
            }
            throw new RuntimeException("Download failed (HTTP {$httpCode}, {$totalDownloaded} bytes): {$error}");
        }

        // Verify cache file
        clearstatcache(true, $cacheFile);
        if (!file_exists($cacheFile)) {
            throw new RuntimeException('Cache file not created: ' . $cacheFile);
        }
        $finalSize = filesize($cacheFile);
        if ($finalSize === false || $finalSize === 0) {
            if (!$isResume) {
                @unlink($cacheFile);
            }
            throw new RuntimeException("Decrypted file is empty (output {$totalDecrypted} bytes)");
        }

        // Verify: check if actual size matches expected size
        if ($remoteFileSize > 0 && $finalSize !== $remoteFileSize) {
            $this->log('WARN', 'File size mismatch!', [
                'actual_size'   => $finalSize,
                'actual_mb'     => round($finalSize / 1048576, 2),
                'expected_size' => $remoteFileSize,
                'expected_mb'   => round($remoteFileSize / 1048576, 2),
                'diff_mb'       => round(($remoteFileSize - $finalSize) / 1048576, 2),
            ]);
        }

        // Mark as complete
        file_put_contents($doneFile, (string)time());
    }

    /**
     * Forward Range request to CDN: only download the requested byte range, decrypt and return to the player
     * No cache write, no lock needed — fast response for player seeking
     */
    private function streamRangeFromCDN(string $url, string $ekey, int $rangeStart, ?int $rangeEnd, string $cacheFile): void
    {
        // Get total file size (prefer .size file, then CDN)
        $totalSize = 0;
        $sizeFile = $cacheFile . '.size';
        if (file_exists($sizeFile)) {
            $totalSize = (int)file_get_contents($sizeFile);
        }
        if ($totalSize === 0) {
            $totalSize = $this->getRemoteFileSize($url);
            if ($totalSize > 0) {
                @file_put_contents($sizeFile, (string)$totalSize);
            }
        }

        if ($rangeEnd === null || ($totalSize > 0 && $rangeEnd >= $totalSize)) {
            $rangeEnd = $totalSize > 0 ? ($totalSize - 1) : null;
        }

        $length = $rangeEnd !== null ? ($rangeEnd - $rangeStart + 1) : 0;

        // Create cipher
        $cipher = QmcKeyDerivation::createCipherFromEkey($ekey);

        // Disable Apache compression
        if (function_exists('apache_setenv')) {
            @apache_setenv('no-gzip', '1');
        }

        // Streaming state
        $offset = $rangeStart;
        $buffer = '';
        $chunkSize = 262144; // 256KB
        $totalDownloaded = 0;
        $totalDecrypted = 0;
        $headersSent = false;
        $cdnHttpCode = 0;
        $clientDisconnected = false;

        // cURL header callback: capture total size (Content-Range: bytes X-Y/Z)
        $headerCallback = function ($ch, $header) use (&$totalSize, $sizeFile) {
            if (preg_match('/Content-Range:\s*bytes\s+\d+-\d+\/(\d+)/i', $header, $m)) {
                $totalSize = (int)$m[1];
                @file_put_contents($sizeFile, (string)$totalSize);
            }
            return strlen($header);
        };

        $forceFlush = function () {
            while (ob_get_level() > 0) {
                @ob_end_flush();
            }
            @flush();
        };

        $checkConnection = function () use (&$clientDisconnected) {
            if (connection_status() !== CONNECTION_NORMAL) {
                $clientDisconnected = true;
                return false;
            }
            return true;
        };

        // Decrypt and output a chunk
        $processChunk = function (string $chunk) use (
            $cipher, &$offset, &$totalDecrypted,
            &$headersSent, $rangeStart, &$totalSize, &$rangeEnd, &$length,
            $forceFlush, $checkConnection
        ) {
            $decrypted = $cipher->decrypt($chunk, $offset);
            $offset += strlen($chunk);

            // First chunk: send HTTP headers (totalSize should already be obtained from CDN response headers)
            if (!$headersSent) {
                if ($rangeEnd === null && $totalSize > 0) {
                    $rangeEnd = $totalSize - 1;
                }
                if ($length === 0 && $rangeEnd !== null) {
                    $length = $rangeEnd - $rangeStart + 1;
                }

                http_response_code(206);
                header('Content-Type: ' . $this->contentType);
                header('Accept-Ranges: bytes');
                if ($totalSize > 0 && $rangeEnd !== null) {
                    header("Content-Range: bytes {$rangeStart}-{$rangeEnd}/{$totalSize}");
                }
                if ($length > 0) {
                    header('Content-Length: ' . $length);
                }
                header('Cache-Control: public, max-age=3600');
                header('X-Accel-Buffering: no');
                $headersSent = true;

                $this->log('INFO', 'Range streaming headers sent', [
                    'range_start' => $rangeStart,
                    'range_end'   => $rangeEnd,
                    'total_size'  => $totalSize,
                    'length'      => $length,
                ]);
            }

            if (!$checkConnection()) {
                return;
            }

            echo $decrypted;
            $forceFlush();
            $totalDecrypted += strlen($decrypted);
        };

        // cURL write callback
        $writeCallback = function ($ch, $data) use (
            &$buffer, &$totalDownloaded, &$processChunk,
            &$clientDisconnected, $chunkSize, $checkConnection
        ) {
            if ($clientDisconnected) {
                return 0;
            }

            $len = strlen($data);
            $totalDownloaded += $len;
            $buffer .= $data;

            while (strlen($buffer) >= $chunkSize && !$clientDisconnected) {
                $chunk = substr($buffer, 0, $chunkSize);
                $buffer = substr($buffer, $chunkSize);
                $processChunk($chunk);
            }

            if (!$checkConnection()) {
                return 0;
            }

            return $len;
        };

        $cdnRange = $rangeEnd !== null ? "{$rangeStart}-{$rangeEnd}" : "{$rangeStart}-";

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_WRITEFUNCTION => $writeCallback,
            CURLOPT_HEADERFUNCTION => $headerCallback,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => $this->downloadTimeout,
            CURLOPT_CONNECTTIMEOUT => $this->connectTimeout,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_TCP_NODELAY => true,
            CURLOPT_BUFFERSIZE => 524288,
            CURLOPT_RANGE => $cdnRange,
            CURLOPT_LOW_SPEED_LIMIT => 1024,
            CURLOPT_LOW_SPEED_TIME => 30,
            CURLOPT_HTTPHEADER => [
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept: */*',
                'Connection: keep-alive',
            ],
        ]);

        $success = curl_exec($ch);
        $cdnHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        // Output remaining data in buffer
        if (strlen($buffer) > 0 && !$clientDisconnected) {
            $processChunk($buffer);
            $buffer = '';
        }

        if ($clientDisconnected) {
            $this->log('WARN', 'Range request: client disconnected', [
                'range'      => $cdnRange,
                'dl_bytes'   => $totalDownloaded,
                'dec_bytes'  => $totalDecrypted,
            ]);
            return;
        }

        $this->log('INFO', 'Range download completed', [
            'range'      => $cdnRange,
            'http_code'  => $cdnHttpCode,
            'dl_bytes'   => $totalDownloaded,
            'dec_bytes'  => $totalDecrypted,
        ]);

        // CDN returned an error (URL expired, etc.)
        if (!$success || ($cdnHttpCode !== 200 && $cdnHttpCode !== 206) || $totalDownloaded === 0) {
            if (!$headersSent) {
                http_response_code(502);
                header('Content-Type: text/plain; charset=utf-8');
                echo "CDN error: HTTP {$cdnHttpCode}";
            }
            $this->log('ERROR', "Range CDN request failed: HTTP {$cdnHttpCode}, {$error}");
        }
    }

    /**
     * Serve file from disk (supports Range requests)
     */
    private function serveFile(string $file): void
    {
        clearstatcache(true, $file);
        $fileSize = filesize($file);
        if ($fileSize === false || $fileSize === 0) {
            http_response_code(500);
            header('Content-Type: text/plain; charset=utf-8');
            echo "Error: file does not exist or size is 0: {$file}";
            return;
        }
        $start = 0;
        $end = $fileSize - 1;

        // Handle Range request
        $rangeHeader = $_SERVER['HTTP_RANGE'] ?? null;
        if ($rangeHeader && preg_match('/bytes=(\d+)-(\d*)/', $rangeHeader, $matches)) {
            $start = (int)$matches[1];
            $end = ($matches[2] !== '') ? (int)$matches[2] : ($fileSize - 1);

            if ($start >= $fileSize) {
                http_response_code(416);
                header("Content-Range: bytes */{$fileSize}");
                return;
            }
            if ($end >= $fileSize) {
                $end = $fileSize - 1;
            }

            http_response_code(206);
            header("Content-Range: bytes {$start}-{$end}/{$fileSize}");
        } else {
            http_response_code(200);
        }

        $length = $end - $start + 1;

        // Set response headers
        $download = $_GET['download'] ?? null;
        if ($download) {
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="audio' . $this->cacheExt . '"');
        } else {
            header('Content-Type: ' . $this->contentType);
        }
        header('Content-Length: ' . $length);
        header('Accept-Ranges: bytes');
        header('Cache-Control: public, max-age=3600');

        // Return FLAC metadata (only parsed for FLAC format when Range starts from 0)
        if ($start === 0 && $this->audioFormat === 'flac') {
            $flacInfo = $this->getFlacInfoFromCache($file);
            $this->sendFlacHeaders($flacInfo);
        }

        // Disable Apache compression
        if (function_exists('apache_setenv')) {
            @apache_setenv('no-gzip', '1');
        }

        // Read and send from the specified offset (with flush and connection checks)
        $fp = fopen($file, 'rb');
        if ($start > 0) {
            fseek($fp, $start);
        }

        $remaining = $length;
        $chunkSize = 1048576; // 1MB
        $lastFlushTime = microtime(true);

        while ($remaining > 0 && !feof($fp)) {
            // Check client connection status
            if (connection_status() !== CONNECTION_NORMAL) {
                fclose($fp);
                return;
            }
            $read = min($chunkSize, $remaining);
            $data = fread($fp, $read);
            if ($data === false) break;
            echo $data;
            $remaining -= strlen($data);

            // Flush output every 2 seconds to ensure streaming
            $now = microtime(true);
            if ($now - $lastFlushTime > 2.0) {
                while (ob_get_level() > 0) {
                    @ob_end_flush();
                }
                @flush();
                $lastFlushTime = $now;
            }
        }

        // Final flush
        while (ob_get_level() > 0) {
            @ob_end_flush();
        }
        @flush();

        fclose($fp);
    }

    /**
     * Clean up expired cache
     */
    private function cleanupCache(): void
    {
        $files = glob($this->tempDir . '/*');
        if (!$files) return;

        $now = time();
        $totalSize = 0;
        $validFiles = [];

        foreach ($files as $file) {
            if (!is_file($file)) continue;
            $age = $now - filemtime($file);
            if ($age > $this->cacheTime) {
                $this->deleteCacheEntry($file);
            } else {
                $totalSize += filesize($file);
                $validFiles[] = $file;
            }
        }

        // If total size exceeds the limit, delete oldest first
        if ($totalSize > $this->maxCacheSize || count($validFiles) > $this->maxCacheFiles * 3) {
            usort($validFiles, function ($a, $b) {
                return filemtime($a) - filemtime($b);
            });
            while (($totalSize > $this->maxCacheSize || count($validFiles) > $this->maxCacheFiles * 3) && count($validFiles) > 0) {
                $oldest = array_shift($validFiles);
                $totalSize -= filesize($oldest);
                $this->deleteCacheEntry($oldest);
            }
        }
    }

    /**
     * Delete a cache file and its associated metadata files (.done, .size, .lock)
     */
    private function deleteCacheEntry(string $file): void
    {
        @unlink($file);
        $base = preg_replace('/\.(flac|ogg|mp3|done|size|lock)$/', '', $file);
        if ($base !== $file) {
            foreach (['.flac', '.ogg', '.mp3', '.done', '.size', '.lock'] as $ext) {
                $assoc = $base . $ext;
                if (file_exists($assoc)) @unlink($assoc);
            }
        }
    }

    /**
     * Show help page
     */
    private function showHelpPage(): void
    {
        header('Content-Type: text/html; charset=utf-8');
        $scriptUrl = ($_SERVER['HTTP_HOST'] ?? 'localhost') . ($_SERVER['SCRIPT_NAME'] ?? '/decrypt.php');
        echo <<<HTML
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>酷我音乐中转解密服务器 / Kuwo Music Relay Decrypt Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'PingFang SC', 'Microsoft YaHei', sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .container { max-width: 640px; width: 100%; }
        .card { background: #1e293b; border-radius: 16px; padding: 40px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); }
        h1 { font-size: 22px; margin-bottom: 4px; color: #38bdf8; }
        .subtitle { color: #94a3b8; margin-bottom: 8px; font-size: 13px; }
        .lang-switch { margin-bottom: 24px; }
        .lang-switch button { display: inline-block; width: auto; padding: 6px 16px; background: #334155; border: none; border-radius: 6px; color: #94a3b8; font-size: 13px; cursor: pointer; margin-right: 8px; transition: all 0.2s; }
        .lang-switch button.active { background: #0ea5e9; color: white; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 6px; font-size: 14px; color: #cbd5e1; }
        input[type="text"], textarea { width: 100%; padding: 12px 16px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #e2e8f0; font-size: 14px; font-family: monospace; }
        input[type="text"]:focus, textarea:focus { outline: none; border-color: #38bdf8; }
        textarea { resize: vertical; min-height: 80px; word-break: break-all; }
        button { width: 100%; padding: 14px; background: #0ea5e9; border: none; border-radius: 8px; color: white; font-size: 16px; font-weight: 600; cursor: pointer; transition: background 0.2s; }
        button:hover { background: #0284c7; }
        .usage { margin-top: 32px; padding-top: 24px; border-top: 1px solid #334155; }
        .usage h2 { font-size: 14px; color: #94a3b8; margin-bottom: 12px; }
        .usage code { display: block; background: #0f172a; padding: 12px 16px; border-radius: 8px; font-size: 13px; color: #4ade80; overflow-x: auto; word-break: break-all; }
        .url-preview { margin-top: 12px; padding: 12px 16px; background: #0f172a; border-radius: 8px; font-size: 13px; color: #94a3b8; word-break: break-all; min-height: 20px; }
        .btn-group { display: flex; gap: 12px; }
        .btn-group button { flex: 1; }
        .btn-download { background: #64748b; }
        .btn-download:hover { background: #475569; }
        .note { margin-top: 16px; padding: 12px 16px; background: #0f172a; border-radius: 8px; font-size: 12px; color: #64748b; line-height: 1.6; }
        .note-en { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="lang-switch">
                <button class="active" onclick="switchLang('zh')">中文</button>
                <button onclick="switchLang('en')">English</button>
            </div>

            <h1 class="t-zh">酷我音乐中转解密服务器</h1>
            <h1 class="t-en" style="display:none;">Kuwo Music Relay Decrypt Server</h1>

            <p class="subtitle t-zh">输入加密文件 URL 和 ekey，生成可播放的解密链接</p>
            <p class="subtitle t-en" style="display:none;">Enter the encrypted file URL and ekey to generate a playable decryption link</p>

            <div class="form-group">
                <label class="t-zh" for="url">加密文件 URL</label>
                <label class="t-en" for="url" style="display:none;">Encrypted File URL</label>
                <textarea id="url" placeholder="http://car-lv.kuwo.cn/..."></textarea>
            </div>
            <div class="form-group">
                <label class="t-zh" for="ekey">加密密钥 (ekey)</label>
                <label class="t-en" for="ekey" style="display:none;">Encryption Key (ekey)</label>
                <textarea id="ekey" placeholder="jWYbp9g9MsV4yL1c..."></textarea>
            </div>
            <div class="btn-group">
                <button class="t-zh" onclick="generate(false)">生成播放链接</button>
                <button class="t-en" style="display:none;" onclick="generate(false)">Generate Play URL</button>
                <button class="btn-download t-zh" onclick="generate(true)">生成下载链接</button>
                <button class="btn-download t-en" style="display:none;" onclick="generate(true)">Generate Download URL</button>
            </div>
            <div class="url-preview" id="preview"></div>
            <div class="note t-zh">
                首次访问使用流式传输：下载开始即播放，无需等待整个文件下载完成。<br>
                解密完成后，文件缓存 1 小时。后续访问（包括拖动进度条）从磁盘瞬时读取。
            </div>
            <div class="note t-en" style="display:none;">
                First access uses streaming: playback starts as soon as download begins, no need to wait for the full file.<br>
                After decryption completes, the file is cached for 1 hour. Subsequent access (including seeking) reads from disk instantly.
            </div>
            <div class="usage">
                <h2 class="t-zh">直接使用</h2>
                <h2 class="t-en" style="display:none;">Direct Usage</h2>
                <code id="usage">http://{$scriptUrl}?url=<file_url>&ekey=<key></code>
            </div>
            <div class="note t-zh" style="margin-top:24px;border:1px solid #475569;border-left:3px solid #f59e0b;">
                <strong style="color:#f59e0b;">免责声明</strong><br>
                本项目仅供个人学习与技术交流使用，不存储、不托管、不分发任何受版权保护的音乐文件。<br>
                使用本工具前请确保已获得版权所有者的授权。使用者需自行承担一切法律责任。<br>
                严禁用于商业用途或传播解密后的内容。
            </div>
            <div class="note t-en" style="display:none;margin-top:24px;border:1px solid #475569;border-left:3px solid #f59e0b;">
                <strong style="color:#f59e0b;">Disclaimer</strong><br>
                For personal study and technical research only. This project does not host, store, or distribute copyrighted audio files.<br>
                Ensure you have proper authorization before using this tool. Users bear all legal responsibilities.<br>
                Commercial use and redistribution of decrypted content are strictly prohibited.
            </div>
        </div>
    </div>
    <script>
        function switchLang(lang) {
            document.querySelectorAll('.lang-switch button').forEach(function(b) { b.classList.remove('active'); });
            event.target.classList.add('active');
            document.querySelectorAll('.t-zh').forEach(function(el) { el.style.display = (lang === 'zh') ? '' : 'none'; });
            document.querySelectorAll('.t-en').forEach(function(el) { el.style.display = (lang === 'en') ? '' : 'none'; });
        }
        function generate(isDownload) {
            const url = encodeURIComponent(document.getElementById('url').value.trim());
            const ekey = encodeURIComponent(document.getElementById('ekey').value.trim());
            const isZh = document.querySelector('.lang-switch button.active').textContent === '中文';
            if (!url || !ekey) {
                document.getElementById('preview').textContent = isZh ? '请填写 URL 和 ekey' : 'Please fill in both URL and ekey';
                return;
            }
            const baseUrl = window.location.origin + window.location.pathname;
            let playUrl = baseUrl + '?url=' + url + '&ekey=' + ekey;
            if (isDownload) playUrl += '&download=1';
            document.getElementById('preview').innerHTML = '<a href="' + playUrl + '" target="_blank" style="color:#38bdf8;text-decoration:none;">' + playUrl + '</a>';
        }
    </script>
</body>
</html>
HTML;
    }
}

// ============================================================
// Entry point
// ============================================================
$server = new MflacRelayServer();
$server->handle();
