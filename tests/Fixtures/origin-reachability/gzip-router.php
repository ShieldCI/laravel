<?php

declare(strict_types=1);

/**
 * Router for `php -S`: answers every request with a gzip-encoded body.
 *
 * The bytes are precomputed so the server process needs no zlib of its own, and the
 * Content-Encoding header is the origin's word that the body is compressed. Whether that
 * word survives to the caller is what the stream-decoding test asserts.
 */
$body = base64_decode('H4sIAAAAAAACE8svykzPzFMoTi0qS01RKMnILFZIyk+pVEivyizQTc1Lzk9JTeECAD9z6+klAAAA', true);

if ($body === false) {
    http_response_code(500);

    return;
}

header('Content-Type: text/plain');
header('Content-Encoding: gzip');
header('Content-Length: '.strlen($body));

echo $body;
