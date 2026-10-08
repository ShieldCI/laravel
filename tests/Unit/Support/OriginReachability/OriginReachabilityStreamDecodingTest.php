<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support\OriginReachability;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ShieldCI\Support\OriginReachability\DeclaredOrigin;
use ShieldCI\Support\OriginReachability\OriginProbeResult;
use ShieldCI\Support\OriginReachability\OriginReachabilityChecker;
use ShieldCI\Support\OriginReachability\ProbeRequest;

/**
 * Probes a real gzip-encoded origin through Guzzle's default handler stack.
 *
 * A MockHandler cannot show what these tests are about: it hands back whatever headers it
 * was given, whatever decode_content says. The decoding happens in Guzzle's StreamHandler,
 * which the default stack routes a `stream => true` request through, and which inflates a
 * gzip body and removes its Content-Encoding header on the way. So the origin here is a
 * `php -S` process on loopback, and the checker is built with no client of its own.
 */
class OriginReachabilityStreamDecodingTest extends TestCase
{
    private const PLAIN_BODY = "origin served this body gzip-encoded\n";

    /** @var resource|null */
    private static $server = null;

    private static string $origin = '';

    public static function setUpBeforeClass(): void
    {
        $port = self::freePort();
        $router = dirname(__DIR__, 3).'/Fixtures/origin-reachability/gzip-router.php';

        $process = proc_open(
            [PHP_BINARY, '-d', 'zlib.output_compression=0', '-S', '127.0.0.1:'.$port, $router],
            [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes,
        );

        if (! is_resource($process)) {
            self::fail('Could not start the php -S origin.');
        }

        self::$server = $process;
        self::$origin = 'http://127.0.0.1:'.$port;

        // Failing rather than skipping is deliberate: a server that never came up must not
        // read as a pass for the behaviour these tests exist to pin.
        $deadline = microtime(true) + 5.0;

        while (microtime(true) < $deadline) {
            $socket = @fsockopen('127.0.0.1', $port, $errno, $error, 0.2);

            if (is_resource($socket)) {
                fclose($socket);

                return;
            }

            usleep(50_000);
        }

        self::fail('The php -S origin did not accept connections within 5 seconds.');
    }

    public static function tearDownAfterClass(): void
    {
        if (is_resource(self::$server)) {
            proc_terminate(self::$server);
            proc_close(self::$server);
        }

        self::$server = null;
    }

    private static function freePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);

        if ($socket === false) {
            self::fail('Could not reserve a loopback port: '.$error);
        }

        $name = stream_socket_get_name($socket, false);
        fclose($socket);

        if ($name === false) {
            self::fail('Could not read the reserved loopback port.');
        }

        return (int) substr($name, (int) strrpos($name, ':') + 1);
    }

    private function probe(?ProbeRequest $request = null): OriginProbeResult
    {
        $checker = new OriginReachabilityChecker;

        $report = $checker->probe(
            [new DeclaredOrigin(self::$origin, [DeclaredOrigin::SOURCE_APP_URL])],
            request: $request,
        );

        $probe = $report->probeFor(self::$origin);
        $this->assertNotNull($probe);
        $this->assertSame(200, $probe->statusCode, 'the origin must have answered for this test to mean anything');

        return $probe;
    }

    /** @test */
    #[Test]
    public function it_keeps_the_content_encoding_of_a_compressed_origin_when_decoding_is_off(): void
    {
        $probe = $this->probe(new ProbeRequest(['Accept-Encoding' => 'gzip'], decodeContent: false));

        $this->assertSame('gzip', $probe->header('content-encoding'));
        $this->assertNotNull($probe->bodyPrefix);
        $this->assertStringStartsWith("\x1f\x8b", $probe->bodyPrefix, 'the body must arrive as the gzip bytes the origin sent');
    }

    /**
     * The control: with decoding at its default, the same origin reads as uncompressed. This
     * is what makes the test above mean something, since it shows the stack in use really does
     * strip the header that test asserts is kept.
     */
    /** @test */
    #[Test]
    public function it_reads_a_compressed_origin_as_uncompressed_when_decoding_is_left_on(): void
    {
        $probe = $this->probe();

        $this->assertNull($probe->header('content-encoding'));
        $this->assertSame(self::PLAIN_BODY, $probe->bodyPrefix);
    }
}
