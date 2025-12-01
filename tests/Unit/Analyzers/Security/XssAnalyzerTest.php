<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Illuminate\Support\Facades\URL;
use ShieldCI\Analyzers\Security\XssAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class XssAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        /** @var \Illuminate\Routing\Router $router */
        $router = $this->app?->make('router');

        if ($router === null) {
            throw new \RuntimeException('Router not available in test application');
        }

        return new XssAnalyzer($router);
    }

    /**
     * Create analyzer with mocked HTTP client for header testing.
     *
     * @param  array<int, (\Psr\Http\Message\ResponseInterface|\Throwable)>  $responses
     */
    protected function createAnalyzerWithHttpMock(array $responses): XssAnalyzer
    {
        $appUrl = config('app.url');
        if ($appUrl && is_string($appUrl)) {
            URL::forceRootUrl($appUrl);
        }

        /** @var \Illuminate\Routing\Router $router */
        $router = $this->app?->make('router');

        if ($router === null) {
            throw new \RuntimeException('Router not available in test application');
        }

        $analyzer = new XssAnalyzer($router);

        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);
        $analyzer->setHttpClient($client);

        return $analyzer;
    }

    public function test_passes_with_escaped_blade_output(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <h1>{{ $title }}</h1>
    <p>{{ $user->name }}</p>
    <div>{{ request('search') }}</div>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['welcome.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_unescaped_blade_output_with_user_input(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <h1>{!! $title !!}</h1>
    <div>{!! request('content') !!}</div>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['page.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Unescaped blade output', $result);
    }

    public function test_does_not_duplicate_blade_issues(): void
    {
        config(['shieldci.ci_mode' => true]);

        $bladeCode = <<<'BLADE'
<div>{!! request('payload') !!}</div>
BLADE;

        $tempDir = $this->createTempDirectory(['dup.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_detects_echo_with_superglobals(): void
    {
        $phpCode = <<<'PHP'
<?php

class ViewController
{
    public function display()
    {
        echo $_GET['message'];
        echo $_POST['content'];
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['ViewController.php' => $phpCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Direct echo of superglobal', $result);
        $this->assertIssueCount(2, $result);
    }

    public function test_detects_echo_with_request_helper(): void
    {
        $phpCode = <<<'PHP'
<?php

class PageController
{
    public function show()
    {
        echo request('title');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['PageController.php' => $phpCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Echo of request data', $result);
    }

    public function test_passes_with_escaped_echo(): void
    {
        $phpCode = <<<'PHP'
<?php

class SafeController
{
    public function display()
    {
        echo htmlspecialchars($_GET['message'], ENT_QUOTES, 'UTF-8');
        echo e(request('title'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['SafeController.php' => $phpCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_response_make_with_user_input(): void
    {
        $phpCode = <<<'PHP'
<?php

class ApiController
{
    public function render()
    {
        return Response::make(request('html'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['ApiController.php' => $phpCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Response::make()', $result);
    }

    public function test_detects_user_data_in_javascript(): void
    {
        $bladeCode = <<<'BLADE'
<script>
    var username = '{{ $user->name }}';
    var searchQuery = @json($request->get('search'));
    var data = {{ $_GET['data'] }};
</script>
BLADE;

        $tempDir = $this->createTempDirectory(['script.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('User data in JavaScript', $result);
    }

    public function test_allows_unescaped_output_for_safe_html(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    {!! $safeHtml !!}
    {!! $content !!}
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['content.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass because variable names don't indicate user input
        $this->assertPassed($result);
    }

    public function test_detects_multiple_xss_vulnerabilities(): void
    {
        $bladeCode = <<<'BLADE'
<html>
<head>
    <script>
        var query = {{ $_GET['q'] }};
    </script>
</head>
<body>
    <h1>{!! request('title') !!}</h1>
    <div><?php echo $_POST['content']; ?></div>
</body>
</html>
BLADE;

        $tempDir = $this->createTempDirectory(['vulnerable.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertGreaterThanOrEqual(3, count($result->getIssues()));
    }

    public function test_scans_both_php_and_blade_files(): void
    {
        $phpCode = <<<'PHP'
<?php
class TestController {
    public function index() {
        echo $_GET['test'];
    }
}
PHP;

        $bladeCode = <<<'BLADE'
<div>{!! request('data') !!}</div>
BLADE;

        $tempDir = $this->createTempDirectory([
            'TestController.php' => $phpCode,
            'test.blade.php' => $bladeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Should detect both issues (may detect more than 2)
        $this->assertGreaterThanOrEqual(2, count($result->getIssues()));
    }

    // ==========================================
    // HTTP Header Tests (New Functionality)
    // ==========================================

    public function test_passes_http_check_when_csp_header_is_valid(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);
        config(['shieldci.ci_mode' => false]); // Enable HTTP checks

        $responses = [
            new Response(200, [
                'Content-Security-Policy' => "default-src 'self'; script-src 'self'",
            ], '<html></html>'),
        ];

        $analyzer = $this->createAnalyzerWithHttpMock($responses);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
        $this->assertStringContainsString('headers verified', $result->getMessage());
    }

    public function test_fails_http_check_when_csp_header_is_missing(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);
        config(['shieldci.ci_mode' => false]);

        $responses = [
            new Response(200, [], '<html></html>'),
        ];

        $analyzer = $this->createAnalyzerWithHttpMock($responses);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Content-Security-Policy header not set', $result);
    }

    public function test_fails_http_check_when_csp_contains_unsafe_inline(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);
        config(['shieldci.ci_mode' => false]);

        $responses = [
            new Response(200, [
                'Content-Security-Policy' => "default-src 'self'; script-src 'self' 'unsafe-inline'",
            ], '<html></html>'),
        ];

        $analyzer = $this->createAnalyzerWithHttpMock($responses);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('inadequate', $result);
    }

    public function test_fails_http_check_when_csp_contains_unsafe_eval(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);
        config(['shieldci.ci_mode' => false]);

        $responses = [
            new Response(200, [
                'Content-Security-Policy' => "default-src 'self'; script-src 'self' 'unsafe-eval'",
            ], '<html></html>'),
        ];

        $analyzer = $this->createAnalyzerWithHttpMock($responses);
        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('inadequate', $result);
    }

    public function test_passes_http_check_with_script_src_directive(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);
        config(['shieldci.ci_mode' => false]);

        $responses = [
            new Response(200, [
                'Content-Security-Policy' => "script-src 'self' 'nonce-abc123'",
            ], '<html></html>'),
        ];

        $analyzer = $this->createAnalyzerWithHttpMock($responses);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_http_checks_in_ci_mode(): void
    {
        config(['shieldci.ci_mode' => true]); // CI mode enabled

        $tempDir = $this->createTempDirectory(['test.blade.php' => '<div>{{ $safe }}</div>']);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should only check code, not HTTP headers
        $this->assertPassed($result);
        $this->assertStringNotContainsString('headers verified', $result->getMessage());
        $this->assertStringContainsString('in code', $result->getMessage());
    }

    public function test_reports_both_code_and_header_issues_in_production(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);
        config(['shieldci.ci_mode' => false]);

        // Create code with XSS vulnerability
        $bladeCode = <<<'BLADE'
<div>{!! request('xss') !!}</div>
BLADE;

        $tempDir = $this->createTempDirectory(['vulnerable.blade.php' => $bladeCode]);

        // Mock HTTP response without CSP header
        $responses = [
            new Response(200, [], '<html></html>'),
        ];

        $analyzer = $this->createAnalyzerWithHttpMock($responses);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Should report both code and HTTP issues (at least 2)
        $issueCount = count($result->getIssues());
        $this->assertGreaterThanOrEqual(2, $issueCount);
        $this->assertStringContainsString('XSS issue(s)', $result->getMessage());
    }

    public function test_skips_http_checks_on_localhost(): void
    {
        config(['app.url' => 'http://localhost']);
        config(['shieldci.guest_url' => '/']);
        config(['shieldci.ci_mode' => false]);

        $tempDir = $this->createTempDirectory(['test.blade.php' => '<div>{{ $safe }}</div>']);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should skip HTTP checks for localhost
        $this->assertPassed($result);
    }

    public function test_handles_network_errors_gracefully(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);
        config(['shieldci.ci_mode' => false]);

        $tempDir = $this->createTempDirectory(['test.blade.php' => '<div>{{ $safe }}</div>']);

        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);
        config(['shieldci.ci_mode' => false]);

        $responses = [
            new ConnectException('Timeout', new Request('GET', 'https://example.com')),
        ];

        $analyzer = $this->createAnalyzerWithHttpMock($responses);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should not fail due to network error
        $this->assertPassed($result);
    }
}
