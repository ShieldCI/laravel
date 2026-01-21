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
            /** @phpstan-ignore-next-line */
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
        $this->assertHasIssueContaining('unescaped user input', $result);
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
        $this->assertHasIssueContaining('User data injected into JavaScript', $result);
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

    // ==========================================
    // Additional Test Cases for Edge Cases
    // ==========================================

    public function test_detects_single_line_script_tag_with_user_input(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <script>var data = {{ $_GET['data'] }};</script>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['inline-script.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('User data injected into JavaScript', $result);
    }

    public function test_detects_multiline_script_with_user_input(): void
    {
        $bladeCode = <<<'BLADE'
<script>
var config = {
    search: {{ $request->get('query') }},
    filter: {{ $_POST['filter'] }}
};
</script>
BLADE;

        $tempDir = $this->createTempDirectory(['multiline-script.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('User data injected into JavaScript', $result);
    }

    public function test_detects_print_statement_with_user_input(): void
    {
        $phpCode = <<<'PHP'
<?php

class OutputController
{
    public function display()
    {
        print $_GET['message'];
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['OutputController.php' => $phpCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Print is similar to echo but not explicitly detected
        // This test documents current behavior
        $this->assertPassed($result);
    }

    public function test_detects_printf_with_user_input(): void
    {
        $phpCode = <<<'PHP'
<?php

class FormatterController
{
    public function display()
    {
        printf('%s', $_GET['message']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['FormatterController.php' => $phpCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Printf is not explicitly detected (current behavior)
        $this->assertPassed($result);
    }

    public function test_allows_verbatim_blocks_without_false_positives(): void
    {
        $bladeCode = <<<'BLADE'
@verbatim
    <script>
        var template = '{{ $variable }}';
    </script>
@endverbatim
BLADE;

        $tempDir = $this->createTempDirectory(['template.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // @verbatim blocks should be safe (current behavior may flag this)
        // This test documents current behavior
        $this->assertPassed($result);
    }

    public function test_detects_inline_event_handlers_with_user_input(): void
    {
        $bladeCode = <<<'BLADE'
<button onclick="alert('{{ request('msg') }}')">Click</button>
<img onerror="console.log('{{ $_GET['err'] }}')" />
BLADE;

        $tempDir = $this->createTempDirectory(['events.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Event handlers not explicitly detected (current behavior)
        // This test documents current behavior
        $this->assertPassed($result);
    }

    public function test_context_aware_user_input_detection(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    {!! $collection->get('key') !!}
    {!! $array->post() !!}
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['context.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass because ->get() and ->post() are not on $request
        $this->assertPassed($result);
    }

    public function test_detects_request_object_methods(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    {!! $request->input('data') !!}
    {!! $request->query('search') !!}
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['request-methods.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Unescaped blade output', $result);
    }

    public function test_detects_request_cookie_method(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    {!! $request->cookie('session') !!}
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['cookie.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Unescaped blade output', $result);
    }

    public function test_detects_input_facade(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    {!! Input::get('name') !!}
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['input-facade.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Unescaped blade output', $result);
    }

    public function test_detects_request_facade(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    {!! Request::input('email') !!}
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['request-facade.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Unescaped blade output', $result);
    }

    public function test_handles_nested_script_tags(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <script>
        var html = '<script>alert(1)</script>';
    </script>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['nested-script.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass as there's no user input
        $this->assertPassed($result);
    }

    public function test_handles_script_tag_in_string(): void
    {
        $phpCode = <<<'PHP'
<?php

class HtmlHelper
{
    public function getTemplate()
    {
        return '<script>var x = 1;</script>';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['HtmlHelper.php' => $phpCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_response_make_with_escaped_input(): void
    {
        $phpCode = <<<'PHP'
<?php

class SafeApiController
{
    public function render()
    {
        return Response::make(e(request('html')));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['SafeApiController.php' => $phpCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass because e() helper is used
        $this->assertPassed($result);
    }

    public function test_passes_with_csp_from_meta_tag(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);
        config(['shieldci.ci_mode' => false]);

        $htmlWithMetaTag = <<<'HTML'
<html>
<head>
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'">
</head>
<body>Content</body>
</html>
HTML;

        $responses = [
            new Response(200, [], $htmlWithMetaTag),
        ];

        $analyzer = $this->createAnalyzerWithHttpMock($responses);
        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_unsafe_csp_from_meta_tag(): void
    {
        config(['app.url' => 'https://example.com']);
        config(['shieldci.guest_url' => '/']);
        config(['shieldci.ci_mode' => false]);

        $tempDir = $this->createTempDirectory(['test.blade.php' => '<div>{{ $safe }}</div>']);

        $htmlWithUnsafeMetaTag = <<<'HTML'
<html>
<head>
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline'">
</head>
<body>Content</body>
</html>
HTML;

        $responses = [
            new Response(200, [], $htmlWithUnsafeMetaTag),
        ];

        $analyzer = $this->createAnalyzerWithHttpMock($responses);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('inadequate', $result);
    }

    public function test_detects_request_helper_with_arrow_chaining(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    {!! request()->get('data') !!}
    {!! request()->input('name') !!}
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['chain.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Unescaped blade output', $result);
    }

    public function test_detects_javascript_protocol_in_href_attribute(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <a href="javascript:alert('XSS')">Click me</a>
    <a href="javascript:{{ $userInput }}">Dangerous</a>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['links.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('javascript: protocol', $result);
    }

    public function test_detects_data_protocol_in_src_attribute(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <img src="data:text/html,<script>alert('XSS')</script>">
    <iframe src="data:{{ request('content') }}"></iframe>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['images.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('data: protocol', $result);
    }

    public function test_detects_user_input_in_event_handler_attributes(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <button onclick="{{ $userScript }}">Click</button>
    <img onerror="alert({{ request('xss') }})">
    <body onload="{!! $dangerous !!}">
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['events.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('event handler attribute', $result);
    }

    public function test_detects_user_input_in_href_without_validation(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <a href="{{ $userUrl }}">Link</a>
    <a href="{{ request('redirect') }}">Redirect</a>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['hrefs.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('href attribute', $result);
    }

    public function test_detects_user_input_in_src_attribute(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <img src="{{ $imageUrl }}">
    <script src="{{ request('script') }}"></script>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['sources.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('src attribute', $result);
    }

    public function test_detects_unescaped_output_in_data_attributes(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <button data-user="{!! $userId !!}">Submit</button>
    <div data-config="{!! request('config') !!}"></div>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['data-attrs.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('data-* attribute', $result);
    }

    public function test_passes_with_safe_data_attributes(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <button data-user="{{ $userId }}">Submit</button>
    <div data-config="{{ $config }}"></div>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['safe-data.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_validated_urls(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <a href="{{ url('/safe/path') }}">Internal Link</a>
    <a href="{{ route('profile') }}">Route Link</a>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['safe-urls.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==========================================
    // Attribute-Level Context Tests (False Positive Prevention)
    // ==========================================

    public function test_does_not_flag_href_when_user_input_is_in_link_text(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <a href="/safe/path">{{ request('name') }}</a>
    <a href="/another/safe/path">Hello {{ $user->name }}</a>
    <a href="/profile">Welcome, {{ $_GET['user'] }}</a>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['safe-links.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass because user input is in link text, not href attribute
        $this->assertPassed($result);
    }

    public function test_does_not_flag_src_when_user_input_is_in_alt_text(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <img src="/images/avatar.png" alt="{{ request('username') }}">
    <img src="/images/logo.png" title="{{ $_GET['title'] }}">
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['safe-images.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass because user input is in alt/title, not src attribute
        $this->assertPassed($result);
    }

    public function test_detects_user_input_in_href_with_safe_surrounding_text(): void
    {
        $bladeCode = <<<'BLADE'
<a href="{{ request('url') }}">Safe Text</a>
BLADE;

        $tempDir = $this->createTempDirectory(['mixed.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should fail because user input IS in the href attribute
        $this->assertFailed($result);
        $this->assertHasIssueContaining('href attribute', $result);
    }

    public function test_detects_user_input_in_src_with_safe_surrounding_attributes(): void
    {
        $bladeCode = <<<'BLADE'
<img src="{{ request('image_url') }}" alt="Safe alt text" class="avatar">
BLADE;

        $tempDir = $this->createTempDirectory(['mixed-img.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should fail because user input IS in the src attribute
        $this->assertFailed($result);
        $this->assertHasIssueContaining('src attribute', $result);
    }
}
