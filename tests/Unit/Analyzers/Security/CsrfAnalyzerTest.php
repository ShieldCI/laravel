<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\Security\CsrfAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class CsrfAnalyzerTest extends AnalyzerTestCase
{
    private const APP_VERIFY_CSRF_TOKEN = "<?php\n\nnamespace App\\Http\\Middleware;\n\nclass VerifyCsrfToken extends \\Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken\n{\n}\n";

    protected function createAnalyzer(): CsrfAnalyzer
    {
        return new CsrfAnalyzer($this->parser);
    }

    // ==================== Blade Form CSRF Tests (10 tests) ====================

    public function test_passes_with_csrf_token_in_form(): void
    {
        $blade = <<<'BLADE'
<form method="POST">
    @csrf
    <input type="text" name="name">
    <button type="submit">Submit</button>
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/form.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_form_without_csrf(): void
    {
        $blade = <<<'BLADE'
<form method="POST">
    <input type="text" name="name">
    <button type="submit">Submit</button>
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/form.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('CSRF', $result);
    }

    public function test_ignores_get_forms(): void
    {
        $blade = <<<'BLADE'
<form method="GET">
    <input type="text" name="search">
    <button type="submit">Search</button>
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/search.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_csrf_field_helper(): void
    {
        $blade = <<<'BLADE'
<form method="POST" action="/submit">
    {{ csrf_field() }}
    <input type="text" name="email">
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/form.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_token_input(): void
    {
        $blade = <<<'BLADE'
<form method="POST">
    <input type="hidden" name="_token" value="token">
    <input type="text" name="username">
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/form.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_put_form_without_csrf(): void
    {
        $blade = <<<'BLADE'
<form method="PUT" action="/users/1">
    <input type="text" name="name">
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/edit.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('CSRF', $result);
    }

    public function test_detects_patch_form_without_csrf(): void
    {
        $blade = <<<'BLADE'
<form method="PATCH" action="/profile">
    <input type="email" name="email">
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/profile.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('CSRF', $result);
    }

    public function test_detects_delete_form_without_csrf(): void
    {
        $blade = <<<'BLADE'
<form method="DELETE" action="/posts/1">
    <button type="submit">Delete</button>
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/delete.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('CSRF', $result);
    }

    public function test_passes_with_csrf_on_different_line(): void
    {
        $blade = <<<'BLADE'
<form method="POST" action="/login">
    <input type="text" name="username">
    @csrf
    <input type="password" name="password">
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/login.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_multiple_forms_in_file(): void
    {
        $blade = <<<'BLADE'
<form method="POST" action="/form1">
    @csrf
    <input type="text" name="field1">
</form>

<form method="POST" action="/form2">
    <input type="text" name="field2">
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/multiple.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues()); // Only second form should fail
    }

    public function test_passes_with_csrf_parentheses(): void
    {
        $blade = <<<'BLADE'
<form method="POST" action="/submit">
    @csrf()
    <input type="text" name="email">
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/form.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_csrf_component_self_closing(): void
    {
        $blade = <<<'BLADE'
<form method="POST" action="/update">
    <x-csrf />
    <input type="text" name="username">
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/form.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_csrf_component_non_self_closing(): void
    {
        $blade = <<<'BLADE'
<form method="POST" action="/create">
    <x-csrf>
    <input type="text" name="title">
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/form.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_scans_beyond_10_lines_for_csrf_token(): void
    {
        $blade = <<<'BLADE'
<form method="POST" action="/long-form">
    <div class="form-group">
        <label>Field 1</label>
        <input type="text" name="field1">
    </div>
    <div class="form-group">
        <label>Field 2</label>
        <input type="text" name="field2">
    </div>
    <div class="form-group">
        <label>Field 3</label>
        <input type="text" name="field3">
    </div>
    <div class="form-group">
        @csrf
        <label>Field 4</label>
        <input type="text" name="field4">
    </div>
    <button type="submit">Submit</button>
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/long-form.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_form_without_csrf_after_many_lines(): void
    {
        $blade = <<<'BLADE'
<form method="POST" action="/long-form-no-csrf">
    <div class="form-group">
        <label>Field 1</label>
        <input type="text" name="field1">
    </div>
    <div class="form-group">
        <label>Field 2</label>
        <input type="text" name="field2">
    </div>
    <div class="form-group">
        <label>Field 3</label>
        <input type="text" name="field3">
    </div>
    <button type="submit">Submit</button>
</form>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/long-form-no-csrf.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('CSRF', $result);
    }

    // ==================== Blade AJAX Tests (8 tests) ====================

    public function test_detects_jquery_ajax_post_without_csrf(): void
    {
        $blade = <<<'BLADE'
<script>
$.ajax({
    url: '/api/users',
    method: 'POST',
    data: { name: 'John' }
});
</script>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/ajax.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('AJAX', $result);
    }

    public function test_passes_jquery_ajax_with_csrf_token(): void
    {
        $blade = <<<'BLADE'
<script>
$.ajax({
    url: '/api/users',
    method: 'POST',
    headers: { 'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content') },
    data: { name: 'John' }
});
</script>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/ajax.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_fetch_post_without_csrf(): void
    {
        $blade = <<<'BLADE'
<script>
fetch('/api/posts', {
    method: 'POST',
    body: JSON.stringify({ title: 'New Post' })
});
</script>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/fetch.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('AJAX', $result);
    }

    public function test_passes_fetch_with_csrf_token(): void
    {
        $blade = <<<'BLADE'
<script>
fetch('/api/posts', {
    method: 'POST',
    headers: { 'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content },
    body: JSON.stringify({ title: 'New Post' })
});
</script>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/fetch.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_ajax_put_without_csrf(): void
    {
        $blade = <<<'BLADE'
<script>
$.ajax({
    url: '/users/1',
    method: 'PUT',
    data: { name: 'Updated' }
});
</script>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/update.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('AJAX', $result);
    }

    public function test_passes_ajax_with_get_method(): void
    {
        $blade = <<<'BLADE'
<script>
$.ajax({
    url: '/api/users',
    method: 'GET'
});
</script>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/get.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_multiple_ajax_calls(): void
    {
        $blade = <<<'BLADE'
<script>
// With CSRF
$.ajax({
    url: '/api/users',
    method: 'POST',
    headers: { 'X-CSRF-TOKEN': token }
});

// Without CSRF
fetch('/api/posts', {
    method: 'POST',
    body: JSON.stringify({ title: 'Test' })
});
</script>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/multi-ajax.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues()); // Only second call should fail
    }

    public function test_detects_ajax_delete_without_csrf(): void
    {
        $blade = <<<'BLADE'
<script>
$.ajax({
    url: '/posts/1',
    method: 'DELETE'
});
</script>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/delete-ajax.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('AJAX', $result);
    }

    public function test_detects_ajax_patch_without_csrf(): void
    {
        $blade = <<<'BLADE'
<script>
$.ajax({
    url: '/posts/1',
    method: 'PATCH',
    data: { status: 'published' }
});
</script>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/patch-ajax.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('AJAX', $result);
    }

    public function test_handles_ajax_spanning_many_lines(): void
    {
        $blade = <<<'BLADE'
<script>
$.ajax({
    url: '/api/complex',
    method: 'POST',
    data: {
        field1: 'value1',
        field2: 'value2',
        nested: {
            key1: 'val1',
            key2: 'val2'
        }
    },
    success: function(response) {
        console.log(response);
    },
    error: function(xhr) {
        console.error(xhr);
    }
});
</script>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/complex-ajax.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('AJAX', $result);
    }

    public function test_passes_ajax_spanning_many_lines_with_csrf(): void
    {
        $blade = <<<'BLADE'
<script>
$.ajax({
    url: '/api/complex',
    method: 'POST',
    headers: {
        'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
    },
    data: {
        field1: 'value1',
        field2: 'value2',
        nested: {
            key1: 'val1',
            key2: 'val2'
        }
    },
    success: function(response) {
        console.log(response);
    }
});
</script>
BLADE;

        $tempDir = $this->createTempDirectory(['resources/views/complex-ajax.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==================== JavaScript AJAX Tests (7 tests) ====================

    public function test_warns_fetch_in_js_without_csrf(): void
    {
        $js = <<<'JS'
fetch('/api/users', {
    method: 'POST',
    body: JSON.stringify({ name: 'John' })
});
JS;

        $tempDir = $this->createTempDirectory(['resources/js/app.js' => $js]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('JavaScript AJAX', $result);
    }

    public function test_passes_fetch_in_js_with_csrf(): void
    {
        $js = <<<'JS'
fetch('/api/users', {
    method: 'POST',
    headers: { 'X-CSRF-TOKEN': getCsrfToken() },
    body: JSON.stringify({ name: 'John' })
});
JS;

        $tempDir = $this->createTempDirectory(['resources/js/app.js' => $js]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_warns_axios_post_without_csrf(): void
    {
        $js = <<<'JS'
axios.post('/api/posts', {
    title: 'New Post',
    content: 'Content here'
});
JS;

        $tempDir = $this->createTempDirectory(['resources/js/api.js' => $js]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('JavaScript AJAX', $result);
    }

    public function test_passes_axios_with_csrf_header(): void
    {
        $js = <<<'JS'
axios.post('/api/posts', {
    title: 'New Post'
}, {
    headers: { 'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content }
});
JS;

        $tempDir = $this->createTempDirectory(['resources/js/api.js' => $js]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_warns_jquery_ajax_in_js_without_csrf(): void
    {
        $js = <<<'JS'
$.ajax({
    url: '/api/data',
    method: 'POST',
    data: { value: 123 }
});
JS;

        $tempDir = $this->createTempDirectory(['resources/js/jquery.js' => $js]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('JavaScript AJAX', $result);
    }

    public function test_warns_axios_put_without_csrf(): void
    {
        $js = <<<'JS'
axios.put('/api/users/1', {
    name: 'Updated Name'
});
JS;

        $tempDir = $this->createTempDirectory(['resources/js/update.js' => $js]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('JavaScript AJAX', $result);
    }

    public function test_warns_axios_delete_without_csrf(): void
    {
        $js = <<<'JS'
axios.delete('/api/posts/1');
JS;

        $tempDir = $this->createTempDirectory(['resources/js/delete.js' => $js]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('JavaScript AJAX', $result);
    }

    public function test_warns_axios_patch_without_csrf(): void
    {
        $js = <<<'JS'
axios.patch('/api/users/1', {
    status: 'active'
});
JS;

        $tempDir = $this->createTempDirectory(['resources/js/patch.js' => $js]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('JavaScript AJAX', $result);
    }

    public function test_passes_fetch_get_in_js(): void
    {
        $js = <<<'JS'
fetch('/api/users', {
    method: 'GET'
});
JS;

        $tempDir = $this->createTempDirectory(['resources/js/fetch-get.js' => $js]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_axios_get_in_js(): void
    {
        $js = <<<'JS'
axios.get('/api/users');
JS;

        $tempDir = $this->createTempDirectory(['resources/js/axios-get.js' => $js]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_fetch_without_method_in_js(): void
    {
        $js = <<<'JS'
fetch('/api/users').then(response => response.json());
JS;

        $tempDir = $this->createTempDirectory(['resources/js/fetch-default.js' => $js]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ==================== CSRF Middleware Exception Tests (9 tests) ====================

    public function test_passes_when_no_csrf_middleware_file(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_empty_except_array(): void
    {
        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as Middleware;

class VerifyCsrfToken extends Middleware
{
    protected $except = [];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/VerifyCsrfToken.php' => $middleware,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_critical_with_wildcard_asterisk(): void
    {
        $middleware = <<<'PHP'
<?php

class VerifyCsrfToken
{
    protected $except = [
        '*',
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/VerifyCsrfToken.php' => $middleware,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('wildcard', $result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
        $this->assertSame(5, $issues[0]->location?->line);
    }

    public function test_fails_when_single_line_except_lists_wildcard(): void
    {
        $result = $this->analyzeCsrfMiddlewareExcept("['*']");

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('All routes excluded from CSRF protection with wildcard', $result->getIssues()[0]->message);
        $this->assertEquals(Severity::Critical, $result->getIssues()[0]->severity);
        $this->assertSame(7, $result->getIssues()[0]->location?->line);
    }

    public function test_fails_when_wildcard_is_not_the_first_except_entry_on_its_line(): void
    {
        $result = $this->analyzeCsrfMiddlewareExcept("[\n        'paddle/*', '/*',\n    ]");

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('All routes excluded from CSRF protection with wildcard', $result->getIssues()[0]->message);
        $this->assertSame('/*', $result->getIssues()[0]->metadata['exception']);
    }

    public function test_fails_broad_exception_that_shares_a_line_with_another_entry(): void
    {
        $result = $this->analyzeCsrfMiddlewareExcept("[\n        'stripe/*', 'reports/*',\n    ]");

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('Broad CSRF exception pattern: reports/*', $result->getIssues()[0]->message);
        $this->assertEquals(Severity::High, $result->getIssues()[0]->severity);
    }

    public function test_fails_when_wildcard_follows_a_long_except_list(): void
    {
        $entries = '';
        for ($i = 1; $i <= 25; $i++) {
            $entries .= "        'service/hook-{$i}',\n";
        }

        $result = $this->analyzeCsrfMiddlewareExcept("[\n{$entries}        '*',\n    ]");

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('All routes excluded from CSRF protection with wildcard', $result->getIssues()[0]->message);
        $this->assertSame(7, $result->getIssues()[0]->location?->line);
    }

    public function test_passes_when_except_wildcard_is_only_in_a_comment(): void
    {
        $result = $this->analyzeCsrfMiddlewareExcept("[\n        // '*',\n        'stripe/*',\n    ]");

        $this->assertPassed($result);
    }

    private function analyzeCsrfMiddlewareExcept(string $except): ResultInterface
    {
        $middleware = <<<PHP
<?php

namespace App\\Http\\Middleware;

class VerifyCsrfToken
{
    protected \$except = {$except};
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/VerifyCsrfToken.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        return $analyzer->analyze();
    }

    public function test_fails_critical_with_wildcard_slash_asterisk(): void
    {
        $middleware = <<<'PHP'
<?php

class VerifyCsrfToken
{
    protected $except = [
        '/*',
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/VerifyCsrfToken.php' => $middleware,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('wildcard', $result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_fails_with_broad_admin_wildcard(): void
    {
        $middleware = <<<'PHP'
<?php

class VerifyCsrfToken
{
    protected $except = [
        'admin/*',
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/VerifyCsrfToken.php' => $middleware,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Broad CSRF exception', $result);
    }

    public function test_passes_with_api_wildcard_exception(): void
    {
        $middleware = <<<'PHP'
<?php

class VerifyCsrfToken
{
    protected $except = [
        'api/*',
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/VerifyCsrfToken.php' => $middleware,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_specific_route_exception(): void
    {
        $middleware = <<<'PHP'
<?php

class VerifyCsrfToken
{
    protected $except = [
        'webhooks/stripe',
        'webhooks/github',
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/VerifyCsrfToken.php' => $middleware,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_multiple_exceptions_with_wildcards(): void
    {
        $middleware = <<<'PHP'
<?php

class VerifyCsrfToken
{
    protected $except = [
        'webhooks/stripe',
        'admin/*',
        'api/*',
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/VerifyCsrfToken.php' => $middleware,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues()); // Only admin/* should fail
        $this->assertHasIssueContaining('admin/*', $result);
    }

    public function test_passes_with_sanctum_api_exception(): void
    {
        $middleware = <<<'PHP'
<?php

class VerifyCsrfToken
{
    protected $except = [
        'api/sanctum/*',
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/VerifyCsrfToken.php' => $middleware,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_known_webhook_service_stripe(): void
    {
        $middleware = <<<'PHP'
<?php

class VerifyCsrfToken
{
    protected $except = [
        'stripe/*',
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/VerifyCsrfToken.php' => $middleware,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_known_webhook_service_mailgun(): void
    {
        $middleware = <<<'PHP'
<?php

class VerifyCsrfToken
{
    protected $except = [
        'mailgun/*',
        'mailslurp/*',
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/VerifyCsrfToken.php' => $middleware,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_multi_segment_pattern(): void
    {
        $middleware = <<<'PHP'
<?php

class VerifyCsrfToken
{
    protected $except = [
        '/clock/switch/*',
        'api/external/callback/*',
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/VerifyCsrfToken.php' => $middleware,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_with_broad_dashboard_wildcard(): void
    {
        $middleware = <<<'PHP'
<?php

class VerifyCsrfToken
{
    protected $except = [
        'dashboard/*',
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/VerifyCsrfToken.php' => $middleware,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Broad CSRF exception', $result);
        $this->assertHasIssueContaining('dashboard/*', $result);
    }

    // ==================== Middleware Registration Tests (4 tests) ====================

    public function test_passes_when_verify_csrf_token_registered(): void
    {
        $kernel = <<<'PHP'
<?php

namespace App\Http;

use App\Http\Middleware\VerifyCsrfToken;

class Kernel
{
    protected $middlewareGroups = [
        'web' => [
            VerifyCsrfToken::class,
        ],
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernel,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_verify_csrf_token_commented_out(): void
    {
        $kernel = <<<'PHP'
<?php

namespace App\Http;

class Kernel
{
    protected $middlewareGroups = [
        'web' => [
            // \App\Http\Middleware\VerifyCsrfToken::class,
        ],
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernel,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('commented out', $result);
    }

    public function test_checks_bootstrap_app_for_laravel_11(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        // No CSRF middleware configured
    })
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_with_middleware_only_decorates_web_group(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware): void {
        if (env('CACHE_STORE', 'database') === 'redis') {
            $middleware->throttleWithRedis();
        }

        $middleware->web(append: [
            \App\Http\Middleware\HandleInertiaRequests::class,
            \Illuminate\Http\Middleware\AddLinkHeadersForPreloadedAssets::class,
        ]);

        $middleware->alias([
            'api.token' => \App\Http\Middleware\ValidateApiToken::class,
        ]);
    })
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_global_stack_customised_without_csrf_middleware(): void
    {
        // use() replaces the global stack; CSRF belongs to the web group, which use() does not touch
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        $middleware->use([
            \Illuminate\Foundation\Http\Middleware\InvokeDeferredCallbacks::class,
            \Illuminate\Http\Middleware\TrustProxies::class,
            \Illuminate\Http\Middleware\HandleCors::class,
            \Illuminate\Foundation\Http\Middleware\PreventRequestsDuringMaintenance::class,
            \Illuminate\Http\Middleware\ValidatePostSize::class,
            \Illuminate\Foundation\Http\Middleware\TrimStrings::class,
            \Illuminate\Foundation\Http\Middleware\ConvertEmptyStringsToNull::class,
        ]);
    })
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_csrf_removed_from_web_group(): void
    {
        $this->skipUnlessDefaultWebGroupOf(12);

        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        $middleware->web(remove: [
            \Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class,
        ]);
    })
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('ValidateCsrfToken removed from web middleware group', $result);
        $issues = $result->getIssues();
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_passes_when_csrf_middleware_removed_from_global_stack(): void
    {
        // remove() edits the global stack only; CSRF middleware is in the web group, which it does not touch
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        $middleware->remove(\Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class);
        $middleware->remove([\Illuminate\Foundation\Http\Middleware\PreventRequestForgery::class]);
    })
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_when_validate_csrf_tokens_excludes_all_with_wildcard(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        $middleware->validateCsrfTokens(except: ['*']);
    })
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('All routes excluded from CSRF protection', $result);
        $issues = $result->getIssues();
        $this->assertEquals(Severity::Critical, $issues[0]->severity);
    }

    public function test_passes_validate_csrf_tokens_with_known_webhook(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        $middleware->validateCsrfTokens(except: [
            'stripe/*',
            'mailgun/*',
        ]);
    })
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_validate_csrf_tokens_with_multi_segment_pattern(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        $middleware->validateCsrfTokens(except: [
            'api/webhooks/stripe',
            '/clock/switch/*',
        ]);
    })
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'resources']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_validate_csrf_tokens_with_broad_exception(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        $middleware->validateCsrfTokens(except: [
            'admin/*',
            'dashboard/*',
        ]);
    })
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrap,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Broad CSRF exception pattern in bootstrap/app.php', $result);
        $this->assertCount(2, $result->getIssues()); // Both admin/* and dashboard/*
    }

    // ==================== Laravel 13 PreventRequestForgery Tests ====================

    public function test_fails_when_prevent_request_forgery_excludes_all_with_wildcard(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->preventRequestForgery(except: ['*'], originOnly: true);"
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertHasIssueContaining('All routes excluded from CSRF protection in bootstrap/app.php', $result);
        $this->assertEquals(Severity::Critical, $result->getIssues()[0]->severity);
    }

    public function test_fails_prevent_request_forgery_with_broad_exception(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->preventRequestForgery(except: [\n            'admin/*',\n            'stripe/*',\n        ]);"
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertHasIssueContaining('Broad CSRF exception pattern in bootstrap/app.php: admin/*', $result);
        $this->assertEquals(Severity::High, $result->getIssues()[0]->severity);
    }

    public function test_passes_prevent_request_forgery_with_specific_exceptions(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->preventRequestForgery(except: ['stripe/*', 'service/hooks/*']);"
        );

        $this->assertPassed($result);
    }

    public function test_fails_when_prevent_request_forgery_removed_from_web_group(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->web(remove: [\n            \\Illuminate\\Foundation\\Http\\Middleware\\PreventRequestForgery::class,\n        ]);",
            13
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertHasIssueContaining('PreventRequestForgery removed from web middleware group', $result);
        $this->assertEquals(Severity::Critical, $result->getIssues()[0]->severity);
    }

    public function test_passes_when_prevent_request_forgery_registered_in_kernel(): void
    {
        $result = $this->analyzeKernelWebGroup('\Illuminate\Foundation\Http\Middleware\PreventRequestForgery::class,');

        $this->assertPassed($result);
    }

    public function test_fails_when_prevent_request_forgery_commented_out_in_kernel(): void
    {
        $result = $this->analyzeKernelWebGroup('// \Illuminate\Foundation\Http\Middleware\PreventRequestForgery::class,');

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertHasIssueContaining('PreventRequestForgery middleware is commented out', $result);
        $this->assertEquals(Severity::Critical, $result->getIssues()[0]->severity);
    }

    public function test_prevent_request_forgery_findings_report_laravel_13(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->preventRequestForgery(except: ['*']);"
        );

        $this->assertFailed($result);
        $this->assertSame('13+', $result->getIssues()[0]->metadata['laravel_version']);
    }

    public function test_validate_csrf_token_findings_report_laravel_11(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->validateCsrfTokens(except: ['*']);"
        );

        $this->assertFailed($result);
        $this->assertSame('11+', $result->getIssues()[0]->metadata['laravel_version']);
    }

    public function test_fails_when_prevent_request_forgery_subclass_excludes_all_routes(): void
    {
        $middleware = <<<'PHP'
<?php

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery as Middleware;

class PreventRequestForgery extends Middleware
{
    protected $except = [
        '*',
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/PreventRequestForgery.php' => $middleware,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertHasIssueContaining('All routes excluded from CSRF protection with wildcard', $result);
        $this->assertSame('PreventRequestForgery.php', $result->getIssues()[0]->metadata['file']);
    }

    public function test_fails_when_web_group_redefined_without_csrf_middleware(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->group('web', [\n            \\Illuminate\\Cookie\\Middleware\\EncryptCookies::class,\n            \\Illuminate\\Session\\Middleware\\StartSession::class,\n            \\Illuminate\\Routing\\Middleware\\SubstituteBindings::class,\n        ]);"
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertHasIssueContaining('web middleware group redefined without CSRF middleware', $result);
        $this->assertEquals(Severity::High, $result->getIssues()[0]->severity);
    }

    public function test_passes_when_web_group_redefined_with_csrf_middleware(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->group('web', [\n            \\Illuminate\\Session\\Middleware\\StartSession::class,\n            \\App\\Http\\Middleware\\VerifyCsrfToken::class,\n        ]);"
        );

        $this->assertPassed($result);
    }

    public function test_passes_when_api_group_redefined_without_csrf_middleware(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->group('api', [\\Illuminate\\Routing\\Middleware\\SubstituteBindings::class]);"
        );

        $this->assertPassed($result);
    }

    public function test_fails_when_web_replace_swaps_out_csrf_middleware(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->web(append: [\n            \\App\\Http\\Middleware\\HandleInertiaRequests::class,\n        ], replace: [\n            \\Illuminate\\Foundation\\Http\\Middleware\\PreventRequestForgery::class => \\App\\Http\\Middleware\\NoopMiddleware::class,\n        ]);",
            13
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertHasIssueContaining('PreventRequestForgery replaced in web middleware group', $result);
        $this->assertSame('13+', $result->getIssues()[0]->metadata['laravel_version']);
    }

    public function test_passes_when_web_replace_swaps_in_csrf_subclass(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->web(replace: [\n            \\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class => \\App\\Http\\Middleware\\VerifyCsrfToken::class,\n        ]);"
        );

        $this->assertPassed($result);
    }

    public function test_fails_when_replace_in_group_swaps_out_csrf_middleware(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->replaceInGroup('web', \\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class, \\App\\Http\\Middleware\\NoopMiddleware::class);",
            12
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertHasIssueContaining('ValidateCsrfToken replaced in web middleware group', $result);
    }

    public function test_fails_when_csrf_middleware_removed_from_web_group_by_name(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->removeFromGroup('web', [\n            \\Illuminate\\Foundation\\Http\\Middleware\\PreventRequestForgery::class,\n        ]);",
            13
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertHasIssueContaining('PreventRequestForgery removed from web middleware group', $result);
        $this->assertEquals(Severity::Critical, $result->getIssues()[0]->severity);
    }

    // ==================== bootstrap/app.php Read Through the AST (#540) ====================

    public function test_fails_when_wildcard_is_not_the_first_except_entry(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->preventRequestForgery(except: [\n            'paddle/*',\n            '*',\n        ]);"
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $issue = $result->getIssues()[0];
        $this->assertSame('All routes excluded from CSRF protection in bootstrap/app.php', $issue->message);
        $this->assertEquals(Severity::Critical, $issue->severity);
        $this->assertSame(7, $issue->location?->line);
        $this->assertSame('*', $issue->metadata['exception']);
    }

    public function test_fails_when_except_lists_slash_wildcard(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->validateCsrfTokens(except: ['/*']);"
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('All routes excluded from CSRF protection in bootstrap/app.php', $result->getIssues()[0]->message);
        $this->assertSame('/*', $result->getIssues()[0]->metadata['exception']);
    }

    public function test_fails_when_except_is_not_the_first_named_argument(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->preventRequestForgery(originOnly: true, except: ['*']);"
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('All routes excluded from CSRF protection in bootstrap/app.php', $result->getIssues()[0]->message);
        $this->assertSame('13+', $result->getIssues()[0]->metadata['laravel_version']);
    }

    public function test_fails_broad_exception_when_except_is_not_the_first_named_argument(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->preventRequestForgery(allowSameSite: true, except: ['reports/*']);"
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('Broad CSRF exception pattern in bootstrap/app.php: reports/*', $result->getIssues()[0]->message);
        $this->assertEquals(Severity::High, $result->getIssues()[0]->severity);
    }

    public function test_fails_when_except_is_passed_positionally(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->validateCsrfTokens(['*']);"
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('All routes excluded from CSRF protection in bootstrap/app.php', $result->getIssues()[0]->message);
    }

    public function test_passes_when_except_is_not_a_literal_list(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->validateCsrfTokens(except: config('csrf.except'));"
        );

        $this->assertPassed($result);
    }

    public function test_single_line_wildcard_keeps_its_line(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->alias([]);\n        \$middleware->validateCsrfTokens(except: ['*']);"
        );

        $this->assertFailed($result);
        $this->assertSame(8, $result->getIssues()[0]->location?->line);
    }

    public function test_passes_when_kernel_comment_names_csrf_middleware_in_prose(): void
    {
        $result = $this->analyzeKernelWebGroup(
            "// ValidateCsrfToken extends PreventRequestForgery since Laravel 13\n            \\App\\Http\\Middleware\\VerifyCsrfToken::class,"
        );

        $this->assertPassed($result);
    }

    public function test_fails_not_registered_when_only_a_kernel_comment_names_csrf_middleware(): void
    {
        $result = $this->analyzeKernelWebGroup('// VerifyCsrfToken now lives in the shared web stack');

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('CSRF middleware is not registered in HTTP Kernel', $result->getIssues()[0]->message);
    }

    public function test_fails_when_kernel_entry_is_commented_out_as_a_string(): void
    {
        $result = $this->analyzeKernelWebGroup("// 'App\\Http\\Middleware\\VerifyCsrfToken',");

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('VerifyCsrfToken middleware is commented out', $result->getIssues()[0]->message);
    }

    public function test_passes_when_kernel_comments_out_csrf_in_priority_but_web_group_registers_it(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            \App\Http\Middleware\VerifyCsrfToken::class,
        ],
    ];

    protected $middlewarePriority = [
        // \App\Http\Middleware\VerifyCsrfToken::class,
    ];
PHP);

        $this->assertPassed($result);
    }

    public function test_passes_when_kernel_comments_out_csrf_in_web_group_but_global_stack_registers_it(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middleware = [
        \App\Http\Middleware\VerifyCsrfToken::class,
    ];

    protected $middlewareGroups = [
        'web' => [
            // \App\Http\Middleware\VerifyCsrfToken::class,
        ],
    ];
PHP);

        $this->assertPassed($result);
    }

    public function test_passes_when_kernel_web_group_comments_out_one_csrf_name_and_registers_another(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            // \App\Http\Middleware\VerifyCsrfToken::class,
            \Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class,
        ],
    ];
PHP);

        $this->assertPassed($result);
    }

    public function test_passes_when_kernel_web_group_registers_csrf_through_an_aliased_import(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            Csrf::class,
        ],
    ];

    protected $middlewarePriority = [
        // \App\Http\Middleware\VerifyCsrfToken::class,
    ];
PHP, 'use App\Http\Middleware\VerifyCsrfToken as Csrf;');

        $this->assertPassed($result);
    }

    public function test_passes_when_kernel_web_group_registers_csrf_through_an_alias(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            'csrf',
        ],
    ];

    protected $middlewareAliases = [
        'csrf' => \App\Http\Middleware\VerifyCsrfToken::class,
    ];

    protected $middlewarePriority = [
        // \App\Http\Middleware\VerifyCsrfToken::class,
    ];
PHP);

        $this->assertPassed($result);
    }

    public function test_passes_when_kernel_web_group_registers_csrf_through_a_route_middleware_alias_with_parameters(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            'csrf:strict',
        ],
    ];

    protected $routeMiddleware = [
        'csrf' => \App\Http\Middleware\VerifyCsrfToken::class,
    ];

    protected $middlewarePriority = [
        // \App\Http\Middleware\VerifyCsrfToken::class,
    ];
PHP);

        $this->assertPassed($result);
    }

    public function test_passes_when_kernel_web_group_registers_csrf_through_a_nested_group(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            'csrf-stack',
        ],
        'csrf-stack' => [
            \App\Http\Middleware\VerifyCsrfToken::class,
        ],
    ];

    protected $middlewarePriority = [
        // \App\Http\Middleware\VerifyCsrfToken::class,
    ];
PHP);

        $this->assertPassed($result);
    }

    public function test_fails_when_kernel_web_group_alias_names_no_csrf_middleware(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            'csrf',
            'loop',
            // \App\Http\Middleware\VerifyCsrfToken::class,
        ],
        'loop' => [
            'loop',
        ],
    ];

    protected $middlewareAliases = [
        'csrf' => \App\Http\Middleware\EncryptCookies::class,
        'loop' => \App\Http\Middleware\VerifyCsrfToken::class,
    ];
PHP);

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('VerifyCsrfToken middleware is commented out', $result->getIssues()[0]->message);
    }

    public function test_fails_when_kernel_alias_named_after_csrf_middleware_resolves_elsewhere(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            'VerifyCsrfToken',
            // \App\Http\Middleware\VerifyCsrfToken::class,
        ],
    ];

    protected $middlewareAliases = [
        'VerifyCsrfToken' => \App\Http\Middleware\EncryptCookies::class,
    ];
PHP);

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('VerifyCsrfToken middleware is commented out', $result->getIssues()[0]->message);
    }

    public function test_fails_when_kernel_global_stack_names_csrf_only_through_an_alias(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middleware = [
        'csrf',
    ];

    protected $middlewareGroups = [
        'web' => [
            // \App\Http\Middleware\VerifyCsrfToken::class,
        ],
    ];

    protected $middlewareAliases = [
        'csrf' => \App\Http\Middleware\VerifyCsrfToken::class,
    ];
PHP);

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('VerifyCsrfToken middleware is commented out', $result->getIssues()[0]->message);
    }

    public function test_fails_when_kernel_middleware_aliases_override_a_csrf_route_middleware_alias(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            'csrf',
            // \App\Http\Middleware\VerifyCsrfToken::class,
        ],
    ];

    protected $middlewareAliases = [
        'csrf' => \App\Http\Middleware\EncryptCookies::class,
    ];

    protected $routeMiddleware = [
        'csrf' => \App\Http\Middleware\VerifyCsrfToken::class,
    ];
PHP);

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('VerifyCsrfToken middleware is commented out', $result->getIssues()[0]->message);
    }

    public function test_keeps_commented_out_finding_when_kernel_web_group_lists_csrf_in_other_case(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            \App\Http\Middleware\verifycsrftoken::class,
        ],
    ];

    protected $middlewarePriority = [
        // \App\Http\Middleware\VerifyCsrfToken::class,
    ];
PHP);

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('VerifyCsrfToken middleware is commented out', $result->getIssues()[0]->message);
    }

    public function test_fails_when_another_class_in_the_kernel_file_lists_csrf_middleware(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            // \App\Http\Middleware\VerifyCsrfToken::class,
        ],
    ];
}

class LegacyKernel
{
    protected $middlewareGroups = [
        'web' => [
            \App\Http\Middleware\VerifyCsrfToken::class,
        ],
    ];
PHP);

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('VerifyCsrfToken middleware is commented out', $result->getIssues()[0]->message);
    }

    public function test_fails_when_kernel_web_group_lists_a_class_whose_name_only_contains_csrf_middleware(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            \App\Http\Middleware\SkipVerifyCsrfTokenForWebhooks::class,
            // \App\Http\Middleware\VerifyCsrfToken::class,
        ],
    ];
PHP);

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('VerifyCsrfToken middleware is commented out', $result->getIssues()[0]->message);
    }

    public function test_fails_when_only_an_anonymous_class_in_the_kernel_file_lists_csrf_middleware(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            // \App\Http\Middleware\VerifyCsrfToken::class,
        ],
    ];

    public function fake(): object
    {
        return new class
        {
            protected $middleware = [
                \App\Http\Middleware\VerifyCsrfToken::class,
            ];
        };
    }
PHP);

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('VerifyCsrfToken middleware is commented out', $result->getIssues()[0]->message);
    }

    public function test_fails_when_kernel_comments_out_csrf_in_web_group_and_only_priority_lists_it(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            // \App\Http\Middleware\VerifyCsrfToken::class,
        ],
    ];

    protected $middlewarePriority = [
        \App\Http\Middleware\VerifyCsrfToken::class,
    ];
PHP);

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('VerifyCsrfToken middleware is commented out', $result->getIssues()[0]->message);
        $this->assertSame(Severity::Critical, $result->getIssues()[0]->severity);
    }

    public function test_fails_when_kernel_comments_out_csrf_in_web_group_and_only_an_alias_names_it(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            // \App\Http\Middleware\VerifyCsrfToken::class,
        ],
    ];

    protected $middlewareAliases = [
        'csrf' => \App\Http\Middleware\VerifyCsrfToken::class,
    ];
PHP);

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('VerifyCsrfToken middleware is commented out', $result->getIssues()[0]->message);
    }

    public function test_fails_when_kernel_comments_out_csrf_in_web_group_and_only_api_group_lists_it(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            // \App\Http\Middleware\VerifyCsrfToken::class,
        ],
        'api' => [
            \App\Http\Middleware\VerifyCsrfToken::class,
        ],
    ];
PHP);

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('VerifyCsrfToken middleware is commented out', $result->getIssues()[0]->message);
    }

    public function test_fails_when_kernel_web_group_cannot_be_read_and_csrf_is_commented_out(): void
    {
        $result = $this->analyzeKernel(<<<'PHP'
    protected $middlewareGroups = [
        'web' => [
            ...self::SHARED,
            // \App\Http\Middleware\VerifyCsrfToken::class,
        ],
    ];
PHP);

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('VerifyCsrfToken middleware is commented out', $result->getIssues()[0]->message);
    }

    public function test_passes_when_laravel_13_removes_validate_csrf_token_from_web_group(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            '$middleware->web(remove: [\\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class]);',
            13
        );

        $this->assertPassed($result);
    }

    public function test_passes_when_laravel_13_removes_validate_csrf_token_by_group_name(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->removeFromGroup('web', \\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class);",
            13
        );

        $this->assertPassed($result);
    }

    public function test_passes_when_laravel_12_removes_prevent_request_forgery_from_web_group(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            '$middleware->web(remove: [\\Illuminate\\Foundation\\Http\\Middleware\\PreventRequestForgery::class]);',
            12
        );

        $this->assertPassed($result);
    }

    public function test_passes_when_laravel_13_replaces_validate_csrf_token_in_web_group(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            '$middleware->web(replace: [\\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class => \\App\\Http\\Middleware\\NoopMiddleware::class]);',
            13
        );

        $this->assertPassed($result);
    }

    public function test_fails_when_laravel_12_removes_validate_csrf_token_from_web_group(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            '$middleware->web(remove: [\\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class]);',
            12
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('ValidateCsrfToken removed from web middleware group', $result->getIssues()[0]->message);
        $this->assertEquals(Severity::Critical, $result->getIssues()[0]->severity);
        $this->assertSame(7, $result->getIssues()[0]->location?->line);
    }

    public function test_fails_when_laravel_13_removes_prevent_request_forgery_given_as_a_string(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->web(remove: 'Illuminate\\Foundation\\Http\\Middleware\\PreventRequestForgery');",
            13
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('PreventRequestForgery removed from web middleware group', $result->getIssues()[0]->message);
    }

    public function test_fails_when_imported_csrf_middleware_is_removed_from_web_group(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            '$middleware->web(remove: [ValidateCsrfToken::class]);',
            11,
            'use Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken;'
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('ValidateCsrfToken removed from web middleware group', $result->getIssues()[0]->message);
    }

    public function test_passes_when_removed_name_is_replaced_first(): void
    {
        // Replacements apply before removals, so the removal finds no ValidateCsrfToken left
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->web(replace: [\\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class => \\App\\Http\\Middleware\\VerifyCsrfToken::class]);\n        \$middleware->web(remove: [\\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class]);",
            12
        );

        $this->assertPassed($result);
    }

    public function test_fails_when_replacement_csrf_middleware_is_removed(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->web(replace: [\\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class => \\App\\Http\\Middleware\\VerifyCsrfToken::class]);\n        \$middleware->removeFromGroup('web', [\\App\\Http\\Middleware\\VerifyCsrfToken::class]);",
            12
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('VerifyCsrfToken removed from web middleware group', $result->getIssues()[0]->message);
        $this->assertSame(8, $result->getIssues()[0]->location?->line);
    }

    public function test_passes_when_csrf_middleware_is_removed_and_appended_again(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->web(\n            remove: [\\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class],\n            append: [\\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class],\n        );",
            12
        );

        $this->assertPassed($result);
    }

    public function test_passes_when_redefined_web_group_gets_csrf_middleware_appended(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->group('web', [\\Illuminate\\Session\\Middleware\\StartSession::class]);\n        \$middleware->appendToGroup('web', \\App\\Http\\Middleware\\VerifyCsrfToken::class);"
        );

        $this->assertPassed($result);
    }

    public function test_fails_when_csrf_middleware_is_removed_from_web_group_redefined_from_a_variable(): void
    {
        // The variable may hold CSRF middleware, so naming it in a removal counts
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->group('web', \$webMiddleware);\n        \$middleware->web(remove: [\\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class]);"
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('ValidateCsrfToken removed from web middleware group', $result->getIssues()[0]->message);
    }

    public function test_passes_when_web_group_redefined_from_a_variable_is_left_alone(): void
    {
        $result = $this->analyzeBootstrapMiddleware("\$middleware->group('web', \$webMiddleware);");

        $this->assertPassed($result);
    }

    public function test_fails_when_later_web_group_redefinition_drops_csrf_middleware(): void
    {
        // The last group() call wins, so an unreadable earlier one does not end the check
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->group('web', \$webMiddleware);\n        \$middleware->group('web', [\\Illuminate\\Session\\Middleware\\StartSession::class]);"
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('web middleware group redefined without CSRF middleware', $result->getIssues()[0]->message);
        $this->assertSame(8, $result->getIssues()[0]->location?->line);
    }

    public function test_fails_when_csrf_middleware_is_removed_from_web_group_with_a_spread_entry(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->group('web', [...\$defaults]);\n        \$middleware->removeFromGroup('web', \\App\\Http\\Middleware\\VerifyCsrfToken::class);"
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('VerifyCsrfToken removed from web middleware group', $result->getIssues()[0]->message);
    }

    public function test_fails_when_redefined_web_group_has_its_csrf_middleware_removed(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->group('web', [\\App\\Http\\Middleware\\VerifyCsrfToken::class]);\n        \$middleware->web(remove: [\\App\\Http\\Middleware\\VerifyCsrfToken::class]);",
            13
        );

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('VerifyCsrfToken removed from web middleware group', $result->getIssues()[0]->message);
    }

    public function test_reports_medium_when_unreadable_value_replaces_csrf_middleware(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->replaceInGroup('web', \\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class, \$csrfMiddleware);",
            12
        );

        $this->assertWarning($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('ValidateCsrfToken replaced in web middleware group', $result->getIssues()[0]->message);
        $this->assertEquals(Severity::Medium, $result->getIssues()[0]->severity);
        $this->assertNull($result->getIssues()[0]->metadata['replacement']);
    }

    public function test_reports_medium_when_config_value_replaces_csrf_middleware(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->web(replace: [\\Illuminate\\Foundation\\Http\\Middleware\\PreventRequestForgery::class => config('app.csrf')]);",
            13
        );

        $this->assertWarning($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame('PreventRequestForgery replaced in web middleware group', $result->getIssues()[0]->message);
        $this->assertEquals(Severity::Medium, $result->getIssues()[0]->severity);
    }

    public function test_passes_when_unreadable_value_replaces_middleware_the_group_does_not_hold(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$middleware->replaceInGroup('web', \\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class, \$csrfMiddleware);",
            13
        );

        $this->assertPassed($result);
    }

    public function test_reads_middleware_calls_from_a_differently_named_configurator(): void
    {
        $result = $this->analyzeBootstrapMiddleware(
            "\$m = \$middleware;\n        \$m->alias([])->web(remove: [\\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class]);",
            11
        );

        $this->assertFailed($result);
        $this->assertSame('ValidateCsrfToken removed from web middleware group', $result->getIssues()[0]->message);
        $this->assertSame(8, $result->getIssues()[0]->location?->line);
    }

    /**
     * Skip the test unless the running framework's default web group holds the CSRF middleware
     * of the given Laravel major: PreventRequestForgery from 13, ValidateCsrfToken before it.
     */
    private function skipUnlessDefaultWebGroupOf(int $laravelMajor): void
    {
        $running = app()->version();

        if (version_compare($running, '13.0.0', '>=') !== ($laravelMajor >= 13)) {
            $this->markTestSkipped(sprintf('Running on Laravel %s, whose default web group differs from Laravel %d.', $running, $laravelMajor));
        }
    }

    /**
     * Analyze a bootstrap/app.php whose withMiddleware() closure runs the statement, and imports
     * go after the file's own. A test given a Laravel major runs only where the default web
     * group matches it.
     */
    private function analyzeBootstrapMiddleware(string $statement, ?int $laravelMajor = null, string $import = ''): ResultInterface
    {
        if ($laravelMajor !== null) {
            $this->skipUnlessDefaultWebGroupOf($laravelMajor);
        }

        $bootstrap = <<<PHP
<?php

use Illuminate\\Foundation\\Application;{$import}

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (\$middleware) {
        {$statement}
    })
    ->create();
PHP;

        $files = [
            'bootstrap/app.php' => $bootstrap,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ];

        $tempDir = $this->createTempDirectory($files);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['bootstrap', 'resources']);

        return $analyzer->analyze();
    }

    private function analyzeKernel(string $properties, string $import = ''): ResultInterface
    {
        $kernel = <<<PHP
<?php

namespace App\\Http;

{$import}

class Kernel
{
{$properties}
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernel,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources']);

        return $analyzer->analyze();
    }

    private function analyzeKernelWebGroup(string $entry): ResultInterface
    {
        $kernel = <<<PHP
<?php

namespace App\\Http;

class Kernel
{
    protected \$middlewareGroups = [
        'web' => [
            {$entry}
        ],
    ];
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Kernel.php' => $kernel,
            'resources/views/form.blade.php' => '<form method="POST">@csrf</form>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app', 'resources']);

        return $analyzer->analyze();
    }

    // ==================== Route Middleware Tests (6 tests) ====================

    public function test_skips_api_routes_file(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/users', function () {
    // API route - no CSRF needed
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/api.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_warns_post_route_without_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/submit', function () {
    return 'submitted';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/admin.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('route', $result);
    }

    public function test_detects_post_route_with_chained_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/submit', function () {
    return 'submitted';
})->middleware('auth');
PHP;

        $tempDir = $this->createTempDirectory(['routes/custom.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Flags routes with 'auth' middleware (no CSRF protection) in custom route files
        $this->assertFailed($result);
    }

    public function test_passes_put_route_with_middleware(): void
    {
        $routes = <<<'PHP'
<?php

Route::put('/users/{id}', 'UserController@update')->middleware('web');
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_unprotected_route_in_group(): void
    {
        $routes = <<<'PHP'
<?php

Route::group([], function () {
    Route::post('/submit', function () {
        return 'submitted';
    });
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/custom.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('route', $result);
    }

    public function test_detects_multiple_unprotected_routes(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/route1', function () {});
Route::put('/route2', function () {});
Route::patch('/route3', function () {});
Route::delete('/route4', function () {});
PHP;

        $tempDir = $this->createTempDirectory(['routes/custom.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(4, $result->getIssues());
    }

    public function test_skips_routes_in_web_php(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/submit', function () {
    return 'submitted';
});

Route::put('/update', function () {
    return 'updated';
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // routes/web.php automatically gets 'web' middleware globally, so no issues
        $this->assertPassed($result);
    }

    public function test_passes_route_with_web_middleware_array(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/submit', function () {
    return 'submitted';
})->middleware(['web', 'auth']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/custom.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_fails_route_with_auth_middleware_only(): void
    {
        $routes = <<<'PHP'
<?php

Route::post('/submit', function () {
    return 'submitted';
})->middleware(['auth', 'verified']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/custom.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('route', $result);
    }

    public function test_passes_nested_route_groups_with_web(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => 'web'], function () {
    Route::post('/level1', function () {});

    Route::group(['prefix' => 'admin'], function () {
        Route::post('/level2', function () {});

        Route::group(['prefix' => 'settings'], function () {
            Route::post('/level3', function () {});
        });
    });
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/custom.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // All routes inside nested web groups should be protected
        $this->assertPassed($result);
    }

    public function test_passes_route_group_with_web_in_middleware_array(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => ['web', 'auth']], function () {
    Route::post('/protected', function () {});
    Route::put('/update', function () {});
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/custom.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_route_after_web_group_ends(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => 'web'], function () {
    Route::post('/protected', function () {});
});

Route::post('/unprotected', function () {});
PHP;

        $tempDir = $this->createTempDirectory(['routes/custom.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues()); // Only the route outside the group
    }

    public function test_tracks_multiple_separate_web_groups(): void
    {
        $routes = <<<'PHP'
<?php

Route::group(['middleware' => 'web'], function () {
    Route::post('/group1', function () {});
});

Route::post('/between', function () {});

Route::group(['middleware' => 'web'], function () {
    Route::post('/group2', function () {});
});
PHP;

        $tempDir = $this->createTempDirectory(['routes/custom.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues()); // Only /between route
    }

    public function test_passes_route_with_web_after_another_middleware_in_array(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::post('/invoices', [InvoiceController::class, 'store'])->middleware(['auth', 'web']);
PHP);

        $this->assertPassed($result);
    }

    public function test_passes_route_with_web_as_a_later_middleware_argument(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::post('/invoices', [InvoiceController::class, 'store'])->middleware('auth', 'web');
PHP);

        $this->assertPassed($result);
    }

    public function test_fails_route_with_web_after_a_leading_middleware_array(): void
    {
        // Laravel reads a leading array as the whole list and drops the later arguments
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::post('/invoices', [InvoiceController::class, 'store'])->middleware(['auth'], 'web');
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_passes_route_group_with_web_after_another_middleware(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::group(['prefix' => 'billing', 'middleware' => ['auth', 'web']], function () {
    Route::post('/invoices', [InvoiceController::class, 'store']);
});
PHP);

        $this->assertPassed($result);
    }

    public function test_passes_fluent_route_group_with_web_middleware(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::middleware(['auth', 'web'])->prefix('billing')->group(function () {
    Route::post('/invoices', [InvoiceController::class, 'store']);
    Route::delete('/invoices/{invoice}', [InvoiceController::class, 'destroy']);
});
PHP);

        $this->assertPassed($result);
    }

    public function test_passes_route_after_nested_group_inside_web_group(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::group(['middleware' => 'web'], function () {
    Route::group(['prefix' => 'billing'], function () {
        Route::post('/invoices', [InvoiceController::class, 'store']);
    });

    Route::post('/receipts', [ReceiptController::class, 'store']);
});
PHP);

        $this->assertPassed($result);
    }

    public function test_route_does_not_borrow_web_middleware_from_next_statement(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::post('/invoices', [InvoiceController::class, 'store']);
Route::post('/receipts', [ReceiptController::class, 'store'])->middleware('web');
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame(3, $result->getIssues()[0]->location?->line);
    }

    public function test_web_group_on_one_line_covers_only_its_own_routes(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::middleware('web')->group(fn () => Route::post('/invoices', [InvoiceController::class, 'store']));

Route::post('/receipts', [ReceiptController::class, 'store']);
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame(5, $result->getIssues()[0]->location?->line);
    }

    public function test_commented_out_web_middleware_does_not_protect_route(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::post('/invoices', [InvoiceController::class, 'store'])
    // ->middleware('web')
    ->name('invoices.store');
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_ignores_commented_out_route(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

// Route::post('/invoices', [InvoiceController::class, 'store']);
/* Route::put('/invoices/{invoice}', [InvoiceController::class, 'update']); */
PHP);

        $this->assertPassed($result);
    }

    public function test_reports_multi_line_route_on_its_route_line(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::patch(
    '/invoices/{invoice}',
    [InvoiceController::class, 'update']
)->middleware('auth');
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertSame(3, $issue->location?->line);
        $this->assertSame('PATCH route in custom route file missing CSRF protection - no "web" middleware detected', $issue->message);
    }

    public function test_reports_routes_sharing_a_line_once(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::post('/invoices', [InvoiceController::class, 'store']); Route::put('/invoices/{invoice}', [InvoiceController::class, 'update']);
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_passes_web_middleware_called_in_mixed_case(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::post('/invoices', [InvoiceController::class, 'store'])->Middleware('web');

Route::MIDDLEWARE('web')->group(function () {
    Route::post('/receipts', [ReceiptController::class, 'store']);
});
PHP);

        $this->assertPassed($result);
    }

    public function test_fails_route_excluding_csrf_middleware_inside_web_group(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::middleware('web')->group(function () {
    Route::post('/payments/callback', PaymentCallbackController::class)
        ->withoutMiddleware([VerifyCsrfToken::class]);
    Route::post('/payments/notify', PaymentNotifyController::class)->withoutMiddleware('web');
    Route::post('/payments', [PaymentController::class, 'store']);
});
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(2, $result);
        $this->assertSame(
            'POST route in custom route file missing CSRF protection - the CSRF middleware is excluded from it',
            $result->getIssues()[0]->message,
        );
        $this->assertSame(4, $result->getIssues()[0]->location?->line);
        $this->assertSame(6, $result->getIssues()[1]->location?->line);
    }

    public function test_fails_routes_in_group_excluding_csrf_middleware(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::middleware('web')->group(function () {
    Route::withoutMiddleware(ValidateCsrfToken::class)->group(function () {
        Route::post('/payments/callback', PaymentCallbackController::class);
    });

    Route::group(['excluded_middleware' => ['web']], function () {
        Route::post('/payments/notify', PaymentNotifyController::class);
    });
});
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(2, $result);
    }

    public function test_excluding_other_middleware_keeps_web_protection(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::middleware('web')->group(function () {
    Route::post('/payments', [PaymentController::class, 'store'])->withoutMiddleware('throttle');
});
PHP);

        $this->assertPassed($result);
    }

    public function test_fails_fluent_and_other_state_changing_route_forms(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::middleware('auth')->post('/invoices', [InvoiceController::class, 'store']);
Route::prefix('billing')->delete('/invoices/{invoice}', [InvoiceController::class, 'destroy']);
Route::match(['get', 'post'], '/search', SearchController::class);
Route::any('/hooks', HookController::class);
Route::resource('receipts', ReceiptController::class);
PHP);

        $this->assertFailed($result);
        $this->assertSame(
            ['POST', 'DELETE', 'MATCH', 'ANY', 'RESOURCE'],
            array_map(fn ($issue) => $issue->metadata['method'], $result->getIssues()),
        );
    }

    public function test_passes_read_only_match_and_resource_routes(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::match(['get', 'head'], '/reports', ReportController::class);
Route::resource('reports', ReportController::class)->only(['index', 'show']);
Route::resource('exports', ExportController::class)->except('store', 'update', 'destroy');
Route::get('/status', StatusController::class);
PHP);

        $this->assertPassed($result);
    }

    public function test_passes_read_only_resource_routes_filtered_by_options(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::resource('reports', ReportController::class, ['only' => ['index', 'show']]);
Route::resource('exports', ExportController::class, ['except' => ['store', 'update', 'destroy']]);
PHP);

        $this->assertPassed($result);
    }

    public function test_resource_only_call_replaces_only_option(): void
    {
        // PendingResourceRegistration::only() overwrites the 'only' option
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::resource('reports', ReportController::class, ['only' => ['index']])->only(['index', 'store']);
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_passes_resource_with_web_middleware_option(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::resource('receipts', ReceiptController::class, ['middleware' => ['auth', 'web']]);
PHP);

        $this->assertPassed($result);
    }

    public function test_resource_middleware_call_replaces_middleware_option(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::resource('receipts', ReceiptController::class, ['middleware' => 'web'])->middleware('auth');
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_resource_middleware_call_reads_only_its_first_argument(): void
    {
        // Unlike a route, a resource registration wraps one argument and ignores the rest
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::resource('receipts', ReceiptController::class)->middleware('auth', 'web');
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_resource_excluded_middleware_option_strips_csrf(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::middleware('web')->group(function () {
    Route::resource('receipts', ReceiptController::class, ['excluded_middleware' => [VerifyCsrfToken::class]]);
});
PHP);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('the CSRF middleware is excluded from it', $result);
    }

    public function test_passes_fluent_routes_with_web_middleware(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::middleware('web')->post('/invoices', [InvoiceController::class, 'store']);
Route::resource('receipts', ReceiptController::class)->middleware(['auth', 'web']);
PHP);

        $this->assertPassed($result);
    }

    public function test_passes_router_variable_group_with_web_attribute(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

$router->group(['middleware' => 'web'], function () use ($router) {
    $router->post('/invoices', [InvoiceController::class, 'store']);
});
PHP);

        $this->assertPassed($result);
    }

    public function test_fails_router_variable_route_without_web(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

$router->post('/invoices', [InvoiceController::class, 'store']);
$client->post('/invoices', ['amount' => 10]);
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_passes_web_group_with_variable_callback(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

$billingRoutes = function () {
    Route::post('/invoices', [InvoiceController::class, 'store']);
};

Route::middleware('web')->group($billingRoutes);
PHP);

        $this->assertPassed($result);
    }

    public function test_reassigned_variable_callback_binds_to_closure_assigned_before_group(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

$routes = function () {
    Route::post('/invoices', [InvoiceController::class, 'store']);
};
Route::middleware('web')->group($routes);

$routes = function () {
    Route::post('/receipts', [ReceiptController::class, 'store']);
};
Route::middleware('auth')->group($routes);
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame(9, $result->getIssues()[0]->location?->line);
    }

    public function test_reports_route_excluding_aliased_csrf_middleware(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

use App\Http\Middleware\VerifyCsrfToken as CsrfGuard;

Route::middleware('web')->group(function () {
    Route::post('/payments/callback', PaymentCallbackController::class)->withoutMiddleware(CsrfGuard::class);
});
PHP);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('the CSRF middleware is excluded from it', $result);
    }

    public function test_passes_routes_applying_csrf_middleware_directly(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Session\Middleware\StartSession;

Route::post('/invoices', [InvoiceController::class, 'store'])
    ->middleware([StartSession::class, PreventRequestForgery::class]);

Route::group(['middleware' => [StartSession::class, VerifyCsrfToken::class]], function () {
    Route::post('/receipts', [ReceiptController::class, 'store']);
});
PHP);

        $this->assertPassed($result);
    }

    public function test_fails_group_with_variable_callback_without_web(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

$billingRoutes = function () {
    Route::post('/invoices', [InvoiceController::class, 'store']);
};

Route::middleware('auth')->group($billingRoutes);
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_passes_file_required_inside_web_group_of_custom_route_file(): void
    {
        $tempDir = $this->createTempDirectory([
            'routes/admin.php' => <<<'PHP'
<?php

Route::middleware('web')->group(function () {
    require __DIR__.'/admin-billing.php';
});

require __DIR__.'/admin-reports.php';
PHP,
            'routes/admin-billing.php' => <<<'PHP'
<?php

require __DIR__.'/admin-billing-refunds.php';

Route::post('/invoices', [InvoiceController::class, 'store']);
PHP,
            'routes/admin-billing-refunds.php' => <<<'PHP'
<?php

Route::post('/refunds', [RefundController::class, 'store']);
PHP,
            'routes/admin-reports.php' => <<<'PHP'
<?php

Route::post('/reports', [ReportController::class, 'store']);
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertStringEndsWith('admin-reports.php', (string) $result->getIssues()[0]->location?->file);
    }

    // ==================== Excluded CSRF in Covered Route Files ====================

    public function test_reports_web_php_route_excluding_csrf_middleware(): void
    {
        $result = $this->analyzeRouteFiles(['routes/web.php' => <<<'PHP'
<?php

use App\Http\Middleware\VerifyCsrfToken;

Route::post('/orders', [OrderController::class, 'store']);

Route::post('/orders/notify', OrderNotifyController::class)
    ->withoutMiddleware(VerifyCsrfToken::class);
PHP]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $issue = $result->getIssues()[0];
        $this->assertSame('POST route excludes the CSRF middleware through withoutMiddleware() or excluded_middleware', $issue->message);
        $this->assertSame(Severity::High, $issue->severity);
        $this->assertSame(7, $issue->location?->line);
    }

    public function test_reports_web_php_group_excluding_web(): void
    {
        $result = $this->analyzeRouteFiles(['routes/web.php' => <<<'PHP'
<?php

Route::group(['excluded_middleware' => ['web']], function () {
    Route::delete('/sessions', [SessionController::class, 'destroy']);
    Route::get('/sessions', [SessionController::class, 'index']);
});
PHP]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('DELETE route excludes the CSRF middleware', $result);
    }

    public function test_passes_web_php_route_excluding_other_middleware(): void
    {
        $result = $this->analyzeRouteFiles(['routes/web.php' => <<<'PHP'
<?php

Route::post('/orders', [OrderController::class, 'store'])->withoutMiddleware('auth');
PHP]);

        $this->assertPassed($result);
    }

    public function test_reports_excluded_csrf_in_file_registered_under_web_in_bootstrap(): void
    {
        $result = $this->analyzeRouteFiles([
            'bootstrap/app.php' => <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::middleware('web')->group(base_path('routes/portal.php'));
        },
    )
    ->create();
PHP,
            'routes/web.php' => '<?php',
            'routes/portal.php' => <<<'PHP'
<?php

Route::post('/portal/messages', [MessageController::class, 'store']);
Route::put('/portal/hooks', HookController::class)->withoutMiddleware('web');
PHP,
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('PUT route excludes the CSRF middleware', $result);
    }

    public function test_reports_file_required_inside_group_excluding_csrf_in_web_php(): void
    {
        $result = $this->analyzeRouteFiles([
            'routes/web.php' => <<<'PHP'
<?php

use App\Http\Middleware\VerifyCsrfToken;

Route::withoutMiddleware(VerifyCsrfToken::class)->group(function () {
    require __DIR__.'/hooks.php';
});
PHP,
            'routes/hooks.php' => <<<'PHP'
<?php

Route::post('/hooks/billing', BillingHookController::class);
PHP,
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('the CSRF middleware is excluded from it', $result);
        $this->assertStringEndsWith('hooks.php', (string) $result->getIssues()[0]->location?->file);
    }

    public function test_excluding_the_framework_verify_csrf_token_keeps_laravel_13_protection(): void
    {
        // On Laravel 13 VerifyCsrfToken is an empty subclass of PreventRequestForgery, which the
        // web group holds, and excluding a subclass leaves its parent running
        $this->skipUnlessDefaultWebGroupOf(13);

        $result = $this->analyzeRouteFiles(['routes/web.php' => <<<'PHP'
<?php

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;

Route::post('/orders', OrderController::class)->withoutMiddleware(VerifyCsrfToken::class);
Route::post('/refunds', RefundController::class)->withoutMiddleware(ValidateCsrfToken::class);
Route::post('/hooks', HookController::class)->withoutMiddleware(PreventRequestForgery::class);
PHP]);

        $this->assertFailed($result);
        $this->assertSame([9], array_map(fn ($issue) => $issue->location?->line, $result->getIssues()));
    }

    public function test_excluding_the_framework_verify_csrf_token_strips_protection_before_laravel_13(): void
    {
        $this->skipUnlessDefaultWebGroupOf(12);

        $result = $this->analyzeRouteFiles(['routes/web.php' => <<<'PHP'
<?php

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;

Route::post('/orders', OrderController::class)->withoutMiddleware(VerifyCsrfToken::class);
PHP]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    public function test_excluding_the_framework_verify_csrf_token_strips_an_application_subclass(): void
    {
        // The application's own VerifyCsrfToken extends the framework's, so excluding the
        // framework class removes it on every version
        $result = $this->analyzeRouteFiles([
            'app/Http/Middleware/VerifyCsrfToken.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nclass VerifyCsrfToken extends \\Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken\n{\n}\n",
            'routes/web.php' => <<<'PHP'
<?php

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;

Route::post('/orders', OrderController::class)->withoutMiddleware(VerifyCsrfToken::class);
PHP,
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
    }

    /**
     * @dataProvider webGroupCsrfExclusionProvider
     */
    #[DataProvider('webGroupCsrfExclusionProvider')]
    public function test_exclusion_is_matched_against_the_web_group_csrf_middleware(string $statement, string $excluded, bool $reported): void
    {
        $this->assertSame($reported, $this->webPhpExclusionReported($statement, $excluded));
    }

    public function test_excluding_the_versions_base_csrf_class_strips_a_subclass_in_the_web_group(): void
    {
        // Laravel 13 derives ValidateCsrfToken from PreventRequestForgery; earlier versions from VerifyCsrfToken
        $framework = '\\Illuminate\\Foundation\\Http\\Middleware\\';
        $group = "\$middleware->group('web', [{$framework}ValidateCsrfToken::class]);";
        $laravel13 = version_compare(app()->version(), '13.0.0', '>=');

        $this->assertSame($laravel13, $this->webPhpExclusionReported($group, "{$framework}PreventRequestForgery"));
        $this->assertSame(! $laravel13, $this->webPhpExclusionReported($group, "{$framework}VerifyCsrfToken"));
    }

    public function test_exclusion_of_a_class_removed_from_the_web_group_strips_nothing(): void
    {
        $app = '\\App\\Http\\Middleware\\VerifyCsrfToken';
        $framework = '\\Illuminate\\Foundation\\Http\\Middleware\\';

        $this->assertFalse($this->webPhpExclusionReported(
            "\$middleware->group('web', [{$app}::class, {$framework}ValidateCsrfToken::class]); \$middleware->web(remove: [{$app}::class]);",
            $app,
        ));
    }

    public function test_unreadable_web_group_entry_falls_back_to_the_assumed_csrf_class(): void
    {
        $this->assertTrue($this->webPhpExclusionReported(
            "\$middleware->group('web', [\$csrfMiddleware]);",
            '\\App\\Http\\Middleware\\VerifyCsrfToken',
        ));
    }

    /**
     * @dataProvider unreadableWebGroupListProvider
     */
    #[DataProvider('unreadableWebGroupListProvider')]
    public function test_unreadable_web_group_list_falls_back_to_the_assumed_csrf_class(string $statement): void
    {
        $this->assertTrue($this->webPhpExclusionReported($statement, '\\App\\Http\\Middleware\\VerifyCsrfToken'));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unreadableWebGroupListProvider(): array
    {
        return [
            'web(append:)' => ['$middleware->web(append: $extra);'],
            'web(remove:)' => ['$middleware->web(remove: $extra);'],
            'appendToGroup()' => ["\$middleware->appendToGroup('web', \$extra);"],
            'removeFromGroup()' => ["\$middleware->removeFromGroup('web', \$extra);"],
            'web(replace:)' => ['$middleware->web(replace: $map);'],
            'a replace key' => ['$middleware->web(replace: [$search => \\App\\Http\\Middleware\\VerifyCsrfToken::class]);'],
            'replaceInGroup()' => ["\$middleware->replaceInGroup('web', \$search, \\App\\Http\\Middleware\\VerifyCsrfToken::class);"],
        ];
    }

    public function test_web_group_configured_outside_a_closure_falls_back_to_the_assumed_csrf_class(): void
    {
        $result = $this->analyzeRouteFiles([
            'bootstrap/app.php' => <<<'PHP'
<?php

use App\Http\ConfigureMiddleware;
use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(web: __DIR__.'/../routes/web.php')
    ->withMiddleware(new ConfigureMiddleware)
    ->create();
PHP,
            'routes/web.php' => "<?php\n\nRoute::post('/orders', OrderController::class)->withoutMiddleware(\\App\\Http\\Middleware\\VerifyCsrfToken::class);\n",
        ]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('POST route excludes the CSRF middleware', $result);
    }

    public function test_csrf_middleware_appended_to_the_web_group_counts(): void
    {
        $framework = '\\Illuminate\\Foundation\\Http\\Middleware\\';
        $app = '\\App\\Http\\Middleware\\VerifyCsrfToken';

        $this->assertTrue($this->webPhpExclusionReported(
            "\$middleware->group('web', [{$framework}ValidateCsrfToken::class]); \$middleware->web(remove: [{$framework}ValidateCsrfToken::class], append: [{$app}::class]);",
            "{$framework}VerifyCsrfToken",
        ));
    }

    public function test_application_csrf_class_is_matched_by_the_class_it_extends(): void
    {
        $framework = '\\Illuminate\\Foundation\\Http\\Middleware\\';
        $files = ['app/Http/Middleware/ValidateCsrfToken.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nuse Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken as Middleware;\n\nclass ValidateCsrfToken extends Middleware\n{\n}\n"];
        $group = "\$middleware->group('web', [\\App\\Http\\Middleware\\ValidateCsrfToken::class]);";

        // The framework's ValidateCsrfToken is its parent on every version; VerifyCsrfToken is
        // an ancestor only before Laravel 13
        $this->assertTrue($this->webPhpExclusionReported($group, "{$framework}ValidateCsrfToken", files: $files));
        $this->assertSame(
            version_compare(app()->version(), '13.0.0', '<'),
            $this->webPhpExclusionReported($group, "{$framework}VerifyCsrfToken", files: $files),
        );
    }

    public function test_application_prevent_request_forgery_subclass_keeps_protection_when_verify_csrf_token_is_excluded(): void
    {
        $this->skipUnlessDefaultWebGroupOf(13);

        $framework = '\\Illuminate\\Foundation\\Http\\Middleware\\';
        $this->assertFalse($this->webPhpExclusionReported(
            "\$middleware->web(replace: [{$framework}PreventRequestForgery::class => \\App\\Http\\Middleware\\PreventRequestForgery::class]);",
            "{$framework}VerifyCsrfToken",
            files: ['app/Http/Middleware/PreventRequestForgery.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nclass PreventRequestForgery extends \\Illuminate\\Foundation\\Http\\Middleware\\PreventRequestForgery\n{\n}\n"],
        ));
    }

    public function test_excluding_a_csrf_class_the_route_applies_itself_removes_it(): void
    {
        $result = $this->analyzeRouteFiles([
            'bootstrap/app.php' => <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(web: __DIR__.'/../routes/web.php')
    ->withMiddleware(function ($middleware) {
    })
    ->create();
PHP,
            'app/Http/Middleware/VerifyCsrfToken.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nclass VerifyCsrfToken extends \\Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken\n{\n}\n",
            'routes/web.php' => '<?php',
            'routes/partner.php' => <<<'PHP'
<?php

use App\Http\Middleware\VerifyCsrfToken;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;

Route::middleware(['throttle:60,1', ValidateCsrfToken::class])->group(function () {
    Route::post('/hooks', HookController::class)->withoutMiddleware(ValidateCsrfToken::class);
});

Route::post('/orders', OrderController::class)->middleware(VerifyCsrfToken::class)->withoutMiddleware(VerifyCsrfToken::class);

Route::middleware(['web', VerifyCsrfToken::class])->group(function () {
    Route::post('/refunds', RefundController::class)->withoutMiddleware(VerifyCsrfToken::class);
});
PHP,
        ]);

        // The web group's own CSRF middleware still checks /refunds
        $this->assertFailed($result);
        $this->assertSame([7, 10], array_map(fn ($issue) => $issue->location?->line, $result->getIssues()));
        $this->assertHasIssueContaining('the CSRF middleware is excluded from it', $result);
    }

    public function test_csrf_class_a_covered_route_applies_survives_an_exclusion_of_the_web_group_class(): void
    {
        $result = $this->analyzeRouteFiles([
            'bootstrap/app.php' => <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(web: __DIR__.'/../routes/web.php')
    ->withMiddleware(function ($middleware) {
        $middleware->group('web', [ValidateCsrfToken::class]);
    })
    ->create();
PHP,
            'routes/web.php' => <<<'PHP'
<?php

use App\Http\Middleware\VerifyCsrfToken;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;

// The route's own VerifyCsrfToken is not a ValidateCsrfToken, so it still checks the token
Route::post('/orders', OrderController::class)
    ->middleware(VerifyCsrfToken::class)
    ->withoutMiddleware(ValidateCsrfToken::class);
PHP,
        ]);

        $this->assertPassed($result);
    }

    public function test_excluding_web_removes_a_csrf_class_the_route_applies_when_the_group_is_not_modelled(): void
    {
        // Router::resolveMiddleware() expands an excluded 'web' to the group's members; without
        // bootstrap/app.php the group is assumed to hold the application's CSRF middleware
        $result = $this->analyzeRouteFiles([
            'app/Http/Middleware/VerifyCsrfToken.php' => self::APP_VERIFY_CSRF_TOKEN,
            'routes/partner.php' => "<?php\n\nRoute::post('/orders', OrderController::class)->middleware(\\App\\Http\\Middleware\\VerifyCsrfToken::class)->withoutMiddleware('web');\n",
        ]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('the CSRF middleware is excluded from it', $result);
    }

    public function test_excluding_web_removes_a_csrf_class_only_when_it_extends_the_modelled_group_csrf_middleware(): void
    {
        $route = "->middleware(\\App\\Http\\Middleware\\VerifyCsrfToken::class)->withoutMiddleware('web'";
        $result = $this->analyzeRouteFiles([
            'bootstrap/app.php' => "<?php\n\nuse Illuminate\\Foundation\\Application;\n\nreturn Application::configure(basePath: dirname(__DIR__))\n    ->withRouting(then: function () {})\n    ->withMiddleware(function (\$middleware) {})\n    ->create();\n",
            'app/Http/Middleware/VerifyCsrfToken.php' => self::APP_VERIFY_CSRF_TOKEN,
            'routes/partner.php' => "<?php\n\nRoute::post('/orders', OrderController::class){$route});\n",
        ]);

        // The application class extends PreventRequestForgery, the default group's, only on Laravel 13
        if (version_compare(app()->version(), '13.0.0', '>=')) {
            $this->assertFailed($result);
            $this->assertHasIssueContaining('the CSRF middleware is excluded from it', $result);
        } else {
            $this->assertPassed($result);
        }
    }

    public function test_application_csrf_class_is_matched_through_every_parent(): void
    {
        $this->assertTrue($this->webPhpExclusionReported(
            "\$middleware->group('web', [\\App\\Http\\Middleware\\TenantVerifyCsrfToken::class]);",
            '\\Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken',
            files: [
                'app/Http/Middleware/TenantVerifyCsrfToken.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nclass TenantVerifyCsrfToken extends BaseVerifyCsrfToken\n{\n}\n",
                'app/Http/Middleware/BaseVerifyCsrfToken.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nclass BaseVerifyCsrfToken extends \\Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken\n{\n}\n",
            ],
        ));
    }

    public function test_file_the_api_routes_also_load_is_reported_when_a_web_load_strips_it(): void
    {
        $result = $this->analyzeRouteFiles([
            'bootstrap/app.php' => <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        then: function () {
            Route::middleware('web')->withoutMiddleware('web')->group(base_path('routes/partner.php'));
        },
    )
    ->create();
PHP,
            // A file web.php requires is covered, so a group there that strips CSRF strips a web load
            'routes/web.php' => "<?php\n\nrequire __DIR__.'/account.php';\n",
            'routes/account.php' => <<<'PHP'
<?php

Route::withoutMiddleware('web')->group(function () {
    require __DIR__.'/shared-hooks.php';
});
PHP,
            // The stripped partner file passes its strip down to what it requires
            'routes/partner.php' => "<?php\n\nrequire __DIR__.'/shared-orders.php';\n",
            'routes/api.php' => "<?php\n\nrequire __DIR__.'/shared-hooks.php';\nrequire __DIR__.'/shared-orders.php';\n",
            'routes/shared-hooks.php' => "<?php\n\nRoute::post('/hooks', HookController::class);\n",
            'routes/shared-orders.php' => "<?php\n\nRoute::post('/orders', OrderController::class);\n",
        ]);

        $this->assertFailed($result);
        $files = array_map(fn ($issue) => basename((string) $issue->location?->file), $result->getIssues());
        sort($files);
        $this->assertSame(['shared-hooks.php', 'shared-orders.php'], $files);
        foreach ($result->getIssues() as $issue) {
            $this->assertStringContainsString('the CSRF middleware is excluded from it', $issue->message);
        }
    }

    public function test_strip_on_a_plain_load_removes_only_what_routes_apply_themselves(): void
    {
        $result = $this->analyzeRouteFiles([
            'bootstrap/app.php' => <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(then: function () {
        Route::prefix('hooks')->group(base_path('routes/hooks.php'));
    })
    ->create();
PHP,
            'routes/hooks.php' => <<<'PHP'
<?php

Route::withoutMiddleware('web')->group(function () {
    Route::post('/inline', InlineHookController::class);
    require __DIR__.'/hooks-stripe.php';
});
PHP,
            'routes/hooks-stripe.php' => "<?php\n\nRoute::post('/stripe', StripeController::class);\nRoute::middleware('web')->post('/stripe/portal', StripePortalController::class);\n",
        ]);

        // No web load exists, so a route without 'web' is missing it rather than excluded from it
        $messages = [];
        foreach ($result->getIssues() as $issue) {
            $messages[basename((string) $issue->location?->file).':'.$issue->location?->line] = str_contains($issue->message, 'excluded from it') ? 'stripped' : 'missing';
        }
        ksort($messages);
        $this->assertSame(['hooks-stripe.php:3' => 'missing', 'hooks-stripe.php:4' => 'stripped', 'hooks.php:4' => 'missing'], $messages);
    }

    public function test_csrf_exclusion_on_an_api_load_leaves_a_file_web_also_loads_protected(): void
    {
        // Laravel registers the file twice: the web copy keeps CSRF, the api copy never had it
        $result = $this->analyzeRouteFiles([
            'app/Providers/RouteServiceProvider.php' => <<<'PHP'
<?php

namespace App\Providers;

use App\Http\Middleware\VerifyCsrfToken;
use Illuminate\Support\Facades\Route;

class RouteServiceProvider
{
    public function boot(): void
    {
        Route::middleware('api')->withoutMiddleware(VerifyCsrfToken::class)->prefix('api')->group(base_path('routes/api.php'));
        Route::middleware('web')->group(base_path('routes/web.php'));
    }
}
PHP,
            'routes/web.php' => "<?php\n\nrequire __DIR__.'/shared.php';\n",
            'routes/api.php' => <<<'PHP'
<?php

require __DIR__.'/shared.php';

Route::withoutMiddleware('web')->group(function () {
    require __DIR__.'/shared-account.php';
});
PHP,
            'routes/shared.php' => "<?php\n\nrequire __DIR__.'/shared-child.php';\n\nRoute::post('/newsletter', NewsletterController::class);\n",
            'routes/shared-child.php' => "<?php\n\nRoute::post('/newsletter/confirm', NewsletterController::class);\n",
            'routes/shared-account.php' => "<?php\n\nRoute::post('/account', AccountController::class);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_csrf_exclusion_on_an_api_load_removes_nothing(): void
    {
        // The api group never ran CSRF, so excluding it out of habit leaves the file an api file
        $result = $this->analyzeRouteFiles([
            'app/Providers/RouteServiceProvider.php' => <<<'PHP'
<?php

namespace App\Providers;

use App\Http\Middleware\VerifyCsrfToken;
use Illuminate\Support\Facades\Route;

class RouteServiceProvider
{
    public function boot(): void
    {
        Route::middleware('api')->prefix('api')->group(base_path('routes/api.php'));
        Route::middleware('api')->withoutMiddleware([VerifyCsrfToken::class])->prefix('webhooks')->group(base_path('routes/webhooks.php'));
    }
}
PHP,
            'routes/api.php' => <<<'PHP'
<?php

use App\Http\Middleware\VerifyCsrfToken;

Route::post('/orders', [OrderController::class, 'store']);
Route::withoutMiddleware(VerifyCsrfToken::class)->group(function () {
    require __DIR__.'/api-hooks.php';
});
PHP,
            'routes/api-hooks.php' => "<?php\n\nRoute::post('/hooks', HookController::class);\n",
            'routes/webhooks.php' => "<?php\n\nRoute::post('/stripe', StripeController::class);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_exclusion_written_with_a_leading_backslash_names_the_class(): void
    {
        $this->assertTrue($this->webPhpExclusionReported(
            "\$middleware->group('web', [\\App\\Http\\Middleware\\VerifyCsrfToken::class]);",
            "'\\App\\Http\\Middleware\\VerifyCsrfToken'",
            literal: true,
        ));

        $result = $this->analyzeRouteFile("<?php\n\nRoute::post('/orders', OrderController::class)->middleware(\\App\\Http\\Middleware\\VerifyCsrfToken::class)->withoutMiddleware('\\App\\Http\\Middleware\\VerifyCsrfToken');\n");

        $this->assertFailed($result);
        $this->assertHasIssueContaining('the CSRF middleware is excluded from it', $result);
    }

    public function test_route_exclusions_add_up_along_the_chain(): void
    {
        $result = $this->analyzeRouteFiles(['routes/web.php' => "<?php\n\nRoute::withoutMiddleware('web')->withoutMiddleware('throttle')->post('/orders', OrderController::class);\nRoute::post('/refunds', RefundController::class)->withoutMiddleware('web')->withoutMiddleware('throttle');\n"]);

        $this->assertFailed($result);
        $this->assertIssueCount(2, $result);
    }

    public function test_exclusion_from_a_web_group_without_csrf_middleware_removes_nothing(): void
    {
        // The redefined group is reported in bootstrap/app.php; the route has nothing left to lose
        $this->assertFalse($this->webPhpExclusionReported(
            "\$middleware->group('web', ['auth']);",
            '\\App\\Http\\Middleware\\VerifyCsrfToken',
        ));
    }

    public function test_exclusion_must_remove_every_csrf_middleware_in_the_web_group(): void
    {
        // The default CSRF middleware stays when only the appended application class is excluded
        $this->assertFalse($this->webPhpExclusionReported(
            '$middleware->web(append: [\\App\\Http\\Middleware\\VerifyCsrfToken::class]);',
            '\\App\\Http\\Middleware\\VerifyCsrfToken',
        ));
    }

    public function test_web_group_model_does_not_carry_over_to_the_next_analysis(): void
    {
        $this->assertFalse($this->webPhpExclusionReported(
            "\$middleware->group('web', [\\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class]);",
            '\\App\\Http\\Middleware\\VerifyCsrfToken',
            $analyzer = $this->createAnalyzer(),
        ));

        // Without bootstrap/app.php the group is not modelled, and an application class counts
        $analyzer->setBasePath($this->createTempDirectory([
            'routes/web.php' => "<?php\n\nRoute::post('/orders', OrderController::class)->withoutMiddleware(\\App\\Http\\Middleware\\VerifyCsrfToken::class);\n",
        ]));
        $analyzer->setPaths(['routes']);

        $this->assertFailed($analyzer->analyze());
    }

    /**
     * Whether a routes/web.php route excluding $excluded is reported when bootstrap/app.php
     * configures the web group with $statement.
     *
     * @param  array<string, string>  $files  Further files, such as application middleware
     * @param  bool  $literal  Whether $excluded is the argument as written rather than a class name
     */
    private function webPhpExclusionReported(string $statement, string $excluded, ?CsrfAnalyzer $analyzer = null, array $files = [], bool $literal = false): bool
    {
        $tempDir = $this->createTempDirectory([
            ...$files,
            'bootstrap/app.php' => <<<PHP
<?php

use Illuminate\\Foundation\\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(web: __DIR__.'/../routes/web.php')
    ->withMiddleware(function (\$middleware) {
        {$statement}
    })
    ->create();
PHP,
            'routes/web.php' => "<?php\n\nRoute::post('/orders', OrderController::class)->withoutMiddleware(".($literal ? $excluded : "{$excluded}::class").");\n",
        ]);

        $analyzer ??= $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        foreach ($analyzer->analyze()->getIssues() as $issue) {
            if (str_ends_with($issue->location->file ?? '', 'routes/web.php')) {
                $this->assertStringContainsString('POST route excludes the CSRF middleware', $issue->message);

                return true;
            }
        }

        return false;
    }

    /**
     * @return array<string, array{string, string, bool}>
     */
    public static function webGroupCsrfExclusionProvider(): array
    {
        $framework = '\\Illuminate\\Foundation\\Http\\Middleware\\';
        $app = '\\App\\Http\\Middleware\\VerifyCsrfToken';

        return [
            'the class the group holds' => ["\$middleware->group('web', [{$framework}ValidateCsrfToken::class]);", "{$framework}ValidateCsrfToken", true],
            'the framework parent of an application class' => ["\$middleware->group('web', [{$app}::class]);", "{$framework}VerifyCsrfToken", true],
            'an application class the group does not hold' => ['', $app, false],
            'a sibling the group does not extend' => ["\$middleware->group('web', [{$framework}ValidateCsrfToken::class]);", "{$framework}VerifyCsrfTokenAlias", false],
        ];
    }

    public function test_leftover_application_csrf_class_does_not_strip_the_laravel_13_web_group(): void
    {
        $this->skipUnlessDefaultWebGroupOf(13);

        $result = $this->analyzeRouteFiles([
            'bootstrap/app.php' => <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(web: __DIR__.'/../routes/web.php')
    ->create();
PHP,
            'app/Http/Middleware/VerifyCsrfToken.php' => "<?php\n\nnamespace App\\Http\\Middleware;\n\nclass VerifyCsrfToken extends \\Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken\n{\n}\n",
            'routes/web.php' => "<?php\n\nRoute::post('/orders', OrderController::class)->withoutMiddleware(\\Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken::class);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_exclusion_in_a_file_bootstrap_registers_without_web_strips_what_it_requires(): void
    {
        $result = $this->analyzeRouteFiles([
            'bootstrap/app.php' => <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::prefix('admin')->group(base_path('routes/admin.php'));
        },
    )
    ->create();
PHP,
            'routes/web.php' => '<?php',
            'routes/admin.php' => <<<'PHP'
<?php

Route::withoutMiddleware('web')->group(function () {
    require __DIR__.'/admin-hooks.php';
});
PHP,
            'routes/admin-hooks.php' => <<<'PHP'
<?php

Route::middleware('web')->group(function () {
    Route::post('/hooks', HookController::class);
});
PHP,
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('the CSRF middleware is excluded from it', $result);
        $this->assertStringEndsWith('admin-hooks.php', (string) $result->getIssues()[0]->location?->file);
    }

    public function test_require_in_a_file_nothing_loads_does_not_strip_a_covered_file(): void
    {
        $result = $this->analyzeRouteFiles([
            'bootstrap/app.php' => <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(web: [__DIR__.'/../routes/web.php', __DIR__.'/../routes/shop.php'])
    ->create();
PHP,
            'routes/web.php' => '<?php',
            'routes/shop.php' => "<?php\n\nRoute::post('/cart', [CartController::class, 'store']);\n",
            'routes/legacy.php' => <<<'PHP'
<?php

Route::withoutMiddleware('web')->group(function () {
    require __DIR__.'/shop.php';
});
PHP,
        ]);

        $this->assertPassed($result);
    }

    public function test_require_in_a_file_nothing_loads_keeps_the_no_web_message(): void
    {
        $result = $this->analyzeRouteFiles([
            'routes/legacy.php' => <<<'PHP'
<?php

Route::withoutMiddleware('web')->group(function () {
    require __DIR__.'/admin.php';
});
PHP,
            'routes/admin.php' => "<?php\n\nRoute::post('/admin/users', [UserController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('POST route in custom route file missing CSRF protection - no "web" middleware detected', $result);
    }

    public function test_exclusion_in_a_file_loaded_through_a_require_chain_strips_what_it_requires(): void
    {
        $result = $this->analyzeRouteFiles([
            'routes/web.php' => "<?php\n\nrequire __DIR__.'/account.php';\n",
            'routes/account.php' => "<?php\n\nrequire __DIR__.'/account-billing.php';\n",
            'routes/account-billing.php' => <<<'PHP'
<?php

Route::withoutMiddleware('web')->group(function () {
    require __DIR__.'/account-hooks.php';
});
PHP,
            'routes/account-hooks.php' => "<?php\n\nRoute::post('/hooks/billing', BillingHookController::class);\n",
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertStringEndsWith('account-hooks.php', (string) $result->getIssues()[0]->location?->file);
        $this->assertHasIssueContaining('the CSRF middleware is excluded from it', $result);
    }

    public function test_exclusion_in_a_file_nothing_loads_does_not_cover_what_it_requires(): void
    {
        $result = $this->analyzeRouteFiles([
            'routes/legacy.php' => <<<'PHP'
<?php

Route::middleware('web')->group(function () {
    require __DIR__.'/legacy-admin.php';
});
PHP,
            'routes/legacy-admin.php' => <<<'PHP'
<?php

Route::withoutMiddleware('web')->group(function () {
    require __DIR__.'/legacy-hooks.php';
});
PHP,
            'routes/legacy-hooks.php' => "<?php\n\nRoute::post('/hooks', HookController::class);\n",
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('no "web" middleware detected', $result);
    }

    public function test_skips_files_the_api_routes_load_through_requires_and_group_paths(): void
    {
        $result = $this->analyzeRouteFiles([
            'bootstrap/app.php' => <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        api: __DIR__.'/../routes/api.php',
        then: function () {
            Route::middleware('api')->prefix('v2')->group(base_path('routes/api-v2.php'));
        },
    )
    ->create();
PHP,
            'routes/api.php' => <<<'PHP'
<?php

Route::prefix('v1')->group(base_path('routes/api/v1.php'));
require __DIR__.'/api/legacy.php';
PHP,
            'routes/api/v1.php' => "<?php\n\nRoute::apiResource('orders', OrderController::class);\n",
            'routes/api/legacy.php' => "<?php\n\nrequire __DIR__.'/legacy/orders.php';\n",
            'routes/api/legacy/orders.php' => "<?php\n\nRoute::apiResource('orders', OrderController::class);\n",
            'routes/api-v2.php' => "<?php\n\nrequire __DIR__.'/api-v2-admin.php';\n",
            'routes/api-v2-admin.php' => "<?php\n\nRoute::apiResource('users', UserController::class);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_file_the_api_routes_load_inside_a_web_group_is_covered_not_skipped(): void
    {
        $result = $this->analyzeRouteFiles([
            'routes/api.php' => "<?php\n\nRoute::middleware('web')->group(base_path('routes/portal.php'));\n",
            'routes/portal.php' => <<<'PHP'
<?php

Route::post('/portal/messages', [MessageController::class, 'store']);
Route::post('/portal/hooks', HookController::class)->withoutMiddleware('web');
PHP,
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('POST route excludes the CSRF middleware', $result);
    }

    public function test_file_the_api_routes_load_through_a_stripping_web_group_is_reported(): void
    {
        $result = $this->analyzeRouteFiles([
            'routes/api.php' => <<<'PHP'
<?php

use App\Http\Middleware\VerifyCsrfToken;

Route::middleware('web')->withoutMiddleware('web')->group(base_path('routes/spa.php'));
Route::middleware('web')->withoutMiddleware(VerifyCsrfToken::class)->group(function () {
    require __DIR__.'/spa-admin.php';
});
PHP,
            'routes/spa.php' => "<?php\n\nRoute::post('/spa/orders', [OrderController::class, 'store']);\n",
            'routes/spa-admin.php' => "<?php\n\nRoute::post('/spa/users', [UserController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(2, $result);
        $this->assertHasIssueContaining('the CSRF middleware is excluded from it', $result);
    }

    public function test_file_the_api_routes_load_where_a_csrf_class_is_applied_is_not_api(): void
    {
        // On Laravel 13 excluding the class it applies leaves the group no CSRF, yet the load is
        // not an api load: the file is judged on its own routes
        $this->skipUnlessDefaultWebGroupOf(13);

        $result = $this->analyzeRouteFiles([
            'routes/api.php' => "<?php\n\nuse Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken;\n\nRoute::middleware(ValidateCsrfToken::class)->withoutMiddleware(ValidateCsrfToken::class)->group(base_path('routes/spa.php'));\n",
            'routes/spa.php' => "<?php\n\nRoute::post('/spa/orders', [OrderController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertHasIssueContaining('no "web" middleware detected', $result);
    }

    public function test_route_file_group_list_loads_each_file_it_names(): void
    {
        $result = $this->analyzeRouteFiles([
            'routes/api.php' => "<?php\n\nRoute::prefix('v3')->group([__DIR__.'/api/v3.php', base_path('routes/api/v4.php')]);\n",
            'routes/api/v3.php' => "<?php\n\nRoute::apiResources(['orders' => OrderController::class]);\n",
            'routes/api/v4.php' => "<?php\n\nRoute::apiSingleton('profile', ProfileController::class)->creatable();\n",
            'routes/web.php' => <<<'PHP'
<?php

Route::withoutMiddleware('web')->group([
    base_path('routes/hooks.php'),
    function () {
        Route::post('/inline', InlineHookController::class);
    },
]);
PHP,
            'routes/hooks.php' => "<?php\n\nRoute::post('/hooks', HookController::class);\n",
        ]);

        // The api list's files are api files; the web list strips both its file and its closure
        $this->assertFailed($result);
        $files = array_map(fn ($issue) => basename((string) $issue->location?->file), $result->getIssues());
        sort($files);
        $this->assertSame(['hooks.php', 'web.php'], $files);
    }

    public function test_file_web_php_loads_through_a_group_path_is_covered(): void
    {
        $result = $this->analyzeRouteFiles([
            'routes/web.php' => "<?php\n\nRoute::prefix('billing')->group(base_path('routes/billing.php'));\n",
            'routes/billing.php' => "<?php\n\nRoute::post('/invoices', [InvoiceController::class, 'store']);\n",
        ]);

        $this->assertPassed($result);
    }

    public function test_without_middleware_reads_only_its_first_argument(): void
    {
        $result = $this->analyzeRouteFiles(['routes/web.php' => <<<'PHP'
<?php

use App\Http\Middleware\VerifyCsrfToken;

Route::post('/orders', OrderController::class)->withoutMiddleware('auth', VerifyCsrfToken::class);
Route::withoutMiddleware('auth', VerifyCsrfToken::class)->post('/refunds', RefundController::class);
PHP]);

        $this->assertPassed($result);
    }

    public function test_reads_bootstrap_registrations_when_the_project_path_contains_a_routes_directory(): void
    {
        $tempDir = $this->createTempDirectory([
            'routes/shop/bootstrap/app.php' => <<<'PHP'
<?php

use App\Http\Middleware\VerifyCsrfToken;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::middleware('web')->withoutMiddleware('web')->group(base_path('routes/partner.php'));
        },
    )
    ->create();
PHP,
            'routes/shop/routes/partner.php' => "<?php\n\nRoute::post('/orders', [OrderController::class, 'store']);\n",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir.'/routes/shop');
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('the CSRF middleware is excluded from it', $result);
    }

    public function test_file_api_php_requires_inside_a_web_group_is_covered_not_skipped(): void
    {
        $result = $this->analyzeRouteFiles([
            'routes/api.php' => <<<'PHP'
<?php

Route::middleware('web')->group(function () {
    require __DIR__.'/portal.php';
});
PHP,
            'routes/portal.php' => <<<'PHP'
<?php

Route::post('/portal/messages', [MessageController::class, 'store']);
Route::post('/portal/hooks', HookController::class)->withoutMiddleware('web');
PHP,
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('POST route excludes the CSRF middleware', $result);
    }

    public function test_route_file_group_on_the_container_router_reads_its_registrar_middleware(): void
    {
        $result = $this->analyzeRouteFiles([
            'routes/admin.php' => <<<'PHP'
<?php

app()->make('router')->middleware('web')->middleware('auth')->group(function () {
    require __DIR__.'/admin-users.php';
});
PHP,
            'routes/admin-users.php' => "<?php\n\nRoute::post('/users', [UserController::class, 'store']);\n",
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertStringEndsWith('admin-users.php', (string) $result->getIssues()[0]->location?->file);
    }

    public function test_group_path_in_a_variable_callback_is_reached_by_the_group_running_it(): void
    {
        $result = $this->analyzeRouteFiles([
            'routes/web.php' => <<<'PHP'
<?php

$hooks = function () {
    Route::group([], base_path('routes/hooks.php'));
};
Route::withoutMiddleware('web')->group($hooks);
PHP,
            'routes/hooks.php' => "<?php\n\nRoute::post('/hooks', HookController::class);\n",
            'routes/portal.php' => <<<'PHP'
<?php

$portal = function () {
    Route::group([], base_path('routes/portal-web.php'));
};
Route::middleware('web')->group($portal);
PHP,
            'routes/portal-web.php' => "<?php\n\nRoute::post('/portal', PortalController::class);\n",
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertStringEndsWith('hooks.php', (string) $result->getIssues()[0]->location?->file);
        $this->assertHasIssueContaining('the CSRF middleware is excluded from it', $result);
    }

    public function test_group_path_in_a_stripping_group_strips_the_file_it_loads(): void
    {
        $result = $this->analyzeRouteFiles([
            'routes/web.php' => "<?php\n\nRoute::withoutMiddleware('web')->group(base_path('routes/hooks.php'));\n",
            'routes/hooks.php' => "<?php\n\nRoute::middleware('web')->post('/hooks', HookController::class);\n",
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('the CSRF middleware is excluded from it', $result);
    }

    public function test_file_the_api_routes_load_under_web_strips_what_it_requires_outside_web(): void
    {
        $result = $this->analyzeRouteFiles([
            'routes/api.php' => "<?php\n\nRoute::middleware('web')->group(base_path('routes/portal.php'));\n",
            'routes/portal.php' => <<<'PHP'
<?php

Route::withoutMiddleware('web')->group(function () {
    require __DIR__.'/portal-hooks.php';
});
PHP,
            'routes/portal-hooks.php' => "<?php\n\nRoute::post('/portal/hooks', HookController::class);\n",
        ]);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertStringEndsWith('portal-hooks.php', (string) $result->getIssues()[0]->location?->file);
    }

    // ==================== Router Roots Other Than Route:: ====================

    public function test_reads_web_group_opened_on_app_router(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

app('router')->middleware('web')->group(function () {
    Route::post('/orders', [OrderController::class, 'store']);
});

app()->make(\Illuminate\Routing\Router::class)->middleware('web')->group(function () {
    Route::post('/refunds', [RefundController::class, 'store']);
});
PHP);

        $this->assertPassed($result);
    }

    public function test_reports_routes_registered_on_other_router_roots(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

use Illuminate\Contracts\Routing\Registrar;
use Illuminate\Routing\Router;

app('router')->post('/orders', [OrderController::class, 'store']);
resolve(Router::class)->put('/orders', [OrderController::class, 'update']);
$this->router->patch('/orders', [OrderController::class, 'update']);

$register = function (Router $routes) {
    $routes->delete('/orders', [OrderController::class, 'destroy']);
};

function registerRefunds(Registrar $registrar): void
{
    $registrar->post('/refunds', [RefundController::class, 'store']);
}

$routes = app('router');
$routes->any('/payments', PaymentController::class);

$client->post('/orders', ['amount' => 10]);
$this->client->post('/orders', ['amount' => 10]);
PHP);

        $this->assertFailed($result);
        $this->assertSame(
            ['POST', 'PUT', 'PATCH', 'DELETE', 'POST', 'ANY'],
            array_map(fn ($issue) => $issue->metadata['method'], $result->getIssues()),
        );
    }

    public function test_reads_nullable_router_parameter_and_ignores_make_on_a_resolved_service(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

use Illuminate\Routing\Router;

$register = function (?Router $routes) {
    $routes->post('/orders', [OrderController::class, 'store']);
};

app('cache')->make('router')->post('/refunds', ['amount' => 10]);
PHP);

        $this->assertFailed($result);
        $this->assertSame([6], array_map(fn ($issue) => $issue->location?->line, $result->getIssues()));
    }

    public function test_reads_aliased_route_facade(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

use Illuminate\Support\Facades\Route as Routes;

Routes::middleware('web')->group(function () {
    Routes::post('/orders', [OrderController::class, 'store']);
});

Routes::post('/refunds', [RefundController::class, 'store']);
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame(9, $result->getIssues()[0]->location?->line);
    }

    public function test_group_callback_parameter_is_the_router(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::middleware('web')->group(function ($routes) {
    $routes->post('/orders', [OrderController::class, 'store']);
});

Route::middleware('auth')->group(function ($routes) {
    $routes->post('/refunds', [RefundController::class, 'store']);
});

$notify = function ($client) {
    $client->post('/hooks', ['event' => 'paid']);
};
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame(8, $result->getIssues()[0]->location?->line);
    }

    public function test_variable_group_callback_is_reached_by_groups_around_the_call_running_it(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

$billing = function ($routes) {
    $routes->post('/invoices', [InvoiceController::class, 'store']);
};

Route::middleware('web')->group(function () use ($billing) {
    Route::prefix('billing')->group($billing);
});
PHP);

        $this->assertPassed($result);
    }

    public function test_only_the_first_group_callback_parameter_is_the_router(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::middleware('auth')->group(function ($routes, $client) {
    $client->post('/hooks', ['event' => 'paid']);
});
PHP);

        $this->assertPassed($result);
    }

    public function test_router_variable_captured_by_closure_and_arrow_function(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

$routes = app('router');

$register = function () use ($routes) {
    $routes->post('/orders', [OrderController::class, 'store']);
};

$registerRefunds = fn () => $routes->post('/refunds', [RefundController::class, 'store']);

$detached = function () {
    $routes->post('/payments', [PaymentController::class, 'store']);
};
PHP);

        $this->assertFailed($result);
        $this->assertSame([6, 9], array_map(fn ($issue) => $issue->location?->line, $result->getIssues()));
    }

    public function test_reassigned_router_variable_no_longer_reads_as_router(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

$routes = app('router');
$routes->post('/orders', [OrderController::class, 'store']);

$routes = new HttpClient;
$routes->post('/hooks', ['event' => 'paid']);
PHP);

        $this->assertFailed($result);
        $this->assertSame([4], array_map(fn ($issue) => $issue->location?->line, $result->getIssues()));
    }

    public function test_variable_group_callback_parameter_is_the_router(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

$billing = function ($routes) {
    $routes->post('/invoices', [InvoiceController::class, 'store']);
};
Route::prefix('billing')->group($billing);

$orders = function ($routes) {
    $routes->post('/orders', [OrderController::class, 'store']);
};
Route::middleware('web')->group($orders);
PHP);

        $this->assertFailed($result);
        $this->assertSame([4], array_map(fn ($issue) => $issue->location?->line, $result->getIssues()));
    }

    // ==================== Resource Forms ====================

    public function test_reports_api_resource_and_plural_resource_forms(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::apiResource('orders', OrderController::class);
Route::resources(['invoices' => InvoiceController::class]);
Route::apiResources(['receipts' => ReceiptController::class]);
Route::softDeletableResources(['refunds' => RefundController::class]);
Route::middleware('auth')->apiResource('payments', PaymentController::class);
PHP);

        $this->assertFailed($result);
        $this->assertSame(
            [3, 4, 5, 6, 7],
            array_map(fn ($issue) => $issue->location?->line, $result->getIssues()),
        );
        $this->assertSame('RESOURCE', $result->getIssues()[0]->metadata['method']);
    }

    public function test_passes_read_only_api_resource_and_plural_resource_forms(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::apiResource('orders', OrderController::class)->only(['index', 'show']);
Route::apiResource('refunds', RefundController::class, ['except' => ['store', 'update', 'destroy']]);
Route::resources(['invoices' => InvoiceController::class], ['only' => ['index']]);
Route::apiResources(['receipts' => ReceiptController::class], ['except' => ['store', 'update', 'destroy']]);
Route::resources([]);
Route::resources($resources);
Route::apiResource('payments', PaymentController::class)->middleware('web');
Route::resources(['credits' => CreditController::class], ['middleware' => 'web']);
PHP);

        $this->assertPassed($result);
    }

    public function test_reports_singleton_update_and_creatable_writes(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::singleton('profile', ProfileController::class);
Route::apiSingleton('settings', SettingsController::class)->creatable()->except('update');
Route::singleton('avatar', AvatarController::class)->destroyable()->only(['show', 'destroy']);
Route::singletons(['account' => AccountController::class]);
Route::apiSingletons(['plan' => PlanController::class]);
Route::singleton('team', TeamController::class, ['creatable' => true, 'except' => ['update']]);
Route::singleton('logo', LogoController::class, ['destroyable' => true, 'except' => ['update']]);
PHP);

        $this->assertFailed($result);
        $this->assertSame(
            [3, 4, 5, 6, 7, 8, 9],
            array_map(fn ($issue) => $issue->location?->line, $result->getIssues()),
        );
        $this->assertSame('SINGLETON', $result->getIssues()[0]->metadata['method']);
    }

    public function test_passes_read_only_singletons(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::singleton('profile', ProfileController::class)->only('show');
Route::singleton('avatar', AvatarController::class)->except(['update']);
Route::apiSingleton('settings', SettingsController::class, ['only' => ['show']]);
Route::singleton('plan', PlanController::class)->destroyable()->only(['show', 'edit']);
Route::singletons(['account' => AccountController::class], ['except' => ['update']]);
PHP);

        $this->assertPassed($result);
    }

    public function test_resource_middleware_for_covers_only_listed_methods(): void
    {
        // middlewareFor() adds to the resource middleware, before or after middleware() is called
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::apiResource('orders', OrderController::class)->middlewareFor(['store', 'update', 'destroy'], 'web');
Route::apiResource('refunds', RefundController::class)->middlewareFor('store', 'web');
Route::apiResource('payments', PaymentController::class)->middleware('web')->middlewareFor('destroy', 'auth');
Route::apiResource('credits', CreditController::class)->middlewareFor('destroy', 'auth')->middleware('web');
Route::apiResource('vouchers', VoucherController::class)->middlewareFor('destroy', 'web');
Route::apiResource('coupons', CouponController::class)->middlewareFor(['update', 'destroy'], \App\Http\Middleware\VerifyCsrfToken::class);
PHP);

        $this->assertFailed($result);
        $this->assertSame([4, 7, 8], array_map(fn ($issue) => $issue->location?->line, $result->getIssues()));
    }

    public function test_resource_without_middleware_for_strips_csrf_from_a_write(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

use App\Http\Middleware\VerifyCsrfToken;

Route::middleware('web')->group(function () {
    Route::apiResource('orders', OrderController::class)->withoutMiddlewareFor('store', VerifyCsrfToken::class);
    Route::apiResource('refunds', RefundController::class)->withoutMiddlewareFor('index', VerifyCsrfToken::class);
    Route::singleton('profile', ProfileController::class)->withoutMiddleware('web');
    Route::apiResource('payments', PaymentController::class)->withoutMiddlewareFor($methods, VerifyCsrfToken::class);
});
PHP);

        $this->assertFailed($result);
        $this->assertSame([6, 8, 9], array_map(fn ($issue) => $issue->location?->line, $result->getIssues()));
        $this->assertHasIssueContaining('the CSRF middleware is excluded from it', $result);
    }

    public function test_registrar_middleware_is_replaced_by_a_later_resource_middleware_call(): void
    {
        // RouteRegistrar passes its attributes as the resource's options, so a later
        // middleware() call on the pending registration replaces 'web'
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::middleware('web')->apiResource('orders', OrderController::class)->middleware('auth');
Route::middleware('auth')->resource('refunds', RefundController::class, ['middleware' => 'web']);
Route::middleware('web')->singleton('profile', ProfileController::class);
Route::middleware('web', 'auth')->resource('payments', PaymentController::class);
Route::middleware('web')->withoutMiddleware('web')->resource('credits', CreditController::class);
Route::middleware('auth')->middleware('web')->resource('receipts', ReceiptController::class);
Route::middleware('web')->middleware('auth')->resource('vouchers', VoucherController::class);
PHP);

        $this->assertFailed($result);
        $this->assertSame([3, 4, 7, 9], array_map(fn ($issue) => $issue->location?->line, $result->getIssues()));
    }

    public function test_registrar_attributes_between_middleware_calls_keep_the_replace_rule(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::middleware('web')->prefix('admin')->middleware('auth')->group(function () {
    Route::post('/users', [UserController::class, 'store']);
});
Route::middleware('web')->name('billing.')->middleware('auth')->post('/invoices', [InvoiceController::class, 'store']);
Route::middleware('web')->domain('app.myapp.com')->as('app.')->post('/orders', [OrderController::class, 'store']);
PHP);

        $this->assertFailed($result);
        $this->assertSame([4, 6], array_map(fn ($issue) => $issue->location?->line, $result->getIssues()));
    }

    public function test_callback_two_groups_run_is_judged_by_the_weaker_registration(): void
    {
        // Laravel registers the callback's routes once per group; the prefix copy has no 'web'
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

$orders = function () {
    Route::post('/orders', [OrderController::class, 'store']);
};
Route::prefix('legacy')->group($orders);
Route::middleware('web')->group($orders);

$refunds = function () {
    Route::post('/refunds', [RefundController::class, 'store']);
};
Route::middleware('web')->group($refunds);
Route::middleware(['web', 'auth'])->prefix('admin')->group($refunds);
PHP);

        $this->assertFailed($result);
        $this->assertSame([4], array_map(fn ($issue) => $issue->location?->line, $result->getIssues()));
    }

    /**
     * @dataProvider reusedCallbackRegistrationOrderProvider
     */
    #[DataProvider('reusedCallbackRegistrationOrderProvider')]
    public function test_each_registration_of_a_reused_callback_is_judged_with_its_own_groups(string $first, string $second): void
    {
        // Only the registration inside the web group gets 'web'; the legacy one runs without it
        $result = $this->analyzeRouteFile(<<<PHP
<?php

\$admin = function () {
    Route::post('/admin/orders', [OrderController::class, 'store']);
};
{$first}
{$second}
PHP);

        $this->assertFailed($result);
        $this->assertSame([4], array_map(fn ($issue) => $issue->location?->line, $result->getIssues()));
        $this->assertHasIssueContaining('no "web" middleware detected', $result);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function reusedCallbackRegistrationOrderProvider(): array
    {
        $web = "Route::middleware('web')->group(function () use (\$admin) {\n    Route::prefix('admin')->group(\$admin);\n});";
        $legacy = "Route::prefix('legacy')->group(\$admin);";
        $direct = "Route::middleware('web')->group(\$admin);";

        return [
            'web group around the first call' => [$web, $legacy],
            'web group around the second call' => [$legacy, $web],
            'web on the first call' => [$direct, $legacy],
        ];
    }

    public function test_reused_callback_reports_its_weakest_registration(): void
    {
        $result = $this->analyzeRouteFiles([
            'routes/web.php' => <<<'PHP'
<?php

$hooks = function () {
    require __DIR__.'/hooks.php';
};
Route::middleware('web')->group($hooks);
Route::middleware('web')->withoutMiddleware('web')->group($hooks);
PHP,
            'routes/hooks.php' => "<?php\n\nRoute::post('/hooks', HookController::class);\n",
            'routes/admin.php' => <<<'PHP'
<?php

$admin = function () {
    Route::post('/admin/orders', [OrderController::class, 'store']);
};
Route::middleware('web')->withoutMiddleware('web')->group($admin);
Route::prefix('legacy')->group($admin);
PHP,
        ]);

        // hooks.php is loaded once with web and once stripped of it; the admin route is stripped
        // in one registration and has no web at all in the other, which is the weaker
        $messages = [];
        foreach ($result->getIssues() as $issue) {
            $messages[basename((string) $issue->location?->file)] = str_contains($issue->message, 'excluded from it') ? 'stripped' : 'missing';
        }
        ksort($messages);
        $this->assertSame(['admin.php' => 'missing', 'hooks.php' => 'stripped'], $messages);
    }

    public function test_each_registration_of_a_reused_callback_may_protect_it_its_own_way(): void
    {
        $result = $this->analyzeRouteFiles([
            'app/Http/Middleware/VerifyCsrfToken.php' => self::APP_VERIFY_CSRF_TOKEN,
            'routes/admin.php' => <<<'PHP'
<?php

use App\Http\Middleware\VerifyCsrfToken;

$admin = function () {
    Route::post('/admin/orders', [OrderController::class, 'store']);
};
Route::middleware('web')->group($admin);
Route::middleware(['auth', VerifyCsrfToken::class])->prefix('internal')->group($admin);

Route::apiResource('refunds', RefundController::class)
    ->middlewareFor('store', 'web')
    ->middlewareFor(['update', 'destroy'], VerifyCsrfToken::class);
PHP,
        ]);

        $this->assertPassed($result);
    }

    public function test_resource_filter_that_cannot_be_read_is_skipped(): void
    {
        $result = $this->analyzeRouteFile("<?php\n\nRoute::resource('orders', OrderController::class)->only(\$methods);\nRoute::apiResource('refunds', RefundController::class, ['except' => [\$excluded]]);\n");

        $this->assertPassed($result);
    }

    public function test_where_helpers_keep_the_chain_on_the_registrar(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::middleware('web')->whereNumber('id')->middleware('auth')->post('/orders/{id}', [OrderController::class, 'update']);
Route::middleware('web')->whereNumber('id')->post('/refunds/{id}', [RefundController::class, 'update']);
PHP);

        $this->assertFailed($result);
        $this->assertSame([3], array_map(fn ($issue) => $issue->location?->line, $result->getIssues()));
    }

    public function test_later_registrar_middleware_call_replaces_web_on_routes_and_groups(): void
    {
        // RouteRegistrar::attribute() overwrites 'middleware'; a route's own middleware() adds
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::middleware('web')->middleware('auth')->post('/orders', [OrderController::class, 'store']);
Route::middleware('web')->middleware('auth')->group(function () {
    Route::post('/refunds', [RefundController::class, 'store']);
});
Route::middleware('auth')->middleware('web')->post('/payments', [PaymentController::class, 'store']);
Route::middleware('web')->post('/credits', [CreditController::class, 'store'])->middleware('auth');
Route::middleware('web')->prefix('billing')->name('billing.')->post('/invoices', [InvoiceController::class, 'store']);
PHP);

        $this->assertFailed($result);
        $this->assertSame([3, 5], array_map(fn ($issue) => $issue->location?->line, $result->getIssues()));
    }

    public function test_registrar_without_middleware_replaces_the_excluded_middleware_option(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

Route::middleware('web')->group(function () {
    Route::withoutMiddleware('auth')->resource('orders', OrderController::class, ['excluded_middleware' => ['web']]);
});
PHP);

        $this->assertPassed($result);
    }

    /**
     * @param  array<string, string>  $files
     */
    private function analyzeRouteFiles(array $files): ResultInterface
    {
        $tempDir = $this->createTempDirectory($files);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        return $analyzer->analyze();
    }

    private function analyzeRouteFile(string $routes): ResultInterface
    {
        return $this->analyzeRouteFiles(['routes/billing.php' => $routes]);
    }

    // ==================== Excluded Paths Tests (3 tests) ====================

    public function test_skips_blade_files_under_excluded_paths(): void
    {
        $blade = <<<'BLADE'
<form method="POST" action="/newsletter">
    <input type="email" name="email">
</form>
BLADE;

        $tempDir = $this->createTempDirectory([
            'resources/views/legacy/signup.blade.php' => $blade,
            'resources/views/current/signup.blade.php' => $blade,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);
        $analyzer->setExcludePatterns(['resources/views/legacy/*']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssuesOnlyUnder('resources/views/current/', $result);
    }

    public function test_skips_javascript_files_under_excluded_paths(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/js/legacy/newsletter.js' => $this->unprotectedFetch(),
            'resources/js/current/newsletter.js' => $this->unprotectedFetch(),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);
        $analyzer->setExcludePatterns(['resources/js/legacy/*']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssuesOnlyUnder('resources/js/current/', $result);
    }

    public function test_skips_javascript_files_under_absolute_excluded_paths(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/js/legacy/newsletter.js' => $this->unprotectedFetch(),
            'resources/js/current/newsletter.js' => $this->unprotectedFetch(),
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);
        $analyzer->setExcludePatterns([$tempDir.'/resources/js/legacy/*']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertIssuesOnlyUnder('resources/js/current/', $result);
    }

    private function unprotectedFetch(): string
    {
        return <<<'JS'
fetch('/newsletter', {
    method: 'POST',
    body: JSON.stringify({ email: 'reader@example.test' })
});
JS;
    }

    /**
     * @param  non-empty-string  $directory
     */
    private function assertIssuesOnlyUnder(string $directory, ResultInterface $result): void
    {
        $this->assertNotEmpty($result->getIssues());

        foreach ($result->getIssues() as $issue) {
            $this->assertStringStartsWith($directory, $issue->location->file ?? '');
        }
    }

    // ==================== shouldRun Tests (4 tests) ====================

    public function test_should_run_when_blade_files_exist(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/views/test.blade.php' => '<div>Test</div>',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_run_when_js_files_exist(): void
    {
        $tempDir = $this->createTempDirectory([
            'resources/js/app.js' => 'console.log("test");',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_run_when_csrf_middleware_exists(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Http/Middleware/VerifyCsrfToken.php' => '<?php class VerifyCsrfToken {}',
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $this->assertTrue($analyzer->shouldRun());
    }

    public function test_should_not_run_when_no_files_exist(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);

        $this->assertFalse($analyzer->shouldRun());
    }

    // ==================== Metadata Tests (3 tests) ====================

    public function test_includes_metadata_for_form_issue(): void
    {
        $blade = '<form method="POST"><input name="test"></form>';

        $tempDir = $this->createTempDirectory(['resources/views/form.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['resources']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('file', $metadata);
        $this->assertArrayHasKey('form_method', $metadata);
        $this->assertArrayHasKey('line', $metadata);
    }

    // Removed test_includes_metadata_for_wildcard_exception - redundant with earlier wildcard tests that already verify metadata

    public function test_includes_metadata_for_route_issue(): void
    {
        $routes = '<?php Route::post("/test", function () {});';

        $tempDir = $this->createTempDirectory(['routes/custom.php' => $routes]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotEmpty($issues);
        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('method', $metadata);
        $this->assertArrayHasKey('file', $metadata);
        $this->assertArrayHasKey('line', $metadata);
    }

    // ==================== withRouting(then: ...) False Positive Tests ====================

    public function test_skips_route_file_required_from_web_php(): void
    {
        // auth.php has a POST route with no 'web' middleware — but it's require'd from
        // web.php, so it inherits web middleware (including CSRF) automatically.
        $webPhp = <<<'PHP'
<?php
require __DIR__.'/auth.php';
PHP;

        $authPhp = <<<'PHP'
<?php
Route::post('/login', [LoginController::class, 'store']);
PHP;

        $tempDir = $this->createTempDirectory([
            'routes/web.php' => $webPhp,
            'routes/auth.php' => $authPhp,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should pass — auth.php inherits web middleware from the require in web.php
        $this->assertPassed($result);
    }

    public function test_skips_route_file_registered_with_web_middleware_in_bootstrap(): void
    {
        // auth.php registered via Route::middleware('web')->group(...) in bootstrap/app.php
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::middleware('web')
                ->group(base_path('routes/auth.php'));
        },
    )
    ->create();
PHP;

        $authPhp = <<<'PHP'
<?php
Route::post('/login', [LoginController::class, 'store']);
Route::post('/register', [RegisterController::class, 'store']);
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/web.php' => '<?php // main web routes',
            'routes/auth.php' => $authPhp,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should pass — auth.php is registered with 'web' middleware externally
        $this->assertPassed($result);
    }

    public function test_skips_route_file_registered_with_web_as_a_later_middleware_argument(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::middleware('auth', 'web')
                ->group(base_path('routes/partner.php'));
        },
    )
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/partner.php' => "<?php\nRoute::post('/orders', [OrderController::class, 'store']);",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_route_file_registered_with_web_in_a_group_attribute_array(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::group(['middleware' => 'web'], base_path('routes/partner.php'));
        },
    )
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/partner.php' => "<?php\nRoute::post('/orders', [OrderController::class, 'store']);",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_skips_route_file_registered_with_api_in_a_group_attribute_array(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::group(['middleware' => ['api']], base_path('routes/partner-api.php'));
        },
    )
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/partner-api.php' => "<?php\nRoute::post('/orders', [OrderController::class, 'store']);",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        // Should pass: a file registered under 'api' uses token authentication, not CSRF
        $this->assertPassed($analyzer->analyze());
    }

    public function test_fails_route_file_registered_in_a_group_attribute_array_without_web(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::group(['middleware' => 'auth'], base_path('routes/partner.php'));
        },
    )
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/partner.php' => "<?php\nRoute::post('/orders', [OrderController::class, 'store']);",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('POST route in custom route file missing CSRF protection - no "web" middleware detected', $result);
    }

    /**
     * @dataProvider externalGroupRegistrationProvider
     */
    #[DataProvider('externalGroupRegistrationProvider')]
    public function test_route_file_registered_by_a_group_in_bootstrap(string $registration, bool $protected): void
    {
        $bootstrapApp = <<<PHP
<?php

use Illuminate\\Foundation\\Application;
use App\\Http\\Middleware\\VerifyCsrfToken;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            {$registration}
        },
    )
    ->withMiddleware(function (\$middleware) {
        \$middleware->group('web', [VerifyCsrfToken::class]);
    })
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/partner.php' => "<?php\nRoute::post('/orders', [OrderController::class, 'store']);",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        if ($protected) {
            $this->assertPassed($result);
        } else {
            $this->assertFailed($result);
            $this->assertIssueCount(1, $result);
            $this->assertHasIssueContaining('POST route in custom route file missing CSRF protection - the CSRF middleware is excluded from it', $result);
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function externalGroupRegistrationProvider(): array
    {
        $file = "base_path('routes/partner.php')";

        return [
            'CSRF class in the attribute array' => ["Route::group(['middleware' => [VerifyCsrfToken::class]], {$file});", true],
            'CSRF class on the chain' => ["Route::middleware(VerifyCsrfToken::class)->group({$file});", true],
            'web from an enclosing group' => ["Route::middleware('web')->group(function () { Route::group(['prefix' => 'partner'], {$file}); });", true],
            'file given relative to __DIR__' => ["Route::middleware('web')->group(__DIR__.'/../routes/partner.php');", true],
            'CSRF class excluded by excluded_middleware' => ["Route::group(['middleware' => 'web', 'excluded_middleware' => [VerifyCsrfToken::class]], {$file});", false],
            'CSRF class excluded on the chain' => ["Route::middleware('web')->withoutMiddleware(VerifyCsrfToken::class)->group({$file});", false],
            'web excluded by an enclosing group' => ["Route::withoutMiddleware('web')->group(function () { Route::middleware('web')->group({$file}); });", false],
        ];
    }

    /**
     * @dataProvider groupRouteListProvider
     */
    #[DataProvider('groupRouteListProvider')]
    public function test_route_files_listed_on_a_group_in_bootstrap(string $registration, string $expected): void
    {
        $bootstrapApp = <<<PHP
<?php

use App\\Http\\Middleware\\VerifyCsrfToken;
use Illuminate\\Foundation\\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            {$registration}
        },
    )
    ->withMiddleware(function (\$middleware) {
        \$middleware->group('web', [VerifyCsrfToken::class]);
    })
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/partner.php' => "<?php\nRoute::post('/orders', [OrderController::class, 'store']);",
            'routes/billing.php' => "<?php\nRoute::post('/invoices', [InvoiceController::class, 'store']);",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        if ($expected === '') {
            $this->assertPassed($result);
        } else {
            $this->assertFailed($result);
            $this->assertIssueCount(2, $result);
            $this->assertHasIssueContaining($expected, $result);
        }
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function groupRouteListProvider(): array
    {
        $list = "[base_path('routes/partner.php'), __DIR__.'/../routes/billing.php']";

        return [
            'web on the chain' => ["Route::middleware('web')->group({$list});", ''],
            'web in the attribute array' => ["Route::group(['middleware' => ['web']], {$list});", ''],
            'api in the attribute array' => ["Route::group(['middleware' => 'api', 'prefix' => 'api'], {$list});", ''],
            'CSRF class excluded' => ["Route::middleware('web')->withoutMiddleware(VerifyCsrfToken::class)->group({$list});", 'the CSRF middleware is excluded from it'],
            'no web' => ["Route::middleware('auth')->group({$list});", 'no "web" middleware detected'],
        ];
    }

    public function test_in_file_group_given_a_list_covers_each_callback(): void
    {
        $result = $this->analyzeRouteFile(<<<'PHP'
<?php

$billingRoutes = function () {
    Route::post('/invoices', [InvoiceController::class, 'store']);
};

Route::middleware('web')->group([function () {
    Route::post('/orders', [OrderController::class, 'store']);
}, $billingRoutes, fn () => Route::post('/refunds', [RefundController::class, 'store'])]);

Route::middleware('auth')->group([function () {
    Route::post('/receipts', [ReceiptController::class, 'store']);
}]);
PHP);

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertSame(12, $result->getIssues()[0]->location?->line);
    }

    public function test_csrf_exclusion_on_a_route_file_reaches_the_files_it_loads(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use App\Http\Middleware\VerifyCsrfToken;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::withoutMiddleware(VerifyCsrfToken::class)->group(base_path('routes/partner.php'));
        },
    )
    ->withMiddleware(function ($middleware) {
        $middleware->group('web', [VerifyCsrfToken::class]);
    })
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/partner.php' => "<?php\nRoute::middleware('web')->group(function () {\n    require __DIR__.'/orders.php';\n});",
            'routes/orders.php' => "<?php\nRoute::post('/orders', [OrderController::class, 'store']);",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining('the CSRF middleware is excluded from it', $result);
        $this->assertStringEndsWith('orders.php', (string) $result->getIssues()[0]->location?->file);
    }

    public function test_group_in_an_unloaded_route_file_does_not_strip_a_web_registered_file(): void
    {
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::middleware('web')->group(base_path('routes/partner.php'));
        },
    )
    ->create();
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/legacy.php' => "<?php\nRoute::withoutMiddleware('web')->group(base_path('routes/partner.php'));",
            'routes/partner.php' => "<?php\nRoute::post('/orders', [OrderController::class, 'store']);",
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $this->assertPassed($analyzer->analyze());
    }

    public function test_skips_route_file_required_inside_web_group_closure_in_bootstrap(): void
    {
        // Compass pattern: auth.php is require'd inside a ->group(Closure) on a
        // Route::domain()->middleware('web') chain (not via ->group(base_path())).
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::domain(config('app.domain'))
                ->middleware('web')
                ->group(function () {
                    require __DIR__.'/../routes/auth.php';
                });
        },
    )
    ->create();
PHP;

        $authPhp = <<<'PHP'
<?php
Route::post('/login', [LoginController::class, 'store']);
Route::post('/register', [RegisterController::class, 'store']);
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/web.php' => '<?php // main web routes',
            'routes/auth.php' => $authPhp,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        // Should pass — auth.php inherits 'web' middleware from the enclosing closure group.
        $this->assertPassed($analyzer->analyze());
    }

    public function test_passes_api_route_file_registered_with_api_middleware_array(): void
    {
        // Platform's exact pattern: ->middleware(['api', 'throttle:api.rest'])->group(base_path('routes/api-v1.php'))
        // API route files must NOT be flagged — they use Sanctum token auth, not CSRF.
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        then: function () {
            Route::prefix('api/v1')
                ->middleware(['api', 'throttle:api.rest'])
                ->group(base_path('routes/api-v1.php'));
        },
    )
    ->create();
PHP;

        $apiV1Php = <<<'PHP'
<?php
Route::post('/users', [UserController::class, 'store']);
Route::put('/users/{id}', [UserController::class, 'update']);
Route::delete('/users/{id}', [UserController::class, 'destroy']);
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/web.php' => '<?php // main web routes',
            'routes/api-v1.php' => $apiV1Php,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should pass — api-v1.php is registered under 'api' middleware (token auth, not CSRF)
        $this->assertPassed($result);
    }

    public function test_skips_route_file_registered_with_api_middleware_in_bootstrap(): void
    {
        // auth.php registered via Route::middleware('api')->group(...) — uses token auth, not CSRF
        $bootstrapApp = <<<'PHP'
<?php

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        then: function () {
            Route::middleware('api')
                ->group(base_path('routes/auth.php'));
        },
    )
    ->create();
PHP;

        $authPhp = <<<'PHP'
<?php
Route::post('/login', [LoginController::class, 'store']);
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/web.php' => '<?php // main web routes',
            'routes/auth.php' => $authPhp,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should pass — 'api' middleware means token-based auth (Sanctum), CSRF does not apply
        $this->assertPassed($result);
    }

    public function test_skips_versioned_api_routes_file_via_bootstrap_with_routing(): void
    {
        // Pure API app using withRouting(api: [...]) with versioned route files
        $bootstrapApp = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        api: [__DIR__.'/../routes/v1/api.php', __DIR__.'/../routes/v2/api.php'],
    )
    ->create();
PHP;

        $v1Routes = <<<'PHP'
<?php
Route::post('/v1/users', [UserController::class, 'store']);
PHP;

        $v2Routes = <<<'PHP'
<?php
Route::post('/v2/users', [UserController::class, 'store']);
PHP;

        $tempDir = $this->createTempDirectory([
            'bootstrap/app.php' => $bootstrapApp,
            'routes/v1/api.php' => $v1Routes,
            'routes/v2/api.php' => $v2Routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes']);

        $result = $analyzer->analyze();

        // Should pass — both files are declared as API routes via withRouting(api: [...])
        $this->assertPassed($result);
    }

    public function test_skips_versioned_api_routes_registered_in_provider(): void
    {
        // Laravel 9/10 pattern: RouteServiceProvider registers versioned API files
        $provider = <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Route;

class RoutingServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->routes(function () {
            Route::middleware('api')
                ->prefix('api/v1')
                ->group(base_path('routes/v1/api.php'));

            Route::middleware('api')
                ->prefix('api/v2')
                ->group(base_path('routes/v2/api.php'));
        });
    }
}
PHP;

        $v1Routes = <<<'PHP'
<?php
Route::post('/users', [UserController::class, 'store']);
PHP;

        $v2Routes = <<<'PHP'
<?php
Route::post('/users', [UserController::class, 'store']);
Route::delete('/users/{id}', [UserController::class, 'destroy']);
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Providers/RoutingServiceProvider.php' => $provider,
            'routes/v1/api.php' => $v1Routes,
            'routes/v2/api.php' => $v2Routes,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['routes', 'app']);

        $result = $analyzer->analyze();

        // Should pass — both versioned API files are registered under 'api' middleware in provider
        $this->assertPassed($result);
    }
}
