<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\CsrfAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class CsrfAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new CsrfAnalyzer;
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
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
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
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
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

        $this->assertFailed($result);
        $this->assertHasIssueContaining('may not be properly configured', $result);
    }

    public function test_passes_bootstrap_app_with_csrf_mentioned(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use App\Http\Middleware\VerifyCsrfToken;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        // CSRF protection is enabled by default
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

    public function test_fails_when_validate_csrf_token_missing_from_use_array(): void
    {
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
        $this->assertHasIssueContaining('ValidateCsrfToken missing from global middleware stack', $result);
    }

    public function test_passes_when_validate_csrf_token_in_use_array(): void
    {
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
            \Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class,
            \Illuminate\Foundation\Http\Middleware\TrimStrings::class,
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
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
    }

    public function test_fails_when_csrf_removed_entirely(): void
    {
        $bootstrap = <<<'PHP'
<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        $middleware->remove(\Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class);
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
        $this->assertHasIssueContaining('ValidateCsrfToken middleware has been removed', $result);
        $issues = $result->getIssues();
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
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
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
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
        $routes = 'Route::post("/test", function () {});';

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
}
