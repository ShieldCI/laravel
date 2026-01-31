<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\BestPractices\PhpSideFilteringAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class PhpSideFilteringAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        // Build best-practices config with defaults
        $bestPracticesConfig = [
            'enabled' => true,
            'php-side-filtering' => [
                'whitelist' => $config['whitelist'] ?? [],
            ],
        ];

        $configRepo = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => $bestPracticesConfig,
                ],
            ],
        ]);

        return new PhpSideFilteringAnalyzer($this->parser, $configRepo);
    }

    public function test_passes_with_database_filtering(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveUsers()
    {
        return User::where('status', 'active')->get();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_filter_after_get(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveUsers()
    {
        return User::all()->filter(function($user) {
            return $user->status === 'active';
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Filtering data in PHP', $result);
    }

    public function test_passes_with_where_after_get(): void
    {
        // where() is covered by Larastan/CollectionCallAnalyzer, not by this analyzer
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function getExpensiveProducts()
    {
        return Product::all()->where('price', '>', 100);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // This should pass because where() is detected by CollectionCallAnalyzer (Larastan)
        $this->assertPassed($result);
    }

    public function test_detects_collection_filtering_on_query_results(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function getPendingOrders()
    {
        return Order::get()->filter(fn($order) => $order->status === 'pending');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('filter', $result);
    }

    public function test_provides_performance_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getVerifiedUsers()
    {
        return User::all()->filter(function($user) {
            return $user->email_verified_at !== null;
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('database', $issues[0]->recommendation);
    }

    public function test_ignores_files_with_parse_errors(): void
    {
        $code = '<?php this is invalid PHP code {{{';

        $tempDir = $this->createTempDirectory(['Invalid.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_reject_after_get(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveUsers()
    {
        return User::all()->reject(function($user) {
            return $user->status === 'inactive';
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('reject', $result);
    }

    public function test_detects_wherein_after_get(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function getProductsByIds($ids)
    {
        return Product::all()->whereIn('id', $ids);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('whereIn', $result);
    }

    public function test_detects_wherenotin_after_get(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function getProductsExcludingIds($excludeIds)
    {
        return Product::get()->whereNotIn('id', $excludeIds);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('whereNotIn', $result);
    }

    public function test_passes_with_first_after_get(): void
    {
        // first() is covered by Larastan/CollectionCallAnalyzer, not by this analyzer
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getFirstUser()
    {
        return User::get()->first();
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // This should pass because first() is detected by CollectionCallAnalyzer (Larastan)
        $this->assertPassed($result);
    }

    public function test_respects_whitelist_configuration(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class LegacyUserService
{
    public function getActiveUsers()
    {
        return User::all()->filter(function($user) {
            return $user->status === 'active';
        });
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/LegacyUserService.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'whitelist' => ['LegacyUserService'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ========================================================================
    // FALSE POSITIVE PREVENTION TESTS
    // ========================================================================

    public function test_ignores_request_all_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function store()
    {
        // This is NOT a database query - it's filtering request input
        $data = request()->all()->filter(fn($v) => !empty($v));
        return $data;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_config_get_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ConfigService
{
    public function getEnabledProviders()
    {
        // This is NOT a database query - it's filtering config values
        return config()->get('providers')->filter(fn($p) => $p['enabled']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ConfigService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_session_get_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CartService
{
    public function getActiveItems()
    {
        // This is NOT a database query - it's filtering session data
        return session()->get('cart_items')->filter(fn($item) => $item->quantity > 0);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CartService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_cache_get_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CacheService
{
    public function getActiveData()
    {
        // This is NOT a database query - it's filtering cached data
        return cache()->get('data')->filter(fn($d) => $d->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CacheService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_collect_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ArrayService
{
    public function filterArray(array $items)
    {
        // This is NOT a database query - it's an explicit collection from an array
        return collect($items)->filter(fn($item) => $item['active']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ArrayService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_collection_static_make_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Collection;

class ArrayService
{
    public function processData(array $data)
    {
        // This is NOT a database query - Collection::make creates from array
        return Collection::make($data)->filter(fn($item) => $item['valid']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ArrayService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_http_facade_json_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;

class ApiService
{
    public function fetchActiveUsers()
    {
        // This is NOT a database query - it's HTTP response data
        return Http::get('/api/users')->json()->filter(fn($u) => $u['active']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_injected_request_property(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class UserController
{
    private Request $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    public function store()
    {
        // This is NOT a database query - it's filtering request input
        return $this->request->all()->filter(fn($v) => !empty($v));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Controllers/UserController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_detects_model_all_filter(): void
    {
        // Ensure we still detect the actual problematic pattern
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveUsers()
    {
        // This IS a database query - should be flagged
        return User::all()->filter(fn($user) => $user->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('filter', $result);
    }

    public function test_ignores_cookie_get_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PreferenceService
{
    public function getActivePreferences()
    {
        // This is NOT a database query - it's cookie data
        return cookie()->get('preferences')->filter(fn($p) => $p['enabled']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/PreferenceService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_arr_facade_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Arr;

class ArrayService
{
    public function processData(array $data)
    {
        // This is NOT a database query - Arr is a utility class
        return Arr::wrap($data)->filter(fn($item) => $item['valid']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ArrayService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_api_client_get_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserSyncService
{
    public function __construct(private ApiClient $apiClient) {}

    public function getActiveUsers()
    {
        // NOT a database query - API client returning data
        return $this->apiClient->getUsers()->filter(fn($u) => $u['active']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserSyncService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_service_all_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DataProcessor
{
    public function __construct(private DataService $service) {}

    public function processActive()
    {
        // NOT a database query - service method
        return $this->service->all()->filter(fn($item) => $item->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DataProcessor.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_variable_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CollectionProcessor
{
    public function process($collection)
    {
        // Cannot determine type - should not flag
        return $collection->filter(fn($item) => $item->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CollectionProcessor.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_model_in_models_namespace(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function getActiveProducts()
    {
        // This IS a database query - App\Models namespace
        return Product::all()->filter(fn($p) => $p->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('filter', $result);
    }

    public function test_detects_model_with_ddd_namespace(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Domain\Users\Models\User;

class UserService
{
    public function getActiveUsers()
    {
        // This IS a database query - Domain\*\Models namespace (DDD)
        return User::all()->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('filter', $result);
    }

    public function test_detects_short_class_name_model(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function getPendingOrders()
    {
        // Short class name (no namespace in call) - assumed to be model
        return Order::get()->filter(fn($o) => $o->status === 'pending');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('filter', $result);
    }

    public function test_ignores_non_model_namespace_with_fqn(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function processUsers()
    {
        // NOT a model - App\DataTransfer namespace (using FQN)
        return \App\DataTransfer\UserCollection::all()->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ========================================================================
    // WHITELIST PATTERN TESTS
    // ========================================================================

    public function test_whitelist_glob_pattern_matches_directory(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Legacy;

use App\Models\User;

class LegacyService
{
    public function getUsers()
    {
        return User::all()->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Legacy/LegacyService.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'whitelist' => ['*/LegacyService.php'],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_whitelist_does_not_match_substring(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class SuperUserService
{
    public function getUsers()
    {
        // Should be flagged - "User" whitelist should NOT match "SuperUserService"
        return User::all()->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/SuperUserService.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'whitelist' => ['User'], // Should NOT match SuperUserService
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_whitelist_matches_exact_filename(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getUsers()
    {
        return User::all()->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'whitelist' => ['UserService'], // Exact filename match (without extension)
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_whitelist_matches_directory_segment(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Legacy;

use App\Models\User;

class UserService
{
    public function getUsers()
    {
        return User::all()->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Legacy/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'whitelist' => ['Legacy'], // Directory segment match
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_whitelist_recursive_glob_pattern(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Legacy\Users;

use App\Models\User;

class UserProcessor
{
    public function getUsers()
    {
        return User::all()->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Legacy/Users/UserProcessor.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'whitelist' => ['**/Users/*.php'], // Recursive glob
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // ========================================================================
    // EXPANDED FETCH METHOD TESTS (Issue 1)
    // ========================================================================

    public function test_detects_filter_after_paginate(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveUsers()
    {
        return User::paginate(10)->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('filter', $result);
    }

    public function test_detects_filter_after_cursor(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function processUsers()
    {
        return User::cursor()->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('filter', $result);
    }

    public function test_detects_filter_after_pluck(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveEmails()
    {
        return User::pluck('email', 'id')->filter(fn($email) => str_contains($email, '@company.com'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('filter', $result);
    }

    public function test_detects_filter_with_intermediate_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function processUsers()
    {
        // get()->map()->filter() - filter after fetch with intermediate method
        return User::get()->map(fn($u) => $u->toArray())->filter(fn($u) => $u['active']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('filter', $result);
    }

    public function test_detects_reject_after_simple_paginate(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Product;

class ProductService
{
    public function getVisibleProducts()
    {
        return Product::simplePaginate(20)->reject(fn($p) => $p->hidden);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('reject', $result);
    }

    public function test_detects_wherein_after_find_many(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function filterUsers(array $ids, array $activeIds)
    {
        return User::findMany($ids)->whereIn('id', $activeIds);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('whereIn', $result);
    }

    // ========================================================================
    // SEVERITY TIER TESTS (Issue 4)
    // ========================================================================

    public function test_paginate_filter_has_medium_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveUsers()
    {
        return User::paginate(10)->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $issues[0]->severity);
        $this->assertStringContainsString('WARNING', $issues[0]->message);
    }

    public function test_get_filter_has_critical_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveUsers()
    {
        return User::get()->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
        $this->assertStringContainsString('CRITICAL', $issues[0]->message);
    }

    public function test_all_filter_has_critical_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveUsers()
    {
        return User::all()->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Critical, $issues[0]->severity);
    }

    public function test_cursor_filter_has_medium_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveUsers()
    {
        return User::cursor()->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $issues[0]->severity);
    }

    public function test_pluck_filter_has_medium_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveEmails()
    {
        return User::pluck('email')->filter(fn($e) => str_ends_with($e, '@company.com'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $issues[0]->severity);
    }

    public function test_simple_paginate_filter_has_medium_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveUsers()
    {
        return User::simplePaginate(15)->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $issues[0]->severity);
    }
}