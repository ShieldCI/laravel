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
        $phpSideFilteringConfig = [
            'whitelist' => $config['whitelist'] ?? [],
        ];

        // Add model_namespaces if provided
        if (isset($config['model_namespaces'])) {
            $phpSideFilteringConfig['model_namespaces'] = $config['model_namespaces'];
        }

        $bestPracticesConfig = [
            'enabled' => true,
            'php-side-filtering' => $phpSideFilteringConfig,
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

class UserService
{
    public function getActiveUsers()
    {
        // Using FQN - should be detected
        return \App\Models\User::all()->filter(function($user) {
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

class OrderService
{
    public function getPendingOrders()
    {
        // Using FQN - should be detected
        return \App\Models\Order::get()->filter(fn($order) => $order->status === 'pending');
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

class UserService
{
    public function getVerifiedUsers()
    {
        // Using FQN - should be detected
        return \App\Models\User::all()->filter(function($user) {
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

class UserService
{
    public function getActiveUsers()
    {
        // Using FQN - should be detected
        return \App\Models\User::all()->reject(function($user) {
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

class ProductService
{
    public function getProductsByIds($ids)
    {
        // Using FQN - should be detected
        return \App\Models\Product::all()->whereIn('id', $ids);
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

class ProductService
{
    public function getProductsExcludingIds($excludeIds)
    {
        // Using FQN - should be detected
        return \App\Models\Product::get()->whereNotIn('id', $excludeIds);
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

class LegacyUserService
{
    public function getActiveUsers()
    {
        // Using FQN - would be detected, but whitelisted
        return \App\Models\User::all()->filter(function($user) {
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
        // Ensure we still detect the actual problematic pattern with FQN
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActiveUsers()
    {
        // This IS a database query with FQN - should be flagged
        return \App\Models\User::all()->filter(fn($user) => $user->active);
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

    public function test_ignores_variable_filter_without_fetch(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CollectionProcessor
{
    public function process($collection)
    {
        // No fetch method in chain - cannot determine if Eloquent, should not flag
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

    public function test_detects_variable_with_fetch_and_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActiveUsers($query)
    {
        // Variable with get() + filter() - likely Eloquent query
        return $query->get()->filter(fn($u) => $u->active);
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

    public function test_detects_variable_with_all_and_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActiveUsers($query)
    {
        // Variable with all() + filter() - likely Eloquent query
        return $query->all()->filter(fn($u) => $u->active);
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

    public function test_detects_variable_with_get_and_reject(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActiveUsers($query)
    {
        // Variable with get() + reject() - likely Eloquent query
        return $query->get()->reject(fn($u) => $u->inactive);
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

    public function test_detects_variable_with_paginate_and_wherein(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function filterUsers($query, array $ids)
    {
        // Variable with paginate() + whereIn() - likely Eloquent query
        return $query->paginate(10)->whereIn('id', $ids);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('whereIn', $result);
    }

    public function test_ignores_variable_with_only_fetch(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getUsers($query)
    {
        // Variable with only get() - no filter method, should pass
        return $query->get();
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

    public function test_detects_stored_query_variable_pattern(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function getActiveAdmins()
    {
        $query = User::where('active', true);
        // Later in code: variable with get() + filter()
        return $query->get()->filter(fn($u) => $u->isAdmin());
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

    public function test_detects_model_in_models_namespace(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ProductService
{
    public function getActiveProducts()
    {
        // This IS a database query - App\Models namespace with FQN
        return \App\Models\Product::all()->filter(fn($p) => $p->active);
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

class UserService
{
    public function getActiveUsers()
    {
        // This IS a database query - Domain\*\Models namespace (DDD) with FQN
        return \Domain\Users\Models\User::all()->filter(fn($u) => $u->active);
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

    public function test_detects_short_class_name_as_potential_model(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function getPendingOrders()
    {
        // Short class name (no namespace in call) - IS detected as potential model
        // This handles the common Laravel pattern: `use App\Models\Order;` then `Order::get()`
        return Order::get()->filter(fn($o) => $o->status === 'pending');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Short model names ARE detected as potential models (unless they look like services)
        $this->assertFailed($result);
        $this->assertHasIssueContaining('filter', $result);
    }

    public function test_ignores_short_class_name_with_service_suffix(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Services\DataService;

class DataProcessor
{
    public function processData()
    {
        // Short class name with Service suffix - NOT detected (looks like a service)
        return DataService::get()->filter(fn($item) => $item->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DataProcessor.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Service-suffixed short names should NOT be flagged
        $this->assertPassed($result);
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

class LegacyService
{
    public function getUsers()
    {
        // Using FQN - would be detected, but whitelisted by glob
        return \App\Models\User::all()->filter(fn($u) => $u->active);
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

class SuperUserService
{
    public function getUsers()
    {
        // Should be flagged - "User" whitelist should NOT match "SuperUserService"
        return \App\Models\User::all()->filter(fn($u) => $u->active);
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

class UserService
{
    public function getUsers()
    {
        // Using FQN - would be detected, but whitelisted by filename
        return \App\Models\User::all()->filter(fn($u) => $u->active);
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

class UserService
{
    public function getUsers()
    {
        // Using FQN - would be detected, but whitelisted by directory segment
        return \App\Models\User::all()->filter(fn($u) => $u->active);
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

class UserProcessor
{
    public function getUsers()
    {
        // Using FQN - would be detected, but whitelisted by recursive glob
        return \App\Models\User::all()->filter(fn($u) => $u->active);
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

class UserService
{
    public function getActiveUsers()
    {
        // Using FQN - should be detected
        return \App\Models\User::paginate(10)->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('filter', $result);
    }

    public function test_detects_filter_after_cursor(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function processUsers()
    {
        // Using FQN - should be detected
        return \App\Models\User::cursor()->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('filter', $result);
    }

    public function test_detects_filter_after_pluck(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActiveEmails()
    {
        // Using FQN - should be detected
        return \App\Models\User::pluck('email', 'id')->filter(fn($email) => str_contains($email, '@company.com'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('filter', $result);
    }

    public function test_detects_filter_with_intermediate_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function processUsers()
    {
        // get()->map()->filter() - filter after fetch with intermediate method
        // Using FQN - should be detected
        return \App\Models\User::get()->map(fn($u) => $u->toArray())->filter(fn($u) => $u['active']);
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

class ProductService
{
    public function getVisibleProducts()
    {
        // Using FQN - should be detected
        return \App\Models\Product::simplePaginate(20)->reject(fn($p) => $p->hidden);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('reject', $result);
    }

    public function test_detects_wherein_after_find_many(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function filterUsers(array $ids, array $activeIds)
    {
        // Using FQN - should be detected
        return \App\Models\User::findMany($ids)->whereIn('id', $activeIds);
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

class UserService
{
    public function getActiveUsers()
    {
        // Using FQN - should be detected
        return \App\Models\User::paginate(10)->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
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

class UserService
{
    public function getActiveUsers()
    {
        // Using FQN - should be detected
        return \App\Models\User::get()->filter(fn($u) => $u->active);
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

class UserService
{
    public function getActiveUsers()
    {
        // Using FQN - should be detected
        return \App\Models\User::all()->filter(fn($u) => $u->active);
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

class UserService
{
    public function getActiveUsers()
    {
        // Using FQN - should be detected
        return \App\Models\User::cursor()->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $issues[0]->severity);
    }

    public function test_pluck_filter_has_medium_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActiveEmails()
    {
        // Using FQN - should be detected
        return \App\Models\User::pluck('email')->filter(fn($e) => str_ends_with($e, '@company.com'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $issues[0]->severity);
    }

    public function test_simple_paginate_filter_has_medium_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActiveUsers()
    {
        // Using FQN - should be detected
        return \App\Models\User::simplePaginate(15)->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $issues[0]->severity);
    }

    // ========================================================================
    // RELATIONSHIP COLLECTION FILTERING TESTS
    // ========================================================================

    public function test_detects_relationship_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PostService
{
    public function getPublishedPosts($user)
    {
        return $user->posts->filter(fn($p) => $p->published);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/PostService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Filtering data in PHP', $result);
    }

    public function test_detects_relationship_reject(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderService
{
    public function getActiveItems($order)
    {
        return $order->items->reject(fn($i) => $i->cancelled);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Filtering data in PHP', $result);
    }

    public function test_detects_relationship_wherein(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderService
{
    public function getItemsByStatus($order, array $statuses)
    {
        return $order->items->whereIn('status', $statuses);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('whereIn', $result);
    }

    public function test_detects_relationship_wherenotin(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActiveRoles($user, array $excludeRoles)
    {
        return $user->roles->whereNotIn('name', $excludeRoles);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('whereNotIn', $result);
    }

    public function test_ignores_non_relationship_properties(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DataService
{
    public function process($obj)
    {
        // These should NOT be flagged - not relationships
        $obj->data->filter(fn($d) => $d->valid);
        $obj->metadata->reject(fn($m) => $m->empty);
        $obj->settings->whereIn('key', ['a', 'b']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DataService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_generic_suffix_properties(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function process($user)
    {
        // These should NOT be flagged - generic suffixes, not relationships
        // profile_data, shipping_info, custom_attributes are JSON columns
        $user->profile_data->filter(fn($d) => $d->valid);
        $user->shipping_info->reject(fn($i) => $i->empty);
        $user->custom_attributes->whereIn('key', ['a', 'b']);
        $user->profileMetadata->filter(fn($m) => $m->active);
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

    public function test_relationship_issues_have_medium_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActivePosts($user)
    {
        return $user->posts->filter(fn($p) => $p->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertEquals(\ShieldCI\AnalyzersCore\Enums\Severity::Medium, $issues[0]->severity);
    }

    public function test_relationship_recommendation_mentions_eager_loading(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PostService
{
    public function getPublishedPosts($user)
    {
        return $user->posts->filter(fn($p) => $p->published);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/PostService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('eager loading', $issues[0]->recommendation);
    }

    public function test_ignores_excluded_property_patterns(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function processUser($user)
    {
        // Foreign key pattern: *_id
        $user->parent_id->filter(fn($x) => $x);

        // Timestamp pattern: *_at
        $user->logged_in_at->filter(fn($x) => $x);

        // Boolean prefix: is_*, has_*
        $user->is_active->filter(fn($x) => $x);
        $user->has_permission->filter(fn($x) => $x);

        // Count suffix: *_count
        $user->posts_count->filter(fn($x) => $x);

        // Single character
        $user->x->filter(fn($x) => $x);

        // Underscore prefix
        $user->_internal->filter(fn($x) => $x);
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

    public function test_detects_nested_relationship_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CompanyService
{
    public function getActiveEmployees($company)
    {
        // Nested relationship access
        return $company->departments->filter(fn($d) => $d->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CompanyService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('filter', $result);
    }

    // ========================================================================
    // MODEL NAMESPACES CONFIGURATION TESTS
    // ========================================================================

    public function test_respects_custom_model_namespaces_config(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActiveUsers()
    {
        // Using FQN with custom namespace - should be detected when configured
        return \MyCompany\Domain\User::all()->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        // Without custom config - should pass (not detected)
        $analyzer1 = $this->createAnalyzer();
        $analyzer1->setBasePath($tempDir);
        $analyzer1->setPaths(['.']);
        $result1 = $analyzer1->analyze();
        $this->assertPassed($result1);

        // With custom model_namespaces config - should fail (detected)
        $analyzer2 = $this->createAnalyzer([
            'model_namespaces' => ['MyCompany\\Domain'],
        ]);
        $analyzer2->setBasePath($tempDir);
        $analyzer2->setPaths(['.']);
        $result2 = $analyzer2->analyze();
        $this->assertFailed($result2);
        $this->assertHasIssueContaining('filter', $result2);
    }

    public function test_model_namespaces_config_replaces_defaults(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActiveUsers()
    {
        // App\Entities would normally be detected if in default namespace list
        // but with custom config that doesn't include it, should pass
        return \App\Entities\User::all()->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        // First verify it's NOT detected with just the custom namespace
        $analyzer1 = $this->createAnalyzer([
            'model_namespaces' => ['MyCompany\\Domain'],
        ]);
        $analyzer1->setBasePath($tempDir);
        $analyzer1->setPaths(['.']);
        $result1 = $analyzer1->analyze();
        $this->assertPassed($result1);

        // Now verify it IS detected when App\Entities is in the config
        $analyzer2 = $this->createAnalyzer([
            'model_namespaces' => ['App\\Entities'],
        ]);
        $analyzer2->setBasePath($tempDir);
        $analyzer2->setPaths(['.']);
        $result2 = $analyzer2->analyze();
        $this->assertFailed($result2);
    }

    // ========================================================================
    // SERVICE/CLIENT SUFFIX REJECTION TESTS
    // ========================================================================

    public function test_ignores_short_name_with_service_suffix(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DataProcessor
{
    public function processData()
    {
        // UserService is a service class, not a model - should NOT be flagged
        return UserService::all()->filter(fn($item) => $item->active);
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

    public function test_ignores_short_name_with_client_suffix(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiConsumer
{
    public function fetchUsers()
    {
        // ApiClient is a client class, not a model - should NOT be flagged
        return ApiClient::get('users')->filter(fn($u) => $u['active']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiConsumer.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_short_name_with_repository_suffix(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DataHandler
{
    public function getActiveRecords()
    {
        // UserRepository is a repository class, not a model - should NOT be flagged
        return UserRepository::all()->filter(fn($r) => $r->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DataHandler.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_short_name_with_factory_suffix(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ProductionLine
{
    public function getFactoryProducts()
    {
        // ProductFactory is a factory class, not a model - should NOT be flagged
        return ProductFactory::all()->filter(fn($p) => $p->ready);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductionLine.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_short_name_with_controller_suffix(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class MetaService
{
    public function getControllerActions()
    {
        // UserController is a controller class, not a model - should NOT be flagged
        return UserController::all()->filter(fn($a) => $a->public);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/MetaService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_short_name_with_handler_suffix(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class EventProcessor
{
    public function processEvents()
    {
        // EventHandler is a handler class, not a model - should NOT be flagged
        return EventHandler::all()->filter(fn($e) => $e->processed);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/EventProcessor.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_short_name_with_job_suffix(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class QueueManager
{
    public function getPendingJobs()
    {
        // ProcessReportJob is a job class, not a model - should NOT be flagged
        return ProcessReportJob::all()->filter(fn($j) => $j->pending);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/QueueManager.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_detects_model_suffix_class(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DataProcessor
{
    public function getUsers()
    {
        // UserModel ends with "Model" suffix - should be detected
        return UserModel::all()->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DataProcessor.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('filter', $result);
    }

    // ========================================================================
    // FIND() FALSE POSITIVE PREVENTION TESTS
    // ========================================================================

    public function test_ignores_find_with_single_id(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getUser()
    {
        // find(1) returns Model|null, not Collection
        // Calling filter() on this is broken code, not a PHP-side filtering issue
        return \App\Models\User::find(1)->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should NOT be flagged - find(1) returns Model, not Collection
        $this->assertPassed($result);
    }

    public function test_detects_find_with_array_ids(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActiveUsers()
    {
        // find([1, 2, 3]) returns Collection - this is a performance issue
        return \App\Models\User::find([1, 2, 3])->filter(fn($u) => $u->active);
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

    public function test_find_with_array_has_critical_severity(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getUsers()
    {
        // find([...]) with filter should be critical
        return \App\Models\User::find([1, 2, 3])->filter(fn($u) => $u->active);
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

    public function test_ignores_find_with_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getUser($id)
    {
        // find($id) - cannot determine if $id is single value or array
        // Don't flag to avoid false positives
        return \App\Models\User::find($id)->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should NOT be flagged - cannot determine type of $id
        $this->assertPassed($result);
    }

    public function test_still_detects_findmany_with_filter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActiveUsers(array $ids)
    {
        // findMany() always returns Collection - should be detected
        return \App\Models\User::findMany($ids)->filter(fn($u) => $u->active);
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

    public function test_detects_find_with_empty_array(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getNoUsers()
    {
        // find([]) with empty array returns Collection
        return \App\Models\User::find([])->filter(fn($u) => $u->active);
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

    public function test_detects_find_with_array_and_reject(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActiveUsers()
    {
        // find([...]) with reject should be detected
        return \App\Models\User::find([1, 2, 3])->reject(fn($u) => $u->inactive);
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

    public function test_detects_find_with_array_and_wherein(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function filterUsers(array $statuses)
    {
        // find([...]) with whereIn should be detected
        return \App\Models\User::find([1, 2, 3])->whereIn('status', $statuses);
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

    public function test_ignores_find_with_string_id(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getUser()
    {
        // find('uuid-string') returns Model|null, not Collection
        return \App\Models\User::find('550e8400-e29b-41d4-a716-446655440000')->filter(fn($u) => $u->active);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should NOT be flagged - find('uuid') returns Model, not Collection
        $this->assertPassed($result);
    }

    // ========================================================================
    // PLUCK-SPECIFIC RECOMMENDATION TESTS
    // ========================================================================

    public function test_pluck_filter_has_appropriate_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActiveEmails()
    {
        // Using FQN - should be detected with pluck-specific recommendation
        return \App\Models\User::pluck('email')->filter(fn($e) => str_ends_with($e, '@company.com'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        // Should have pluck-specific recommendation (not "loads all data into memory")
        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('where() clauses before pluck()', $recommendation);
        $this->assertStringContainsString('only loads one column', $recommendation);
        $this->assertStringNotContainsString('loads all data into memory', $recommendation);
    }

    public function test_pluck_reject_has_appropriate_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getNonBannedIds()
    {
        return \App\Models\User::pluck('id')->reject(fn($id) => $id < 100);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        // Should have pluck-specific recommendation for reject
        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('whereNot() or where() clauses before pluck()', $recommendation);
        $this->assertStringNotContainsString('loads all data into memory', $recommendation);
    }

    public function test_pluck_wherein_has_appropriate_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getAdminIds(array $roles)
    {
        return \App\Models\User::pluck('id')->whereIn('role', $roles);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        // Should have pluck-specific recommendation for whereIn
        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('whereIn() to the query before pluck()', $recommendation);
        $this->assertStringNotContainsString('loads all data into memory', $recommendation);
    }

    public function test_pluck_wherenotin_has_appropriate_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActiveIds(array $excludeStatuses)
    {
        return \App\Models\User::pluck('id')->whereNotIn('status', $excludeStatuses);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        // Should have pluck-specific recommendation for whereNotIn
        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('whereNotIn() to the query before pluck()', $recommendation);
        $this->assertStringNotContainsString('loads all data into memory', $recommendation);
    }

    public function test_get_filter_still_has_memory_warning(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getActiveUsers()
    {
        // get() should still have the "loads all data into memory" warning
        return \App\Models\User::get()->filter(fn($u) => $u->active);
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

        // get() should still have the memory warning
        $recommendation = $issues[0]->recommendation;
        $this->assertStringContainsString('loads all data into memory', $recommendation);
    }

    // ========================================================================
    // POSITIVE RELATIONSHIP NAMING TESTS
    // ========================================================================

    public function test_detects_plural_relationship_names(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function filterRelationships($user)
    {
        // Plural names - should be detected as relationships
        $user->posts->filter(fn($p) => $p->active);
        $user->comments->reject(fn($c) => $c->deleted);
        $user->users->whereIn('status', ['active']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
    }

    public function test_detects_camelcase_plural_relationships(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class OrderService
{
    public function filterItems($order)
    {
        // CamelCase plural names - should be detected
        $order->orderItems->filter(fn($i) => $i->shipped);
        $order->lineItems->reject(fn($i) => $i->cancelled);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OrderService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
    }

    public function test_detects_known_relationship_names(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CommentService
{
    public function filterRelationships($comment)
    {
        // Known singular relationship names - should be detected
        $comment->parent->filter(fn($p) => $p->visible);
        $comment->author->reject(fn($a) => $a->banned);
        $comment->owner->whereIn('status', ['active']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CommentService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
    }

    public function test_detects_irregular_plural_relationships(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class CategoryService
{
    public function filterRelationships($category)
    {
        // Irregular plurals - should be detected
        $category->children->filter(fn($c) => $c->active);
        $category->people->reject(fn($p) => $p->inactive);
        $category->media->whereIn('type', ['image']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CategoryService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
    }

    public function test_ignores_short_property_names(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DataService
{
    public function process($obj)
    {
        // Short names (less than 4 chars) - should NOT be flagged
        $obj->ids->filter(fn($i) => $i > 0);
        $obj->abc->reject(fn($a) => $a->empty);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DataService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_status_like_words(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ReportService
{
    public function process($report)
    {
        // Words ending in 's' but not plural relationships
        $report->status->filter(fn($s) => $s->current);
        $report->news->reject(fn($n) => $n->old);
        $report->analysis->whereIn('type', ['quick']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ReportService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_snake_case_plural_relationships(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function filterRelationships($user)
    {
        // Snake case plural names - should be detected
        $user->user_roles->filter(fn($r) => $r->active);
        $user->order_items->reject(fn($i) => $i->cancelled);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UserService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
    }

    public function test_ignores_non_plural_generic_names(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class EntityService
{
    public function process($entity)
    {
        // Generic non-plural names - should NOT be flagged
        $entity->payload->filter(fn($p) => $p->valid);
        $entity->extra->reject(fn($e) => $e->empty);
        $entity->detail->whereIn('type', ['main']);
        $entity->result->filter(fn($r) => $r->success);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/EntityService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_ies_plural_relationships(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ProductService
{
    public function filterRelationships($product)
    {
        // -ies plural pattern - should be detected
        $product->categories->filter(fn($c) => $c->active);
        $product->entries->reject(fn($e) => $e->deleted);
        $product->companies->whereIn('status', ['active']);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ProductService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(3, $issues);
    }

    public function test_detects_es_plural_relationships(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class WarehouseService
{
    public function filterRelationships($warehouse)
    {
        // -es plural pattern - should be detected
        $warehouse->boxes->filter(fn($b) => $b->full);
        $warehouse->batches->reject(fn($b) => $b->expired);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/WarehouseService.php' => $code]);
        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
    }
}
