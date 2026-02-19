<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Contracts\Config\Repository as Config;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\ParsesPHPStanResults;
use ShieldCI\Support\PHPStanRunner;

/**
 * Consolidated PHPStan analyzer that replaces 13 separate analyzers.
 *
 * This analyzer runs PHPStan once and categorizes issues into:
 * - Dead Code
 * - Deprecated Code
 * - Invalid Method Calls
 * - Invalid Function Calls
 * - Invalid Property Access
 * - Invalid Offsets
 * - Undefined Variables
 * - Undefined Constants
 * - Missing Return Statements
 * - Invalid Imports
 * - Invalid Method Overrides
 * - Foreach Iterable Issues
 * - Missing Model Relations
 *
 * Configuration allows enabling/disabling specific categories.
 */
class PHPStanAnalyzer extends AbstractFileAnalyzer
{
    use ParsesPHPStanResults;

    /**
     * All issue categories with their patterns and severity levels.
     *
     * @var array<string, array{severity: Severity, patterns?: array<string>, regex?: string, name: string, description: string}>
     */
    private const ISSUE_CATEGORIES = [
        'dead-code' => [
            'name' => 'Dead Code',
            'description' => 'Unreachable code, unused variables, and statements with no effect',
            'severity' => Severity::Medium,
            'patterns' => [
                '*does not do anything*',
                'Unreachable statement*',
                '* is unused*',
                'Empty array passed*',
                'Dead catch*',
                '*has no effect*',
                '*will never be executed*',
                'Left side of && is always *',
                'Left side of || is always *',
                'Right side of && is always *',
                'Right side of || is always *',
                'Result of && is always *',
                'Result of || is always *',
                'Negated boolean expression is always *',
                'Strict comparison using * will always evaluate to *',
                'Comparison operation * between * and * is always *',
            ],
        ],

        'deprecated-code' => [
            'name' => 'Deprecated Code',
            'description' => 'Usage of deprecated methods, classes, and functions',
            'severity' => Severity::High,
            'regex' => '#\s*deprecated\s*#i',
        ],

        'foreach-iterable' => [
            'name' => 'Foreach Iterable Issues',
            'description' => 'Invalid foreach usage with non-iterable values',
            'severity' => Severity::High,
            'patterns' => [
                'Argument of an invalid type * supplied for foreach*',
                'Cannot use * in a foreach loop*',
                'Iterating over * but * does not specify*',
            ],
        ],

        'invalid-function-calls' => [
            'name' => 'Invalid Function Calls',
            'description' => 'Calls to undefined functions or invalid function parameters',
            'severity' => Severity::High,
            'patterns' => [
                'Function * not found*',
                'Function * invoked with * parameter*',
                'Parameter * of function * expects*',
                'Missing parameter * in call to function *',
                'Unknown parameter * in call to function *',
                'Parameter * of * expects * given*',
                'Result of function * (void) is used*',
                'Cannot call function * on *',
            ],
        ],

        'invalid-imports' => [
            'name' => 'Invalid Imports',
            'description' => 'Usage of non-existent classes, interfaces, or traits',
            'severity' => Severity::Critical,
            'patterns' => [
                'Used * not found*',
                'Class * not found*',
                'Interface * not found*',
                'Trait * not found*',
                'Instantiated class * not found*',
                'Reflection class * does not exist*',
            ],
        ],

        'invalid-method-calls' => [
            'name' => 'Invalid Method Calls',
            'description' => 'Calls to undefined methods or invalid method parameters',
            'severity' => Severity::Critical,
            'patterns' => [
                'Method * invoked with *',
                'Parameter * of method * is passed by reference, so *',
                'Unable to resolve the template *',
                'Missing parameter * in call to *',
                'Unknown parameter * in call to *',
                'Call to method * on an unknown class *',
                'Cannot call method * on *',
                'Call to private method * of parent class *',
                'Call to an undefined method *',
                'Call to * method * of class *',
                'Call to an undefined static method *',
                'Static call to instance method *',
                'Calling *::* outside of class scope*',
                '*::* calls parent::* but *',
                'Call to static method * on an unknown class *',
                'Cannot call static method * on *',
                'Cannot call abstract* method *::*',
                '* invoked with * parameter* required*',
                'Parameter * of * expects * given*',
                'Result of * (void) is used*',
                'Result of method *',
            ],
        ],

        'invalid-method-overrides' => [
            'name' => 'Invalid Method Overrides',
            'description' => 'Incompatible method overrides in child classes',
            'severity' => Severity::High,
            'patterns' => [
                'Return type * of method *::* is not covariant with*',
                'Parameter * of method *::* is not contravariant with*',
                'Method *::* overrides method *::* but is missing parameter *',
                'Method *::* has parameter * with no type*',
                'Overridden method *::* is deprecated*',
                'Method *::* with return type * returns * but should return *',
                'Method *::* extends method *::* but changes visibility from *',
                'Method *::* overrides *::* with different parameter *',
                'Method *::* is not compatible with *::*',
                'Method *::* never returns * so it can be removed from*',
            ],
        ],

        'invalid-offset-access' => [
            'name' => 'Invalid Offset Access',
            'description' => 'Invalid array or object offset access',
            'severity' => Severity::High,
            'patterns' => [
                'Cannot assign * offset * to *',
                'Cannot access offset * on *',
                'Offset * does not exist on *',
                'Offset * might not exist on *',
                'Offset * on * always exists*',
                'Cannot unset offset * on *',
                'Offset * on * does not accept type *',
                'Offset string on * in isset*',
            ],
        ],

        'invalid-property-access' => [
            'name' => 'Invalid Property Access',
            'description' => 'Access to undefined or inaccessible properties',
            'severity' => Severity::High,
            'patterns' => [
                'Access to * property *',
                'Cannot access property * on *',
                'Access to an undefined property *',
                'Access to undefined property *',
                'Property * of class * is unused*',
                'Property * does not accept *',
                'Static property * does not exist*',
                'Access to static property * on *',
                'Property * on * is not defined*',
                'Property * in * is not readable*',
                'Property * in * is not writable*',
            ],
        ],

        'missing-model-relation' => [
            'name' => 'Missing Model Relations',
            'description' => 'References to undefined Eloquent model relations',
            'severity' => Severity::High,
            'patterns' => [
                'Relation * is not found in * model*',
                'Call to an undefined method *Model::*',
                'Access to an undefined property *Model::$*',
            ],
        ],

        'missing-return-statement' => [
            'name' => 'Missing Return Statements',
            'description' => 'Methods missing required return statements',
            'severity' => Severity::High,
            'patterns' => [
                '* return statement is missing*',
                'Method * should return * but return statement is missing*',
                'Function * should return * but return statement is missing*',
            ],
        ],

        'undefined-constant' => [
            'name' => 'Undefined Constants',
            'description' => 'References to undefined constants',
            'severity' => Severity::High,
            'patterns' => [
                '* undefined constant *',
                'Using * outside of class scope*',
                'Access to constant * on an unknown class *',
                'Constant * does not exist*',
                'Class constant * not found*',
            ],
        ],

        'undefined-variable' => [
            'name' => 'Undefined Variables',
            'description' => 'References to undefined variables',
            'severity' => Severity::High,
            'patterns' => [
                'Undefined variable*',
                'Variable * might not be defined*',
                'Variable * in isset* always exists*',
            ],
        ],
    ];

    public function __construct(
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'phpstan',
            name: 'PHPStan Static Analyzer',
            description: 'Comprehensive static analysis using PHPStan to detect type errors, undefined references, and code quality issues',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['phpstan', 'static-analysis', 'type-safety', 'reliability'],
            timeToFix: 120
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $basePath = $this->getBasePath();

        if ($basePath === '') {
            return $this->error('Unable to determine base path for PHPStan analysis');
        }

        $runner = new PHPStanRunner($basePath);

        // Check if PHPStan is available
        if (! $runner->isAvailable()) {
            return $this->warning(
                'PHPStan is not available',
                [$this->createIssue(
                    message: 'PHPStan binary not found',
                    location: new Location($basePath),
                    severity: Severity::Medium,
                    recommendation: 'PHPStan is included with ShieldCI. If you\'re seeing this error, ensure you\'ve run `composer install` to install all dependencies. If the issue persists, verify that `vendor/bin/phpstan` exists in your project.',
                    metadata: []
                )]
            );
        }

        // Get configuration with proper type handling
        $levelConfig = $this->config->get('shieldci.analyzers.reliability.phpstan.level', 5);
        $level = is_int($levelConfig) ? $levelConfig : (is_numeric($levelConfig) ? (int) $levelConfig : 5);

        // Use PHPStan-specific paths if configured, otherwise fall back to global paths
        $pathsConfig = $this->config->get(
            'shieldci.analyzers.reliability.phpstan.paths',
            $this->config->get('shieldci.paths.analyze', ['app'])
        );
        /** @var array<string> $paths */
        $paths = is_array($pathsConfig) ? $pathsConfig : [$pathsConfig];

        $enabledCategories = (array) $this->config->get('shieldci.analyzers.reliability.phpstan.categories', array_keys(self::ISSUE_CATEGORIES));
        $disabledCategories = (array) $this->config->get('shieldci.analyzers.reliability.phpstan.disabled_categories', []);

        // Filter categories
        /** @var array<string> $activeCategories */
        $activeCategories = array_values(array_diff($enabledCategories, $disabledCategories));

        try {
            // Run PHPStan once on all paths
            $runner->analyze($paths, $level);

            // Categorize all issues
            $categorizedIssues = $this->categorizeIssues($runner, $activeCategories);
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('PHPStan analysis failed: %s', $e->getMessage()),
                [
                    'exception' => get_class($e),
                    'error_message' => $e->getMessage(),
                ]
            );
        }

        // Count total issues
        $totalIssues = array_sum(array_map(fn ($issues) => $issues->count(), $categorizedIssues));

        if ($totalIssues === 0) {
            return $this->passed('No PHPStan issues detected');
        }

        // Create issue objects for each category
        $allIssueObjects = [];
        foreach ($categorizedIssues as $category => $issues) {
            if ($issues->isEmpty()) {
                continue;
            }

            $categoryConfig = self::ISSUE_CATEGORIES[$category];
            $issueObjects = $this->createIssuesFromPHPStanResults(
                $issues,
                $categoryConfig['name'].' detected',
                $categoryConfig['severity'],
                fn (string $message) => $this->getRecommendation($category, $message)
            );

            $allIssueObjects = array_merge($allIssueObjects, $issueObjects);
        }

        $displayedCount = count($allIssueObjects);
        $message = $this->formatIssueCountMessage($totalIssues, $displayedCount, 'PHPStan issue(s)');

        return $this->resultBySeverity($message, $allIssueObjects);
    }

    /**
     * Categorize PHPStan issues by matching patterns.
     *
     * @param  array<string>  $activeCategories
     * @return array<string, \Illuminate\Support\Collection>
     */
    private function categorizeIssues(PHPStanRunner $runner, array $activeCategories): array
    {
        $categorized = [];

        foreach ($activeCategories as $category) {
            if (! isset(self::ISSUE_CATEGORIES[$category])) {
                continue;
            }

            $config = self::ISSUE_CATEGORIES[$category];

            // Filter by patterns or regex
            if (isset($config['regex'])) {
                $categorized[$category] = $runner->filterByRegex($config['regex']);
            } elseif (isset($config['patterns'])) {
                $categorized[$category] = $runner->filterByPattern($config['patterns']);
            } else {
                $categorized[$category] = collect();
            }
        }

        return $categorized;
    }

    /**
     * Get recommendation message based on category and PHPStan message.
     */
    private function getRecommendation(string $category, string $message): string
    {
        $recommendations = [
            'dead-code' => [
                'Unreachable statement' => 'Remove unreachable code - this statement will never be executed. Check for early returns, throws, or exits before this code.',
                'is unused' => 'Remove unused code - this variable, parameter, or import is never used. Clean up your code by removing it.',
                'does not do anything' => 'This statement has no effect - it does not modify state or return a value. Either use the result or remove the statement.',
                'always' => 'Remove redundant condition - this expression always evaluates to the same value. Simplify your logic or remove the dead branch.',
            ],
            'deprecated-code' => [
                'method' => 'Replace deprecated method - this method is marked as deprecated and may be removed in future versions. Check the documentation for the recommended alternative.',
                'class' => 'Replace deprecated class/interface - this type is marked as deprecated. Migrate to the recommended alternative to ensure compatibility with future versions.',
                'function' => 'Replace deprecated function - this function is marked as deprecated. Use the recommended alternative function.',
                'constant' => 'Replace deprecated constant - this constant is marked as deprecated. Use the recommended alternative constant.',
            ],
            'foreach-iterable' => [
                'invalid type' => 'Fix the foreach loop - the variable being iterated is not of an iterable type. Ensure the variable is an array, Traversable, or Iterator before using it in a foreach loop.',
                'Cannot use' => 'Fix the foreach loop - the value cannot be used in a foreach loop. Check the type of the variable and ensure it implements Traversable or is an array.',
                'does not specify' => 'Fix the foreach loop - the type does not specify that it is iterable. Add proper type hints or ensure the variable is iterable before using it in a foreach loop.',
            ],
            'invalid-function-calls' => [
                'not found' => 'Fix the function call - the function does not exist. Check for typos in the function name or ensure the function is defined.',
                'Parameter' => 'Fix the function parameters - they do not match the function signature. Check the parameter types, order, and count.',
            ],
            'invalid-imports' => [
                'not found' => 'Fix the import - the class, interface, or trait does not exist. Check for typos in the import statement or ensure the file exists.',
            ],
            'invalid-method-calls' => [
                'Eloquent\Builder' => 'Fix the method call - if this is an Eloquent local scope, narrow the Builder type with an inline @var annotation: /** @var \Illuminate\Database\Eloquent\Builder<\App\Models\YourModel> $query */. This is the simplest fix when calling scopes inside closures. Alternatively, add a @method annotation to the model: /** @method static \Illuminate\Database\Eloquent\Builder<static> sent() */. ShieldCI includes Larastan which recognizes most scopes automatically, but scopes inside closures, traits, or parent models may need these annotations.',
                'undefined method' => 'Fix the method call - the method does not exist on this class. Check for typos in the method name or ensure the method is defined.',
                'Parameter' => 'Fix the method parameters - they do not match the method signature. Check the parameter types, order, and count.',
                'private' => 'Fix the method visibility - you are calling a private/protected method outside its scope.',
                'protected' => 'Fix the method visibility - you are calling a private/protected method outside its scope.',
            ],
            'invalid-method-overrides' => [
                'covariant' => 'Fix the method override - the return type is not covariant with the parent method. Ensure the return type is compatible.',
                'contravariant' => 'Fix the method override - the parameter type is not contravariant with the parent method. Ensure the parameter type is compatible.',
                'visibility' => 'Fix the method override - you cannot change method visibility when overriding. Use the same visibility as the parent method.',
            ],
            'invalid-offset-access' => [
                'does not exist' => 'Fix the offset access - the offset does not exist on this array or object. Check the offset key or ensure it exists before accessing.',
                'might not exist' => 'Fix the offset access - the offset might not exist. Add an isset() check before accessing the offset.',
            ],
            'invalid-property-access' => [
                'Access to an undefined property' => 'Fix the property access - the property does not exist on this class. If this is an Eloquent Attribute accessor, add a generic return type PHPDoc: /** @return Attribute<string, never> */. Larastan requires generic Attribute<TGet, TSet> annotations to recognize accessor-defined properties.',
                'undefined property' => 'Fix the property access - the property does not exist on this class. Check for typos in the property name or ensure the property is defined.',
                'private' => 'Fix the property visibility - you are accessing a private/protected property outside its scope.',
                'protected' => 'Fix the property visibility - you are accessing a private/protected property outside its scope.',
            ],
            'missing-model-relation' => [
                'not found' => 'Fix the model relation - the relation does not exist on this model. Ensure the relation method is defined in the model.',
            ],
            'missing-return-statement' => [
                'return statement is missing' => 'Add a return statement - this method is expected to return a value but is missing a return statement.',
            ],
            'undefined-constant' => [
                'undefined constant' => 'Fix the constant reference - the constant does not exist. Check for typos in the constant name or ensure the constant is defined.',
            ],
            'undefined-variable' => [
                'Undefined variable' => 'Fix the variable reference - the variable is used before it is defined. Ensure the variable is initialized before use.',
                'might not be defined' => 'Fix the variable reference - the variable might not be defined in all code paths. Ensure the variable is initialized in all branches.',
            ],
        ];

        // Try to find a specific recommendation
        if (isset($recommendations[$category])) {
            foreach ($recommendations[$category] as $keyword => $recommendation) {
                if (str_contains($message, $keyword)) {
                    return $recommendation.' PHPStan message: '.$message;
                }
            }
        }

        // Fallback to generic recommendation
        $categoryName = self::ISSUE_CATEGORIES[$category]['name'] ?? 'issue';

        return 'Fix the '.$categoryName.' detected by PHPStan. PHPStan message: '.$message;
    }
}
